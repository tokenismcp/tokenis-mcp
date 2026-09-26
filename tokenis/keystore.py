# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Key management: the gateway's secrets, wrapped by a key-management
service and kept in a keystore file.

A gateway has four secrets:

- ``elgamal_private_key`` -- decrypts aggregates (32 bytes);
- ``tokenizer_key`` -- the PRF key behind every token;
- ``audit_key`` -- signs the disclosure trace;
- ``ledger_key`` -- encrypts a persisted ledger (see :mod:`tokenis.ledger`).

``tokenis-mcp secrets init`` generates all four and stores each *wrapped*
(encrypted) by a :class:`KeyWrapper` -- AWS KMS, HashiCorp Vault Transit,
Google Cloud KMS, Azure Key Vault, or a passphrase-protected local file.
Unwrapping needs the KMS, so the keystore file alone is useless to whoever
copies it; revoking the gateway's KMS permission revokes the gateway.

Every wrap binds the tenant and the secret's name as additional
authenticated data (where the service supports it), so a wrapped value
cannot be swapped between tenants or between secret slots.

The unwrapped secrets live in this process's memory for its lifetime (the
decryption key is handed to the Rust core, which zeroes it on drop); a
hardware-isolated decryption path is out of scope.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Protocol

SECRET_NAMES = ("elgamal_private_key", "tokenizer_key", "audit_key", "ledger_key")
KEYSTORE_VERSION = 1


class KeystoreError(RuntimeError):
    """The keystore is missing, malformed, or cannot be unwrapped."""


class KeyWrapper(Protocol):
    """Encrypts and decrypts small secrets under a key the wrapper holds (or
    reaches through a key-management service)."""

    kind: str

    def describe(self) -> Dict[str, str]:
        """Public, non-secret identification of the wrapping key."""
        ...

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes: ...

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes: ...


def _aad(context: Mapping[str, str]) -> bytes:
    return json.dumps(dict(sorted(context.items())), separators=(",", ":")).encode()


# -- local, passphrase-protected ------------------------------------------------------


class LocalPassphraseWrapper:
    """AES-256-GCM under a key derived from a passphrase with scrypt. For
    single-server installs without a KMS; the passphrase comes from an
    environment variable (inject it from your secret manager)."""

    kind = "local"

    def __init__(self, passphrase: bytes, salt: Optional[bytes] = None) -> None:
        if len(passphrase) < 16:
            raise KeystoreError("the keystore passphrase must be at least 16 bytes")
        self.salt = salt or secrets.token_bytes(16)
        self._key = hashlib.scrypt(passphrase, salt=self.salt, n=2**15, r=8, p=1,
                                   maxmem=64 * 1024 * 1024, dklen=32)

    def describe(self) -> Dict[str, str]:
        return {"kdf": "scrypt-n32768-r8-p1", "salt": base64.b64encode(self.salt).decode()}

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, _aad(context))

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            return AESGCM(self._key).decrypt(blob[:12], blob[12:], _aad(context))
        except (InvalidTag, ValueError) as exc:
            raise KeystoreError("cannot unwrap: wrong passphrase or tampered keystore") from exc


# -- AWS KMS ------------------------------------------------------------------------------


class AwsKmsWrapper:
    """AWS KMS ``Encrypt``/``Decrypt`` with an encryption context. Credentials
    come from the standard AWS chain (instance/pod role, environment, ...).
    Needs ``pip install 'tokenis-mcp[aws]'``."""

    kind = "aws-kms"

    def __init__(self, key_id: str, region: Optional[str] = None, client: Any = None) -> None:
        if client is None:
            import boto3

            client = boto3.client("kms", region_name=region)
        self._client = client
        self.key_id = key_id
        self.region = region or ""

    def describe(self) -> Dict[str, str]:
        return {"key_id": self.key_id, "region": self.region}

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes:
        out = self._client.encrypt(KeyId=self.key_id, Plaintext=plaintext,
                                   EncryptionContext=dict(context))
        return bytes(out["CiphertextBlob"])

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes:
        try:
            out = self._client.decrypt(CiphertextBlob=blob, KeyId=self.key_id,
                                       EncryptionContext=dict(context))
        except Exception as exc:
            raise KeystoreError(f"AWS KMS refused to decrypt: {exc}") from exc
        return bytes(out["Plaintext"])


# -- HashiCorp Vault Transit ---------------------------------------------------------


class VaultTransitWrapper:
    """Vault's Transit secrets engine over its HTTP API (no client library
    needed). The token comes from an environment variable -- in production a
    short-lived token from Vault's Kubernetes or AppRole auth."""

    kind = "vault-transit"

    def __init__(self, address: str, key_name: str, token: str, mount: str = "transit",
                 namespace: Optional[str] = None, timeout: float = 15.0) -> None:
        if not address.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise KeystoreError("vault address must be https:// (plain http only for localhost)")
        if not token:
            raise KeystoreError("no Vault token")
        self.address = address.rstrip("/")
        self.key_name = key_name
        self.mount = mount.strip("/")
        self.namespace = namespace
        self._token = token
        self._timeout = timeout

    def describe(self) -> Dict[str, str]:
        return {"address": self.address, "mount": self.mount, "key": self.key_name,
                "namespace": self.namespace or ""}

    def _post(self, op: str, body: Dict[str, Any]) -> Dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 -- https (or localhost) enforced in __init__
            f"{self.address}/v1/{self.mount}/{op}/{self.key_name}",
            data=json.dumps(body).encode(), method="POST",
            headers={"X-Vault-Token": self._token, "Content-Type": "application/json",
                     **({"X-Vault-Namespace": self.namespace} if self.namespace else {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310 -- configured Vault URL
                return dict(json.load(response)["data"])
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise KeystoreError(f"Vault {op} failed ({exc.code}): {detail}") from exc
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            raise KeystoreError(f"Vault {op} failed: {exc}") from exc

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes:
        data = self._post("encrypt", {
            "plaintext": base64.b64encode(plaintext).decode(),
            "associated_data": base64.b64encode(_aad(context)).decode(),
        })
        return str(data["ciphertext"]).encode()

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes:
        data = self._post("decrypt", {
            "ciphertext": blob.decode(),
            "associated_data": base64.b64encode(_aad(context)).decode(),
        })
        return base64.b64decode(data["plaintext"])


# -- Google Cloud KMS -----------------------------------------------------------------


class GcpKmsWrapper:
    """Cloud KMS symmetric ``encrypt``/``decrypt`` with additional
    authenticated data. Credentials: Application Default Credentials.
    Needs ``pip install 'tokenis-mcp[gcp]'``."""

    kind = "gcp-kms"

    def __init__(self, key_name: str, client: Any = None) -> None:
        if client is None:
            from google.cloud import kms

            client = kms.KeyManagementServiceClient()
        self._client = client
        self.key_name = key_name

    def describe(self) -> Dict[str, str]:
        return {"key_name": self.key_name}

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes:
        out = self._client.encrypt(request={"name": self.key_name, "plaintext": plaintext,
                                            "additional_authenticated_data": _aad(context)})
        return bytes(out.ciphertext)

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes:
        try:
            out = self._client.decrypt(request={"name": self.key_name, "ciphertext": blob,
                                                "additional_authenticated_data": _aad(context)})
        except Exception as exc:
            raise KeystoreError(f"Cloud KMS refused to decrypt: {exc}") from exc
        return bytes(out.plaintext)


# -- Azure Key Vault ------------------------------------------------------------------


class AzureKeyVaultWrapper:
    """Key Vault ``wrapKey``/``unwrapKey`` (RSA-OAEP-256) with an RSA key;
    the key never leaves the vault (or its HSM, on Premium). RSA key wrap
    has no associated data, so the context is authenticated by an HMAC over
    the wrapped value, keyed with material only an unwrap can recover.
    Credentials: ``DefaultAzureCredential``. Needs
    ``pip install 'tokenis-mcp[azure]'``."""

    kind = "azure-keyvault"

    def __init__(self, vault_url: str, key_name: str, client: Any = None) -> None:
        if client is None:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient

            credential = DefaultAzureCredential()
            key = KeyClient(vault_url=vault_url, credential=credential).get_key(key_name)
            client = CryptographyClient(key, credential=credential)
        self._client = client
        self.vault_url = vault_url
        self.key_name = key_name

    def describe(self) -> Dict[str, str]:
        return {"vault_url": self.vault_url, "key_name": self.key_name}

    def wrap(self, plaintext: bytes, context: Mapping[str, str]) -> bytes:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm

        # Bind the context: wrap (context digest || secret) so unwrapping
        # under a different context is detected.
        payload = hashlib.sha256(_aad(context)).digest() + plaintext
        return bytes(self._client.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, payload).encrypted_key)

    def unwrap(self, blob: bytes, context: Mapping[str, str]) -> bytes:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm

        try:
            payload = bytes(self._client.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, blob).key)
        except Exception as exc:
            raise KeystoreError(f"Azure Key Vault refused to unwrap: {exc}") from exc
        if payload[:32] != hashlib.sha256(_aad(context)).digest():
            raise KeystoreError("wrapped secret belongs to a different tenant or slot")
        return payload[32:]


# -- keystore file --------------------------------------------------------------------------


@dataclass
class Secrets:
    elgamal_private_key: bytes
    tokenizer_key: bytes
    audit_key: bytes
    ledger_key: bytes

    def __repr__(self) -> str:
        return "Secrets(<redacted>)"


def _context(tenant: str, name: str) -> Dict[str, str]:
    return {"tokenis": "keystore-v1", "tenant": tenant, "secret": name}


def _generate() -> Dict[str, bytes]:
    from tokenis._core import PrivateKey

    return {
        "elgamal_private_key": PrivateKey.generate().export_secret_bytes(),
        "tokenizer_key": secrets.token_bytes(32),
        "audit_key": secrets.token_bytes(32),
        "ledger_key": secrets.token_bytes(32),
    }


def create_keystore(path: Path, wrapper: KeyWrapper, tenant: str) -> None:
    """Generate fresh secrets, wrap each, and write the keystore (mode 0600).
    Refuses to overwrite an existing keystore: losing one loses every token
    and every persisted ledger."""
    path = Path(path)
    if path.exists():
        raise KeystoreError(f"{path} already exists; refusing to overwrite it")
    values = _generate()
    doc = {
        "version": KEYSTORE_VERSION,
        "tenant": tenant,
        "created": int(time.time()),
        "wrapper": {"kind": wrapper.kind, **wrapper.describe()},
        "secrets": {
            name: base64.b64encode(wrapper.wrap(value, _context(tenant, name))).decode()
            for name, value in values.items()
        },
    }
    _write_private(path, json.dumps(doc, indent=2) + "\n")


def rewrap_keystore(path: Path, old: KeyWrapper, new: KeyWrapper, tenant: str) -> None:
    """Move a keystore to a different wrapping key (KMS migration or key
    rotation) without changing the secrets themselves."""
    values = load_keystore(path, old, tenant)
    doc = json.loads(Path(path).read_text())
    doc["wrapper"] = {"kind": new.kind, **new.describe()}
    doc["secrets"] = {
        name: base64.b64encode(new.wrap(getattr(values, name), _context(tenant, name))).decode()
        for name in SECRET_NAMES
    }
    doc["rewrapped"] = int(time.time())
    _write_private(Path(path), json.dumps(doc, indent=2) + "\n")


def keystore_header(path: Path) -> Dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise KeystoreError(f"cannot read keystore {path}: {exc}") from exc
    if doc.get("version") != KEYSTORE_VERSION:
        raise KeystoreError(f"{path}: unsupported keystore version")
    return dict(doc)


def load_keystore(path: Path, wrapper: KeyWrapper, tenant: str) -> Secrets:
    doc = keystore_header(path)
    if doc.get("tenant") != tenant:
        raise KeystoreError(f"{path} belongs to tenant {doc.get('tenant')!r}, not {tenant!r}")
    if doc["wrapper"]["kind"] != wrapper.kind:
        raise KeystoreError(
            f"{path} is wrapped with {doc['wrapper']['kind']}, but {wrapper.kind} is configured"
        )
    out = {}
    for name in SECRET_NAMES:
        try:
            blob = base64.b64decode(doc["secrets"][name])
        except (KeyError, ValueError) as exc:
            raise KeystoreError(f"{path}: missing or malformed {name}") from exc
        out[name] = wrapper.unwrap(blob, _context(tenant, name))
    return Secrets(**out)


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".keystore-")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
