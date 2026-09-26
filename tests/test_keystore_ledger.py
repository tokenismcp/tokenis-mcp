# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Key management (every supported KMS) and the persisted, encrypted ledger."""
import base64
import hashlib
import http.server
import json
import os
import stat
import threading
from typing import ClassVar

import pytest

from tokenis.gateway.demo import DEMO_SCHEMA, DEMO_SETTINGS, demo_rows
from tokenis.gateway.service import AdmissionDenied, TokenisGatewayService
from tokenis.keystore import (
    AwsKmsWrapper,
    AzureKeyVaultWrapper,
    GcpKmsWrapper,
    KeystoreError,
    LocalPassphraseWrapper,
    VaultTransitWrapper,
    create_keystore,
    keystore_header,
    load_keystore,
    rewrap_keystore,
)
from tokenis.ledger import LedgerError, load_ledger, write_ledger

PASS = b"correct horse battery staple!!"


def roundtrip(wrapper, tmp_path, tenant="acme"):
    path = tmp_path / "keystore.json"
    create_keystore(path, wrapper, tenant)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    secrets = load_keystore(path, wrapper, tenant)
    assert len(secrets.elgamal_private_key) == 32 and len(secrets.tokenizer_key) == 32
    assert "redacted" in repr(secrets)
    # No secret appears in the file.
    text = path.read_text()
    for value in (secrets.tokenizer_key, secrets.audit_key, secrets.ledger_key):
        assert base64.b64encode(value).decode() not in text and value.hex() not in text
    return path, secrets


# -- wrappers -------------------------------------------------------------------------------


def test_local_keystore_lifecycle(tmp_path):
    wrapper = LocalPassphraseWrapper(PASS)
    path, secrets = roundtrip(wrapper, tmp_path)
    with pytest.raises(KeystoreError, match="refusing to overwrite"):
        create_keystore(path, wrapper, "acme")
    salt = base64.b64decode(keystore_header(path)["wrapper"]["salt"])
    again = load_keystore(path, LocalPassphraseWrapper(PASS, salt), "acme")
    assert again.ledger_key == secrets.ledger_key
    with pytest.raises(KeystoreError, match="wrong passphrase"):
        load_keystore(path, LocalPassphraseWrapper(b"not the passphrase at all!!", salt), "acme")
    with pytest.raises(KeystoreError, match="tenant"):
        load_keystore(path, wrapper, "other")


def test_secrets_cannot_be_swapped_between_slots(tmp_path):
    wrapper = LocalPassphraseWrapper(PASS)
    path, _ = roundtrip(wrapper, tmp_path)
    doc = json.loads(path.read_text())
    doc["secrets"]["tokenizer_key"], doc["secrets"]["audit_key"] = (
        doc["secrets"]["audit_key"], doc["secrets"]["tokenizer_key"])
    path.write_text(json.dumps(doc))
    with pytest.raises(KeystoreError):
        load_keystore(path, wrapper, "acme")


def test_rewrap_moves_keys_without_changing_them(tmp_path):
    old, new = LocalPassphraseWrapper(PASS), LocalPassphraseWrapper(b"a brand new passphrase 2026!")
    path, before = roundtrip(old, tmp_path)
    rewrap_keystore(path, old, new, "acme")
    after = load_keystore(path, new, "acme")
    assert after.elgamal_private_key == before.elgamal_private_key
    with pytest.raises(KeystoreError):
        load_keystore(path, old, "acme")


def test_aws_kms(tmp_path):
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        client = boto3.client("kms", region_name="ap-northeast-2")
        key_id = client.create_key(Description="tokenis")["KeyMetadata"]["KeyId"]
        wrapper = AwsKmsWrapper(key_id, "ap-northeast-2", client=client)
        path, _secrets = roundtrip(wrapper, tmp_path)
        doc = json.loads(path.read_text())
        assert doc["wrapper"] == {"kind": "aws-kms", "key_id": key_id, "region": "ap-northeast-2"}
        # The encryption context binds the tenant: another tenant's config
        # cannot unwrap this keystore even with KMS access.
        blob = base64.b64decode(doc["secrets"]["tokenizer_key"])
        with pytest.raises(KeystoreError):
            wrapper.unwrap(blob, {"tokenis": "keystore-v1", "tenant": "other", "secret": "tokenizer_key"})


class _FakeVault(http.server.BaseHTTPRequestHandler):
    """Vault Transit's encrypt/decrypt contract, including associated data."""

    store: ClassVar[dict] = {}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("X-Vault-Token") != "s.test":
            payload = b'{"errors":["permission denied"]}'
            self.send_response(403)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        op = self.path.split("/")[3]
        if op == "encrypt":
            handle = f"vault:v1:{len(self.store)}"
            self.store[handle] = (body["plaintext"], body["associated_data"])
            data = {"ciphertext": handle}
        else:
            plaintext, aad = self.store.get(body["ciphertext"], (None, None))
            if aad != body["associated_data"]:
                payload = b'{"errors":["cipher: message authentication failed"]}'
                self.send_response(400)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            data = {"plaintext": plaintext}
        payload = json.dumps({"data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def test_vault_transit(tmp_path):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    address = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        roundtrip(VaultTransitWrapper(address, "tokenis", token="s.test"), tmp_path)
        with pytest.raises(KeystoreError, match="403"):
            VaultTransitWrapper(address, "tokenis", token="s.wrong").wrap(b"x", {})
    finally:
        server.shutdown()
    with pytest.raises(KeystoreError, match="https"):
        VaultTransitWrapper("http://vault.example.com", "k", token="t")


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeGcp:
    """Cloud KMS client stand-in: authenticated encryption keyed per call."""

    def __init__(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.aead, self.nonce = AESGCM(os.urandom(32)), os.urandom(12)

    def encrypt(self, request):
        return _Obj(ciphertext=self.aead.encrypt(self.nonce, request["plaintext"],
                                                 request["additional_authenticated_data"]))

    def decrypt(self, request):
        return _Obj(plaintext=self.aead.decrypt(self.nonce, request["ciphertext"],
                                                request["additional_authenticated_data"]))


def test_gcp_kms_contract(tmp_path):
    roundtrip(GcpKmsWrapper("projects/p/locations/l/keyRings/r/cryptoKeys/k", client=_FakeGcp()),
              tmp_path)


def test_azure_key_vault_contract(tmp_path):
    pytest.importorskip("azure.keyvault.keys")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import utils

    pkcs1 = padding.PKCS1v15()

    class Client:
        """Stands in for CryptographyClient: the private key stays inside."""

        def wrap_key(self, _alg, payload):
            return _Obj(encrypted_key=key.public_key().encrypt(payload, oaep))

        def unwrap_key(self, _alg, blob):
            return _Obj(key=key.decrypt(blob, oaep))

        def sign(self, _alg, digest):
            return _Obj(signature=key.sign(digest, pkcs1, utils.Prehashed(hashes.SHA256())))

        def verify(self, _alg, digest, signature):
            try:
                key.public_key().verify(signature, digest, pkcs1, utils.Prehashed(hashes.SHA256()))
                return _Obj(is_valid=True)
            except InvalidSignature:
                return _Obj(is_valid=False)

    wrapper = AzureKeyVaultWrapper("https://v.vault.azure.net", "tokenis", client=Client())
    path, _ = roundtrip(wrapper, tmp_path)
    blob = base64.b64decode(json.loads(path.read_text())["secrets"]["audit_key"])
    with pytest.raises(KeystoreError, match="not produced by this vault key"):
        wrapper.unwrap(blob, {"tokenis": "keystore-v1", "tenant": "acme", "secret": "tokenizer_key"})

    # Regression (security review): with only the public key, an attacker
    # could wrap a secret of their choosing. Without the vault's signature
    # it is now refused.
    ctx = {"tokenis": "keystore-v1", "tenant": "acme", "secret": "tokenizer_key"}
    forged_payload = hashlib.sha256(json.dumps(ctx, sort_keys=True).encode()).digest() + b"\x00" * 32
    forged_wrapped = key.public_key().encrypt(forged_payload, oaep)
    forged = bytes([2]) + len(forged_wrapped).to_bytes(2, "big") + forged_wrapped + b"\x01" * 256
    with pytest.raises(KeystoreError, match="not produced by this vault key"):
        wrapper.unwrap(forged, ctx)


# -- ledger ---------------------------------------------------------------------------------


@pytest.fixture
def keys(tmp_path):
    wrapper = LocalPassphraseWrapper(PASS)
    _, secrets = roundtrip(wrapper, tmp_path, tenant=DEMO_SETTINGS.tenant)
    return secrets


def loaded(secrets, **kw):
    svc = TokenisGatewayService(DEMO_SCHEMA, secrets.tokenizer_key, DEMO_SETTINGS,
                                private_key=secrets.elgamal_private_key, **kw)
    svc.ingest_many((r.pop("id"), r, r.pop("embedding")) for r in demo_rows())
    return svc


def test_ledger_serves_the_same_answers_without_the_plaintext(tmp_path, keys):
    source = loaded(keys)
    manifest = write_ledger(source, tmp_path / "ledger", keys.ledger_key)
    assert manifest["records"] == 8
    payload = (tmp_path / "ledger" / "payload.bin").read_bytes()
    for plaintext in (b"Acme Corp", b"finance", b"Seoul-Gangnam", b"1000000"):
        assert plaintext not in payload
    served = load_ledger(tmp_path / "ledger", DEMO_SCHEMA, keys.ledger_key,
                         keys.elgamal_private_key, keys.tokenizer_key, DEMO_SETTINGS)
    for call in (
        ("aggregate", {"function": "sum", "column": "revenue_2025", "filters": {"industry": "finance"}}),
        ("group_by", {"key": "industry", "column": "revenue_2024"}),
        ("compare_periods", {"column_a": "revenue_2024", "column_b": "revenue_2025",
                             "filters": {"industry": "tech"}}),
    ):
        assert served.invoke(*call[:1], "a", call[1]) == loaded(keys).invoke(*call[:1], "a", call[1])
    token = source._tokenizer.tokenize("customer_name", source._scope, "Acme Corp")
    assert served.invoke("similarity_search", "a", {"token": token, "top_k": 2})["results"]
    fresh = load_ledger(tmp_path / "ledger", DEMO_SCHEMA, keys.ledger_key,
                        keys.elgamal_private_key, keys.tokenizer_key, DEMO_SETTINGS)
    with pytest.raises(RuntimeError, match="re-run ingest"):
        fresh.ingest("x", {})


def test_ledger_keeps_admission_history_compatible(tmp_path, keys):
    """A ledger-backed restart must continue the same D2 history as the
    source-backed gateway (same fingerprint)."""
    state = tmp_path / "state"
    first = loaded(keys, state_dir=state)
    write_ledger(first, tmp_path / "ledger", keys.ledger_key)
    first.invoke("aggregate", "m", {"function": "sum", "column": "revenue_2025",
                                    "filters": {"region": "Seoul-Gangnam"}})
    served = load_ledger(tmp_path / "ledger", DEMO_SCHEMA, keys.ledger_key,
                         keys.elgamal_private_key, keys.tokenizer_key, DEMO_SETTINGS,
                         state_dir=state)
    served.seal()  # would raise StateMismatchError if the fingerprint differed
    assert len(served.trace) == 1


def test_tampered_or_mismatched_ledgers_are_refused(tmp_path, keys):
    write_ledger(loaded(keys), tmp_path / "ledger", keys.ledger_key)
    args = (DEMO_SCHEMA, keys.ledger_key, keys.elgamal_private_key, keys.tokenizer_key)
    manifest_path = tmp_path / "ledger" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"] = 9
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(LedgerError, match="modified|wrong ledger key"):
        load_ledger(tmp_path / "ledger", *args, DEMO_SETTINGS)
    write_ledger(loaded(keys), tmp_path / "ledger", keys.ledger_key)
    with pytest.raises(LedgerError, match="wrong ledger key"):
        load_ledger(tmp_path / "ledger", DEMO_SCHEMA, os.urandom(32), keys.elgamal_private_key,
                    keys.tokenizer_key, DEMO_SETTINGS)
    from dataclasses import replace

    with pytest.raises(LedgerError, match="tenant"):
        load_ledger(tmp_path / "ledger", *args, replace(DEMO_SETTINGS, tenant="other"))
    other_key = TokenisGatewayService(DEMO_SCHEMA, keys.tokenizer_key, DEMO_SETTINGS)
    del other_key
    with pytest.raises(ValueError, match="different key"):
        from tokenis._core import PrivateKey

        load_ledger(tmp_path / "ledger", DEMO_SCHEMA, keys.ledger_key,
                    PrivateKey.generate().export_secret_bytes(), keys.tokenizer_key, DEMO_SETTINGS)


def test_denials_still_apply_to_a_ledger(tmp_path, keys):
    write_ledger(loaded(keys), tmp_path / "ledger", keys.ledger_key)
    served = load_ledger(tmp_path / "ledger", DEMO_SCHEMA, keys.ledger_key,
                         keys.elgamal_private_key, keys.tokenizer_key, DEMO_SETTINGS)
    with pytest.raises(AdmissionDenied):
        served.invoke("aggregate", "a", {"function": "sum", "column": "revenue_2025",
                                         "filters": {"industry": "retail"}})
