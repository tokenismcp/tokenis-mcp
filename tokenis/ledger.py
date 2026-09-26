# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The persisted ledger: a dataset after ingestion, stored so the serving
gateway never needs the plaintext source.

``tokenis-mcp ingest`` reads the source once -- in whatever environment the
data owner trusts -- and writes a ledger directory:

- ``manifest.json``: public metadata (format version, tenant, record count,
  schema, the ElGamal public key, payload digest);
- ``payload.bin``: everything else, AES-256-GCM encrypted under the
  keystore's ``ledger_key`` with the manifest as associated data -- sealed
  columns (already EC-ElGamal ciphertexts), the public and token columns,
  the per-column decryption bounds and any embeddings.

A serving gateway loads the ledger with its keystore and never sees a
plaintext sealed value. Editing either file, pairing the ledger with another
tenant's keystore, or changing the schema makes loading fail.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import numpy as np

if TYPE_CHECKING:  # pragma: no cover
    from tokenis.gateway.schema import GatewaySettings, Schema
    from tokenis.gateway.service import TokenisGatewayService

FORMAT = "tokenis-ledger"
VERSION = 1


class LedgerError(RuntimeError):
    """The ledger is missing, tampered with, or does not match this config."""


def schema_descriptor(schema: "Schema") -> Dict[str, Any]:
    return {
        "columns": [
            {"name": c.name, "protection": c.protection, "scale": c.scale,
             "allow_variance": c.allow_variance, "entity": c.entity}
            for c in schema.columns
        ],
        "embedding": schema.embedding_column is not None,
    }


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def write_ledger(service: "TokenisGatewayService", path: Path, ledger_key: bytes) -> Dict[str, Any]:
    """Persist an unsealed, loaded ``service`` to ``path`` (a directory,
    created; an existing ledger there is replaced atomically)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    state = service._export_state()
    arrays: Dict[str, np.ndarray] = {}
    meta: Dict[str, Any] = {"domains": {}, "bounds": state["bounds"]}
    for name, values in state["public"].items():
        index: Dict[str, int] = {}
        arrays[f"pub:{name}"] = np.fromiter(
            (index.setdefault(v, len(index)) for v in values), dtype=np.int32, count=len(values))
        meta["domains"][name] = list(index)
    for name, blob in state["sealed"].items():
        arrays[f"ct:{name}"] = np.frombuffer(blob, dtype=np.uint8)
    for name, blob in state["squares"].items():
        arrays[f"sq:{name}"] = np.frombuffer(blob, dtype=np.uint8)
    if state["embeddings"]:
        tokens, vectors = zip(*state["embeddings"].items())
        meta["embedding_tokens"] = list(tokens)
        arrays["embeddings"] = np.stack(vectors).astype(np.float64)
    buffer = io.BytesIO()
    np.savez(buffer, allow_pickle=False, **arrays)
    body = _canonical(meta)
    plaintext = len(body).to_bytes(8, "big") + body + buffer.getvalue()

    manifest = {
        "format": FORMAT,
        "version": VERSION,
        "tenant": service.settings.tenant,
        "epoch": service.settings.epoch,
        "records": state["records"],
        "schema": schema_descriptor(service.schema),
        "public_key": state["public_key"],
        "created": int(time.time()),
        "nonce": secrets.token_bytes(12).hex(),
    }
    ciphertext = AESGCM(ledger_key).encrypt(bytes.fromhex(manifest["nonce"]), plaintext,
                                            _canonical(manifest))
    manifest["payload_sha256"] = hashlib.sha256(ciphertext).hexdigest()

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A unique name: a killed ingest leaves its directory behind, and
    # container pids repeat, so a pid-based name would block the next run.
    tmp = Path(tempfile.mkdtemp(prefix=path.name + ".tmp-", dir=path.parent))
    for name, data in (("payload.bin", ciphertext),
                       ("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())):
        fd = os.open(tmp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    if path.exists():
        old = path.with_name(path.name + f".old-{int(time.time())}")
        path.rename(old)
        tmp.rename(path)
        for child in old.iterdir():
            child.unlink()
        old.rmdir()
    else:
        tmp.rename(path)
    return manifest


def read_manifest(path: Path) -> Dict[str, Any]:
    try:
        manifest = json.loads((Path(path) / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise LedgerError(f"cannot read ledger manifest in {path}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("version") != VERSION:
        raise LedgerError(f"{path} is not a version-{VERSION} Tokenis ledger")
    for key, kind in _MANIFEST_FIELDS.items():
        if not isinstance(manifest.get(key), kind) or isinstance(manifest.get(key), bool) is not (kind is bool):
            raise LedgerError(f"{path}: manifest field {key!r} is missing or malformed")
    return dict(manifest)


_MANIFEST_FIELDS: Dict[str, Any] = {
    "tenant": str, "epoch": int, "records": int, "schema": dict, "public_key": str,
    "created": int, "nonce": str, "payload_sha256": str,
}


def load_ledger(
    path: Path,
    schema: "Schema",
    ledger_key: bytes,
    private_key: bytes,
    tokenizer_key: bytes,
    settings: Optional["GatewaySettings"] = None,
    **service_kwargs: Any,
) -> "TokenisGatewayService":
    """A gateway loaded from a persisted ledger (not yet sealed)."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from tokenis.gateway.schema import GatewaySettings
    from tokenis.gateway.service import TokenisGatewayService

    settings = settings or GatewaySettings()
    manifest = read_manifest(path)
    if manifest["tenant"] != settings.tenant or manifest["epoch"] != settings.epoch:
        raise LedgerError(
            f"{path} was written for tenant {manifest['tenant']!r} epoch {manifest['epoch']}, "
            f"not {settings.tenant!r} epoch {settings.epoch}"
        )
    if manifest["schema"] != schema_descriptor(schema):
        raise LedgerError(f"{path} was written for a different schema; re-run ingest")
    ciphertext = (Path(path) / "payload.bin").read_bytes()
    if hashlib.sha256(ciphertext).hexdigest() != manifest.get("payload_sha256"):
        raise LedgerError(f"{path}/payload.bin does not match its manifest")
    core = {k: v for k, v in manifest.items() if k != "payload_sha256"}
    try:
        plaintext = AESGCM(ledger_key).decrypt(bytes.fromhex(manifest["nonce"]), ciphertext,
                                               _canonical(core))
    except (InvalidTag, ValueError) as exc:  # ValueError: a malformed nonce
        raise LedgerError(f"{path}: wrong ledger key, or the ledger was modified") from exc
    size = int.from_bytes(plaintext[:8], "big")
    meta = json.loads(plaintext[8:8 + size])
    arrays = np.load(io.BytesIO(plaintext[8 + size:]), allow_pickle=False)

    public: Dict[str, List[str]] = {}
    for name, domain in meta["domains"].items():
        codes = arrays[f"pub:{name}"]
        lookup = np.array(domain, dtype=object)
        public[name] = list(lookup[codes]) if len(codes) else []
    embeddings: List[Tuple[str, np.ndarray]] = []
    if "embeddings" in arrays.files:
        embeddings = list(zip(meta["embedding_tokens"], arrays["embeddings"]))
    service = TokenisGatewayService(schema, tokenizer_key, settings, private_key=private_key,
                                    **service_kwargs)
    service._import_state({
        "records": manifest["records"],
        "public_key": manifest["public_key"],
        "public": public,
        "sealed": {k.split(":", 1)[1]: arrays[k].tobytes() for k in arrays.files if k.startswith("ct:")},
        "squares": {k.split(":", 1)[1]: arrays[k].tobytes() for k in arrays.files if k.startswith("sq:")},
        "bounds": meta["bounds"],
        "embeddings": embeddings,
    })
    return service
