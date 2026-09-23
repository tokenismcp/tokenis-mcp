# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deployment configuration: one TOML file describing the dataset, the
policy, the server and its authentication, plus a loader for CSV/JSON-lines
data. See ``examples/tokenis.toml`` for an annotated example.

Secrets never live in the file: the tokenizer key and the audit-trace HMAC
key are read from environment variables it names (hex, or base64/base64url,
at least 16 bytes; generate with ``tokenis-mcp keygen-secret``). Unknown keys
in the file are errors, so a typo cannot silently fall back to a default.
"""
from __future__ import annotations

import base64
import binascii
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

from tokenis.gateway.schema import (
    AdmissionSettings,
    ColumnSpec,
    DecryptionSettings,
    DisclosureSettings,
    GatewaySettings,
    RevealPurpose,
    Schema,
)
from tokenis.gateway.service import IngestError, TokenisGatewayService

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 only
    import tomli as tomllib


class ConfigError(ValueError):
    """The configuration file (or an environment variable it names) is
    invalid."""


@dataclass(frozen=True)
class DataSource:
    path: Path
    format: str = "csv"  # "csv" | "jsonl"
    delimiter: str = ","
    encoding: str = "utf-8"


@dataclass(frozen=True)
class JwtSettings:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: Tuple[str, ...] = ("RS256", "ES256")
    principal_claim: str = "sub"
    required_scopes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthSettings:
    mode: str = "none"  # "none" (stdio only) | "api_keys" | "jwt"
    api_keys_file: Optional[Path] = None
    jwt: Optional[JwtSettings] = None


@dataclass(frozen=True)
class ServerSettings:
    transport: str = "stdio"  # "stdio" | "http"
    host: str = "127.0.0.1"
    port: int = 8000
    public_url: Optional[str] = None
    allowed_hosts: Tuple[str, ...] = ()
    stdio_principal: Optional[str] = None
    taint_header: Optional[str] = None
    default_taint: int = 0
    max_concurrency: int = 16


@dataclass(frozen=True)
class TokenisConfig:
    schema: Schema
    settings: GatewaySettings
    data: DataSource
    tokenizer_key_env: str = "TOKENIS_TOKENIZER_KEY"
    audit_key_env: Optional[str] = None
    state_dir: Optional[Path] = None
    server: ServerSettings = field(default_factory=ServerSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    source: Optional[Path] = None


# -- TOML parsing -----------------------------------------------------------------


def _table(raw: Any, where: str, allowed: Tuple[str, ...]) -> Dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"[{where}] must be a table")
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        raise ConfigError(f"[{where}]: unknown key(s) {', '.join(unknown)}")
    return dict(raw)


def _path(base: Path, value: Any, where: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where} must be a path string")
    p = Path(value).expanduser()
    return p if p.is_absolute() else (base / p).resolve()


def _build(kind: Any, where: str, **kwargs: Any) -> Any:
    try:
        return kind(**kwargs)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: {exc}") from None


def parse_config(raw: Mapping[str, Any], base_dir: Path, source: Optional[Path] = None) -> TokenisConfig:
    top = _table(
        dict(raw), "top level",
        ("tenant", "data", "columns", "admission", "decryption", "disclosure", "reveal",
         "state", "server", "auth"),
    )
    tenant = _table(top.get("tenant"), "tenant", ("name", "epoch", "tokenizer_key_env"))
    data = _table(
        top.get("data"), "data",
        ("path", "format", "delimiter", "encoding", "id_column", "embedding_column"),
    )
    if "path" not in data:
        raise ConfigError("[data] path is required")
    data_path = _path(base_dir, data["path"], "[data] path")
    fmt = data.get("format") or ("jsonl" if data_path.suffix in (".jsonl", ".ndjson") else "csv")
    if fmt not in ("csv", "jsonl"):
        raise ConfigError("[data] format must be csv or jsonl")

    raw_columns = top.get("columns")
    if not isinstance(raw_columns, list) or not raw_columns:
        raise ConfigError("at least one [[columns]] entry is required")
    columns = []
    for i, entry in enumerate(raw_columns):
        col = _table(
            entry, f"columns #{i + 1}",
            ("name", "protection", "description", "unit", "scale", "result_mode",
             "allow_variance", "entity"),
        )
        columns.append(_build(ColumnSpec, f"[[columns]] #{i + 1}", **col))
    schema = _build(
        Schema, "schema", columns=tuple(columns),
        id_column=data.get("id_column"), embedding_column=data.get("embedding_column"),
    )

    admission = _build(
        AdmissionSettings, "[admission]",
        **_table(top.get("admission"), "admission",
                 ("min_query_set_size", "budget", "window", "taint_budget", "taint_call_cap",
                  "cell_aware")),
    )
    decryption = _build(
        DecryptionSettings, "[decryption]",
        **_table(top.get("decryption"), "decryption", ("max_value", "table_size")),
    )
    disclosure = _build(
        DisclosureSettings, "[disclosure]",
        **_table(top.get("disclosure"), "disclosure",
                 ("latency_granularity_ms", "max_top_k", "max_buckets", "max_groups",
                  "max_enum_values")),
    )
    reveal = _table(top.get("reveal"), "reveal", ("purposes",))
    purposes = []
    for i, entry in enumerate(reveal.get("purposes") or []):
        p = _table(entry, f"reveal.purposes #{i + 1}", ("name", "description", "principals"))
        if "principals" in p:
            p["principals"] = tuple(p["principals"])
        purposes.append(_build(RevealPurpose, f"[[reveal.purposes]] #{i + 1}", **p))
    settings = _build(
        GatewaySettings, "settings",
        tenant=str(tenant.get("name", "default")), epoch=int(tenant.get("epoch", 1)),
        admission=admission, decryption=decryption, disclosure=disclosure,
        purposes=tuple(purposes),
    )

    state = _table(top.get("state"), "state", ("dir", "audit_key_env"))
    server_raw = _table(
        top.get("server"), "server",
        ("transport", "host", "port", "public_url", "allowed_hosts", "stdio_principal",
         "taint_header", "default_taint", "max_concurrency"),
    )
    if "allowed_hosts" in server_raw:
        server_raw["allowed_hosts"] = tuple(server_raw["allowed_hosts"])
    server = _build(ServerSettings, "[server]", **server_raw)
    if server.transport not in ("stdio", "http"):
        raise ConfigError("[server] transport must be stdio or http")

    auth_raw = _table(top.get("auth"), "auth", ("mode", "api_keys_file", "jwt"))
    jwt = None
    if "jwt" in auth_raw:
        j = _table(
            auth_raw.pop("jwt"), "auth.jwt",
            ("issuer", "audience", "jwks_url", "algorithms", "principal_claim", "required_scopes"),
        )
        for key in ("algorithms", "required_scopes"):
            if key in j:
                j[key] = tuple(j[key])
        jwt = _build(JwtSettings, "[auth.jwt]", **j)
    keys_file = auth_raw.pop("api_keys_file", None)
    auth = _build(
        AuthSettings, "[auth]", mode=auth_raw.get("mode", "none"), jwt=jwt,
        api_keys_file=_path(base_dir, keys_file, "[auth] api_keys_file") if keys_file else None,
    )
    if auth.mode not in ("none", "api_keys", "jwt"):
        raise ConfigError("[auth] mode must be none, api_keys or jwt")
    if auth.mode == "api_keys" and auth.api_keys_file is None:
        raise ConfigError("[auth] mode = api_keys needs api_keys_file")
    if auth.mode == "jwt" and auth.jwt is None:
        raise ConfigError("[auth] mode = jwt needs an [auth.jwt] table")
    if server.transport == "http" and auth.mode == "none":
        raise ConfigError(
            "the http transport requires authentication: set [auth] mode to api_keys or jwt"
        )

    return TokenisConfig(
        schema=schema,
        settings=settings,
        data=DataSource(
            path=data_path, format=fmt, delimiter=str(data.get("delimiter", ",")),
            encoding=str(data.get("encoding", "utf-8")),
        ),
        tokenizer_key_env=str(tenant.get("tokenizer_key_env", "TOKENIS_TOKENIZER_KEY")),
        audit_key_env=state.get("audit_key_env"),
        state_dir=_path(base_dir, state["dir"], "[state] dir") if "dir" in state else None,
        server=server,
        auth=auth,
        source=source,
    )


def load_config(path: os.PathLike[str] | str) -> TokenisConfig:
    p = Path(path).expanduser().resolve()
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{p}: {exc}") from None
    return parse_config(raw, p.parent, source=p)


# -- secrets ----------------------------------------------------------------------


def decode_secret(value: str, name: str) -> bytes:
    """Hex, or standard/URL-safe base64; at least 16 bytes."""
    text = value.strip()
    decoded: Optional[bytes] = None
    try:
        decoded = bytes.fromhex(text)
    except ValueError:
        padded = text + "=" * (-len(text) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(padded.encode("ascii"), validate=True) if decoder is base64.b64decode \
                    else decoder(padded.encode("ascii"))
                break
            except (binascii.Error, ValueError):
                continue
    if decoded is None or len(decoded) < 16:
        raise ConfigError(f"${name} must be at least 16 bytes, hex or base64 encoded")
    return decoded


def read_secret(name: str, environ: Mapping[str, str]) -> bytes:
    value = environ.get(name)
    if not value:
        raise ConfigError(
            f"environment variable {name} is not set (generate one with `tokenis-mcp keygen-secret`)"
        )
    return decode_secret(value, name)


# -- data loading -----------------------------------------------------------------


def _parse_embedding(value: Any, where: str) -> Optional[List[float]]:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        text = value.strip()
        try:
            value = json.loads(text) if text.startswith("[") else [float(x) for x in text.split(";")]
        except ValueError as exc:
            raise ConfigError(f"{where}: embedding must be a JSON array or ';'-separated numbers") from exc
    if not isinstance(value, list):
        raise ConfigError(f"{where}: embedding must be a list of numbers")
    try:
        return [float(x) for x in value]
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: embedding must contain only numbers") from exc


def iter_rows(source: DataSource) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """(location, row) for every record in the source file."""
    if source.format == "csv":
        with source.path.open(encoding=source.encoding, newline="") as fh:
            reader = csv.DictReader(fh, delimiter=source.delimiter)
            for row in reader:
                yield f"{source.path.name}:{reader.line_num}", dict(row)
    else:
        with source.path.open(encoding=source.encoding) as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                where = f"{source.path.name}:{lineno}"
                try:
                    row = json.loads(line)
                except ValueError as exc:
                    raise ConfigError(f"{where}: invalid JSON") from exc
                if not isinstance(row, dict):
                    raise ConfigError(f"{where}: each line must be a JSON object")
                yield where, row


def load_dataset(
    service: TokenisGatewayService, source: DataSource, batch_size: int = 4096,
) -> int:
    """Ingest every row of ``source`` into ``service`` in batches (each
    encrypted in parallel); returns the count. Any invalid row aborts the
    load with its file and line."""
    schema = service.schema
    count = 0
    batch: List[Tuple[str, Any, Any]] = []
    wheres: List[str] = []

    def flush() -> None:
        nonlocal count
        try:
            count += service.ingest_many(batch)
        except IngestError as exc:
            raise ConfigError(f"{wheres[exc.index]}: {exc.reason}") from None
        batch.clear()
        wheres.clear()

    try:
        for where, row in iter_rows(source):
            record_id = row.get(schema.id_column) if schema.id_column else where
            if record_id is None or str(record_id).strip() == "":
                raise ConfigError(f"{where}: missing {schema.id_column!r}")
            embedding = None
            if schema.embedding_column:
                embedding = _parse_embedding(row.get(schema.embedding_column), where)
            batch.append((str(record_id), row, embedding))
            wheres.append(where)
            if len(batch) >= batch_size:
                flush()
        if batch:
            flush()
    except OSError as exc:
        raise ConfigError(f"cannot read {source.path}: {exc}") from None
    return count


def build_service(
    config: TokenisConfig,
    *,
    environ: Optional[Mapping[str, str]] = None,
    reset_admission_state: bool = False,
    seal: bool = True,
) -> TokenisGatewayService:
    """A gateway for ``config`` with its dataset loaded (and, by default,
    sealed: admission state built or restored)."""
    env = os.environ if environ is None else environ
    service = TokenisGatewayService(
        config.schema,
        read_secret(config.tokenizer_key_env, env),
        config.settings,
        state_dir=config.state_dir,
        audit_key=read_secret(config.audit_key_env, env) if config.audit_key_env else None,
        reset_admission_state=reset_admission_state,
    )
    load_dataset(service, config.data)
    if seal:
        service.seal()
    return service
