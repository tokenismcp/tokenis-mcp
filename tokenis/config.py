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
import re
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
    """A file (``path``) or a database (``url``/``url_env`` + ``query`` or
    ``table``, read through SQLAlchemy)."""

    path: Optional[Path] = None
    format: str = "csv"  # "csv" | "jsonl" | "sql"
    delimiter: str = ","
    encoding: str = "utf-8"
    url: Optional[str] = None
    url_env: Optional[str] = None
    query: Optional[str] = None
    table: Optional[str] = None
    fetch_size: int = 10_000

    @property
    def label(self) -> str:
        return self.path.name if self.path else (self.table or "query")


@dataclass(frozen=True)
class KeySettings:
    """``[keys]``: where the keystore lives and which KMS wraps it."""

    provider: str
    keystore: Path
    options: Tuple[Tuple[str, str], ...] = ()

    def option(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return dict(self.options).get(name, default)


KEY_PROVIDERS: Dict[str, Tuple[str, ...]] = {
    "local": ("passphrase_env",),
    "aws-kms": ("key_id", "region"),
    "vault-transit": ("address", "key_name", "mount", "namespace", "token_env"),
    "gcp-kms": ("key_name",),
    "azure-keyvault": ("vault_url", "key_name"),
}
REQUIRED_KEY_OPTIONS = {
    "local": ("passphrase_env",),
    "aws-kms": ("key_id",),
    "vault-transit": ("address", "key_name"),
    "gcp-kms": ("key_name",),
    "azure-keyvault": ("vault_url", "key_name"),
}


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
    #: Stateless HTTP: every request stands alone (no MCP session held in
    #: this process), so any replica behind a load balancer can serve it.
    stateless: bool = False
    log_format: str = "text"  # "text" | "json"


@dataclass(frozen=True)
class OpsSettings:
    """Health, metrics and the admin dashboard (HTTP only; see tokenis.ops)."""

    admin_token_env: Optional[str] = None
    metrics_token_env: Optional[str] = None


@dataclass(frozen=True)
class TokenisConfig:
    schema: Schema
    settings: GatewaySettings
    data: Optional[DataSource]
    tokenizer_key_env: str = "TOKENIS_TOKENIZER_KEY"
    audit_key_env: Optional[str] = None
    state_dir: Optional[Path] = None
    server: ServerSettings = field(default_factory=ServerSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    source: Optional[Path] = None
    keys: Optional[KeySettings] = None
    ledger: Optional[Path] = None
    #: "file" (the [state] dir) or "postgres" (shared by several replicas;
    #: the connection URL comes from the environment variable state_url_env).
    state_backend: str = "file"
    state_url_env: str = "TOKENIS_STATE_URL"
    ops: OpsSettings = field(default_factory=OpsSettings)


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
         "state", "server", "auth", "keys", "ledger", "ops"),
    )
    tenant = _table(top.get("tenant"), "tenant", ("name", "epoch", "tokenizer_key_env"))
    data = _table(
        top.get("data"), "data",
        ("path", "format", "delimiter", "encoding", "id_column", "embedding_column",
         "url", "url_env", "query", "table", "fetch_size"),
    )
    ledger_raw = _table(top.get("ledger"), "ledger", ("path",))
    ledger_path = _path(base_dir, ledger_raw["path"], "[ledger] path") if "path" in ledger_raw else None
    source_data: Optional[DataSource] = None
    if "path" in data:
        if any(k in data for k in ("url", "url_env", "query", "table")):
            raise ConfigError("[data]: use either path (a file) or url/url_env with query/table")
        data_path = _path(base_dir, data["path"], "[data] path")
        fmt = data.get("format") or ("jsonl" if data_path.suffix in (".jsonl", ".ndjson") else "csv")
        if fmt not in ("csv", "jsonl"):
            raise ConfigError("[data] format must be csv or jsonl")
        source_data = DataSource(path=data_path, format=fmt,
                                 delimiter=str(data.get("delimiter", ",")),
                                 encoding=str(data.get("encoding", "utf-8")))
    elif "url" in data or "url_env" in data:
        if ("query" in data) == ("table" in data):
            raise ConfigError("[data]: a database source needs exactly one of query or table")
        url = data.get("url")
        if url is not None and re.search(r"://[^/@]*:[^/@]*@", str(url)):
            raise ConfigError(
                "[data] url contains a password; put the whole URL in an environment variable "
                "and name it with url_env"
            )
        table = data.get("table")
        if table is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", str(table)):
            raise ConfigError("[data] table must be a plain (optionally schema-qualified) name")
        fetch = int(data.get("fetch_size", 10_000))
        if fetch < 1:
            raise ConfigError("[data] fetch_size must be positive")
        source_data = DataSource(format="sql", url=url, url_env=data.get("url_env"),
                                 query=data.get("query"), table=table, fetch_size=fetch)
    elif data:
        raise ConfigError("[data] needs a path, or url/url_env with query/table")
    if source_data is None and ledger_path is None:
        raise ConfigError("a [data] source or a [ledger] path is required")

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

    state = _table(top.get("state"), "state", ("dir", "audit_key_env", "backend", "url_env"))
    state_dir = _path(base_dir, state["dir"], "[state] dir") if "dir" in state else None
    state_backend = str(state.get("backend", "file"))
    if state_backend not in ("file", "postgres"):
        raise ConfigError('[state] backend must be "file" or "postgres"')
    if "url_env" in state and state_backend != "postgres":
        raise ConfigError('[state] url_env applies only to backend = "postgres"')
    keys_raw = _table(top.get("keys"), "keys",
                      ("provider", "keystore", *sorted({o for v in KEY_PROVIDERS.values() for o in v})))
    keys: Optional[KeySettings] = None
    if keys_raw:
        provider = str(keys_raw.pop("provider", ""))
        if provider not in KEY_PROVIDERS:
            raise ConfigError(f"[keys] provider must be one of {', '.join(KEY_PROVIDERS)}")
        extra = sorted(set(keys_raw) - {"keystore", *KEY_PROVIDERS[provider]})
        if extra:
            raise ConfigError(f"[keys]: {', '.join(extra)} do not apply to provider {provider}")
        missing = [o for o in REQUIRED_KEY_OPTIONS[provider] if o not in keys_raw]
        if missing:
            raise ConfigError(f"[keys] provider {provider} needs {', '.join(missing)}")
        if "keystore" in keys_raw:
            keystore = _path(base_dir, keys_raw.pop("keystore"), "[keys] keystore")
        elif state_dir is not None:
            keystore = state_dir / "keystore.json"
        else:
            raise ConfigError("[keys] needs keystore (or a [state] dir to keep it in)")
        keys = KeySettings(provider=provider, keystore=keystore,
                           options=tuple(sorted((k, str(v)) for k, v in keys_raw.items())))
    server_raw = _table(
        top.get("server"), "server",
        ("transport", "host", "port", "public_url", "allowed_hosts", "stdio_principal",
         "taint_header", "default_taint", "max_concurrency", "stateless", "log_format"),
    )
    if "allowed_hosts" in server_raw:
        server_raw["allowed_hosts"] = tuple(server_raw["allowed_hosts"])
    server = _build(ServerSettings, "[server]", **server_raw)
    if server.transport not in ("stdio", "http"):
        raise ConfigError("[server] transport must be stdio or http")
    if server.log_format not in ("text", "json"):
        raise ConfigError("[server] log_format must be text or json")
    ops = _build(OpsSettings, "[ops]", **_table(top.get("ops"), "ops",
                                                ("admin_token_env", "metrics_token_env")))

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
    if auth.mode == "api_keys" and auth.api_keys_file is None and state_backend != "postgres":
        raise ConfigError("[auth] mode = api_keys needs api_keys_file (or the postgres state backend)")
    if auth.api_keys_file is not None and state_backend == "postgres":
        raise ConfigError("with the postgres state backend API keys live in the database; "
                          "remove [auth] api_keys_file")
    if auth.mode == "jwt" and auth.jwt is None:
        raise ConfigError("[auth] mode = jwt needs an [auth.jwt] table")
    if server.transport == "http" and auth.mode == "none":
        raise ConfigError(
            "the http transport requires authentication: set [auth] mode to api_keys or jwt"
        )

    return TokenisConfig(
        schema=schema,
        settings=settings,
        data=source_data,
        tokenizer_key_env=str(tenant.get("tokenizer_key_env", "TOKENIS_TOKENIZER_KEY")),
        audit_key_env=state.get("audit_key_env"),
        state_dir=state_dir,
        server=server,
        auth=auth,
        source=source,
        keys=keys,
        ledger=ledger_path,
        state_backend=state_backend,
        state_url_env=str(state.get("url_env", "TOKENIS_STATE_URL")),
        ops=ops,
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


def iter_rows(
    source: DataSource, environ: Optional[Mapping[str, str]] = None,
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """(location, row) for every record in the source."""
    if source.format == "sql":
        yield from _iter_sql(source, os.environ if environ is None else environ)
        return
    assert source.path is not None  # noqa: S101 -- file sources always have a path
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


def database_url(source: DataSource, environ: Mapping[str, str]) -> str:
    if source.url_env:
        url = environ.get(source.url_env)
        if not url:
            raise ConfigError(f"environment variable {source.url_env} (the database URL) is not set")
        return url
    assert source.url is not None  # noqa: S101 -- validated by parse_config
    return source.url


def _iter_sql(
    source: DataSource, environ: Mapping[str, str],
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Stream rows from any SQLAlchemy-supported database (PostgreSQL,
    MySQL/MariaDB, Oracle, SQL Server, Snowflake, BigQuery, SQLite, ...),
    ``fetch_size`` rows at a time, on a read-only query."""
    try:
        import sqlalchemy
    except ImportError as exc:
        raise ConfigError(
            "database sources need SQLAlchemy and a driver: pip install 'tokenis-mcp[postgres]' "
            "(or mysql, oracle, mssql, snowflake, bigquery)"
        ) from exc
    url = database_url(source, environ)
    try:
        engine = sqlalchemy.create_engine(url)
    except (sqlalchemy.exc.ArgumentError, ImportError) as exc:
        raise ConfigError(f"cannot use the database URL: {exc}") from None
    if source.table:
        # The name is validated in parse_config ([A-Za-z_][A-Za-z0-9_.]*).
        statement = sqlalchemy.text(f"SELECT * FROM {source.table}")  # noqa: S608
    else:
        statement = sqlalchemy.text(str(source.query))
    label = source.table or "query"
    try:
        with engine.connect() as conn:
            result = conn.execution_options(
                stream_results=True, yield_per=source.fetch_size).execute(statement)
            for number, row in enumerate(result.mappings(), start=1):
                yield f"{label} row {number}", dict(row)
    except sqlalchemy.exc.SQLAlchemyError as exc:
        first = str(exc).splitlines()[0] if str(exc) else ""
        raise ConfigError(f"database error reading {label}: {exc.__class__.__name__}: {first}") from None
    finally:
        engine.dispose()


def load_dataset(
    service: TokenisGatewayService, source: DataSource, batch_size: int = 4096,
    environ: Optional[Mapping[str, str]] = None,
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
        for where, row in iter_rows(source, environ):
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
        raise ConfigError(f"cannot read {source.label}: {exc}") from None
    return count


def make_wrapper(keys: KeySettings, environ: Mapping[str, str]) -> Any:
    """The configured :class:`tokenis.keystore.KeyWrapper`."""
    from tokenis.keystore import (
        AwsKmsWrapper,
        AzureKeyVaultWrapper,
        GcpKmsWrapper,
        LocalPassphraseWrapper,
        VaultTransitWrapper,
        keystore_header,
    )

    o = keys.option
    try:
        if keys.provider == "local":
            name = str(o("passphrase_env"))
            passphrase = environ.get(name)
            if not passphrase:
                raise ConfigError(f"environment variable {name} (the keystore passphrase) is not set")
            salt = None
            if keys.keystore.exists():
                salt = base64.b64decode(keystore_header(keys.keystore)["wrapper"]["salt"])
            return LocalPassphraseWrapper(passphrase.encode(), salt)
        if keys.provider == "aws-kms":
            return AwsKmsWrapper(str(o("key_id")), o("region"))
        if keys.provider == "vault-transit":
            token_env = o("token_env", "VAULT_TOKEN") or "VAULT_TOKEN"
            return VaultTransitWrapper(str(o("address")), str(o("key_name")),
                                       token=environ.get(token_env, ""),
                                       mount=o("mount", "transit") or "transit",
                                       namespace=o("namespace"))
        if keys.provider == "gcp-kms":
            return GcpKmsWrapper(str(o("key_name")))
        return AzureKeyVaultWrapper(str(o("vault_url")), str(o("key_name")))
    except ImportError as exc:
        extra = {"aws-kms": "aws", "gcp-kms": "gcp", "azure-keyvault": "azure"}.get(keys.provider, "")
        raise ConfigError(f"{keys.provider} needs its client library: "
                          f"pip install 'tokenis-mcp[{extra}]' ({exc})") from None


def load_secrets(config: TokenisConfig, environ: Mapping[str, str]) -> Any:
    """Unwrap the keystore's secrets (``[keys]`` configured)."""
    from tokenis.keystore import KeystoreError, load_keystore

    if config.keys is None:
        raise ConfigError("no [keys] section")
    if not config.keys.keystore.exists():
        raise ConfigError(f"no keystore at {config.keys.keystore}: run `tokenis-mcp secrets init`")
    try:
        return load_keystore(config.keys.keystore, make_wrapper(config.keys, environ),
                             config.settings.tenant)
    except KeystoreError as exc:
        raise ConfigError(str(exc)) from None


def state_url(config: TokenisConfig, environ: Optional[Mapping[str, str]] = None) -> str:
    """The PostgreSQL URL for the shared state (credentials included, so it
    only ever comes from the environment)."""
    env = os.environ if environ is None else environ
    url = env.get(config.state_url_env, "")
    if not url:
        raise ConfigError(f"[state] backend = postgres: set {config.state_url_env} to the "
                          "database URL, e.g. postgresql://tokenis@db:5432/tokenis")
    if url.startswith("postgresql+"):
        url = "postgresql://" + url.split("://", 1)[1]
    return url


def open_shared_state(config: TokenisConfig, environ: Optional[Mapping[str, str]] = None) -> Any:
    """A :class:`tokenis.gateway.pgstate.PostgresState` for ``config``, or
    None with the file backend."""
    if config.state_backend != "postgres":
        return None
    from tokenis.gateway.pgstate import PostgresState

    try:
        return PostgresState(state_url(config, environ), config.settings.tenant)
    except ConfigError:
        raise
    except Exception as exc:  # noqa: BLE001 -- driver errors vary; report them as config errors
        raise ConfigError(f"cannot open the postgres state: {exc}") from None


def api_key_store(config: TokenisConfig, environ: Optional[Mapping[str, str]] = None,
                  path: Optional[Path] = None) -> Any:
    """Where API keys live: the database with the postgres backend, else the
    [auth] api_keys_file (or ``path``)."""
    if config.state_backend == "postgres" and path is None:
        from tokenis.gateway.pgstate import PostgresApiKeyStore

        try:
            return PostgresApiKeyStore(state_url(config, environ), config.settings.tenant)
        except ConfigError:
            raise
        except Exception as exc:  # noqa: BLE001 -- see open_shared_state
            raise ConfigError(f"cannot open the postgres key store: {exc}") from None
    from tokenis.server_auth import ApiKeyStore

    path = path or config.auth.api_keys_file
    if path is None:
        raise ConfigError("the config has no [auth] api_keys_file")
    return ApiKeyStore(path)


def build_service(
    config: TokenisConfig,
    *,
    environ: Optional[Mapping[str, str]] = None,
    reset_admission_state: bool = False,
    seal: bool = True,
    from_source: bool = False,
) -> TokenisGatewayService:
    """A gateway for ``config``: loaded from the persisted ledger when one
    exists (unless ``from_source``), otherwise from the data source; sealed
    by default (admission state built or restored)."""
    from tokenis.ledger import LedgerError, load_ledger

    env = os.environ if environ is None else environ
    private_key: Optional[bytes] = None
    ledger_key: Optional[bytes] = None
    if config.keys is not None:
        secrets = load_secrets(config, env)
        tokenizer_key, audit_key = secrets.tokenizer_key, secrets.audit_key
        private_key, ledger_key = secrets.elgamal_private_key, secrets.ledger_key
    else:
        tokenizer_key = read_secret(config.tokenizer_key_env, env)
        audit_key = read_secret(config.audit_key_env, env) if config.audit_key_env else None
    shared = open_shared_state(config, env)
    kwargs: Dict[str, Any] = {
        "state_dir": config.state_dir if shared is None else None,
        "shared_state": shared,
        "audit_key": audit_key,
        "reset_admission_state": reset_admission_state,
    }
    ledger = config.ledger
    if ledger is not None and (ledger / "manifest.json").exists() and not from_source:
        if ledger_key is None or private_key is None:
            raise ConfigError("a persisted ledger needs [keys]: its keys live in the keystore")
        try:
            service = load_ledger(ledger, config.schema, ledger_key, private_key,
                                  tokenizer_key, config.settings, **kwargs)
        except (LedgerError, ValueError) as exc:
            raise ConfigError(str(exc)) from None
    else:
        if config.data is None:
            raise ConfigError(f"no ledger at {ledger} yet and no [data] source: configure [data] "
                              "and run `tokenis-mcp ingest`")
        service = TokenisGatewayService(config.schema, tokenizer_key, config.settings,
                                        private_key=private_key, **kwargs)
        load_dataset(service, config.data, environ=env)
    if seal:
        service.seal()
    return service


def ingest(config: TokenisConfig, *, environ: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Read the data source once and write the encrypted ledger; returns its
    manifest."""
    from tokenis.ledger import write_ledger

    env = os.environ if environ is None else environ
    if config.keys is None or config.ledger is None:
        raise ConfigError("ingest needs [keys] (the keystore) and a [ledger] path")
    if config.data is None:
        raise ConfigError("ingest needs a [data] source")
    service = build_service(config, environ=env, seal=False, from_source=True)
    return write_ledger(service, config.ledger, load_secrets(config, env).ledger_key)
