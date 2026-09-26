# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""``tokenis-mcp``: run and operate a Tokenis gateway.

    tokenis-mcp serve --demo                      # stdio, fictional data
    tokenis-mcp serve --config tokenis.toml       # transport from the file
    tokenis-mcp check --config tokenis.toml       # validate config + data
    tokenis-mcp tools --demo --format anthropic   # tool schemas for LLM APIs
    tokenis-mcp ask --demo "Which industry grew most?"   # Claude or OpenAI-compatible
    tokenis-mcp keys create alice@example.com --config tokenis.toml
    tokenis-mcp keygen-secret                     # a 32-byte key for the env vars
    tokenis-mcp audit verify --config tokenis.toml

Logs go to stderr (stdout is the MCP channel under stdio).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any, List, NoReturn, Optional, Sequence
from urllib.parse import urlparse

log = logging.getLogger("tokenis")


def _die(message: str, code: int = 2) -> NoReturn:
    print(f"tokenis-mcp: {message}", file=sys.stderr)
    raise SystemExit(code)


def _source(parser: argparse.ArgumentParser, *, demo: bool = True) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--config", type=Path, help="path to tokenis.toml")
    if demo:
        group.add_argument("--demo", action="store_true", help="use the built-in fictional dataset")
        group.add_argument(
            "--config-or-demo", metavar="PATH", dest="config_or_demo",
            help="for launchers that always pass a path: the config if PATH is non-empty, "
                 "otherwise the demo dataset (announced on stderr and in describe_dataset)",
        )


def _service(args: argparse.Namespace, *, reset: bool = False, seal: bool = True) -> Any:
    from tokenis.config import ConfigError, build_service, load_config

    fallback = getattr(args, "config_or_demo", None)
    if fallback is not None:
        if fallback.strip():
            args.config = Path(fallback).expanduser()
        else:
            args.demo = True
            log.warning("no config file given: serving the built-in FICTIONAL demo dataset")
    if getattr(args, "demo", False):
        from tokenis.gateway.demo import demo_service

        return demo_service(), None
    try:
        config = load_config(args.config)
        return build_service(config, reset_admission_state=reset, seal=seal), config
    except ConfigError as exc:
        _die(str(exc))


# -- commands --------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> None:
    import anyio

    from tokenis.mcp_server.server import (
        create_server,
        fixed_principal,
        header_taint,
        local_principal,
    )

    service, config = _service(args, reset=args.reset_admission_state)
    server_cfg = config.server if config else None
    transport = args.transport or (server_cfg.transport if server_cfg else "stdio")
    host = args.host or (server_cfg.host if server_cfg else "127.0.0.1")
    port = args.port or (server_cfg.port if server_cfg else 8000)
    concurrency = server_cfg.max_concurrency if server_cfg else 16
    default_taint = server_cfg.default_taint if server_cfg else 0
    taint = (
        header_taint(server_cfg.taint_header, default_taint)
        if server_cfg and server_cfg.taint_header
        else (lambda _ctx: default_taint)
    )

    if transport == "stdio":
        principal = (server_cfg.stdio_principal if server_cfg else None) or local_principal()
        server = create_server(
            service, principal_resolver=fixed_principal(principal), taint_resolver=taint,
            max_concurrency=concurrency, log_level=args.log_level,
        )
        log.info("serving %d records over stdio as %s", service.record_count, principal)
        anyio.run(server.run_stdio_async)
        return

    if config is None:
        _die("the http transport needs --config (authentication must be configured)")
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.transport_security import TransportSecuritySettings

    from tokenis.config import ConfigError, api_key_store
    from tokenis.server_auth import (
        ApiKeyVerifier,
        JwtVerifier,
        authenticated_principal,
    )

    public_url = (server_cfg.public_url if server_cfg else None) or f"http://{host}:{port}"
    auth_cfg = config.auth
    verifier: Any
    if auth_cfg.mode == "api_keys":
        try:
            verifier = ApiKeyVerifier(api_key_store(config))
        except ConfigError as exc:
            _die(str(exc))
        issuer = public_url
        scopes = None
    elif auth_cfg.mode == "jwt":
        assert auth_cfg.jwt is not None  # noqa: S101 -- validated by parse_config
        jwt = auth_cfg.jwt
        verifier = JwtVerifier(
            issuer=jwt.issuer, audience=jwt.audience, jwks_url=jwt.jwks_url,
            algorithms=jwt.algorithms, principal_claim=jwt.principal_claim,
            required_scopes=jwt.required_scopes,
        )
        issuer = jwt.issuer
        scopes = list(jwt.required_scopes) or None
    else:
        _die("the http transport requires [auth] mode = api_keys or jwt")
    auth = AuthSettings(
        issuer_url=issuer,  # type: ignore[arg-type]
        resource_server_url=public_url.rstrip("/") + "/mcp",  # type: ignore[arg-type]
        required_scopes=scopes,
        validate_token_resource=False,  # the verifiers check audience themselves
    )
    server = create_server(
        service, principal_resolver=authenticated_principal, taint_resolver=taint,
        token_verifier=verifier, auth=auth, max_concurrency=concurrency,
        log_level=args.log_level,
    )
    allowed = list(server_cfg.allowed_hosts) if server_cfg else []
    public_host = urlparse(public_url).netloc
    if public_host and public_host not in allowed:
        allowed.append(public_host)
    security = None
    if host not in ("127.0.0.1", "localhost", "::1"):
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed,
            allowed_origins=[f"{urlparse(public_url).scheme}://{h}" for h in allowed],
        )
    log.info("serving %d records over HTTP on %s:%d (auth: %s)", service.record_count, host,
             port, auth_cfg.mode)
    anyio.run(lambda: server.run_streamable_http_async(host=host, port=port, transport_security=security))


def cmd_check(args: argparse.Namespace) -> None:
    # Unsealed: validates config, secrets and every row without creating or
    # touching the admission state.
    service, config = _service(args, seal=False)
    summary = {
        "config": str(config.source),
        "records": service.record_count,
        "tools": list(service.tool_names),
        "columns": {c.name: c.protection for c in service.schema.columns},
        "min_query_set_size": service.k,
        "state": ("postgres (shared)" if config.state_backend == "postgres"
                  else str(config.state_dir) if config.state_dir else None),
        "transport": config.server.transport,
        "auth": config.auth.mode,
        "keys": config.keys.provider if config.keys else "environment variables",
        "ledger": str(config.ledger) if config.ledger else None,
    }
    print(json.dumps(summary, indent=2))
    if config.state_dir is None and config.state_backend == "file":
        print("warning: no [state] dir -- admission history and the audit trace are lost on "
              "restart; set one for production", file=sys.stderr)


def cmd_tools(args: argparse.Namespace) -> None:
    from tokenis.llm import TokenisToolkit

    service, _ = _service(args)
    toolkit = TokenisToolkit(service, principal="schema-export")
    if args.format == "anthropic":
        out: Any = toolkit.anthropic_tools()
    elif args.format == "openai":
        out = toolkit.openai_tools()
    else:
        out = [d.__dict__ for d in toolkit.definitions()]
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_ask(args: argparse.Namespace) -> None:
    from tokenis.llm import TokenisToolkit, ToolOutcome, ask_anthropic, ask_openai
    from tokenis.mcp_server.server import local_principal

    service, _ = _service(args)
    toolkit = TokenisToolkit(service, principal=args.principal or local_principal())

    def show(name: str, arguments: Any, outcome: ToolOutcome) -> None:
        status = "DENIED" if outcome.is_error else "ok"
        print(f"  -> {name}({json.dumps(arguments, ensure_ascii=False)}) [{status}]", file=sys.stderr)

    provider = args.provider or ("anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "openai")
    try:
        if provider == "anthropic":
            answer = ask_anthropic(toolkit, args.question, model=args.model or "claude-opus-5-5",
                                   on_tool=show)
        else:
            if not args.model:
                _die("--model is required for OpenAI-compatible providers")
            answer = ask_openai(toolkit, args.question, model=args.model, on_tool=show)
    except ImportError as exc:
        _die(f"{exc}; install the client with: pip install 'tokenis-mcp[llm]'")
    print(answer)


def cmd_keys(args: argparse.Namespace) -> None:
    from tokenis.config import ConfigError, api_key_store, load_config
    from tokenis.server_auth import ApiKeyStore

    store: Any
    if args.file is not None:
        store = ApiKeyStore(args.file)
    else:
        try:
            store = api_key_store(load_config(args.config))
        except ConfigError as exc:
            _die(str(exc))
    if args.keys_command == "create":
        try:
            token, record = store.create(args.principal)
        except ValueError as exc:
            _die(str(exc))
        print(token)
        print(f"key id {record.key_id} for {record.principal}; shown once -- store it now",
              file=sys.stderr)
    elif args.keys_command == "list":
        print(json.dumps([r.public_view() for r in store.list()], indent=2))
    else:
        if not store.revoke(args.key_id):
            _die(f"no active key with id {args.key_id}", code=1)
        print(f"revoked {args.key_id}", file=sys.stderr)


def cmd_keygen_secret(_args: argparse.Namespace) -> None:
    print(secrets.token_hex(32))


def cmd_audit(args: argparse.Namespace) -> None:
    from tokenis.audit.trace import DisclosureTrace, TraceIntegrityError
    from tokenis.config import (
        ConfigError,
        load_config,
        load_secrets,
        open_shared_state,
        read_secret,
    )

    try:
        config = load_config(args.config)
        if config.keys is not None:
            key: Optional[bytes] = load_secrets(config, os.environ).audit_key
        else:
            key = read_secret(config.audit_key_env, os.environ) if config.audit_key_env else None
    except ConfigError as exc:
        _die(str(exc))
    try:
        shared = open_shared_state(config)
    except ConfigError as exc:
        _die(str(exc))
    if shared is not None:
        where = f"postgres tokenis_trace (tenant {config.settings.tenant})"
        storage, path = shared.trace_storage(), None
    elif config.state_dir is None:
        _die("the config has no [state] dir, so there is no persisted trace")
    else:
        path, storage = config.state_dir / "trace.jsonl", None
        where = str(path)
    try:
        trace = DisclosureTrace(path=path, hmac_key=key, storage=storage)
    except TraceIntegrityError as exc:
        _die(f"INTEGRITY FAILURE: {exc}", code=1)
    entries = list(trace)
    kinds = {k: sum(e.kind == k for e in entries) for k in ("aggregate", "reveal", "denial")}
    print(json.dumps({"file": where, "entries": len(entries), **kinds, "head": trace.head,
                      "signed": key is not None}, indent=2))


def cmd_secrets(args: argparse.Namespace) -> None:
    from tokenis.config import ConfigError, load_config, make_wrapper
    from tokenis.keystore import (
        KeystoreError,
        create_keystore,
        keystore_header,
        load_keystore,
        rewrap_keystore,
    )

    try:
        config = load_config(args.config)
        if config.keys is None:
            _die("the config has no [keys] section (see docs/configuration.md#keys)")
        keystore = config.keys.keystore
        tenant = config.settings.tenant
        if args.secrets_command == "init":
            create_keystore(keystore, make_wrapper(config.keys, os.environ), tenant)
            print(f"created {keystore} ({config.keys.provider}); back it up -- losing it loses "
                  "every token and every ledger", file=sys.stderr)
        elif args.secrets_command == "status":
            header = keystore_header(keystore)
            load_keystore(keystore, make_wrapper(config.keys, os.environ), tenant)
            print(json.dumps({"keystore": str(keystore), "tenant": header["tenant"],
                              "created": header["created"], "wrapper": header["wrapper"],
                              "unwraps": True}, indent=2))
        else:
            old = load_config(args.from_config)
            if old.keys is None:
                _die("--from config has no [keys] section")
            if old.keys.keystore.resolve() != keystore.resolve():
                import shutil

                if keystore.exists():
                    _die(f"{keystore} already exists")
                shutil.copy2(old.keys.keystore, keystore)
            rewrap_keystore(keystore, make_wrapper(old.keys, os.environ),
                            make_wrapper(config.keys, os.environ), tenant)
            print(f"rewrapped {keystore} with {config.keys.provider}", file=sys.stderr)
    except (ConfigError, KeystoreError) as exc:
        _die(str(exc))


def cmd_ingest(args: argparse.Namespace) -> None:
    from tokenis.config import ConfigError, ingest, load_config

    try:
        manifest = ingest(load_config(args.config))
    except ConfigError as exc:
        _die(str(exc))
    print(json.dumps({k: manifest[k] for k in ("records", "tenant", "epoch", "created",
                                               "payload_sha256")}, indent=2))


# -- entry point -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tokenis-mcp", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-level", default=os.environ.get("TOKENIS_LOG_LEVEL", "INFO"))
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the MCP server")
    _source(p)
    p.add_argument("--transport", choices=("stdio", "http"))
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--reset-admission-state", action="store_true",
                   help="archive an admission history written for different data (see docs)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("check", help="validate the config and data, then exit")
    _source(p, demo=False)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("tools", help="print tool schemas")
    _source(p)
    p.add_argument("--format", choices=("anthropic", "openai", "mcp"), default="anthropic")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("ask", help="answer a question with an LLM using the tools")
    _source(p)
    p.add_argument("question")
    p.add_argument("--provider", choices=("anthropic", "openai"),
                   help="default: anthropic if ANTHROPIC_API_KEY is set, else openai")
    p.add_argument("--model")
    p.add_argument("--principal", help="principal to run as (default: local OS user)")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("keys", help="manage API keys for the http transport")
    keys = p.add_subparsers(dest="keys_command", required=True)
    for name, extra in (("create", "principal"), ("list", None), ("revoke", "key_id")):
        kp = keys.add_parser(name)
        group = kp.add_mutually_exclusive_group(required=True)
        group.add_argument("--config", type=Path)
        group.add_argument("--file", type=Path, help="key store file (instead of --config)")
        if extra:
            kp.add_argument(extra)
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("secrets", help="create and manage the KMS-wrapped keystore")
    sec = p.add_subparsers(dest="secrets_command", required=True)
    for name, text in (("init", "generate the gateway's secrets and wrap them"),
                       ("status", "check that the keystore unwraps with the configured KMS"),
                       ("rewrap", "move the keystore to the KMS in --config from --from")):
        sp = sec.add_parser(name, help=text)
        sp.add_argument("--config", type=Path, required=True)
        if name == "rewrap":
            sp.add_argument("--from", dest="from_config", type=Path, required=True,
                            help="config naming the keystore's current KMS")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("ingest", help="read the data source once and write the encrypted ledger")
    p.add_argument("--config", type=Path, required=True)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("keygen-secret", help="print a random 32-byte hex secret")
    p.set_defaults(func=cmd_keygen_secret)

    p = sub.add_parser("audit", help="inspect the persisted disclosure trace")
    audit = p.add_subparsers(dest="audit_command", required=True)
    vp = audit.add_parser("verify", help="verify the trace's hash chain and HMACs")
    vp.add_argument("--config", type=Path, required=True)
    p.set_defaults(func=cmd_audit)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        stream=sys.stderr, level=str(args.log_level).upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    main()


__all__: List[str] = ["build_parser", "main"]
