# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Operating the gateway over HTTP: health and readiness probes, Prometheus
metrics, structured logs and a read-only admin dashboard.

Endpoints (next to ``/mcp`` on the same port):

- ``GET /healthz`` -- liveness: the process is serving requests.
- ``GET /readyz`` -- readiness: the ledger is sealed and, with the postgres
  state backend, the database answers. 503 otherwise.
- ``GET /metrics`` -- Prometheus text format. Open by default (scrape it
  from inside the cluster); set ``[ops] metrics_token_env`` to require a
  bearer token.
- ``GET /admin`` and ``/admin/api/...`` -- the admin console, enabled when
  ``[ops] admin_token_env`` names a set variable (HTTP Basic with any user
  name and the token as password, or ``Authorization: Bearer``) or
  ``[ops.oidc]`` configures single sign-on (``/admin/auth/...``).
- ``GET /ask`` and ``/ask/api/...`` -- Tokenis Ask (``[ask]``, see
  :mod:`tokenis.ask`), for everyone who may sign in.

Nothing here reveals a sealed value: metrics count calls and outcomes, and
the dashboard lists audit entries without their disclosed values.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

from tokenis.safe import equal

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer

    from tokenis.gateway.service import TokenisGatewayService

log = logging.getLogger("tokenis.ops")

_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
OUTCOMES = ("ok", "denied", "invalid", "unauthenticated", "unavailable", "error")


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class Metrics:
    """Counters and a latency histogram per tool, in Prometheus text format.
    Thread-safe; no dependency on a metrics library."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = time.time()
        self._calls: Dict[Tuple[str, str], int] = {}
        self._denials: Dict[str, int] = {}
        self._hist: Dict[str, List[float]] = {}  # tool -> bucket counts + [sum, count]
        #: Per-minute outcome counts for the last hour (dashboard charts).
        self._minutes: "deque[List[int]]" = deque(maxlen=60)  # [minute, ok, denied, other]
        self._durations: "deque[float]" = deque(maxlen=2000)

    def observe(self, tool: str, outcome: str, seconds: float, rule: Optional[str] = None) -> None:
        with self._lock:
            minute = int(time.time() // 60)
            if not self._minutes or self._minutes[-1][0] != minute:
                self._minutes.append([minute, 0, 0, 0])
            self._minutes[-1][1 if outcome == "ok" else 2 if outcome == "denied" else 3] += 1
            self._durations.append(seconds)
            self._calls[(tool, outcome)] = self._calls.get((tool, outcome), 0) + 1
            if rule:
                self._denials[rule] = self._denials.get(rule, 0) + 1
            h = self._hist.setdefault(tool, [0.0] * (len(_BUCKETS) + 2))
            for i, edge in enumerate(_BUCKETS):
                if seconds <= edge:
                    h[i] += 1
            h[-2] += seconds
            h[-1] += 1

    def snapshot(self) -> Dict[str, Any]:
        now = int(time.time() // 60)
        with self._lock:
            tools: Dict[str, Dict[str, int]] = {}
            for (tool, outcome), n in self._calls.items():
                tools.setdefault(tool, {})[outcome] = n
            by_minute = {m[0]: m[1:] for m in self._minutes}
            durations = sorted(self._durations)
            denials = dict(self._denials)

        def pct(q: float) -> Optional[float]:
            if not durations:
                return None
            return round(durations[min(len(durations) - 1, int(q * len(durations)))], 4)

        return {
            "tools": tools,
            "denials_by_rule": denials,
            "timeline": [
                {"t": (now - i) * 60, "ok": c[0], "denied": c[1], "other": c[2]}
                for i in range(59, -1, -1)
                for c in [by_minute.get(now - i, [0, 0, 0])]
            ],
            "latency": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "samples": len(durations)},
        }

    def render(self, service: "TokenisGatewayService", detail: bool = True) -> str:
        """Prometheus text. Without ``detail``, denials are not broken down
        by rule: an open /metrics would otherwise tell a caller which rule
        refused their last query (the gateway hides that on purpose)."""
        from tokenis import __version__

        backend = "postgres" if service.shared_state is not None else "file"
        info = (f'version="{_label(__version__)}",tenant="{_label(service.settings.tenant)}",'
                f'state_backend="{backend}"')
        lines = [
            "# HELP tokenis_info Gateway build and tenant.",
            "# TYPE tokenis_info gauge",
            f"tokenis_info{{{info}}} 1",
            "# HELP tokenis_process_start_time_seconds Start time of the process.",
            "# TYPE tokenis_process_start_time_seconds gauge",
            f"tokenis_process_start_time_seconds {self.started:.3f}",
            "# HELP tokenis_records Records in the sealed ledger.",
            "# TYPE tokenis_records gauge",
            f"tokenis_records {service.record_count}",
        ]
        try:
            entries = len(service.trace)
        except Exception:  # noqa: BLE001 -- a scrape must not fail on a storage hiccup
            entries = -1
        if service.shared_state is not None:
            lines += ["# HELP tokenis_database_up Whether the shared-state database answers.",
                      "# TYPE tokenis_database_up gauge",
                      f"tokenis_database_up {int(service.shared_state.ping())}",
                      ("# HELP tokenis_state_diverged 1 when the shared history changed under "
                       "this replica (restored or edited); it refuses calls until restarted."),
                      "# TYPE tokenis_state_diverged gauge",
                      f"tokenis_state_diverged {int(service.state_failure is not None)}"]
        lines += [
            "# HELP tokenis_trace_entries Entries in the disclosure trace (-1: storage unavailable).",
            "# TYPE tokenis_trace_entries gauge",
            f"tokenis_trace_entries {entries}",
        ]
        with self._lock:
            lines += ["# HELP tokenis_tool_calls_total Tool calls by outcome.",
                      "# TYPE tokenis_tool_calls_total counter"]
            for (tool, outcome), n in sorted(self._calls.items()):
                lines.append(f'tokenis_tool_calls_total{{tool="{_label(tool)}",outcome="{outcome}"}} {n}')
            lines += [("# HELP tokenis_denials_total Admission denials by rule (D1-D5, ...); "
                       "only when /metrics requires a token."),
                      "# TYPE tokenis_denials_total counter"]
            if detail:
                for rule, n in sorted(self._denials.items()):
                    lines.append(f'tokenis_denials_total{{rule="{_label(rule)}"}} {n}')
            lines += ["# HELP tokenis_tool_call_duration_seconds Tool call latency (after padding).",
                      "# TYPE tokenis_tool_call_duration_seconds histogram"]
            for tool, h in sorted(self._hist.items()):
                t = _label(tool)
                for edge, hits in zip(_BUCKETS, h):
                    lines.append(f'tokenis_tool_call_duration_seconds_bucket{{tool="{t}",le="{edge:g}"}} {hits:.0f}')
                lines.append(f'tokenis_tool_call_duration_seconds_bucket{{tool="{t}",le="+Inf"}} {h[-1]:.0f}')
                lines.append(f'tokenis_tool_call_duration_seconds_sum{{tool="{t}"}} {h[-2]:.6f}')
                lines.append(f'tokenis_tool_call_duration_seconds_count{{tool="{t}"}} {h[-1]:.0f}')
        return "\n".join(lines) + "\n"


class JsonFormatter(logging.Formatter):
    """One JSON object per line, for log pipelines (``--log-format json``)."""

    def format(self, record: logging.LogRecord) -> str:
        out: Dict[str, Any] = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False)


def configure_logging(level: str, fmt: str = "text") -> None:
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


# -- HTTP endpoints -----------------------------------------------------------------


def _bearer_or_basic(header: str) -> str:
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer":
        return value.strip()
    if scheme.lower() == "basic":
        try:
            return base64.b64decode(value.strip()).decode("utf-8").partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            return ""
    return ""


def _authorised(header: str, token: str) -> bool:
    return hmac.compare_digest(_bearer_or_basic(header).encode(), token.encode())


class UnavailableMiddleware:
    """ASGI middleware: a GatewayUnavailable raised before a response has
    started (for instance by the API-key check while the database restarts)
    becomes ``503 Service Unavailable`` with ``Retry-After`` instead of a bare
    500, so clients retry rather than give up or drop their credentials."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        from tokenis.gateway.service import GatewayUnavailable

        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except GatewayUnavailable:
            if started:
                raise
            body = b'{"error": "temporarily unavailable"}'
            await send({"type": "http.response.start", "status": 503, "headers": [
                (b"content-type", b"application/json"), (b"retry-after", b"2"),
                (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})


def summary(service: "TokenisGatewayService", metrics: Metrics, key_store: Any = None,
            recent: int = 50, call_log: Any = None, range_key: str = "24h") -> Dict[str, Any]:
    """What the dashboard shows. No sealed values, no disclosed values.
    Statistics come from the call log (the whole cluster, any range);
    without one, from this process's counters."""
    from tokenis import __version__

    adm = service.settings.admission
    health: Dict[str, str] = {"ledger": "sealed" if service._sealed else "loading"}
    if service.shared_state is not None:
        health["database"] = "ok" if service.shared_state.ping() else "unreachable"
    health["state"] = "diverged" if service.state_failure is not None else "consistent"
    out: Dict[str, Any] = {
        "version": __version__,
        "replica": socket.gethostname(),
        "pid": os.getpid(),
        "now": time.time(),
        "health": health,
        "tenant": service.settings.tenant,
        "epoch": service.settings.epoch,
        "state_backend": "postgres" if service.shared_state is not None else "file",
        "records": service.record_count,
        "uptime_seconds": round(time.time() - metrics.started),
        "policy": {"min_query_set_size": adm.min_query_set_size, "budget": adm.budget,
                   "window": adm.window, "taint_budget": adm.taint_budget,
                   "taint_call_cap": adm.taint_call_cap, "cell_aware": adm.cell_aware,
                   "latency_granularity_ms": service.settings.disclosure.latency_granularity_ms},
        "columns": [{"name": c.name, "protection": c.protection, "description": c.description,
                     "unit": c.unit} for c in service.schema.columns],
        "purposes": [{"name": p.name, "description": p.description} for p in service.settings.purposes],
        "key_management": key_store is not None,
    }
    if call_log is not None:
        try:
            out["stats"] = {"scope": "cluster", **call_log.overview(range_key)}
        except Exception as exc:  # noqa: BLE001 -- show the rest of the dashboard
            out["stats_error"] = type(exc).__name__
    else:
        snap = metrics.snapshot()
        out["stats"] = {"scope": "replica", "range": "1h", "step_seconds": 60,
                        "timeline": snap["timeline"], "tools": snap["tools"],
                        "denials_by_rule": snap["denials_by_rule"], "latency": snap["latency"],
                        "totals": {}, "previous": {}, "replicas": []}
    try:
        out["trace_entries"] = len(service.trace)
        out["recent"] = [
            {"index": e.index, "kind": e.kind, "time": e.audit.timestamp,
             "principal": e.audit.principal, "object": e.audit.obj_ref,
             "purpose": e.audit.purpose, "decision": e.audit.decision, "rule": e.audit.detail}
            for e in service.trace.recent(recent)
        ]
    except Exception as exc:  # noqa: BLE001 -- show the dashboard even if storage is down
        out["trace_error"] = type(exc).__name__
    if key_store is not None:
        try:
            out["api_keys"] = [r.public_view() for r in key_store.list()]
        except Exception as exc:  # noqa: BLE001
            out["api_keys_error"] = type(exc).__name__
    return out


def install_routes(
    server: "MCPServer",
    service: "TokenisGatewayService",
    metrics: Metrics,
    *,
    admin_token: Optional[str] = None,
    metrics_token: Optional[str] = None,
    key_store: Any = None,
    admin_hosts: Optional[List[str]] = None,
    call_log: Any = None,
    oidc: Any = None,
    session_key: Optional[bytes] = None,
    secure_cookies: bool = False,
    ask: Any = None,
) -> None:
    """``admin_hosts``: Host header values the admin console answers to
    (DNS-rebinding protection for the one browser-facing page; probes and
    metrics are addressed by pod IP and are not browser-facing)."""
    import anyio
    from starlette.requests import Request
    from starlette.responses import (
        HTMLResponse,
        JSONResponse,
        PlainTextResponse,
        RedirectResponse,
        Response,
    )

    no_store = {"Cache-Control": "no-store"}

    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"}, headers=no_store)

    def _ready() -> Tuple[bool, Dict[str, str]]:
        checks = {"ledger": "sealed" if service._sealed else "not sealed"}
        ok = service._sealed
        if service.state_failure is not None:
            checks["state"] = "diverged: restart this replica"
            ok = False
        busy = service.busy_seconds()
        if busy > 10:
            checks["calls"] = f"one call has been running for {busy:.0f} s"
            ok = False
        if service.shared_state is not None:
            up = service.shared_state.ping()
            checks["database"] = "ok" if up else "unreachable"
            ok = ok and up
        return ok, checks

    @server.custom_route("/readyz", methods=["GET"], include_in_schema=False)
    async def readyz(_request: Request) -> Response:
        # Answer within a probe's timeout even when the database hangs: an
        # unanswered probe is indistinguishable from a dead process.
        ok, checks = False, {"database": "no answer within 2.5 s"}
        with anyio.move_on_after(2.5):
            ok, checks = await anyio.to_thread.run_sync(_ready, abandon_on_cancel=True)
        return JSONResponse({"status": "ready" if ok else "not ready", "checks": checks},
                            status_code=200 if ok else 503, headers=no_store)

    @server.custom_route("/metrics", methods=["GET"], include_in_schema=False)
    async def prometheus(request: Request) -> Response:
        if metrics_token and not _authorised(request.headers.get("authorization", ""), metrics_token):
            return PlainTextResponse("unauthorized\n", status_code=401,
                                     headers={"WWW-Authenticate": "Bearer"})
        body = await anyio.to_thread.run_sync(metrics.render, service, bool(metrics_token))
        return PlainTextResponse(body, media_type="text/plain; version=0.0.4", headers=no_store)

    @server.custom_route("/lang/{code}", methods=["GET"], include_in_schema=False)
    async def set_language(request: Request) -> Response:
        """Remember the language choice (a cookie) and return to the page."""
        code = request.path_params["code"]
        if code not in ("en", "ko"):
            return PlainTextResponse("unknown language\n", status_code=404)
        target = request.query_params.get("next", "/")
        if not (target.startswith("/") and not target.startswith("//")
                and not any(c in target for c in "\\\r\n")):
            target = "/"
        from tokenis.console_auth import cookie_header

        response = RedirectResponse(target, status_code=302, headers=no_store)
        response.headers.append("set-cookie", cookie_header(
            "tokenis_lang", code, max_age=365 * 24 * 3600, secure=secure_cookies, path="/"))
        return response

    if not admin_token and oidc is None:
        return

    from tokenis.console_auth import (
        FLOW_COOKIE,
        ROLES,
        SESSION_COOKIE,
        ConsoleAuthError,
        SessionSigner,
        at_least,
        cookie_header,
        expired_cookie,
        new_flow,
        read_cookie,
    )

    sessions = SessionSigner(session_key, "session") if oidc is not None and session_key else None
    flows = SessionSigner(session_key, "flow") if oidc is not None and session_key else None
    if oidc is not None and sessions is None:
        raise ValueError("single sign-on needs a session key")
    session_ttl = int(oidc.settings.session_hours * 3600) if oidc is not None else 0

    def _host_ok(request: Request) -> bool:
        return not admin_hosts or request.headers.get("host", "") in admin_hosts

    def _challenge() -> Response:
        return PlainTextResponse("admin token required\n", status_code=401,
                                 headers={"WWW-Authenticate": 'Basic realm="tokenis admin"', **no_store})

    def _who(request: Request) -> Optional[Dict[str, str]]:
        """Who is calling: a console session (single sign-on), or the admin
        token (break-glass and automation; full rights)."""
        header = request.headers.get("authorization", "")
        if admin_token and header and _authorised(header, admin_token):
            return {"identity": "admin token", "role": "admin", "method": "token"}
        if sessions is not None:
            payload = sessions.verify(read_cookie(request.headers.get("cookie", ""), SESSION_COOKIE))
            if payload and payload.get("role") in ROLES:
                return {"identity": str(payload["sub"]), "role": str(payload["role"]), "method": "sso"}
        return None

    def _guard(request: Request, need: str = "viewer", write: bool = False) -> Tuple[Optional[Dict[str, str]], Optional[Response]]:
        """(who, None) if the request may proceed, else (None, response)."""
        if not _host_ok(request):
            return None, PlainTextResponse("misdirected request\n", status_code=421)
        who = _who(request)
        if who is None:
            if oidc is not None:
                return None, JSONResponse({"error": "sign in required", "login": "admin/auth/login"},
                                          status_code=401, headers=no_store)
            return None, _challenge()
        if not at_least(who["role"], need):
            return None, JSONResponse({"error": f"this needs the {need} role; you are {who['role']}"},
                                      status_code=403, headers=no_store)
        if write:
            # CSRF: a JSON body plus a custom header force a CORS preflight,
            # which this server never approves, and the Origin must be ours
            # (the session cookie is also SameSite=Lax).
            origin = request.headers.get("origin")
            host = request.headers.get("host", "")
            if (not request.headers.get("content-type", "").startswith("application/json")
                    or request.headers.get("x-tokenis-console") != "1"
                    or (origin is not None and origin.split("://", 1)[-1] != host)):
                return None, JSONResponse({"error": "rejected: not sent by the console"}, status_code=403)
        return who, None

    def _source(request: Request) -> str:
        client = request.client.host if request.client else "?"
        forwarded = request.headers.get("x-forwarded-for", "")
        agent = request.headers.get("user-agent", "")[:300]
        return f"{client}" + (f" (via {forwarded[:60]})" if forwarded else "") + (f"; {agent}" if agent else "")

    def _audit(who: Dict[str, str], action: str, target: str, detail: str, request: Request) -> None:
        actor = f"{who['identity']} ({who['role']})"
        if call_log is not None:
            call_log.admin_event(actor, action, target, detail, _source(request))
        log.info("console %s by %s: %s %s", action, actor, target, detail)

    @server.custom_route("/admin/api/summary", methods=["GET"], include_in_schema=False)
    async def admin_summary(request: Request) -> Response:
        who, denied = _guard(request)
        if denied is not None:
            return denied
        assert who is not None  # noqa: S101 -- _guard returned a caller
        try:
            recent = max(1, min(500, int(request.query_params.get("recent", "100"))))
        except ValueError:
            recent = 100
        range_key = request.query_params.get("range", "24h")
        data = await anyio.to_thread.run_sync(
            lambda: summary(service, metrics, key_store, recent, call_log, range_key))
        if not at_least(who["role"], "auditor"):
            # Viewers see statistics, not who asked what.
            data.pop("recent", None)
            data.pop("api_keys", None)
        data["me"] = {**who, "sso": oidc is not None}
        data["ask"] = ask is not None
        data["labels"] = dict(ask.settings.labels) if ask is not None else {}
        return JSONResponse(data, headers=no_store)

    def _principals(range_key: str) -> Dict[str, Any]:
        rows = call_log.principals(range_key) if call_log is not None else []
        names = {r["principal"] for r in rows}
        if key_store is not None:
            for record in key_store.list():
                if not record.revoked and record.principal not in names:
                    rows.append({"principal": record.principal, "calls": 0, "answered": 0, "denied": 0,
                                 "last_seen": None, "rules": {}})
                    names.add(record.principal)
        budgets = service.budgets(sorted(names)) if names else {}
        for row in rows:
            row["budget"] = budgets.get(row["principal"])
        return {"range": range_key, "principals": rows}

    @server.custom_route("/admin/api/principals", methods=["GET"], include_in_schema=False)
    async def admin_principals(request: Request) -> Response:
        _, denied = _guard(request, "auditor")
        if denied is not None:
            return denied
        data = await anyio.to_thread.run_sync(_principals, request.query_params.get("range", "24h"))
        return JSONResponse(data, headers=no_store)

    @server.custom_route("/admin/api/activity", methods=["GET"], include_in_schema=False)
    async def admin_activity(request: Request) -> Response:
        _, denied = _guard(request, "auditor")
        if denied is not None:
            return denied
        events = await anyio.to_thread.run_sync(call_log.admin_events) if call_log is not None else []
        return JSONResponse({"events": events}, headers=no_store)

    @server.custom_route("/admin/api/keys", methods=["POST"], include_in_schema=False)
    async def admin_create_key(request: Request) -> Response:
        who, denied = _guard(request, "admin", write=True)
        if denied is not None:
            return denied
        assert who is not None  # noqa: S101
        if key_store is None:
            return JSONResponse({"error": "this gateway authenticates with JWTs; keys are managed by your "
                                          "identity provider"}, status_code=409)
        try:
            body = await request.json()
            principal = str(body.get("principal", "")).strip()
            token, record = await anyio.to_thread.run_sync(key_store.create, principal)
        except ValueError as exc:
            return JSONResponse({"error": str(exc) or "invalid request"}, status_code=400)
        await anyio.to_thread.run_sync(_audit, who, "create key", record.key_id, f"principal {principal}", request)
        return JSONResponse({"token": token, "key": record.public_view()}, status_code=201, headers=no_store)

    @server.custom_route("/admin/api/keys/{key_id}/revoke", methods=["POST"], include_in_schema=False)
    async def admin_revoke_key(request: Request) -> Response:
        who, denied = _guard(request, "admin", write=True)
        if denied is not None:
            return denied
        assert who is not None  # noqa: S101
        if key_store is None:
            return JSONResponse({"error": "no API keys on this gateway"}, status_code=409)
        key_id = request.path_params["key_id"]
        if not key_id.isalnum() or len(key_id) > 64:
            return JSONResponse({"error": "invalid key id"}, status_code=400)
        revoked = await anyio.to_thread.run_sync(key_store.revoke, key_id)
        if not revoked:
            return JSONResponse({"error": "no active key with that id"}, status_code=404)
        await anyio.to_thread.run_sync(_audit, who, "revoke key", key_id, "", request)
        return JSONResponse({"revoked": key_id}, headers=no_store)

    def _csv(rows: Any, header: List[str]) -> Any:
        import csv
        import io

        def stream() -> Iterator[str]:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(header)
            for row in rows:
                # Neutralise spreadsheet formulas in caller-controlled text.
                writer.writerow([f"'{v}" if isinstance(v, str) and v[:1] in "=+-@\t\r" else v for v in row])
                if buffer.tell() > 65536:
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate()
            yield buffer.getvalue()
        return stream()

    def _iso(seconds: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))

    @server.custom_route("/admin/api/export/{kind}.csv", methods=["GET"], include_in_schema=False)
    async def admin_export(request: Request) -> Response:
        from starlette.responses import StreamingResponse

        from tokenis.calllog import range_spec

        who, denied = _guard(request, "auditor")
        if denied is not None:
            return denied
        assert who is not None  # noqa: S101
        kind = request.path_params["kind"]
        range_key, length, _ = range_spec(request.query_params.get("range", "24h"))
        if kind == "calls" and call_log is not None:
            rows: Any = ((_iso(int(ts) / 1000), rep_, tool, principal, outcome, rule, dur)
                         for ts, rep_, tool, principal, outcome, rule, dur in call_log.export(range_key))
            header = ["time_utc", "replica", "tool", "principal", "outcome", "rule", "duration_ms"]
        elif kind == "audit":
            since = time.time() - length
            rows = ((e.index, _iso(e.audit.timestamp), e.kind, e.audit.principal, e.audit.obj_ref,
                     e.audit.purpose, e.audit.decision, e.audit.detail, e.digest)
                    for e, _d, _m, _w in service.trace._storage.scan() if e.audit.timestamp >= since)
            header = ["index", "time_utc", "kind", "principal", "object", "purpose", "decision", "rule", "digest"]
        else:
            return PlainTextResponse("unknown export\n", status_code=404)
        await anyio.to_thread.run_sync(_audit, who, "export", f"{kind}.csv", f"range {range_key}", request)
        name = f"tokenis-{service.settings.tenant}-{kind}-{range_key}-{time.strftime('%Y%m%d-%H%M')}.csv"
        return StreamingResponse(_csv(rows, header), media_type="text/csv; charset=utf-8", headers={
            **no_store, "Content-Disposition": f'attachment; filename="{name}"'})

    def _page(nonce: str, html: str) -> Response:
        return HTMLResponse(html, headers={
            **no_store,
            "Content-Security-Policy": (
                f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                "form-action 'self'"),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })

    def _lang(request: Request) -> str:
        """en or ko: the person's choice (the tokenis_lang cookie, set by the
        language switch), else the configured default (English)."""
        chosen = read_cookie(request.headers.get("cookie", ""), "tokenis_lang")
        if chosen in ("en", "ko"):
            return chosen
        return ask.settings.language if ask is not None else "en"

    def _switch(request: Request) -> str:
        """The EN / 한 switch for the sign-in pages: it returns here."""
        import html as html_lib
        import urllib.parse

        here = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        lang = _lang(request)
        links = []
        for code, label in (("en", "EN"), ("ko", "한")):
            current = ' aria-current="true"' if code == lang else ""
            href = f"/lang/{code}?next={urllib.parse.quote(here, safe='/?=&')}"
            links.append(f'<a href="{html_lib.escape(href)}"{current}>{label}</a>')
        return f'<nav class="lang" aria-label="Language">{"".join(links)}</nav>'

    def _message_page(request: Request, key: str, status: int = 200, action: Optional[Tuple[str, str]] = None,
                      **fmt: str) -> Response:
        import html as html_lib

        lang = _lang(request)
        text = MESSAGES[lang]
        title, body_text = text[key]
        nonce = secrets.token_urlsafe(16)
        body = (message_html().replace("{{nonce}}", nonce).replace("{{icon}}", _icon_uri())
                .replace("{{switch}}", _switch(request)))
        for slot in ("subtitle", "foot_sso", "foot_audit"):
            body = body.replace("{{" + slot + "}}", html_lib.escape(text[slot]))
        body = body.replace("{{lang}}", lang)
        tenant = html_lib.escape(service.settings.tenant)
        # Fill the caller-influenced slots last, escaped, so nothing in them is
        # read as a template marker.
        link = ""
        if action:
            label = text[action[1]].format(**fmt) if action[1] in text else action[1]
            link = (f'<a class="btn" href="{html_lib.escape(action[0])}"><svg viewBox="0 0 24 24" fill="none" '
                    'stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">'
                    '<path d="M10 7.5 14.5 12 10 16.5"/><path d="M14.5 12H4.5"/><path d="M14.5 4.5h3a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2h-3"/></svg>'
                    f'{html_lib.escape(label)}</a>')
            if key in ("sign_in", "sign_in_ask"):
                link += f'<div class="note">{html_lib.escape(text["sign_in_note"])}</div>'
        body = body.replace("{{extra}}", f'<div class="tenant">{html_lib.escape(text["tenant"])} · {tenant}</div>')
        body = body.replace("{{action}}", link)
        body = body.replace("{{title}}", html_lib.escape(title.format(**fmt)))
        body = body.replace("{{text}}", html_lib.escape(body_text.format(**fmt)))
        response = _page(nonce, body)
        response.status_code = status
        return response

    def _sign_in_redirect(next_path: str) -> Response:
        return RedirectResponse(f"/admin/auth/login?next={next_path}", status_code=302, headers=no_store)

    @server.custom_route("/admin", methods=["GET"], include_in_schema=False)
    async def admin_page(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        who = _who(request)
        if who is None:
            if oidc is not None:
                return _sign_in_redirect("/admin")
            return _challenge()
        if not at_least(who["role"], "viewer"):
            if ask is not None:
                return RedirectResponse("/ask", status_code=302, headers=no_store)
            return _message_page(request, "no_console", 403, identity=who["identity"])
        nonce = secrets.token_urlsafe(16)
        html = dashboard_html().replace("{{nonce}}", nonce).replace("{{icon}}", _icon_uri())
        return _page(nonce, html.replace("{{lang}}", _lang(request)))

    @server.custom_route("/", methods=["GET"], include_in_schema=False)
    async def root(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        return RedirectResponse("/ask" if ask is not None else "/admin", status_code=302, headers=no_store)

    if ask is not None:
        _install_ask(server, ask, service, guard=_guard, who_of=_who, page=_page, host_ok=_host_ok,
                     sign_in=_sign_in_redirect if oidc is not None else None, challenge=_challenge,
                     lang_of=_lang, no_store=no_store)

    if oidc is None:
        return
    assert sessions is not None and flows is not None  # noqa: S101 -- checked above

    provider = oidc.settings.display_name or "SSO"

    def _next(value: Optional[str]) -> str:
        return value if value in ("/admin", "/ask") else "/admin"

    @server.custom_route("/admin/auth/login", methods=["GET"], include_in_schema=False)
    async def auth_login(request: Request) -> Response:
        """The sign-in page; the button starts the flow."""
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        target = _next(request.query_params.get("next"))
        who = _who(request)
        if who is not None:
            return RedirectResponse(target if at_least(who["role"], "viewer") or ask is None else "/ask",
                                    status_code=302, headers=no_store)
        return _message_page(request, "sign_in_ask" if target == "/ask" else "sign_in", 200,
                             (f"/admin/auth/start?next={target}", "continue_with"), provider=provider)

    @server.custom_route("/admin/auth/start", methods=["GET"], include_in_schema=False)
    async def auth_start(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        flow = new_flow()
        flow["next"] = _next(request.query_params.get("next"))
        try:
            url = await anyio.to_thread.run_sync(oidc.authorization_url, flow["state"], flow["nonce"],
                                                 flow["verifier"])
        except Exception as exc:  # noqa: BLE001 -- show a page, keep details in the log
            log.warning("single sign-on unavailable: %s: %s", type(exc).__name__, exc)
            return _message_page(request, "unavailable", 503, (f"/admin/auth/start?next={flow['next']}", "try_again"))
        response = RedirectResponse(url, status_code=302, headers=no_store)
        response.headers.append("set-cookie", cookie_header(FLOW_COOKIE, flows.sign(flow, 600), max_age=600,
                                                            secure=secure_cookies, path="/admin/auth"))
        return response

    @server.custom_route("/admin/auth/callback", methods=["GET"], include_in_schema=False)
    async def auth_callback(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        flow = flows.verify(read_cookie(request.headers.get("cookie", ""), FLOW_COOKIE))
        target = _next(str(flow.get("next"))) if flow else "/admin"
        retry = (f"/admin/auth/login?next={target}", "sign_in_again")
        params = request.query_params
        if params.get("error"):
            return _message_page(request, "cancelled", 400, retry)
        if (flow is None or not params.get("code")
                or not equal(str(flow.get("state", "")), params.get("state", ""))):
            return _message_page(request, "expired", 400, retry)
        try:
            claims = await anyio.to_thread.run_sync(oidc.exchange, params["code"], flow["verifier"], flow["nonce"])
        except ConsoleAuthError as exc:
            log.warning("single sign-on failed: %s", exc)
            lang = _lang(request)
            return _message_page(request, "failed", 400, retry,
                                 reason=str(exc) if lang == "en" else MESSAGES[lang]["verify_failed"])
        except Exception as exc:  # noqa: BLE001
            log.warning("single sign-on failed: %s: %s", type(exc).__name__, exc)
            return _message_page(request, "failed", 503, retry, reason=MESSAGES[_lang(request)]["idp_down"])
        role, identity = oidc.settings.role_for(claims)
        if role is None:
            who = {"identity": identity or "(unknown)", "role": "none"}
            await anyio.to_thread.run_sync(_audit, who, "sign-in refused", identity or "-", "no role", request)
            return _message_page(request, "no_role", 403, identity=identity or "?")
        if role == "user" and ask is None:
            await anyio.to_thread.run_sync(_audit, {"identity": identity, "role": role}, "sign-in refused",
                                           identity, "Ask is not enabled", request)
            return _message_page(request, "no_console", 403, identity=identity)
        if not at_least(role, "viewer"):
            target = "/ask"
        session = {"sub": identity, "role": role, "sid": secrets.token_urlsafe(12), "iat": int(time.time())}
        response = RedirectResponse(target, status_code=302, headers=no_store)
        response.headers.append("set-cookie", cookie_header(SESSION_COOKIE, sessions.sign(session, session_ttl),
                                                            max_age=session_ttl, secure=secure_cookies, path="/"))
        response.headers.append("set-cookie", expired_cookie(FLOW_COOKIE, secure=secure_cookies, path="/admin/auth"))
        await anyio.to_thread.run_sync(_audit, {"identity": identity, "role": role}, "sign in", identity, "", request)
        return response

    @server.custom_route("/admin/auth/logout", methods=["POST"], include_in_schema=False)
    async def auth_logout(request: Request) -> Response:
        who, denied = _guard(request, "user", write=True)
        if denied is not None:
            return denied
        assert who is not None  # noqa: S101
        response = JSONResponse({"signed_out": True}, headers=no_store)
        response.headers.append("set-cookie", expired_cookie(SESSION_COOKIE, secure=secure_cookies, path="/"))
        # Sessions from before Ask were scoped to /admin.
        response.headers.append("set-cookie", expired_cookie(SESSION_COOKIE, secure=secure_cookies, path="/admin"))
        if who["method"] == "sso":
            await anyio.to_thread.run_sync(_audit, who, "sign out", who["identity"], "", request)
        return response


def _principal_for(who: Dict[str, str]) -> str:
    """The admission principal for a signed-in person: their identity (so
    Ask shares the budget of the API keys issued to the same identity)."""
    import re

    if who.get("method") == "token":
        return "console:admin-token"
    principal = re.sub(r"[^A-Za-z0-9._@:+-]", "_", who["identity"])[:128]
    return principal or "console:unknown"


def _install_ask(server: Any, ask: Any, service: Any, *, guard: Any, who_of: Any, page: Any, host_ok: Any,
                 sign_in: Any, challenge: Any, lang_of: Any, no_store: Dict[str, str]) -> None:
    """/ask, /ask/api/context and /ask/api/chat (tokenis.ask)."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

    from tokenis.ask import MAX_QUESTION_CHARS, ask_page_html, clean_history
    from tokenis.console_auth import at_least

    @server.custom_route("/ask", methods=["GET"], include_in_schema=False)
    async def ask_page(request: Request) -> Response:
        if not host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        if who_of(request) is None:
            return sign_in("/ask") if sign_in is not None else challenge()
        nonce = secrets.token_urlsafe(16)
        html = ask_page_html().replace("{{nonce}}", nonce).replace("{{icon}}", _icon_uri())
        return page(nonce, html.replace("{{lang}}", lang_of(request)))

    @server.custom_route("/ask/api/context", methods=["GET"], include_in_schema=False)
    async def ask_context(request: Request) -> Response:
        import anyio

        who, denied = guard(request, "user")
        if denied is not None:
            return denied
        principal = _principal_for(who)
        catalog = await anyio.to_thread.run_sync(ask.catalog)
        return JSONResponse({
            "me": {"identity": who["identity"], "role": who["role"], "method": who["method"],
                   "console": at_least(who["role"], "viewer")},
            "tenant": service.settings.tenant,
            "model": ask.settings.display_name or ask.settings.model,
            "language": ask.settings.language,
            "limits": {"question_chars": MAX_QUESTION_CHARS, "per_hour": ask.settings.questions_per_hour},
            "catalog": catalog,
            "budget": await ask.budget(principal),
        }, headers=no_store)

    @server.custom_route("/ask/api/chat", methods=["POST"], include_in_schema=False)
    async def ask_chat(request: Request) -> Response:
        who, denied = guard(request, "user", write=True)
        if denied is not None:
            return denied
        if int(request.headers.get("content-length") or 0) > 256 * 1024:
            return JSONResponse({"error": "request too large"}, status_code=413)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        question = str(body.get("question", "")).strip()
        if not question or len(question) > MAX_QUESTION_CHARS:
            return JSONResponse({"error": f"ask a question of 1 to {MAX_QUESTION_CHARS} characters"},
                                status_code=400)
        history = clean_history(body.get("history"))
        lang = "en" if body.get("lang") == "en" else "ko"
        principal = _principal_for(who)

        async def events() -> Any:
            # Acquired inside the stream, so a client that leaves before it
            # starts never holds the slot.
            why = ask.limiter.acquire(principal)
            if why is not None:
                yield _sse({"type": "error", "code": why, "message": why})
                return
            try:
                async for event in ask.run(principal, question, history, lang):
                    yield _sse(event)
            except Exception:
                log.exception("ask failed")
                yield _sse({"type": "error", "code": "internal", "message": "Something went wrong."})
                yield _sse({"type": "done", "steps": 0, "budget": None})
            finally:
                ask.limiter.release(principal)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={**no_store, "X-Accel-Buffering": "no"})


def _sse(event: Dict[str, Any]) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


#: Sign-in and error pages, per language: key -> (title, text), plus labels.
MESSAGES: Dict[str, Dict[str, Any]] = {
    "en": {
        "subtitle": "Disclosure-boundary gateway", "foot_sso": "Single sign-on",
        "foot_audit": "Every sign-in is recorded", "tenant": "Tenant",
        "sign_in": ("Sign in to the console", ("Use your organisation account. Your role decides what you can "
                                              "see and do here.")),
        "sign_in_ask": ("Sign in to Tokenis Ask", ("Use your organisation account to ask questions about your "
                                                   "organisation's data. Individual records stay protected.")),
        "sign_in_note": "You will continue on your organisation's sign-in page.",
        "continue_with": "Continue with {provider}", "try_again": "Try again", "sign_in_again": "Sign in again",
        "unavailable": ("Sign-in is unavailable", ("The identity provider could not be reached. Try again in a "
                                                  "moment, or ask your administrator.")),
        "cancelled": ("Sign-in was cancelled", "The identity provider did not complete the sign-in."),
        "expired": ("Sign-in expired", "This sign-in link is no longer valid. Start again."),
        "failed": ("Sign-in failed", "{reason}"),
        "idp_down": "The identity provider could not be reached.",
        "verify_failed": "The identity provider's answer could not be verified. Sign in again.",
        "no_role": ("No access yet", ("You signed in as {identity}, which has no access to this gateway. Ask an "
                                     "administrator to add you.")),
        "no_console": ("No access to the console", ("You signed in as {identity}. Your role does not include the "
                                                   "admin console.")),
    },
    "ko": {
        "subtitle": "데이터 보호 게이트웨이", "foot_sso": "회사 계정 로그인(SSO)",
        "foot_audit": "모든 로그인은 기록됩니다", "tenant": "테넌트",
        "sign_in": ("관리 콘솔 로그인", ("회사 계정으로 로그인하세요. 역할에 따라 볼 수 있는 내용과 할 수 있는 일이 "
                                       "정해집니다.")),
        "sign_in_ask": ("Tokenis Ask 로그인", ("회사 계정으로 로그인하면 우리 회사 데이터에 대해 바로 질문할 수 "
                                              "있어요. 개별 고객·직원 정보는 보호됩니다.")),
        "sign_in_note": "회사 로그인 페이지로 이동한 뒤 다시 돌아옵니다.",
        "continue_with": "{provider} 계정으로 계속", "try_again": "다시 시도", "sign_in_again": "다시 로그인",
        "unavailable": ("지금은 로그인할 수 없어요", ("회사 로그인 서비스에 연결하지 못했습니다. 잠시 후 다시 "
                                                    "시도하거나 관리자에게 문의하세요.")),
        "cancelled": ("로그인이 취소되었어요", "회사 로그인 페이지에서 로그인이 완료되지 않았습니다."),
        "expired": ("로그인 시간이 지났어요", ("이 로그인 링크는 더 이상 유효하지 않습니다. 처음부터 다시 "
                                               "시작하세요.")),
        "failed": ("로그인하지 못했어요", "{reason}"),
        "idp_down": "회사 로그인 서비스에 연결하지 못했습니다.",
        "verify_failed": "회사 로그인 서비스의 응답을 확인하지 못했습니다. 다시 로그인해 주세요.",
        "no_role": ("아직 권한이 없어요", ("{identity} 계정으로 로그인했지만 이 게이트웨이를 쓸 권한이 없습니다. "
                                         "관리자에게 추가를 요청하세요.")),
        "no_console": ("관리 콘솔 권한이 없어요", ("{identity} 계정으로 로그인했습니다. 이 계정의 역할로는 관리 "
                                                 "콘솔을 열 수 없습니다.")),
    },
}

def _icon_uri() -> str:
    from importlib import resources

    png = resources.files("tokenis").joinpath("assets/icon-64.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def message_html() -> str:
    """A small branded page for sign-in outcomes (tokenis/assets/message.html)."""
    from importlib import resources

    return resources.files("tokenis").joinpath("assets/message.html").read_text(encoding="utf-8")


def dashboard_html() -> str:
    """The admin dashboard (tokenis/assets/admin.html): one self-contained
    page, no external requests, served under a nonce-based CSP."""
    from importlib import resources

    return resources.files("tokenis").joinpath("assets/admin.html").read_text(encoding="utf-8")
