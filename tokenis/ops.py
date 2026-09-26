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
- ``GET /admin`` and ``GET /admin/api/summary`` -- the dashboard, enabled
  only when ``[ops] admin_token_env`` names a set variable. HTTP Basic
  (any user name, the token as password) or ``Authorization: Bearer``.

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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer

    from tokenis.gateway.service import TokenisGatewayService

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
            recent: int = 50) -> Dict[str, Any]:
    """What the dashboard shows. No sealed values, no disclosed values."""
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
        **metrics.snapshot(),
    }
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
) -> None:
    """``admin_hosts``: Host header values the admin console answers to
    (DNS-rebinding protection for the one browser-facing page; probes and
    metrics are addressed by pod IP and are not browser-facing)."""
    import anyio
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

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

    if not admin_token:
        return

    def _host_ok(request: Request) -> bool:
        return not admin_hosts or request.headers.get("host", "") in admin_hosts

    def _challenge() -> Response:
        return PlainTextResponse("admin token required\n", status_code=401,
                                 headers={"WWW-Authenticate": 'Basic realm="tokenis admin"', **no_store})

    @server.custom_route("/admin/api/summary", methods=["GET"], include_in_schema=False)
    async def admin_summary(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        if not _authorised(request.headers.get("authorization", ""), admin_token):
            return _challenge()
        try:
            recent = max(1, min(500, int(request.query_params.get("recent", "100"))))
        except ValueError:
            recent = 100
        data = await anyio.to_thread.run_sync(summary, service, metrics, key_store, recent)
        return JSONResponse(data, headers=no_store)

    @server.custom_route("/admin", methods=["GET"], include_in_schema=False)
    async def admin_page(request: Request) -> Response:
        if not _host_ok(request):
            return PlainTextResponse("misdirected request\n", status_code=421)
        if not _authorised(request.headers.get("authorization", ""), admin_token):
            return _challenge()
        nonce = secrets.token_urlsafe(16)
        html = (dashboard_html().replace("{{nonce}}", nonce)
                .replace("{{icon}}", _icon_uri()))
        return HTMLResponse(html, headers={
            **no_store,
            "Content-Security-Policy": (
                f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "img-src data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })


def _icon_uri() -> str:
    from importlib import resources

    png = resources.files("tokenis").joinpath("assets/icon-64.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def dashboard_html() -> str:
    """The admin dashboard (tokenis/assets/admin.html): one self-contained
    page, no external requests, served under a nonce-based CSP."""
    from importlib import resources

    return resources.files("tokenis").joinpath("assets/admin.html").read_text(encoding="utf-8")
