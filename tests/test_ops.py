# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Health, readiness, metrics and the admin dashboard."""
import asyncio
import base64
import json
import logging

import pytest

pytest.importorskip("mcp")
from mcp.server.mcpserver.exceptions import ToolError
from starlette.testclient import TestClient

from tokenis.gateway.demo import demo_service
from tokenis.mcp_server.server import create_server, fixed_principal
from tokenis.ops import JsonFormatter, Metrics, install_routes

ADMIN = "admin-token-0123456789"
SCRAPE = "scrape-token-0123456789"


def build(**kwargs):
    service = demo_service(latency_granularity_ms=1.0)
    metrics = Metrics()
    server = create_server(service, principal_resolver=fixed_principal("alice"), metrics=metrics)
    install_routes(server, service, metrics, **kwargs)
    return service, server, TestClient(server.streamable_http_app())


def call(server, tool, args):
    return asyncio.run(server.call_tool(tool, args))


def test_probes():
    _, _, client = build()
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["checks"] == {"ledger": "sealed"}


def test_metrics_count_outcomes_and_rules_without_values():
    service, server, client = build()
    call(server, "aggregate", {"function": "sum", "column": "revenue_2025",
                               "filters": {"industry": "finance"}})
    with pytest.raises(ToolError):
        call(server, "aggregate", {"function": "sum", "column": "revenue_2025",
                                   "filters": {"industry": "retail"}})
    body = client.get("/metrics").text
    assert 'tokenis_tool_calls_total{tool="aggregate",outcome="ok"} 1' in body
    assert 'tokenis_tool_calls_total{tool="aggregate",outcome="denied"} 1' in body
    assert "rule=" not in body  # open /metrics: no per-rule breakdown
    assert 'tokenis_tool_call_duration_seconds_count{tool="aggregate"} 2' in body
    assert f"tokenis_records {service.record_count}\n" in body
    assert "4250000" not in body and "4,250,000" not in body
    # Histogram buckets are cumulative.
    buckets = [float(line.rsplit(" ", 1)[1]) for line in body.splitlines()
               if line.startswith('tokenis_tool_call_duration_seconds_bucket{tool="aggregate"')]
    assert buckets == sorted(buckets) and buckets[-1] == 2


def test_metrics_token():
    _, server, client = build(metrics_token=SCRAPE)
    with pytest.raises(ToolError):
        call(server, "aggregate", {"function": "sum", "column": "revenue_2025",
                                   "filters": {"industry": "retail"}})
    assert client.get("/metrics").status_code == 401
    body = client.get("/metrics", headers={"Authorization": f"Bearer {SCRAPE}"}).text
    assert 'tokenis_denials_total{rule="D1"} 1' in body


def test_open_metrics_do_not_reveal_denial_rules():
    """Regression (security review): a caller reading an open /metrics before
    and after a query learned which rule refused it."""
    _, server, client = build()
    with pytest.raises(ToolError):
        call(server, "aggregate", {"function": "sum", "column": "revenue_2025",
                                   "filters": {"industry": "retail"}})
    body = client.get("/metrics").text
    assert 'outcome="denied"} 1' in body and "rule=" not in body


def test_admin_is_off_without_a_token():
    _, _, client = build()
    assert client.get("/admin").status_code == 404


def test_admin_dashboard_requires_the_token_and_hides_values():
    service, server, client = build(admin_token=ADMIN)
    call(server, "aggregate", {"function": "sum", "column": "revenue_2025",
                               "filters": {"industry": "finance"}})
    denied = client.get("/admin")
    assert denied.status_code == 401 and "Basic" in denied.headers["www-authenticate"]
    wrong = base64.b64encode(b"admin:nope").decode()
    assert client.get("/admin", headers={"Authorization": f"Basic {wrong}"}).status_code == 401

    basic = base64.b64encode(f"admin:{ADMIN}".encode()).decode()
    page = client.get("/admin", headers={"Authorization": f"Basic {basic}"})
    assert page.status_code == 200 and "Tokenis Console" in page.text
    csp = page.headers["content-security-policy"]
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"' in page.text and "unsafe-inline" not in csp
    assert page.headers["cache-control"] == "no-store"

    data = client.get("/admin/api/summary", headers={"Authorization": f"Bearer {ADMIN}"}).json()
    assert data["records"] == service.record_count and data["trace_entries"] == 1
    assert data["tools"]["aggregate"]["ok"] == 1
    assert data["recent"][0]["principal"] == "alice"
    assert "4250000" not in json.dumps(data) and "value_summary" not in json.dumps(data)


def test_admin_console_answers_only_its_own_host():
    """Regression (security review): the Host allow-list protected /mcp
    only, so a DNS-rebinding page could reach the console's origin."""
    _, _, client = build(admin_token=ADMIN, admin_hosts=["tokenis.example.com"])
    auth = {"Authorization": f"Bearer {ADMIN}"}
    assert client.get("/admin", headers={**auth, "Host": "evil.example"}).status_code == 421
    assert client.get("/admin", headers={**auth, "Host": "tokenis.example.com"}).status_code == 200
    assert client.get("/healthz", headers={"Host": "10.0.0.7:8000"}).status_code == 200  # probes


def test_json_logs():
    record = logging.LogRecord("tokenis.server", logging.INFO, __file__, 1, "denied tool=%s", ("x",), None)
    line = json.loads(JsonFormatter().format(record))
    assert line["message"] == "denied tool=x" and line["level"] == "INFO"
    assert line["time"].endswith("Z")
