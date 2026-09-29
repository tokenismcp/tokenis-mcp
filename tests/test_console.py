# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The admin console's data and actions: cluster-wide statistics from the
call log, per-user budgets, key management behind CSRF protection, the admin
activity log and CSV exports."""
import asyncio
import csv
import io
import json
import time

import pytest

pytest.importorskip("mcp")
from mcp.server.mcpserver.exceptions import ToolError
from starlette.testclient import TestClient

from tokenis.calllog import SqliteCallLog, _percentile
from tokenis.gateway.demo import demo_service
from tokenis.mcp_server.server import create_server, fixed_principal
from tokenis.ops import Metrics, install_routes
from tokenis.server_auth import ApiKeyStore

ADMIN = "admin-token-0123456789"
AUTH = {"Authorization": f"Bearer {ADMIN}"}
WRITE = {**AUTH, "Content-Type": "application/json", "X-Tokenis-Console": "1"}


def console(tmp_path, principal="alice", replica="replica-a"):
    service = demo_service(latency_granularity_ms=1.0)
    calls = SqliteCallLog(str(tmp_path / "calls.sqlite"), service.settings.tenant, replica=replica)
    keys = ApiKeyStore(tmp_path / "keys.json")
    metrics = Metrics()
    server = create_server(service, principal_resolver=fixed_principal(principal), metrics=metrics,
                           call_log=calls)
    install_routes(server, service, metrics, admin_token=ADMIN, key_store=keys, call_log=calls)
    return service, server, TestClient(server.streamable_http_app()), calls, keys


def call(server, tool, args):
    try:
        return asyncio.run(server.call_tool(tool, args))
    except ToolError:
        return None


FINANCE = {"function": "sum", "column": "revenue_2025", "filters": {"industry": "finance"}}
RETAIL = {"function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}}  # refused (D1)


def test_statistics_are_cluster_wide_and_survive_restarts(tmp_path):
    _, server_a, client_a, _, _ = console(tmp_path, "alice", "replica-a")
    _, server_b, client_b, calls_b, _ = console(tmp_path, "bob", "replica-b")  # same database
    call(server_a, "aggregate", FINANCE)
    call(server_a, "aggregate", RETAIL)
    call(server_b, "aggregate", FINANCE)
    calls_b.flush()  # what replica B's background writer does every 2 s
    for client in (client_a, client_b):  # both replicas report the same totals
        stats = client.get("/admin/api/summary?range=1h", headers=AUTH).json()["stats"]
        assert stats["scope"] == "cluster" and stats["totals"] == {"ok": 2, "denied": 1}
        assert stats["denials_by_rule"] == {"D1": 1}
        assert {r["replica"] for r in stats["replicas"]} == {"replica-a", "replica-b"}
        assert sum(b["ok"] + b["denied"] + b["other"] for b in stats["timeline"]) == 3
    # A restarted process sees the history (nothing lived only in memory).
    _, _, client_c, _, _ = console(tmp_path, "carol", "replica-c")
    assert client_c.get("/admin/api/summary?range=24h", headers=AUTH).json()["stats"]["totals"] == {"ok": 2, "denied": 1}


def test_ranges_and_previous_period(tmp_path):
    service = demo_service(latency_granularity_ms=1.0)
    calls = SqliteCallLog(":memory:", service.settings.tenant, replica="r")
    now = int(time.time() * 1000)
    calls._query("INSERT INTO tokenis_calls VALUES (%s, %s, 'r', 'aggregate', 'a', 'ok', '', 5)",
                 (service.settings.tenant, now - 36 * 3600 * 1000))  # 36 hours ago
    calls.record("aggregate", "a", "ok", None, 0.25)
    assert calls.overview("1h")["totals"] == {"ok": 1}
    assert calls.overview("24h")["previous"] == {"ok": 1}  # the 24h before the last 24h
    assert calls.overview("7d")["totals"] == {"ok": 2}
    assert len(calls.overview("1h")["timeline"]) in (60, 61)
    assert calls.overview("bogus")["range"] == "24h"


def test_latency_percentiles_are_exact():
    values = sorted([260.0] * 40 + [510.0] * 10)
    assert _percentile(values, 0.5) == 260.0     # a bucketed estimate said 406
    assert _percentile(values, 0.95) == 510.0
    assert _percentile([], 0.5) is None
    assert _percentile([7.0], 0.99) == 7.0


def test_users_page_reports_calls_refusals_and_budget(tmp_path):
    _, server, client, _, keys = console(tmp_path, "alice")
    keys.create("dora")  # a key holder who has not called yet
    call(server, "aggregate", FINANCE)
    call(server, "aggregate", RETAIL)
    rows = {r["principal"]: r for r in client.get("/admin/api/principals?range=24h", headers=AUTH).json()["principals"]}
    alice = rows["alice"]
    assert (alice["calls"], alice["answered"], alice["denied"], alice["rules"]) == (2, 1, 1, {"D1": 1})
    assert alice["budget"]["used"] == 1 and alice["budget"]["remaining"] == alice["budget"]["budget"] - 1
    assert rows["dora"]["calls"] == 0 and rows["dora"]["budget"]["used"] == 0


def test_keys_can_be_issued_and_revoked_from_the_console(tmp_path):
    _, _, client, _, keys = console(tmp_path)
    created = client.post("/admin/api/keys", headers=WRITE, content=json.dumps({"principal": "erin@acme.example"}))
    assert created.status_code == 201
    token, key_id = created.json()["token"], created.json()["key"]["key_id"]
    assert keys.verify(token) == "erin@acme.example"
    assert "key_hash" not in created.text
    revoked = client.post(f"/admin/api/keys/{key_id}/revoke", headers=WRITE, content="{}")
    assert revoked.status_code == 200 and keys.verify(token) is None
    assert client.post(f"/admin/api/keys/{key_id}/revoke", headers=WRITE, content="{}").status_code == 404
    bad = client.post("/admin/api/keys", headers=WRITE, content=json.dumps({"principal": "no spaces allowed"}))
    assert bad.status_code == 400
    actions = [e["action"] for e in client.get("/admin/api/activity", headers=AUTH).json()["events"]]
    assert actions == ["revoke key", "create key"]


def test_key_management_is_protected_against_csrf_and_needs_the_token(tmp_path):
    _, _, client, _, keys = console(tmp_path)
    body = json.dumps({"principal": "mallory"})
    assert client.post("/admin/api/keys", content=body, headers={"Content-Type": "application/json",
                                                                 "X-Tokenis-Console": "1"}).status_code == 401
    # A cross-site form post: no custom header, form encoding.
    form = client.post("/admin/api/keys", headers={**AUTH, "Content-Type": "application/x-www-form-urlencoded"},
                       content="principal=mallory")
    assert form.status_code == 403
    # Right headers, but sent from another origin.
    foreign = client.post("/admin/api/keys", headers={**WRITE, "Origin": "https://evil.example"}, content=body)
    assert foreign.status_code == 403
    assert keys.list() == []
    # The console's own requests carry a same-origin Origin.
    ok = client.post("/admin/api/keys", headers={**WRITE, "Origin": "http://testserver"}, content=body)
    assert ok.status_code == 201


def test_exports_are_csv_logged_and_free_of_values(tmp_path):
    _, server, client, _, _ = console(tmp_path)
    call(server, "aggregate", FINANCE)
    call(server, "aggregate", RETAIL)
    calls_csv = client.get("/admin/api/export/calls.csv?range=24h", headers=AUTH)
    assert calls_csv.status_code == 200 and "attachment" in calls_csv.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(calls_csv.text)))
    assert [r["outcome"] for r in rows] == ["ok", "denied"] and rows[1]["rule"] == "D1"
    audit_csv = client.get("/admin/api/export/audit.csv?range=24h", headers=AUTH).text
    audit_rows = list(csv.DictReader(io.StringIO(audit_csv)))
    assert len(audit_rows) == 2 and "4250000" not in audit_csv and "4,250,000" not in audit_csv
    assert client.get("/admin/api/export/other.csv", headers=AUTH).status_code == 404
    events = client.get("/admin/api/activity", headers=AUTH).json()["events"]
    assert [e["target"] for e in events] == ["audit.csv", "calls.csv"]


def test_csv_neutralises_spreadsheet_formulas(tmp_path):
    _, server, client, _, _ = console(tmp_path, principal="-2+3")  # a valid principal a spreadsheet would evaluate
    call(server, "aggregate", FINANCE)
    text = client.get("/admin/api/export/calls.csv?range=1h", headers=AUTH).text
    assert ",'-2+3," in text and ",-2+3," not in text


def test_recording_never_blocks_or_breaks_calls(tmp_path):
    _, server, _, calls, _ = console(tmp_path)

    def broken(*_args, **_kwargs):
        raise RuntimeError("database gone")
    calls._run_sql = broken
    assert call(server, "aggregate", FINANCE) is not None  # the call still succeeds
    assert calls.flush() == 0 and len(calls._queue) == 1  # kept for the next attempt
