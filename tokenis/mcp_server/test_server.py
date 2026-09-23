# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import time

import pytest

pytest.importorskip("mcp", reason="the MCP server needs the `server` extra (Python >= 3.10)")

from mcp.server.mcpserver.exceptions import ToolError

from tokenis.gateway.demo import demo_service
from tokenis.gateway.service import DENIED_MESSAGE
from tokenis.mcp_server.server import (
    create_server,
    fixed_principal,
    header_taint,
    local_principal,
)
from tokenis.server_auth import AuthenticationRequired

GRANULARITY_MS = 40.0


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def service():
    return demo_service(latency_granularity_ms=GRANULARITY_MS)


@pytest.fixture
def server(service):
    return create_server(service, principal_resolver=fixed_principal("alice"))


def payload(result):
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


def test_tool_surface(server):
    tools = {t.name: t for t in run(server.list_tools())}
    assert set(tools) == {
        "describe_dataset", "aggregate", "group_by", "compare_periods", "similarity_search",
        "exists", "disclose_ratio", "disclose_bucket",
    }
    for tool in tools.values():
        assert tool.annotations.read_only_hint is True
        assert "principal" not in json.dumps(tool.input_schema)
    schema = tools["aggregate"].input_schema
    assert schema["properties"]["function"]["enum"] == ["sum", "avg", "count"]
    filters = schema["$defs"]["Filters"]
    assert filters["additionalProperties"] is False
    assert set(filters["properties"]) == {"industry", "region", "customer_name"}
    assert filters["properties"]["industry"]["anyOf"][0]["enum"] == ["finance", "retail", "tech"]


def test_calls_and_generic_denials(server, service):
    result = run(server.call_tool("aggregate", {
        "function": "sum", "column": "revenue_2025", "filters": {"industry": "finance"}}))
    assert payload(result)["value"] == 4_250_000
    with pytest.raises(ToolError) as exc:
        run(server.call_tool("aggregate", {
            "function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}}))
    assert str(exc.value).endswith(DENIED_MESSAGE)
    assert "D1" not in str(exc.value) and "matched" not in str(exc.value)
    assert [e.audit.principal for e in service.trace] == ["alice", "alice"]


def test_schema_validation_happens_before_the_gateway(server, service):
    for bad in (
        {"function": "sum", "column": "industry"},
        {"function": "sum", "column": "revenue_2025", "filters": {"industry": "banking"}},
        {"function": "sum", "column": "revenue_2025", "filters": {"revenue_2025": "1"}},
        {"function": "drop"},
    ):
        with pytest.raises(ToolError):
            run(server.call_tool("aggregate", bad))
    assert len(service.trace) == 0


def test_every_call_is_padded_to_the_quantum(server):
    def elapsed(arguments):
        start = time.perf_counter()
        try:
            run(server.call_tool("aggregate", arguments))
        except ToolError:
            pass
        return (time.perf_counter() - start) * 1000

    admitted = elapsed({"function": "sum", "column": "revenue_2025", "filters": {"industry": "tech"}})
    denied = elapsed({"function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}})
    invalid = elapsed({"function": "sum", "column": "nope"})  # rejected by the SDK, unpadded
    for ms in (admitted, denied):
        assert ms >= GRANULARITY_MS * 0.95
        assert abs(ms - round(ms / GRANULARITY_MS) * GRANULARITY_MS) < GRANULARITY_MS * 0.5
    assert invalid < GRANULARITY_MS  # schema errors depend on nothing but the schema


def test_principal_comes_from_the_resolver_only(service):
    def unauthenticated(_ctx):
        raise AuthenticationRequired("no token")

    server = create_server(service, principal_resolver=unauthenticated)
    with pytest.raises(ToolError, match="authentication required"):
        run(server.call_tool("describe_dataset", {}))
    with pytest.raises(ValueError):
        fixed_principal("not a principal!")
    assert local_principal().startswith("local:")


def test_taint_comes_from_the_host(service):
    server = create_server(service, principal_resolver=fixed_principal("alice"),
                           taint_resolver=lambda _ctx: 1)
    with pytest.raises(ToolError):
        run(server.call_tool("aggregate", {
            "function": "sum", "column": "revenue_2025", "filters": {"industry": "tech"}}))
    assert payload(run(server.call_tool("aggregate", {
        "function": "count", "filters": {"industry": "tech"}})))["value"] == 3

    class Ctx:
        def __init__(self, headers):
            self.headers = headers

    resolve = header_taint("X-Tokenis-Taint")
    assert resolve(Ctx({"x-tokenis-taint": "1"})) == 1
    assert resolve(Ctx({"X-Tokenis-Taint": "no"})) == 0
    assert resolve(Ctx(None)) == 0


def test_catalogue_resource_and_prompt(server):
    contents = run(server.read_resource("tokenis://catalogue"))
    catalogue = json.loads(contents[0].content)
    assert [c["name"] for c in catalogue["columns"]][:2] == ["revenue_2024", "revenue_2025"]
    assert "values" not in json.dumps(catalogue)
    prompt = run(server.get_prompt("analysis_guide", {"question": "Which sector grew?"}))
    assert "describe_dataset" in prompt.messages[0].content.text


def test_verifier_and_auth_go_together(service):
    with pytest.raises(ValueError):
        create_server(service, principal_resolver=fixed_principal("a"), token_verifier=object())  # type: ignore[arg-type]
