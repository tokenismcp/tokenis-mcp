# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json

import pytest

from tokenis.gateway.service import TokenisGatewayService, load_demo_ledger
from tokenis.mcp_server.server import create_server, demo_principal_resolver


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def server():
    svc = TokenisGatewayService()
    load_demo_ledger(svc)
    return create_server(service=svc)


def _content_json(result):
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


def test_all_seven_tools_are_registered(server):
    tools = _run(server.list_tools())
    names = {t.name for t in tools}
    assert names == {
        "aggregate", "group_by", "compare_periods", "similarity_search",
        "exists", "disclose_ratio", "disclose_bucket",
    }


def test_catalogue_resource_has_no_row_values(server):
    contents = _run(server.read_resource("tokenis://catalogue"))
    payload = json.loads(contents[0].content)
    assert set(payload.keys()) == {"revenue", "industry", "region", "customer_name"}
    for meta in payload.values():
        assert "protection_class" in meta
        # No row-level values anywhere in this resource.
        assert "value" not in meta


def test_aggregate_sum_over_admitted_predicate(server):
    result = _run(server.call_tool("aggregate", {"function": "sum", "industry": "finance"}))
    payload = _content_json(result)
    assert payload["value"] == 1_000_000 + 2_000_000 + 1_250_000
    assert payload["matched_count"] == 3


def test_aggregate_denied_below_minimum_size(server):
    # "retail" has only 2 rows in the demo ledger, below the catalogue's
    # minimum aggregate size of 3 -- refused by AdmissionPolicy's D1 rule.
    result = _run(server.call_tool("aggregate", {"function": "sum", "industry": "retail"}))
    payload = _content_json(result)
    assert "error" in payload
    assert "D1" in payload["error"]
    assert "matched 2" in payload["error"]


def test_disclose_ratio_requires_authorized_purpose(server):
    # The purpose-based Reveal gate is checked before either underlying
    # sum is admission-checked, so this denial doesn't depend on which
    # industries are named.
    denied = _run(
        server.call_tool(
            "disclose_ratio",
            {
                "numerator_industry": "finance",
                "denominator_industry": "tech",
                "purpose": "just curious",
            },
        )
    )
    assert "error" in _content_json(denied)

    # "tech" (3 rows) meets the minimum aggregate size, unlike "retail" (2
    # rows) -- both underlying sums go through AdmissionPolicy exactly like
    # a bare `aggregate` call would (see disclose_ratio's decrypt_fn).
    permitted = _run(
        server.call_tool(
            "disclose_ratio",
            {
                "numerator_industry": "finance",
                "denominator_industry": "tech",
                "purpose": "authorized_demo",
            },
        )
    )
    payload = _content_json(permitted)
    assert payload["ratio"] == pytest.approx(4_250_000 / 7_000_000)


def test_disclose_ratio_denied_when_underlying_sum_fails_admission(server):
    # An authorized purpose is not enough: "retail" itself fails D1.
    result = _run(
        server.call_tool(
            "disclose_ratio",
            {
                "numerator_industry": "finance",
                "denominator_industry": "retail",
                "purpose": "authorized_demo",
            },
        )
    )
    payload = _content_json(result)
    assert "error" in payload
    assert "D1" in payload["error"]


def test_group_by_suppresses_small_groups(server):
    result = _run(server.call_tool("group_by", {"key": "industry"}))
    payload = _content_json(result)
    assert payload["groups"]["retail"]["suppressed"] is True
    assert payload["groups"]["finance"]["suppressed"] is False


def test_disclosure_trace_records_every_boundary_crossing():
    # The `server` fixture wraps a TokenisGatewayService we don't have a
    # direct handle to, so build our own here to check the trace invariant.
    own = TokenisGatewayService()
    load_demo_ledger(own)
    srv2 = create_server(service=own)
    _run(srv2.call_tool("aggregate", {"function": "sum", "industry": "finance"}))
    _run(srv2.call_tool("aggregate", {"function": "sum", "industry": "retail"}))
    assert len(own.trace) == 2
    assert own.trace.verify_chain()


def test_require_real_auth_rejects_demo_resolver():
    with pytest.raises(ValueError):
        create_server(require_real_auth=True, principal_resolver=demo_principal_resolver)
