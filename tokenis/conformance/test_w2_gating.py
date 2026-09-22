# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W2 (Gating): every Reveal is preceded by a policy decision and emits an
audit record -- structurally, not just by convention (P2 Remark 18: an
admission denial is disclosure too and must be logged)."""
import pytest

from tokenis.conformance.reference_gateway import AggregateDenied, ReferenceGateway
from tokenis.gateway.reveal import RevealDenied


def test_permitted_disclose_ratio_is_logged():
    gw = ReferenceGateway()
    before = len(gw.trace)
    gw.call_tool(
        "disclose_ratio",
        {"numerator_industry": "finance", "denominator_industry": "retail"},
        principal="analyst",
    )
    assert len(gw.trace) == before + 1
    assert gw.trace.verify_chain()
    last = list(gw.trace)[-1]
    assert last.kind == "reveal"
    assert last.audit.decision == "permit"


def test_denied_disclose_ratio_is_still_logged():
    gw = ReferenceGateway()
    before = len(gw.trace)
    with pytest.raises(RevealDenied):
        gw.call_tool(
            "disclose_ratio",
            {
                "numerator_industry": "finance",
                "denominator_industry": "retail",
                "purpose": "just curious",
            },
            principal="analyst",
        )
    assert len(gw.trace) == before + 1
    last = list(gw.trace)[-1]
    assert last.kind == "denial"
    assert last.audit.decision == "deny"


def test_aggregate_admission_denial_is_logged_too():
    """P2 Remark 18: a data-dependent denial is disclosure. An aggregate
    refused for failing the minimum-aggregate-size rule must appear in the
    trace exactly like a Reveal denial does -- an audit trail that records
    only successful calls is, per P2 §5.4, an incomplete disclosure
    record."""
    gw = ReferenceGateway()
    before = len(gw.trace)
    # No demo row has an industry that yields fewer than 5 matches other
    # than by construction; force it with a nonexistent industry (count=0).
    with pytest.raises(AggregateDenied):
        gw.call_tool("aggregate", {"industry": "nonexistent"}, principal="analyst")
    assert len(gw.trace) == before + 1
    last = list(gw.trace)[-1]
    assert last.kind == "denial"


def test_disclosure_trace_is_append_only_and_chain_verifiable():
    gw = ReferenceGateway()
    # "finance" has exactly 3 matching demo rows, meeting the demo
    # catalogue's minimum aggregate size of 3; "retail" only has 2 and
    # would be denied (covered by test_aggregate_admission_denial_is_logged_too).
    gw.call_tool("aggregate", {"industry": "finance"}, principal="a")
    gw.call_tool("aggregate", {"industry": "finance"}, principal="b")
    assert gw.trace.verify_chain()
    assert len(gw.trace) == 2
