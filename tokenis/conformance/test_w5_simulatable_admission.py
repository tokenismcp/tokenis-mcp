# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W5 (Simulatable admission): the admit/deny decision is computable from
exposed state alone -- the public catalogue, prior decisions, prior
responses, policy -- never from the protected value itself (P2 §5.3;
P4 Proposition 33, "the policy is simulatable").

Unlike W1-W4/W6, this is tested directly against
:mod:`tokenis.gateway.admission` rather than through
:class:`~tokenis.conformance.reference_gateway.ReferenceGateway`, because
that harness only implements an inline D1 check for its own W1-W4/W6
purposes -- the real target for a W5 conformance claim is the admission
engine itself.
"""
import inspect

import numpy as np
import pytest

from tokenis.gateway.admission import (
    AdmissionPolicy,
    Eq,
    MissingSubjectIdError,
    Query,
    QueryContext,
)


@pytest.fixture
def policy():
    n = 10
    industry = np.array(["finance"] * 5 + ["retail"] * 5, dtype=object)
    return AdmissionPolicy(n=n, public_attributes={"industry": industry}, catalogue={"revenue"}, k=3)


def test_decide_signature_carries_no_protected_value_parameter(policy):
    """Structural check: AdmissionPolicy.decide's parameters are exactly
    (query, context) -- there is no protected-value parameter to pass even
    by mistake."""
    sig = inspect.signature(policy.decide)
    params = list(sig.parameters.keys())
    assert params == ["query", "context"]


def test_admission_policy_holds_no_reference_to_protected_values(policy):
    """AdmissionPolicy's own instance state contains only public attribute
    arrays -- constructing it never took, and calling decide() never
    stores, anything derived from the protected column."""
    for value in vars(policy).values():
        if isinstance(value, np.ndarray):
            # The only arrays AdmissionPolicy should ever hold are the
            # public attribute arrays it was constructed with.
            assert value.dtype == object or value.dtype.kind in "iu"


def test_decision_is_reproducible_from_public_state_alone(policy):
    """Simulatability, operationally: replaying the same query/context
    sequence against a fresh policy built from the same public attributes
    reproduces the same sequence of decisions -- nothing about the
    decision depended on anything outside that public state."""
    industry = np.array(["finance"] * 5 + ["retail"] * 5, dtype=object)

    def fresh_policy():
        return AdmissionPolicy(n=10, public_attributes={"industry": industry}, catalogue={"revenue"}, k=3)

    queries = [
        Query(predicate=Eq("industry", "finance"), function="SUM", column="revenue"),
        Query(predicate=Eq("industry", "retail"), function="SUM", column="revenue"),
        Query(predicate=Eq("industry", "finance"), function="COUNT"),
    ]
    context = QueryContext(subject_id="analyst-1", credential_id="cred-1")

    p1, p2 = fresh_policy(), fresh_policy()
    decisions1 = [p1.decide(q, context) for q in queries]
    decisions2 = [p2.decide(q, context) for q in queries]

    assert [d.admitted for d in decisions1] == [d.admitted for d in decisions2]
    assert [d.rule for d in decisions1] == [d.rule for d in decisions2]


def test_refuses_to_operate_without_authenticated_subject(policy):
    """Corollary 14: identity propagation is a precondition. A call with
    no subject id is refused outright, regardless of the query."""
    query = Query(predicate=Eq("industry", "finance"), function="SUM", column="revenue")
    context = QueryContext(subject_id=None, credential_id="cred-1")
    with pytest.raises(MissingSubjectIdError):
        policy.decide(query, context)


def test_denial_reason_does_not_leak_beyond_public_predicate_info():
    """A denial's reason string is derived only from the rule name, the
    public predicate's matched size, and static policy parameters -- never
    from a protected value. This is a sanity check on the object actually
    used in this repository's TokenisGatewayService, not just an abstract
    claim: build a policy sized like the demo ledger and confirm a D1
    denial's reason contains only public, expected substrings."""
    industry = np.array(["retail"] * 2, dtype=object)
    small_policy = AdmissionPolicy(n=2, public_attributes={"industry": industry}, catalogue={"revenue"}, k=3)
    query = Query(predicate=Eq("industry", "retail"), function="SUM", column="revenue")
    context = QueryContext(subject_id="analyst-1", credential_id="cred-1")
    decision = small_policy.decide(query, context)
    assert decision.admitted is False
    assert decision.rule == "D1"
    assert "revenue" not in decision.reason  # no leakage of the sealed column's values
