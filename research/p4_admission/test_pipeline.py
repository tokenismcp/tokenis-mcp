# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fast pytest tests for the P4 admission-control reproduction.

Keep these fast (seconds); the slow, full pipeline lives in
``verify_claims.py``. pytest auto-discovers this file (``research/p4_admission``
is already in the repo's ``pyproject.toml`` testpaths).
"""

from __future__ import annotations

import inspect
import itertools

import numpy as np
import pytest

from research.p4_admission import attacks as A
from research.p4_admission.admission import (
    GF_PRIME,
    AdmissionPolicy,
    And,
    CredentialScopedBudget,
    Eq,
    Exclude,
    MissingSubjectIdError,
    NaiveExposureCapPolicy,
    Not,
    Or,
    Query,
    QueryContext,
    RREFBasis,
    SubjectScopedBudget,
    characteristic_indicator,
)
from research.p4_admission.gateway_sim import GatewaySim
from research.p4_admission.ledger import (
    CLASSIFIED_COLUMNS,
    PUBLIC_ATTRIBUTES,
    cross_classification_stats,
    generate_ledger,
    unique_record_indices,
)


@pytest.fixture(scope="module")
def ledger():
    return generate_ledger()


@pytest.fixture(scope="module")
def gw(ledger):
    return GatewaySim(ledger)


# ---------------------------------------------------------------------------
# ledger.py
# ---------------------------------------------------------------------------


def test_ledger_shape(ledger):
    assert ledger.n == 5000
    for attr in PUBLIC_ATTRIBUTES:
        assert ledger.attributes[attr].shape == (5000,)
    for col in ("revenue", "margin", "headcount"):
        assert ledger.columns[col].shape == (5000,)
        assert col in CLASSIFIED_COLUMNS


def test_ledger_low_cardinality_structure(ledger):
    stats = cross_classification_stats(ledger, k=5)
    # Qualitative, not literal: "most cells small", "a meaningful minority unique".
    assert stats["cells_below_k_fraction"] > 0.5
    assert 0.02 < stats["records_unique_fraction"] < 0.30


def test_ledger_deterministic_with_seed():
    l1 = generate_ledger(seed=42)
    l2 = generate_ledger(seed=42)
    assert np.array_equal(l1.columns["revenue"], l2.columns["revenue"])
    assert np.array_equal(l1.attributes["region"], l2.attributes["region"])
    l3 = generate_ledger(seed=43)
    assert not np.array_equal(l1.columns["revenue"], l3.columns["revenue"])


# ---------------------------------------------------------------------------
# admission.py: RREF over GF(p) on small, hand-checkable matrices.
# ---------------------------------------------------------------------------


def _brute_force_in_rowspace(target: np.ndarray, rows: list, p: int) -> bool:
    """Brute-force rowspace membership over GF(p): try every combination of
    coefficients in {0, 1, p-1} (i.e. 0, +1, -1) for the (tiny, rank <= 2)
    test bases used below. This is an independent check from RREFBasis
    itself, deliberately not sharing any code path with it.
    """
    coeffs = (0, 1, p - 1)
    for combo in itertools.product(coeffs, repeat=len(rows)):
        acc = np.zeros_like(target, dtype=np.int64)
        for c, row in zip(combo, rows):
            if c:
                acc = (acc + c * row) % p
        if np.array_equal(acc, target % p):
            return True
    return False


def test_rref_small_hand_checkable():
    p = GF_PRIME
    n = 5
    basis = RREFBasis(n, p)
    v1 = np.array([1, 1, 0, 0, 0], dtype=np.int64)
    v2 = np.array([0, 1, 1, 0, 0], dtype=np.int64)
    assert basis.try_add(v1, n + 1, -1) is True
    assert basis.try_add(v2, n + 1, -1) is True
    assert basis.rank == 2
    # v1 - v2 should reduce to zero contribution (dependent: v1+v2-v2=v1...);
    # test a genuinely dependent vector: v1 + v2.
    v3 = (v1 + v2) % p
    assert basis.try_add(v3, n + 1, -1) is True
    assert basis.rank == 2  # dependent, rank unchanged

    # Direct exactness check via Lemma 9 vs brute force for several targets.
    e0 = np.array([1, 0, 0, 0, 0], dtype=np.int64)
    for target in [e0, np.array([0, 1, 0, 0, 0]), np.array([1, 1, 1, 0, 0])]:
        in_span_brute = _brute_force_in_rowspace(target.astype(np.int64), [v1, v2], p)
        # Use a fresh basis copy to test "would e_i join the rowspace" via
        # weight-one test AFTER hypothetically adding target with no refusal.
        trial = RREFBasis(n, p)
        trial.try_add(v1, n + 1, -1)
        trial.try_add(v2, n + 1, -1)
        rank_before = trial.rank
        trial.try_add(target.astype(np.int64), n + 1, -1)
        newly_independent = trial.rank > rank_before
        assert newly_independent == (not in_span_brute)


def test_lemma9_weight_one_exact_small_case():
    """A case constructed so e_2 IS in the rowspace: {e_2, e_0+e_1} spans a
    space containing e_2 as an explicit weight-one row."""
    p = GF_PRIME
    n = 4
    basis = RREFBasis(n, p)
    e2 = np.array([0, 0, 1, 0], dtype=np.int64)
    other = np.array([1, 1, 0, 0], dtype=np.int64)
    basis.try_add(e2, n + 1, -1)
    basis.try_add(other, n + 1, -1)
    assert basis.contains_weight_one_row() is True

    # A case where nothing is weight-one: {[1,1,0,0], [0,1,1,0]}.
    basis2 = RREFBasis(n, p)
    basis2.try_add(np.array([1, 1, 0, 0], dtype=np.int64), n + 1, -1)
    basis2.try_add(np.array([0, 1, 1, 0], dtype=np.int64), n + 1, -1)
    assert basis2.contains_weight_one_row() is False


def test_try_add_refuses_weight_one_row_immediately():
    """A candidate that is itself weight-one under weight_hi=1 is refused
    even as the very first row (it would directly reveal an individual
    value), and the basis is left empty/unchanged."""
    p = GF_PRIME
    n = 4
    basis = RREFBasis(n, p)
    e0 = np.array([1, 0, 0, 0], dtype=np.int64)
    assert basis.try_add(e0, 1, 1) is False
    assert basis.rank == 0


def test_try_add_refuses_and_leaves_basis_unchanged():
    p = GF_PRIME
    n = 4
    basis = RREFBasis(n, p)
    # A weight-2 row is admitted under weight_hi=1 (it doesn't itself reveal
    # an individual value, and nothing else is in the basis yet to combine
    # with it).
    broad = np.array([1, 1, 0, 0], dtype=np.int64)
    assert basis.try_add(broad, 1, 1) is True
    snapshot_rows = [r.copy() for r in basis.rows]
    e1 = np.array([0, 1, 0, 0], dtype=np.int64)
    # e1 is independent and itself weight-1: refused under weight_hi=1.
    admitted = basis.try_add(e1, 1, 1)
    assert admitted is False
    assert basis.rank == len(snapshot_rows)
    for a, b in zip(basis.rows, snapshot_rows):
        assert np.array_equal(a, b)


# ---------------------------------------------------------------------------
# admission.py: filter language / predicate algebra.
# ---------------------------------------------------------------------------


def test_predicate_algebra_matches_expected_sets(ledger):
    attrs = ledger.attributes
    n = ledger.n
    region0 = characteristic_indicator(Eq("region", 0), attrs, n)
    industry0 = characteristic_indicator(Eq("industry", 0), attrs, n)
    both = characteristic_indicator(And(Eq("region", 0), Eq("industry", 0)), attrs, n)
    either = characteristic_indicator(Or(Eq("region", 0), Eq("industry", 0)), attrs, n)
    assert np.array_equal(both, region0 & industry0)
    assert np.array_equal(either, region0 | industry0)
    excluded = characteristic_indicator(Exclude(Eq("region", 0), Eq("industry", 0)), attrs, n)
    assert np.array_equal(excluded, region0 & ~industry0)
    complement = characteristic_indicator(Not(Eq("region", 0)), attrs, n)
    assert np.array_equal(complement, ~region0)


# ---------------------------------------------------------------------------
# admission.py: Proposition 33 invariant -- decide() never receives x.
# ---------------------------------------------------------------------------


def test_decide_signature_never_receives_protected_values():
    sig = inspect.signature(AdmissionPolicy.decide)
    params = list(sig.parameters.keys())
    assert params == ["self", "query", "context"], (
        "AdmissionPolicy.decide's signature changed to accept something "
        "beyond (query, context); Proposition 33 requires decide() to be a "
        "pure function of public information only"
    )


def test_admission_policy_never_stores_protected_values(ledger):
    policy = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS)
    # The instance's own state must never reference a protected column array.
    protected_arrays = [id(v) for v in ledger.columns.values()]
    for value in vars(policy).values():
        if isinstance(value, np.ndarray):
            assert id(value) not in protected_arrays


def test_missing_subject_id_refused():
    ledger_small = generate_ledger()
    policy = AdmissionPolicy(ledger_small.n, ledger_small.public_attributes(), CLASSIFIED_COLUMNS)
    ctx = QueryContext(subject_id=None, credential_id="c1", taint=0)
    with pytest.raises(MissingSubjectIdError):
        policy.decide(Query(Eq("region", 0), "COUNT"), ctx)


# ---------------------------------------------------------------------------
# D1-D5 stack vs weaker configurations: attacks 1/2/4/8.
# ---------------------------------------------------------------------------


def test_d1_only_leaves_two_query_tracker_fully_exposed(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:10]]
    policy = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=False)
    result = A.attack_two_query_tracker(gw, policy, targets)
    assert result["success_rate"] == 1.0


def test_full_stack_blocks_two_query_tracker(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:10]]
    policy = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=True, cell_aware=True)
    result = A.attack_two_query_tracker(gw, policy, targets)
    assert result["success_rate"] == 0.0


def test_full_stack_blocks_general_tracker(ledger, gw):
    def weak():
        return AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=False)

    def full():
        return AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=True, cell_aware=True)

    weak_result = A.attack_general_tracker(gw, weak, n_cells=10)
    full_result = A.attack_general_tracker(gw, full, n_cells=10)
    assert weak_result["success_rate"] > 0.0
    assert full_result["success_rate"] == 0.0


def test_exposure_cap_e1_blocks_e2_does_not(ledger, gw):
    e1 = NaiveExposureCapPolicy(ledger.n, ledger.public_attributes(), k=5, exposure_cap=1)
    e2 = NaiveExposureCapPolicy(ledger.n, ledger.public_attributes(), k=5, exposure_cap=2)
    r1 = A.attack_exposure_cap_bypass(gw, e1, n_pairs=10)
    r2 = A.attack_exposure_cap_bypass(gw, e2, n_pairs=10)
    assert r1["success_rate"] == 0.0
    assert r2["success_rate"] > 0.0


def test_avg_exemption_regression_guarded(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:10]]
    buggy = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=True, audit_avg=False)
    correct = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=True, audit_avg=True)
    result = A.attack_avg_exemption_regression(gw, buggy, correct, targets)
    assert result["buggy_policy"]["success_rate"] > 0.0
    assert result["correct_policy"]["success_rate"] == 0.0
    assert result["regression_guarded"] is True


# ---------------------------------------------------------------------------
# D3: CredentialScopedBudget is bypassable, SubjectScopedBudget is not.
# ---------------------------------------------------------------------------


def test_credential_scoped_budget_is_bypassable(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:30]]
    budget = 8
    policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=budget,
        audit_enabled=False, budget_scope=CredentialScopedBudget(budget),
    )
    result = A.attack_credential_rotation(gw, policy, targets, rotate_every=2)
    assert result["success_rate"] == 1.0
    assert result["credentials_used"] > 1


def test_subject_scoped_budget_is_not_bypassable(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:30]]
    budget = 8
    policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=budget,
        audit_enabled=False, budget_scope=SubjectScopedBudget(budget),
    )
    result = A.attack_credential_rotation(gw, policy, targets, rotate_every=2)
    # Bounded by floor(budget/2) regardless of how many credentials were used.
    assert result["recovered"] <= budget // 2
    assert result["success_rate"] < 1.0


def test_d4_taint_gating_blocks_external_effect_exfiltration(ledger, gw):
    targets = [int(x) for x in unique_record_indices(ledger)[:10]]
    taint_on = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=False, enforce_d4=True)
    taint_off = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000, audit_enabled=False, enforce_d4=False)
    on_result = A.attack_external_effect_exfiltration(gw, taint_on, targets, taint=1)
    off_result = A.attack_external_effect_exfiltration(gw, taint_off, targets, taint=1)
    assert on_result["leaked"] == 0
    assert off_result["leaked"] > 0


def test_d5_denies_unclassified_column(ledger, gw):
    policy = AdmissionPolicy(ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000)
    ctx = QueryContext(subject_id="u", credential_id="c", taint=0)
    d = policy.decide(Query(Eq("region", 0), "SUM", "internal_risk_score"), ctx)
    assert d.admitted is False
    assert d.rule == "D5"
