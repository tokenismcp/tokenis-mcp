# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The eight evaluation attacks of paper §8 / Appendix A.

Each attack function takes a :class:`~research.p4_admission.gateway_sim.GatewaySim`
(the ground-truth oracle) and an admission-control object (usually an
:class:`~research.p4_admission.admission.AdmissionPolicy`, sometimes one of the
weaker variants the paper evaluates against), and returns a small, JSON-serialisable
result dict carrying a success rate and/or recovered values, plus enough detail
for ``evaluate.py`` and ``verify_claims.py`` to build the paper's Table 2 / Table 3
style reports.

Honesty note: these attacks measure whatever THIS reproduction's synthetic
ledger and RREF-over-GF(p) auditor actually do, not the paper's literal
percentages (see the top-level README).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from .admission import (
    AdmissionPolicy,
    And,
    Eq,
    Exclude,
    NaiveExposureCapPolicy,
    Not,
    Or,
    Query,
    QueryContext,
)
from .gateway_sim import GatewaySim
from .gateway_sim import Query as GQuery
from .ledger import PUBLIC_ATTRIBUTES, Ledger, unique_record_indices


def _attr_predicate(ledger: Ledger, record: int, attr: str) -> And:
    return Eq(attr, int(ledger.attributes[attr][record]))


def _full_conjunction(ledger: Ledger, record: int) -> And:
    """The unique conjunction psi_t characterising a single record (all four attrs)."""
    return And(*[_attr_predicate(ledger, record, a) for a in PUBLIC_ATTRIBUTES])


def _pick_padding_predicate(
    gw: GatewaySim, ledger: Ledger, target: int, k: int, salt: int
) -> Optional[And]:
    """A single-attribute predicate theta with k <= |C_theta| <= n-k-1 and target not in C_theta.

    Rotates across a few candidate attributes/values (salted by call index) so
    repeated calls for different targets don't all reuse one base predicate --
    the paper notes that reuse understates an attacker's true reach (§5.2,
    "The measured 0.71 is in fact weaker than the proposition predicts").
    """
    n = ledger.n
    attrs = list(PUBLIC_ATTRIBUTES)
    for offset in range(len(attrs)):
        attr = attrs[(salt + offset) % len(attrs)]
        target_val = int(ledger.attributes[attr][target])
        categories = range(len(ledger.attribute_categories[attr]))
        for val in categories:
            if val == target_val:
                continue
            theta = Eq(attr, int(val))
            ind = gw.characteristic_set(theta)
            size = int(ind.sum())
            if k <= size <= n - k - 1 and not ind[target]:
                return theta
    return None


# ---------------------------------------------------------------------------
# A1 / Proposition 4: two-query individual tracker.
# ---------------------------------------------------------------------------


def attack_two_query_tracker(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    targets: Sequence[int],
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    credential_id: str = "cred-1",
    taint: int = 0,
) -> Dict[str, Any]:
    """Proposition 4: xt = q(theta OR psi_t) - q(theta) for isolated records t."""
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
    recovered = 0
    queries_issued = 0
    errors: List[float] = []
    for salt, t in enumerate(targets):
        theta = _pick_padding_predicate(gw, ledger=gw.ledger, target=t, k=k, salt=salt)
        if theta is None:
            continue
        psi_t = _full_conjunction(gw.ledger, t)

        d_union = policy.decide(Query(Or(theta, psi_t), "SUM", column), ctx)
        queries_issued += 1
        if not d_union.admitted:
            continue
        d_theta = policy.decide(Query(theta, "SUM", column), ctx)
        queries_issued += 1
        if not d_theta.admitted:
            continue

        v_union = gw.evaluate(GQuery(Or(theta, psi_t), "SUM", column))
        v_theta = gw.evaluate(GQuery(theta, "SUM", column))
        recovered_value = v_union - v_theta
        actual = gw.ledger.columns[column][t]
        errors.append(abs(recovered_value - actual))
        recovered += 1

    n_targets = len(targets)
    return {
        "attack": "A1_two_query_tracker",
        "n_targets": n_targets,
        "recovered": recovered,
        "success_rate": recovered / n_targets if n_targets else 0.0,
        "queries_issued": queries_issued,
        "queries_per_recovered_record": queries_issued / recovered if recovered else None,
        "max_abs_error": max(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# A2 / §5.2 "First correction": nested-conjunction differencing (no disjunction needed).
# ---------------------------------------------------------------------------


def attack_nested_conjunction_differencing(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    targets: Sequence[int],
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    credential_id: str = "cred-1",
    taint: int = 0,
) -> Dict[str, Any]:
    """A2: alpha and alpha AND NOT beta, differing in exactly the target record.

    Uses only conjunction + exclusion (no disjunction), so it survives a
    filter API restricted to a single conjunction.
    """
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
    recovered = 0
    queries_issued = 0
    errors: List[float] = []
    for salt, t in enumerate(targets):
        # alpha: a broad single-attribute predicate containing t.
        attrs = list(PUBLIC_ATTRIBUTES)
        alpha = None
        for offset in range(len(attrs)):
            attr = attrs[(salt + offset) % len(attrs)]
            candidate = Eq(attr, int(gw.ledger.attributes[attr][t]))
            ind = gw.characteristic_set(candidate)
            if int(ind.sum()) >= k + 1:
                alpha = candidate
                break
        if alpha is None:
            continue
        beta = _full_conjunction(gw.ledger, t)  # |C_alpha AND beta| == 1 since beta pins t exactly
        alpha_minus_beta = Exclude(alpha, beta)

        d_alpha = policy.decide(Query(alpha, "SUM", column), ctx)
        queries_issued += 1
        if not d_alpha.admitted:
            continue
        d_diff = policy.decide(Query(alpha_minus_beta, "SUM", column), ctx)
        queries_issued += 1
        if not d_diff.admitted:
            continue

        v_alpha = gw.evaluate(GQuery(alpha, "SUM", column))
        v_diff = gw.evaluate(GQuery(alpha_minus_beta, "SUM", column))
        recovered_value = v_alpha - v_diff
        actual = gw.ledger.columns[column][t]
        errors.append(abs(recovered_value - actual))
        recovered += 1

    n_targets = len(targets)
    return {
        "attack": "A2_nested_conjunction_differencing",
        "n_targets": n_targets,
        "recovered": recovered,
        "success_rate": recovered / n_targets if n_targets else 0.0,
        "queries_issued": queries_issued,
        "max_abs_error": max(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# A3 / Proposition 5: general tracker against sub-k cells.
# ---------------------------------------------------------------------------


def _sub_k_cells(ledger: Ledger, k: int, max_cells: int) -> List[Tuple[Any, np.ndarray]]:
    """Two-attribute cross-classification cells with 1 <= |C| < k."""
    n = ledger.n
    a1, a2 = "region", "industry"
    v1, v2 = ledger.attributes[a1], ledger.attributes[a2]
    combos: Dict[Tuple[int, int], List[int]] = {}
    for i in range(n):
        combos.setdefault((int(v1[i]), int(v2[i])), []).append(i)
    cells = []
    for (r, ind), members in combos.items():
        if 1 <= len(members) < k:
            phi = And(Eq(a1, r), Eq(a2, ind))
            cells.append((phi, np.array(members)))
        if len(cells) >= max_cells:
            break
    return cells


def attack_general_tracker(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    n_cells: int = 20,
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    credential_id: str = "cred-1",
    taint: int = 0,
) -> Dict[str, Any]:
    """Proposition 5: q(phi)=q(phi OR T)+q(phi OR NOT T)-q(T)-q(NOT T) for sub-k phi."""
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
    cells = _sub_k_cells(gw.ledger, k, n_cells)
    recovered = 0
    queries_issued = 0
    errors: List[float] = []
    n = gw.ledger.n

    for idx, (phi, members) in enumerate(cells):
        # Pick a fresh padding predicate T with 2k <= |C_T| <= n-2k per cell
        # (re-issued per cell, per §5.2: this avoids concentrating exposure).
        T = None
        for offset in range(len(PUBLIC_ATTRIBUTES)):
            attr = PUBLIC_ATTRIBUTES[(idx + offset) % len(PUBLIC_ATTRIBUTES)]
            for val in range(len(gw.ledger.attribute_categories[attr])):
                cand = Eq(attr, val)
                size = int(gw.characteristic_set(cand).sum())
                if 2 * k <= size <= n - 2 * k:
                    T = cand
                    break
            if T is not None:
                break
        if T is None:
            continue
        not_T = Not(T)

        queries = [Or(phi, T), Or(phi, not_T), T, not_T]
        decisions = [policy.decide(Query(q, "SUM", column), ctx) for q in queries]
        queries_issued += len(queries)
        if not all(d.admitted for d in decisions):
            continue

        vals = [gw.evaluate(GQuery(q, "SUM", column)) for q in queries]
        recovered_value = vals[0] + vals[1] - vals[2] - vals[3]
        actual = float(gw.ledger.columns[column][members].sum())
        errors.append(abs(recovered_value - actual))
        recovered += 1

    n_cells_actual = len(cells)
    return {
        "attack": "A3_general_tracker",
        "n_targets": n_cells_actual,
        "recovered": recovered,
        "success_rate": recovered / n_cells_actual if n_cells_actual else 0.0,
        "queries_issued": queries_issued,
        "queries_per_recovered_cell": queries_issued / recovered if recovered else None,
        "max_abs_error": max(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# A9 (not an eval attack, but used by others) / Proposition 6: query economics.
# ---------------------------------------------------------------------------


def attack_query_economics(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    n_queries: int = 400,
    column: str = "revenue",
    subject_id: str = "attacker-econ",
    credential_id: str = "cred-econ",
) -> Dict[str, Any]:
    """Proposition 6: measure decision latency growth as history accumulates.

    Reports median/p95 latency for a stream of admissible-shaped queries,
    which is what the SDK's later performance story (D1 flat, D2's RREF
    auditor growing with history) will care about most directly.
    """
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=0)
    n = gw.ledger.n
    rng = np.random.default_rng(12345)
    latencies: List[float] = []
    admitted_count = 0
    for i in range(n_queries):
        attr = PUBLIC_ATTRIBUTES[i % len(PUBLIC_ATTRIBUTES)]
        val = int(rng.integers(0, len(gw.ledger.attribute_categories[attr])))
        predicate = Eq(attr, val)
        t0 = time.perf_counter()
        d = policy.decide(Query(predicate, "SUM", column), ctx)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        if d.admitted:
            admitted_count += 1

    arr = np.array(latencies)
    return {
        "attack": "A_query_economics",
        "n_queries": n_queries,
        "admitted": admitted_count,
        "latency_ms_median": float(np.median(arr)),
        "latency_ms_p95": float(np.percentile(arr, 95)),
        "latency_ms_first_50_median": float(np.median(arr[:50])) if len(arr) >= 50 else None,
        "latency_ms_last_50_median": float(np.median(arr[-50:])) if len(arr) >= 50 else None,
    }


# ---------------------------------------------------------------------------
# A4 / Proposition 12: per-record exposure-cap bypass.
# ---------------------------------------------------------------------------


def _nested_disjoint_pairs(ledger: Ledger, k: int, n_pairs: int) -> List[Tuple[Any, Any, int]]:
    """J nested pairs (alpha_j, alpha_j AND beta_j) with disjoint C_alpha_j, |C_alpha_j AND beta_j|=1."""
    n = ledger.n
    used = np.zeros(n, dtype=bool)
    uniques = unique_record_indices(ledger)
    pairs = []
    for t in uniques:
        if used[t]:
            continue
        beta = _full_conjunction(ledger, int(t))
        alpha = None
        for attr in PUBLIC_ATTRIBUTES:
            cand = Eq(attr, int(ledger.attributes[attr][t]))
            ind = characteristic_indicator_np(ledger, cand)
            size = int(ind.sum())
            if k + 1 <= size <= n - k and not (ind & used).any():
                alpha = cand
                alpha_ind = ind
                break
        if alpha is None:
            continue
        used |= alpha_ind
        pairs.append((alpha, beta, int(t)))
        if len(pairs) >= n_pairs:
            break
    return pairs


def characteristic_indicator_np(ledger: Ledger, predicate) -> np.ndarray:
    from .admission import characteristic_indicator

    return characteristic_indicator(predicate, ledger.attributes, ledger.n)


def attack_exposure_cap_bypass(
    gw: GatewaySim,
    exposure_policy: NaiveExposureCapPolicy,
    n_pairs: int = 20,
    column: str = "revenue",
    k: int = 5,
) -> Dict[str, Any]:
    """Proposition 12: nested-disjoint pairs defeat the exposure cap for every E >= 2."""
    pairs = _nested_disjoint_pairs(gw.ledger, k, n_pairs)
    recovered = 0
    errors: List[float] = []
    for alpha, beta, t in pairs:
        alpha_minus_beta = Exclude(alpha, beta)
        d_alpha = exposure_policy.decide(GQuery(alpha, "SUM", column))
        if not d_alpha.admitted:
            continue
        d_diff = exposure_policy.decide(GQuery(alpha_minus_beta, "SUM", column))
        if not d_diff.admitted:
            continue
        v_alpha = gw.evaluate(GQuery(alpha, "SUM", column))
        v_diff = gw.evaluate(GQuery(alpha_minus_beta, "SUM", column))
        recovered_value = v_alpha - v_diff
        actual = gw.ledger.columns[column][t]
        errors.append(abs(recovered_value - actual))
        recovered += 1

    n_pairs_actual = len(pairs)
    return {
        "attack": "A4_exposure_cap_bypass",
        "exposure_cap": exposure_policy.exposure_cap,
        "n_targets": n_pairs_actual,
        "recovered": recovered,
        "success_rate": recovered / n_pairs_actual if n_pairs_actual else 0.0,
        "max_abs_error": max(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# A5 / Theorem 13: credential-rotation budget bypass.
# ---------------------------------------------------------------------------


def attack_credential_rotation(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    targets: Sequence[int],
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    rotate_every: int = 2,
) -> Dict[str, Any]:
    """Theorem 13: recover targets by presenting a fresh credential every `rotate_every` calls.

    Run this against a policy constructed with CredentialScopedBudget to see
    the bypass, and against one with SubjectScopedBudget (the default) to see
    it fail to exceed that subject's single budget.
    """
    recovered = 0
    credential_counter = 0
    calls_since_rotation = 0
    credential_id = f"cred-{credential_counter}"
    errors: List[float] = []

    for salt, t in enumerate(targets):
        if calls_since_rotation >= rotate_every:
            credential_counter += 1
            credential_id = f"cred-{credential_counter}"
            calls_since_rotation = 0
        ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=0)

        theta = _pick_padding_predicate(gw, gw.ledger, t, k, salt)
        if theta is None:
            continue
        psi_t = _full_conjunction(gw.ledger, t)

        d_union = policy.decide(Query(Or(theta, psi_t), "SUM", column), ctx)
        calls_since_rotation += 1
        if not d_union.admitted:
            continue
        d_theta = policy.decide(Query(theta, "SUM", column), ctx)
        calls_since_rotation += 1
        if not d_theta.admitted:
            continue

        v_union = gw.evaluate(GQuery(Or(theta, psi_t), "SUM", column))
        v_theta = gw.evaluate(GQuery(theta, "SUM", column))
        recovered_value = v_union - v_theta
        actual = gw.ledger.columns[column][t]
        errors.append(abs(recovered_value - actual))
        recovered += 1

    n_targets = len(targets)
    return {
        "attack": "A5_credential_rotation",
        "n_targets": n_targets,
        "recovered": recovered,
        "success_rate": recovered / n_targets if n_targets else 0.0,
        "credentials_used": credential_counter + 1,
        "max_abs_error": max(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# A6 / Proposition 34: decision/side-channel encoder.
# ---------------------------------------------------------------------------


def attack_decision_side_channel(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    message_bits: Sequence[int],
    k: int = 5,
    subject_id: str = "attacker-channel",
    credential_id: str = "cred-channel",
    taint: int = 0,
) -> Dict[str, Any]:
    """Proposition 34: transmit bits by issuing queries predicted admitted (1) / refused (0).

    Uses a public-threshold probe: a size-1 conjunction is always refused by
    D1 (since 1 < k) and a broad single-attribute predicate is always
    admitted, so the adversary can name two queries whose decisions it can
    predict and which differ, exactly as the proposition requires.
    """
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
    n = gw.ledger.n

    # Find a "certainly admitted" probe (broad, in-range single-attribute
    # predicate) and a "certainly refused" probe (a tiny, sub-k predicate).
    admit_probe = None
    for attr in PUBLIC_ATTRIBUTES:
        for val in range(len(gw.ledger.attribute_categories[attr])):
            cand = Eq(attr, val)
            size = int(gw.characteristic_set(cand).sum())
            if k <= size <= n - k:
                admit_probe = cand
                break
        if admit_probe is not None:
            break

    refuse_probe = None
    uniques = unique_record_indices(gw.ledger)
    if len(uniques):
        refuse_probe = _full_conjunction(gw.ledger, int(uniques[0]))  # |C|=1 < k, refused by D1

    decoded_bits = []
    for bit in message_bits:
        probe = admit_probe if bit == 1 else refuse_probe
        if probe is None:
            decoded_bits.append(None)
            continue
        d = policy.decide(Query(probe, "COUNT"), ctx)
        decoded_bits.append(1 if d.admitted else 0)

    n_bits = len(message_bits)
    correct = sum(1 for a, b in zip(message_bits, decoded_bits) if a == b)
    # Floor a constant-guessing decoder reaches: guessing the majority bit,
    # or 50% for a balanced message; report bits ABOVE that floor.
    floor = n_bits / 2.0
    bits_above_floor = max(0.0, correct - floor)
    return {
        "attack": "A6_decision_side_channel",
        "n_bits": n_bits,
        "bits_correct": correct,
        "bits_above_guessing_floor": bits_above_floor,
        "decoded_bits": decoded_bits,
    }


# ---------------------------------------------------------------------------
# A7 / E2, companion threat model: external-effect exfiltration.
# ---------------------------------------------------------------------------


def attack_external_effect_exfiltration(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    targets: Sequence[int],
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    credential_id: str = "cred-1",
    taint: int = 1,
) -> Dict[str, Any]:
    """E2: recover values, then attempt to push them through an external-effect
    "export" tool. Counts a value as leaked only if it was both recovered AND
    the export tool call was admitted (A8 in the paper's numbering)."""
    ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
    recovered = 0
    exported = 0
    for salt, t in enumerate(targets):
        theta = _pick_padding_predicate(gw, gw.ledger, t, k, salt)
        if theta is None:
            continue
        psi_t = _full_conjunction(gw.ledger, t)

        d_union = policy.decide(Query(Or(theta, psi_t), "SUM", column), ctx)
        if not d_union.admitted:
            continue
        d_theta = policy.decide(Query(theta, "SUM", column), ctx)
        if not d_theta.admitted:
            continue

        v_union = gw.evaluate(GQuery(Or(theta, psi_t), "SUM", column))
        v_theta = gw.evaluate(GQuery(theta, "SUM", column))
        recovered_value = v_union - v_theta  # noqa: F841 (recovered, not further used)
        recovered += 1

        export_call = Query(has_external_effect=True)
        d_export = policy.decide(export_call, ctx)
        if d_export.admitted:
            exported += 1

    n_targets = len(targets)
    return {
        "attack": "A7_external_effect_exfiltration",
        "taint": taint,
        "n_targets": n_targets,
        "recovered": recovered,
        "exported": exported,
        "leaked": exported,  # a value only crosses E2 if both recovered and exported
        "leak_rate": exported / n_targets if n_targets else 0.0,
    }


# ---------------------------------------------------------------------------
# A8 / §5.2 "Second correction": AVG-exemption regression test.
# ---------------------------------------------------------------------------


def attack_avg_exemption_regression(
    gw: GatewaySim,
    buggy_policy: AdmissionPolicy,
    correct_policy: AdmissionPolicy,
    targets: Sequence[int],
    column: str = "revenue",
    k: int = 5,
    subject_id: str = "attacker-1",
    credential_id: str = "cred-1",
) -> Dict[str, Any]:
    """A1 routed through AVG instead of SUM (§5.2's A6).

    Against a policy that only audits SUM and exempts AVG (audit_avg=False),
    this recovers targets via
    ``xt = avg(theta OR psi_t)*(m+1) - avg(theta)*m`` (m = |C_theta|, public).
    Run once against `buggy_policy` and once against `correct_policy` (which
    shares the first-moment basis between SUM and AVG) to demonstrate the
    regression this guards against: the identical attack must succeed against
    the buggy variant and fail against the correct one.
    """

    def run(policy: AdmissionPolicy) -> Dict[str, Any]:
        ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=0)
        recovered = 0
        errors: List[float] = []
        for salt, t in enumerate(targets):
            theta = _pick_padding_predicate(gw, gw.ledger, t, k, salt)
            if theta is None:
                continue
            psi_t = _full_conjunction(gw.ledger, t)
            m = int(gw.characteristic_set(theta).sum())

            d_union = policy.decide(Query(Or(theta, psi_t), "AVG", column), ctx)
            if not d_union.admitted:
                continue
            d_theta = policy.decide(Query(theta, "AVG", column), ctx)
            if not d_theta.admitted:
                continue

            avg_union = gw.evaluate(GQuery(Or(theta, psi_t), "AVG", column))
            avg_theta = gw.evaluate(GQuery(theta, "AVG", column))
            recovered_value = avg_union * (m + 1) - avg_theta * m
            actual = gw.ledger.columns[column][t]
            errors.append(abs(recovered_value - actual))
            recovered += 1

        n_targets = len(targets)
        return {
            "recovered": recovered,
            "n_targets": n_targets,
            "success_rate": recovered / n_targets if n_targets else 0.0,
            "max_abs_error": max(errors) if errors else None,
        }

    buggy_result = run(buggy_policy)
    correct_result = run(correct_policy)
    return {
        "attack": "A8_avg_exemption_regression",
        "buggy_policy": buggy_result,
        "correct_policy": correct_result,
        "regression_guarded": buggy_result["success_rate"] > 0
        and correct_result["success_rate"] == 0.0,
    }


ALL_ATTACK_NAMES = (
    "A1_two_query_tracker",
    "A2_nested_conjunction_differencing",
    "A3_general_tracker",
    "A4_exposure_cap_bypass",
    "A5_credential_rotation",
    "A6_decision_side_channel",
    "A7_external_effect_exfiltration",
    "A8_avg_exemption_regression",
)