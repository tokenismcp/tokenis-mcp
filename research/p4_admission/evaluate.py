# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Security/utility policy-ladder sweep (paper §8, Table 1/2/3/4-style report).

Sweeps a ladder of policy configurations P0 (no control) through P8 (the full
recommended stack, banded everywhere), running the eight attacks of
:mod:`attacks` and a small synthetic benign workload against each, and
reporting attack success rate alongside benign-task utility and decision
latency -- the same security/utility frontier shape as the paper's §8.5,
computed on this reproduction's own ledger and attack constructions (see the
top-level README's honesty note; we do not claim to reproduce the paper's
literal utility/latency figures).

P3 ("+ exposure cap") is not an :class:`~admission.AdmissionPolicy`
configuration -- it is the naive, intentionally weaker
:class:`~admission.NaiveExposureCapPolicy` variant (§5.2) -- so it is swept
separately (see :func:`sweep_exposure_cap`) rather than folded into the main
P0-P8 table, and reported as its own section of the JSON output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import numpy as np

from . import attacks as A
from .admission import (
    AdmissionPolicy,
    CredentialScopedBudget,
    NaiveExposureCapPolicy,
    Query,
    QueryContext,
    SubjectScopedBudget,
    band_value,
)
from .gateway_sim import GatewaySim
from .gateway_sim import Query as GQuery
from .ledger import (
    CLASSIFIED_COLUMNS,
    PUBLIC_ATTRIBUTES,
    Ledger,
    generate_ledger,
    unique_record_indices,
)

DEFAULT_K = 5
DEFAULT_BUDGET = 64
DEFAULT_TAINT_BUDGET = 8
DEFAULT_TAINT_CALL_CAP = 32
DEFAULT_TAINT_ALPHABET = 24


@dataclass
class PolicyConfig:
    name: str
    description: str
    kwargs: Dict[str, Any] = field(default_factory=dict)
    banded: bool = False  # whether to apply D4-style response banding to ALL responses


def policy_ladder() -> List[PolicyConfig]:
    """P0..P8, mirroring Table 1 (minus P3, which is not an AdmissionPolicy)."""
    common = {
        "k": DEFAULT_K, "budget": DEFAULT_BUDGET, "taint_budget": DEFAULT_TAINT_BUDGET,
        "taint_call_cap": DEFAULT_TAINT_CALL_CAP, "taint_alphabet_size": DEFAULT_TAINT_ALPHABET,
    }
    return [
        PolicyConfig("P0", "no admission control", dict(common, k=0, enforce_d1=False,
                     audit_enabled=False, enforce_d4=False, enforce_d5=False, budget=10**9)),
        PolicyConfig("P1", "size only (D1)", dict(common, audit_enabled=False,
                     enforce_d4=False, enforce_d5=False, budget=10**9)),
        PolicyConfig("P2", "+ audit, classical (D1, D2 weight-one)", dict(common, cell_aware=False,
                     enforce_d4=False, enforce_d5=False, budget=10**9)),
        PolicyConfig("P2b", "+ audit, cell-aware (D1, D2 cell-aware)", dict(common, cell_aware=True,
                     enforce_d4=False, enforce_d5=False, budget=10**9)),
        PolicyConfig("P4", "+ budget (credential-scoped, D1)", dict(common, audit_enabled=False,
                     enforce_d4=False, enforce_d5=False)),
        PolicyConfig("P5", "+ budget (subject-scoped, D1, D3)", dict(common, audit_enabled=False,
                     enforce_d4=False, enforce_d5=False)),
        PolicyConfig("P6", "+ taint gating (D1, D3 subject, D4)", dict(common, audit_enabled=False,
                     enforce_d4=True, enforce_d5=False)),
        PolicyConfig("P7", "recommended (D1, D2 cell-aware, D3 subject, D4, D5)",
                     dict(common, cell_aware=True, audit_enabled=True, enforce_d4=True, enforce_d5=True)),
        PolicyConfig("P8", "banded everywhere (P7 + always-banded responses)",
                     dict(common, cell_aware=True, audit_enabled=True, enforce_d4=True, enforce_d5=True),
                     banded=True),
    ]


def build_policy_factory(ledger: Ledger, config: PolicyConfig) -> Callable[[], AdmissionPolicy]:
    kwargs = dict(config.kwargs)
    budget = kwargs.pop("budget")
    scope_kind = "credential" if config.name == "P4" else "subject"

    def factory() -> AdmissionPolicy:
        scope = CredentialScopedBudget(budget) if scope_kind == "credential" else SubjectScopedBudget(budget)
        return AdmissionPolicy(
            ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, budget=budget,
            budget_scope=scope, **kwargs,
        )

    return factory


# ---------------------------------------------------------------------------
# Benign workload.
# ---------------------------------------------------------------------------


def benign_workload(ledger: Ledger, n_queries: int = 60, tainted_fraction: float = 0.3, seed: int = 99):
    """A small synthetic benign analyst workload: single or double-attribute
    predicates, mixed COUNT/SUM/AVG on classified columns, some genuinely
    below k (correct denials, purely a function of population cardinality),
    a fraction of sessions tainted.
    """
    rng = np.random.default_rng(seed)
    functions = ["COUNT", "SUM", "AVG"]
    queries = []
    for i in range(n_queries):
        attr = PUBLIC_ATTRIBUTES[rng.integers(0, len(PUBLIC_ATTRIBUTES))]
        val = int(rng.integers(0, len(ledger.attribute_categories[attr])))
        from .admission import Eq

        predicate = Eq(attr, val)
        function = functions[rng.integers(0, len(functions))]
        column = None if function == "COUNT" else "revenue"
        taint = 1 if rng.random() < tainted_fraction else 0
        queries.append((predicate, function, column, taint))
    return queries


def run_benign_workload(
    gw: GatewaySim,
    policy: AdmissionPolicy,
    queries,
    banded: bool,
    tolerance: float = 0.05,
    subject_id: str = "benign-analyst",
    credential_id: str = "benign-cred",
) -> Dict[str, Any]:
    admitted = 0
    served_accurately = 0
    total = len(queries)
    revenue = gw.ledger.columns["revenue"]
    lo, hi = float(revenue.min()), float(revenue.max())

    for predicate, function, column, taint in queries:
        ctx = QueryContext(subject_id=subject_id, credential_id=credential_id, taint=taint)
        d = policy.decide(Query(predicate, function, column), ctx)
        if not d.admitted:
            continue
        admitted += 1
        truth = gw.evaluate(GQuery(predicate, function, column))
        if not banded or function == "COUNT":
            served_accurately += 1
            continue
        band = band_value(truth, lo, hi, policy.taint_alphabet_size)
        band_width = (hi - lo) / policy.taint_alphabet_size
        approx = lo + (band + 0.5) * band_width
        denom = abs(truth) if abs(truth) > 1e-9 else 1.0
        if abs(approx - truth) / denom <= tolerance:
            served_accurately += 1

    return {
        "total": total,
        "admitted": admitted,
        "served_accurately": served_accurately,
        "admission_rate": admitted / total if total else 0.0,
        "utility": served_accurately / total if total else 0.0,
    }


# ---------------------------------------------------------------------------
# Sweep.
# ---------------------------------------------------------------------------


def sweep_exposure_cap(ledger: Ledger, gw: GatewaySim, n_pairs: int = 15, caps=(1, 2, 3, 12)) -> List[Dict[str, Any]]:
    """P3-equivalent sweep: the naive exposure-cap heuristic (Proposition 12)."""
    results = []
    for E in caps:
        policy = NaiveExposureCapPolicy(ledger.n, ledger.public_attributes(), k=DEFAULT_K, exposure_cap=E)
        result = A.attack_exposure_cap_bypass(gw, policy, n_pairs=n_pairs)
        results.append({"exposure_cap": E, **result})
    return results


def run_policy_ladder(
    ledger: Ledger,
    n_tracker_targets: int = 50,
    n_general_cells: int = 15,
    n_channel_bits: int = 32,
    n_econ_queries: int = 150,
) -> List[Dict[str, Any]]:
    gw = GatewaySim(ledger)
    targets = [int(x) for x in unique_record_indices(ledger)[:n_tracker_targets]]
    benign_queries = benign_workload(ledger)
    rng = np.random.default_rng(7)
    message_bits = list(rng.integers(0, 2, n_channel_bits))

    results = []
    for config in policy_ladder():
        factory = build_policy_factory(ledger, config)

        policy_for_attacks = factory()
        a1 = A.attack_two_query_tracker(gw, policy_for_attacks, targets)
        a2 = A.attack_nested_conjunction_differencing(gw, factory(), targets)
        a3 = A.attack_general_tracker(gw, factory, n_cells=n_general_cells)
        a5 = A.attack_credential_rotation(gw, factory(), targets)
        a6 = A.attack_decision_side_channel(gw, factory(), message_bits)
        a7 = A.attack_external_effect_exfiltration(gw, factory(), targets, taint=1)

        econ_policy = factory()
        econ = A.attack_query_economics(gw, econ_policy, n_queries=n_econ_queries)

        benign_policy = factory()
        benign = run_benign_workload(gw, benign_policy, benign_queries, banded=config.banded)

        results.append({
            "policy": config.name,
            "description": config.description,
            "attacks": {
                "A1_two_query_tracker": a1["success_rate"],
                "A2_nested_conjunction_differencing": a2["success_rate"],
                "A3_general_tracker": a3["success_rate"],
                "A5_credential_rotation": a5["success_rate"],
                "A6_decision_side_channel_bits_above_floor": a6["bits_above_guessing_floor"],
                "A7_external_effect_leak_rate": a7["leak_rate"],
            },
            "max_attack_success_rate": max(
                a1["success_rate"], a2["success_rate"], a3["success_rate"], a5["success_rate"]
            ),
            "benign_utility": benign["utility"],
            "benign_admission_rate": benign["admission_rate"],
            "latency_ms_median": econ["latency_ms_median"],
            "latency_ms_p95": econ["latency_ms_p95"],
        })
    return results


def run_full_evaluation(ledger: Optional[Ledger] = None) -> Dict[str, Any]:
    ledger = ledger or generate_ledger()
    gw = GatewaySim(ledger)
    return {
        "policy_ladder": run_policy_ladder(ledger),
        "exposure_cap_sweep": sweep_exposure_cap(ledger, gw),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_full_evaluation(), indent=2, default=float))
