#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point: ledger -> admission policy -> all 8 attacks -> bounds checks
-> policy sweep, writing JSON to research/p4_admission/results/ and asserting
hard invariants (non-zero exit on failure).

Honesty note (see the top-level README): this script verifies INTERNAL
determinism and the mathematical properties the paper's theorems actually
assert on THIS reproduction's synthetic ledger and attack constructions --
Theorem 7's exact compromise criterion, Theorem 13's credential-budget
bypass, and the Theorem 16/20/26/30/32 bounds holding as inequalities on
measured data. It does not assert that any printed number equals the paper's
own (e.g. "9.8% uniquely identified", "0.77 general-tracker success under
classical audit"), because those depend on an unpublished exact generator.

Hard checks (all must pass; a failure raises AssertionError, giving a
non-zero exit code):

    (a) determinism: two runs with the same seed produce identical results
        (modulo wall-clock latency measurements).
    (b) the full D1-D5 stack blocks the two-query tracker (#1), the general
        tracker (#2), the exposure-cap bypass under E=1 (#4), and the
        AVG-exemption regression (#8) -- each of which a documented WEAKER
        or buggy variant does NOT block.
    (c) every measured bound in bounds.py actually upper-bounds its
        corresponding empirical measurement.

Target total runtime: well under 2 minutes.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import numpy as np

# Support both `python -m research.p4_admission.verify_claims` (relative
# imports would work) and `python research/p4_admission/verify_claims.py`
# (the invocation the project's own instructions use, which has no package
# context for relative imports). Absolute imports work in both cases as long
# as the project root is on sys.path.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from research.p4_admission import attacks as A
from research.p4_admission import bounds as B
from research.p4_admission.admission import (
    AdmissionPolicy,
    CredentialScopedBudget,
    NaiveExposureCapPolicy,
    SubjectScopedBudget,
)
from research.p4_admission.evaluate import run_full_evaluation
from research.p4_admission.gateway_sim import GatewaySim
from research.p4_admission.ledger import (
    CLASSIFIED_COLUMNS,
    DEFAULT_SEED,
    cross_classification_stats,
    generate_ledger,
    unique_record_indices,
)

RESULTS_DIR = Path(__file__).parent / "results"
N_TARGETS = 50
N_GENERAL_CELLS = 15


def _log(source: str, label: str, value: Any) -> None:
    print(f"[{source}] {label} = {value}")


def run_attacks_section(ledger, gw) -> Dict[str, Any]:
    targets = [int(x) for x in unique_record_indices(ledger)[:N_TARGETS]]
    rng = np.random.default_rng(2026)
    message_bits = list(rng.integers(0, 2, 64))

    def full_stack() -> AdmissionPolicy:
        return AdmissionPolicy(
            ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS,
            k=5, budget=1000, cell_aware=True, audit_enabled=True,
        )

    def d1_only() -> AdmissionPolicy:
        return AdmissionPolicy(
            ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS,
            k=5, budget=1000, audit_enabled=False,
        )

    def classical_audit() -> AdmissionPolicy:
        return AdmissionPolicy(
            ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS,
            k=5, budget=1000, cell_aware=False, audit_enabled=True,
        )

    # #1 two-query individual tracker (Proposition 4).
    a1_weak = A.attack_two_query_tracker(gw, d1_only(), targets)
    a1_full = A.attack_two_query_tracker(gw, full_stack(), targets)

    # bonus: nested-conjunction differencing (conjunction-only filter API).
    a2_weak = A.attack_nested_conjunction_differencing(gw, d1_only(), targets)
    a2_full = A.attack_nested_conjunction_differencing(gw, full_stack(), targets)

    # #2 general tracker against sub-k cells (Proposition 5).
    a3_weak = A.attack_general_tracker(gw, d1_only, n_cells=N_GENERAL_CELLS)
    a3_classical = A.attack_general_tracker(gw, classical_audit, n_cells=N_GENERAL_CELLS)
    a3_full = A.attack_general_tracker(gw, full_stack, n_cells=N_GENERAL_CELLS)

    # #3 query economics (Proposition 6): D1-only flat cost vs D2 growth.
    econ_size_only = A.attack_query_economics(gw, d1_only(), n_queries=400)
    econ_audited = A.attack_query_economics(gw, full_stack(), n_queries=400)

    # #4 per-record exposure-cap bypass (Proposition 12).
    a4_e1 = A.attack_exposure_cap_bypass(
        gw, NaiveExposureCapPolicy(ledger.n, ledger.public_attributes(), k=5, exposure_cap=1),
        n_pairs=N_GENERAL_CELLS,
    )
    a4_e2 = A.attack_exposure_cap_bypass(
        gw, NaiveExposureCapPolicy(ledger.n, ledger.public_attributes(), k=5, exposure_cap=2),
        n_pairs=N_GENERAL_CELLS,
    )

    # #5 credential-rotation budget bypass (Theorem 13).
    budget = 64
    cred_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=budget,
        audit_enabled=False, budget_scope=CredentialScopedBudget(budget),
    )
    subj_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=budget,
        audit_enabled=False, budget_scope=SubjectScopedBudget(budget),
    )
    a5_cred = A.attack_credential_rotation(gw, cred_policy, targets)
    a5_subj = A.attack_credential_rotation(gw, subj_policy, targets)

    # #6 decision/side-channel encoder (Proposition 34).
    a6_size_only = A.attack_decision_side_channel(gw, d1_only(), message_bits)
    ctau_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=False, taint_call_cap=8,
    )
    a6_ctau = A.attack_decision_side_channel(gw, ctau_policy, message_bits, taint=1)

    # #7 external-effect exfiltration (E2).
    taint_on = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=False, enforce_d4=True,
    )
    taint_off = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=False, enforce_d4=False,
    )
    a7_taint_on = A.attack_external_effect_exfiltration(gw, taint_on, targets, taint=1)
    a7_taint_off = A.attack_external_effect_exfiltration(gw, taint_off, targets, taint=1)

    # #8 AVG-exemption regression test.
    buggy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=True, audit_avg=False,
    )
    correct = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=True, audit_avg=True,
    )
    a8 = A.attack_avg_exemption_regression(gw, buggy, correct, targets)

    return {
        "A1_two_query_tracker": {"d1_only": a1_weak, "full_stack": a1_full},
        "A2_nested_conjunction_differencing": {"d1_only": a2_weak, "full_stack": a2_full},
        "A3_general_tracker": {"d1_only": a3_weak, "classical_audit": a3_classical, "full_stack": a3_full},
        "A_query_economics": {"size_only": econ_size_only, "audited": econ_audited},
        "A4_exposure_cap_bypass": {"E1": a4_e1, "E2": a4_e2},
        "A5_credential_rotation": {"credential_scoped": a5_cred, "subject_scoped": a5_subj},
        "A6_decision_side_channel": {"size_only": a6_size_only, "taint_call_cap": a6_ctau},
        "A7_external_effect_exfiltration": {"taint_gating_on": a7_taint_on, "taint_gating_off": a7_taint_off},
        "A8_avg_exemption_regression": a8,
    }


def run_bounds_section(ledger, gw) -> Dict[str, Any]:
    targets = [int(x) for x in unique_record_indices(ledger)[:N_TARGETS]]
    domain_bits = B.value_domain_bits(ledger, "revenue")
    budget = 64

    # Theorem 26 (+ Corollary 18, Theorem 16 instance): tight record-recovery
    # bound under a subject-scoped budget, exact SUM responses.
    subj_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=budget,
        audit_enabled=False, budget_scope=SubjectScopedBudget(budget),
    )
    recovery = A.attack_two_query_tracker(gw, subj_policy, targets)
    recovered = recovery["recovered"]
    theorem26 = B.theorem26_check(budget, domain_bits, recovered)
    theorem26["bound_bits"] = theorem26["upper_bound_bits"]
    theorem26["holds"] = theorem26["lower_holds"] and theorem26["upper_holds"]
    # Corollary 18 with M = |X| (exact mode): log2(M)/log2(|X|) == 1, so the
    # bound on recoverable records reduces to B itself.
    corollary18 = {
        "bound_max_records": budget,  # log2(M)/log2(|X|) == 1 when M == |X|
        "measured_records": recovered,
        "holds": recovered <= budget,
    }

    # Theorem 20: rank refinement, reusing admission.py's own GF(p) RREF.
    d1_only_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=10**6,
        audit_enabled=False,
    )
    rank_targets = targets[:20]
    rank_recovery = A.attack_two_query_tracker(gw, d1_only_policy, rank_targets)
    vectors = []
    from research.p4_admission.admission import Or, characteristic_indicator
    for i, t in enumerate(rank_targets):
        theta = A._pick_padding_predicate(gw, ledger, t, k=5, salt=i)
        if theta is None:
            continue
        psi_t = A._full_conjunction(ledger, t)
        vectors.append(characteristic_indicator(Or(theta, psi_t), ledger.attributes, ledger.n).astype(np.int64))
        vectors.append(characteristic_indicator(theta, ledger.attributes, ledger.n).astype(np.int64))
    rank = B.first_moment_rank(vectors, ledger.n)
    measured_20 = rank_recovery["recovered"] * domain_bits
    theorem20 = {
        "rank": rank,
        "bound_bits": rank * domain_bits,
        "measured_bits": measured_20,
        "holds": measured_20 <= rank * domain_bits + 1e-6,
    }

    # Theorem 30: injection-attributable bound under sound taint gating.
    B_tau, M_tau = 8, 24
    taint_on_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=1000,
        audit_enabled=False, enforce_d4=True, taint_budget=B_tau, taint_alphabet_size=M_tau,
    )
    a7 = A.attack_external_effect_exfiltration(gw, taint_on_policy, targets, taint=1)
    theorem30_bound = B.theorem30_bound(B_tau, M_tau)
    # Under D4, only COUNT (a public set size) is admissible while tainted,
    # so measured injection-attributable leakage about x is 0 -- matching
    # the paper's own P7 finding (§6.2: "the actual ... leakage ... is zero
    # rather than thirty-seven bits").
    measured_30 = a7["leaked"] * domain_bits
    theorem30 = {"bound_bits": theorem30_bound, "measured_bits": measured_30, "holds": measured_30 <= theorem30_bound + 1e-6}

    # Theorem 32: degradation under L-leaky taint tracking.
    L = 10
    leaky_policy = AdmissionPolicy(
        ledger.n, ledger.public_attributes(), CLASSIFIED_COLUMNS, k=5, budget=10**6,
        audit_enabled=False, enforce_d4=True, taint_budget=B_tau, taint_alphabet_size=M_tau,
    )
    escaped_targets = targets[:L // 2]
    escaped_recovery = A.attack_two_query_tracker(gw, leaky_policy, escaped_targets, taint=0)
    theorem32_bound = B.theorem32_bound_bits(B_tau, M_tau, L, domain_bits)
    measured_32 = escaped_recovery["recovered"] * domain_bits
    theorem32 = {"bound_bits": theorem32_bound, "measured_bits": measured_32, "holds": measured_32 <= theorem32_bound + 1e-6}

    return {
        "domain_bits": domain_bits,
        "theorem16_corollary18": corollary18,
        "theorem26": theorem26,
        "theorem20": theorem20,
        "theorem30": theorem30,
        "theorem32": theorem32,
    }


def run_pipeline(seed: int = DEFAULT_SEED) -> Dict[str, Any]:
    ledger = generate_ledger(seed=seed)
    gw = GatewaySim(ledger)
    stats = cross_classification_stats(ledger)
    attacks_section = run_attacks_section(ledger, gw)
    bounds_section = run_bounds_section(ledger, gw)
    sweep_section = run_full_evaluation(ledger)
    return {
        "seed": seed,
        "ledger_stats": stats,
        "attacks": attacks_section,
        "bounds": bounds_section,
        "sweep": sweep_section,
    }


def _strip_nondeterministic(obj: Any) -> Any:
    """Recursively drop wall-clock-sensitive keys (latency measurements) so
    two runs can be compared for determinism."""
    if isinstance(obj, dict):
        return {
            k: _strip_nondeterministic(v)
            for k, v in obj.items()
            if "latency" not in k
        }
    if isinstance(obj, list):
        return [_strip_nondeterministic(v) for v in obj]
    return obj


def check_determinism(result1: Dict[str, Any], result2: Dict[str, Any]) -> None:
    j1 = json.dumps(_strip_nondeterministic(result1), sort_keys=True, default=float)
    j2 = json.dumps(_strip_nondeterministic(result2), sort_keys=True, default=float)
    assert j1 == j2, "determinism check FAILED: two runs with the same seed produced different results"
    _log("check (a)", "determinism", "PASS")


def check_full_stack_blocks(result: Dict[str, Any]) -> None:
    attacks = result["attacks"]

    a1 = attacks["A1_two_query_tracker"]
    assert a1["full_stack"]["success_rate"] == 0.0, "full stack failed to block A1 (two-query tracker)"
    assert a1["d1_only"]["success_rate"] > 0.0, "D1-only unexpectedly blocked A1 (test is vacuous)"

    a3 = attacks["A3_general_tracker"]
    assert a3["full_stack"]["success_rate"] == 0.0, "full stack failed to block A3 (general tracker)"
    assert a3["d1_only"]["success_rate"] > 0.0, "D1-only unexpectedly blocked A3 (test is vacuous)"

    a4 = attacks["A4_exposure_cap_bypass"]
    assert a4["E1"]["success_rate"] == 0.0, "E=1 failed to block A4 (exposure-cap bypass)"
    assert a4["E2"]["success_rate"] > 0.0, "E=2 unexpectedly blocked A4 (test is vacuous)"

    a8 = attacks["A8_avg_exemption_regression"]
    assert a8["correct_policy"]["success_rate"] == 0.0, "correct policy failed to block A8 (AVG-exemption regression)"
    assert a8["buggy_policy"]["success_rate"] > 0.0, "buggy policy unexpectedly blocked A8 (test is vacuous)"

    a5 = attacks["A5_credential_rotation"]
    assert a5["credential_scoped"]["success_rate"] > a5["subject_scoped"]["success_rate"], (
        "Theorem 13 regression: subject-scoped budget failed to outperform credential-scoped"
    )

    _log("check (b)", "full D1-D5 stack blocks #1/#2/#4(E=1)/#8, weaker variants do not", "PASS")


def check_bounds_hold(result: Dict[str, Any]) -> None:
    bounds_section = result["bounds"]
    for name in ("theorem16_corollary18", "theorem26", "theorem20", "theorem30", "theorem32"):
        entry = bounds_section[name]
        assert entry["holds"], f"bound {name} FAILED to upper-bound its measurement: {entry}"
    _log("check (c)", "all measured bounds hold as inequalities", "PASS")


def main() -> int:
    t0 = time.time()

    print("=" * 72)
    print("P4 admission-control reproduction: verify_claims.py")
    print("Honesty note: verifying internal determinism and the mathematical")
    print("properties the theorems assert, NOT the paper's literal percentages.")
    print("=" * 72)

    result = run_pipeline()

    stats = result["ledger_stats"]
    _log("§4/§8.1 (this reproduction)", "occupied cells", stats["occupied_cells"])
    _log("§4/§8.1 (this reproduction)", "fraction of cells below k=5", round(stats["cells_below_k_fraction"], 4))
    _log("§4/§8.1 (this reproduction)", "fraction of records unique on public attrs", round(stats["records_unique_fraction"], 4))

    a1 = result["attacks"]["A1_two_query_tracker"]
    _log("Proposition 4", "two-query tracker success rate, D1-only", a1["d1_only"]["success_rate"])
    _log("Theorem 7 / Lemma 9", "two-query tracker success rate, full D1-D5 stack", a1["full_stack"]["success_rate"])

    a3 = result["attacks"]["A3_general_tracker"]
    _log("Proposition 5", "general tracker success rate, D1-only", a3["d1_only"]["success_rate"])
    _log("§5.2 'First correction'", "general tracker success rate, classical (weight-one) audit", a3["classical_audit"]["success_rate"])
    _log("§5.2 cell-aware test", "general tracker success rate, cell-aware audit", a3["full_stack"]["success_rate"])

    econ = result["attacks"]["A_query_economics"]
    _log("Proposition 6", "median decision latency, size-only (ms)", round(econ["size_only"]["latency_ms_median"], 5))
    _log("Proposition 6", "median decision latency, audited (ms)", round(econ["audited"]["latency_ms_median"], 5))
    _log("Proposition 6", "audited latency growth (last50/first50 median)",
         round(econ["audited"]["latency_ms_last_50_median"] / max(econ["audited"]["latency_ms_first_50_median"], 1e-9), 2))

    a4 = result["attacks"]["A4_exposure_cap_bypass"]
    _log("Proposition 12", "exposure-cap bypass success rate, E=1", a4["E1"]["success_rate"])
    _log("Proposition 12", "exposure-cap bypass success rate, E=2", a4["E2"]["success_rate"])

    a5 = result["attacks"]["A5_credential_rotation"]
    _log("Theorem 13", "credential-scoped budget: rotation success rate", a5["credential_scoped"]["success_rate"])
    _log("Corollary 14", "subject-scoped budget: rotation success rate", a5["subject_scoped"]["success_rate"])

    a6 = result["attacks"]["A6_decision_side_channel"]
    _log("Proposition 34", "decision channel bits above floor, size-only policy", a6["size_only"]["bits_above_guessing_floor"])
    _log("Proposition 34 / C_tau", "decision channel bits above floor, C_tau=8 cap", a6["taint_call_cap"]["bits_above_guessing_floor"])

    a7 = result["attacks"]["A7_external_effect_exfiltration"]
    _log("D4 / E2", "external-effect leak rate, taint gating ON", a7["taint_gating_on"]["leak_rate"])
    _log("D4 / E2", "external-effect leak rate, taint gating OFF", a7["taint_gating_off"]["leak_rate"])

    a8 = result["attacks"]["A8_avg_exemption_regression"]
    _log("§5.2 'Second correction'", "AVG-exemption regression guarded", a8["regression_guarded"])

    bounds_section = result["bounds"]
    for name, label in [
        ("theorem16_corollary18", "Theorem 16 / Corollary 18"),
        ("theorem26", "Theorem 26"),
        ("theorem20", "Theorem 20"),
        ("theorem30", "Theorem 30"),
        ("theorem32", "Theorem 32"),
    ]:
        entry = bounds_section[name]
        _log(label, "bound vs measured (bits)", f"{entry.get('bound_bits', entry.get('bound_max_records'))} >= {entry.get('measured_bits', entry.get('measured_records'))}")

    print("-" * 72)
    print("Frontier (policy ladder, max attack success rate vs benign utility):")
    for row in result["sweep"]["policy_ladder"]:
        print(f"  {row['policy']:5s} {row['description']:55s} "
              f"ASR={row['max_attack_success_rate']:.2f} utility={row['benign_utility']:.2f}")

    # Hard checks.
    print("-" * 72)
    result2 = run_pipeline()
    check_determinism(result, result2)
    check_full_stack_blocks(result)
    check_bounds_hold(result)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "verify_claims.json"
    out_path.write_text(json.dumps(result, indent=2, default=float, sort_keys=True))
    print(f"Wrote {out_path}")

    elapsed = time.time() - t0
    print(f"Total runtime: {elapsed:.2f}s")
    assert elapsed < 120, f"runtime {elapsed:.2f}s exceeded the 2-minute budget"

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
