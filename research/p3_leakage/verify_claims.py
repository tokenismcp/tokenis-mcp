#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Provenance checker for the P3 reproduction, standing in for the paper's
own `verify_claims.py` (Section 4.4, Appendix B: "the released
verify_claims.py prints each of the 65 headline numbers in this paper beside
the result-file field that produced it").

WHAT THIS SCRIPT DOES AND DOES NOT CLAIM
------------------------------------------
This script runs the full corpus -> attacks -> defenses -> budget pipeline
with the paper's own fixed seeds (corpus seed 20260920, workload seed 7),
writes each module's output to `results/*.json`, and prints every computed
headline number next to the (module, JSON path) that produced it -- exactly
like the paper's own checker. What it does NOT do is assert that any of
those numbers equals a number printed in the paper's PDF. As `corpus.py`'s
module docstring explains, the paper's own generator source was never
published, only its seeds and a prose description of its calibrated
marginals -- so this is a faithful re-implementation of the *method*, and
the standard this script holds itself to is:

  1. Internal determinism: running the pipeline twice from the same seeds
     produces byte-identical JSON (checked below by literally doing that).
  2. Internal consistency: sanity bounds that must hold for any correct
     instance of this method (percentages in [0, 100], isolability curves
     non-increasing in the generalization/aggregate-size sweeps, etc.).
  3. Qualitative parity with the paper's reported *shapes* -- which a human
     reader can eyeball from the printed headline numbers, but which this
     script does not attempt to grade automatically, because doing so would
     misrepresent how much a synthetic reproduction can promise.

Exit code is non-zero if either (1) or (2) fails.

RUNTIME PROFILE
------------------
This script uses `corpus.CorpusSizes.ci_scale()` (see `corpus.py`), a much
smaller sizing than the paper's own defaults (`CorpusSizes.paper_scale()`),
specifically so the full pipeline -- run *twice*, for the determinism check
-- finishes in well under the repository's 2-minute budget on a laptop. Pass
`--paper-scale` to instead run at the paper's own sizes (|U|=40,000,
ledger=4,000, sessions=1,600); this takes several minutes and only runs the
pipeline once (no determinism double-run), matching how `figures.py` is
meant to be driven for producing publication-scale plots.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import attack_differential_inference as adi
import attack_schema_uniqueness as asu
import attack_token_linkage as atl
import budget as budget_mod
import corpus as corpus_mod
import defenses as defenses_mod
import numpy as np

RESULTS_DIR = Path(__file__).parent / "results"


def sanitize(obj: Any) -> Any:
    """Recursively convert numpy scalar/array types to plain Python types so
    the result is valid, deterministic JSON (sorted keys, no NaN/Infinity
    literals sneaking through as numpy repr artifacts)."""
    if isinstance(obj, dict):
        return {str(k): sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        v = float(obj)
        if not np.isfinite(v):
            return None
        return v
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.ndarray):
        return sanitize(obj.tolist())
    if isinstance(obj, float) and not np.isfinite(obj):
        return None
    return obj


def run_full_pipeline(sizes: corpus_mod.CorpusSizes) -> Dict[str, Any]:
    c = corpus_mod.build_corpus(
        sizes=sizes,
        corpus_seed=corpus_mod.DEFAULT_CORPUS_SEED,
        workload_seed=corpus_mod.DEFAULT_WORKLOAD_SEED,
    )
    results: Dict[str, Any] = {}
    results["corpus"] = sanitize(
        {
            "directory_size": c.directory.size,
            "ledger_size": c.ledger.size,
            "n_sessions": len(c.workload.sessions),
            "public_graph_edges": int(c.public_graph.edges.shape[0]),
            "public_graph_edges_within_ledger": _edges_within_ledger(c),
            "rho": c.workload.rho,
            "seed_corpus": c.seed_corpus,
            "seed_workload": c.seed_workload,
            "industry_cells": corpus_mod.INDUSTRY_CELLS,
            "n_localities": corpus_mod.N_LOCALITY,
        }
    )
    results["attack_schema_uniqueness"] = sanitize(asu.run(c))
    results["attack_token_linkage"] = sanitize(atl.run(c))
    results["attack_differential_inference"] = sanitize(adi.run(c))
    results["defenses"] = sanitize(defenses_mod.run(c))
    results["budget"] = sanitize(budget_mod.run(c))
    return results


def _edges_within_ledger(c: corpus_mod.Corpus) -> int:
    ledger_dir = {int(x) for x in c.ledger.directory_index}
    count = 0
    for a, b in c.public_graph.edges:
        if int(a) in ledger_dir and int(b) in ledger_dir:
            count += 1
    return count


def write_results(results: Dict[str, Any]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for name, payload in results.items():
        path = RESULTS_DIR / f"{name}.json"
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")


def canonical_json(results: Dict[str, Any]) -> str:
    return json.dumps(results, sort_keys=True)


# ---------------------------------------------------------------------------
# Headline numbers
# ---------------------------------------------------------------------------


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if part.startswith("[") and part.endswith("]"):
            part = part[1:-1]
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def build_headline_numbers(results: Dict[str, Any]) -> List[Tuple[str, str, Any]]:
    """Returns (description, json_path, value) triples, mirroring the
    paper's own verify_claims.py: "prints each ... headline number beside
    the result-file field that produced it"."""
    lines: List[Tuple[str, str, Any]] = []

    def add(desc: str, module: str, path: str):
        try:
            value = _get(results[module], path)
        except (KeyError, IndexError, TypeError) as exc:
            value = f"<missing: {exc}>"
        lines.append((desc, f"{module}.json :: {path}", value))

    # --- corpus / Section 4 ---
    add("directory size |U|", "corpus", "directory_size")
    add("ledger size |D|", "corpus", "ledger_size")
    add("public graph edges over U", "corpus", "public_graph_edges")
    add("public graph edges within ledger", "corpus", "public_graph_edges_within_ledger")
    add("industry x locality cells (published)", "corpus", "industry_cells")

    # --- Section 5: schema uniqueness ---
    add("occupied industry x locality cells", "attack_schema_uniqueness", "cell_occupancy.occupied_cells")
    add("singleton cell share (%)", "attack_schema_uniqueness", "cell_occupancy.singleton_cell_share_pct")
    for t in range(1, 8):
        idx = t - 1
        add(
            f"t={t}: most-informative subset unique (%)",
            "attack_schema_uniqueness",
            f"subset_size.[{idx}].most_informative_fraction_pct",
        )
        add(
            f"t={t}: median subset unique (%)",
            "attack_schema_uniqueness",
            f"subset_size.[{idx}].median_fraction_pct",
        )
    for g in range(6):
        add(f"g={g}: unique in directory (%)", "attack_schema_uniqueness", f"generalization_ladder.[{g}].unique_in_directory_pct")
        add(f"g={g}: isolable in ledger (%)", "attack_schema_uniqueness", f"generalization_ladder.[{g}].isolable_in_ledger_pct")
        add(f"g={g}: groups addressable", "attack_schema_uniqueness", f"generalization_ladder.[{g}].groups_addressable")

    # --- Section 6: token linkage / composition ---
    for combo in ("S", "A", "T", "S+A", "S+T", "A+T", "S+A+T"):
        add(f"ablation {combo}: re-id at m=2 (%)", "attack_token_linkage", f"ablation.{combo}.scores.2.pct_of_ledger")
        add(f"ablation {combo}: precision at m=2", "attack_token_linkage", f"ablation.{combo}.scores.2.precision")
    for profile in ("P0_token_only", "P1_coarse", "P2_typical", "P3_rich"):
        add(f"{profile}: median |C(tau)|", "attack_token_linkage", f"disclosure_profile_sweep.{profile}.median_candidate_set_size")
        add(f"{profile}: full pipeline re-id (%)", "attack_token_linkage", f"disclosure_profile_sweep.{profile}.full_pipeline_pct_of_ledger")
    n_growth_points = len(results["attack_token_linkage"]["observation_growth_sweep"])
    add(
        "observation growth: max sessions accounts re-identified",
        "attack_token_linkage",
        f"observation_growth_sweep.{n_growth_points - 1}.accounts_reidentified",
    )

    # --- Section 7: differential inference ---
    add("isolable (set-difference) at k=1 (%)", "attack_differential_inference", "isolation.set_difference_expressible.0.isolable_pct")
    add("isolable (set-difference) at k=100 (%)", "attack_differential_inference", "isolation.set_difference_expressible.7.isolable_pct")
    add("isolable (conjunction-only) at k=1 (%)", "attack_differential_inference", "isolation.conjunction_only.0.isolable_pct")
    add("isolable (conjunction-only) at k=5 (%)", "attack_differential_inference", "isolation.conjunction_only.3.isolable_pct")
    add("bulk reconstruction: exact-determined at q/n=1.0 (%)", "attack_differential_inference", "bulk_reconstruction.3.exact_determined_pct")
    add("bulk reconstruction: exact-determined at q/n=0.5 (%)", "attack_differential_inference", "bulk_reconstruction.1.exact_determined_pct")
    add("averaging: median queries for 5% error at sigma=0.5", "attack_differential_inference", "noise_averaging_vs_deterministic.averaging.2.median_queries_needed")
    add("deterministic cache: one-shot success at sigma=0.5 (%)", "attack_differential_inference", "noise_averaging_vs_deterministic.deterministic_cache.2.one_shot_success_rate_pct")
    add("query budget B=1000: adversary median rel. error (%)", "attack_differential_inference", "budget_relative_error.4.median_relative_error_pct")

    # --- Section 8: defenses ---
    add("D1 E=1: re-identified (%)", "defenses", "D1_epoch_scoped_tokens.0.reidentified_pct")
    add("D1 E=1: cross-session links preserved (%)", "defenses", "D1_epoch_scoped_tokens.0.cross_session_links_preserved_pct")
    n_d1 = len(results["defenses"]["D1_epoch_scoped_tokens"])
    add("D1 E=max: re-identified (%)", "defenses", f"D1_epoch_scoped_tokens.{n_d1 - 1}.reidentified_pct")
    add("D2 g=0: re-identified (%)", "defenses", "D2_generalization.0.reidentified_pct")
    add("D2 g=5: re-identified (%)", "defenses", "D2_generalization.5.reidentified_pct")
    add("D3 k=1: amounts recovered", "defenses", "D3_min_aggregate_size.0.amounts_recovered")
    add("D3 k=5: amounts recovered", "defenses", "D3_min_aggregate_size.2.amounts_recovered")
    add("D4 B=2: pct workload served (%)", "defenses", "D4_query_budget.0.pct_legitimate_workload_served")
    add("D5 sigma=0.5: analyst median rel. error (%)", "defenses", "D5_cached_noise.2.analyst_median_relative_error_pct")
    add("D5 sigma=0.5: adversary cached success (%)", "defenses", "D5_cached_noise.2.adversary_cached_success_rate_pct")

    # --- Section 9: disclosure budget ---
    for profile in ("P0_token_only", "P1_coarse", "P2_typical", "P3_rich"):
        add(f"beta_schema[{profile}] (bits/row)", "budget", f"beta_schema.{profile}.bits_per_row")
        add(f"beta_token[{profile}] (points)", "budget", f"beta_token.{profile}")
    add("beta_pattern: mutual information (bits)", "budget", "beta_pattern.mutual_information_bits")
    add("Claim 1 holds (proof-checked)", "budget", "beta_agg.claim1.holds")
    add("Gaussian mechanism sigma=0.5: epsilon/query", "budget", "beta_agg.gaussian_mechanism_sweep.1.epsilon_per_query")
    for i, mode in enumerate(("A", "B", "C", "D")):
        add(f"Mode {mode}: beta_schema (bits)", "budget", f"four_mode_table.{i}.beta_schema_bits")
        add(f"Mode {mode}: re-identified (%)", "budget", f"four_mode_table.{i}.reidentified_pct")
        add(f"Mode {mode}: isolable (%)", "budget", f"four_mode_table.{i}.isolable_pct")
        add(f"Mode {mode}: pct workload answered (%)", "budget", f"four_mode_table.{i}.pct_workload_answered")

    return lines


def print_headline_numbers(lines: List[Tuple[str, str, Any]]) -> None:
    print()
    print("=" * 100)
    print(f"HEADLINE NUMBERS ({len(lines)} computed values, each traced to its source file/field)")
    print("=" * 100)
    for desc, source, value in lines:
        if isinstance(value, float):
            value_str = f"{value:.4f}"
        else:
            value_str = str(value)
        print(f"  {desc:<58} = {value_str:<14} <- {source}")
    print("=" * 100)


# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------


def sanity_checks(results: Dict[str, Any]) -> List[str]:
    """Returns a list of failure messages (empty list = all passed)."""
    failures: List[str] = []

    def check(cond: bool, msg: str):
        if not cond:
            failures.append(msg)

    def is_pct(x) -> bool:
        return isinstance(x, (int, float)) and -1e-6 <= x <= 100 + 1e-6

    # 1. Every "_pct" field that represents a share of a fixed population
    #    (re-identified / isolable / unique / addressable / answered / ...)
    #    is bounded to [0, 100]. Relative-error percentages are explicitly
    #    excluded: they are ratios to a true value, not shares of a
    #    population, and the paper itself reports figures far past 100%
    #    (e.g. "buying epsilon=1 costs a median answer error of 867%").
    UNBOUNDED_PCT_MARKERS = ("relative_error",)

    def walk(obj: Any, path: str):
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{path}.{k}"
                if (
                    isinstance(k, str)
                    and k.endswith("_pct")
                    and isinstance(v, (int, float))
                    and not any(marker in k for marker in UNBOUNDED_PCT_MARKERS)
                ):
                    check(is_pct(v), f"{p} = {v} is out of [0,100]")
                walk(v, p)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(results, "results")

    # 2. Precision values are in [0, 1].
    ablation = results["attack_token_linkage"]["ablation"]
    for combo, payload in ablation.items():
        for m, score in payload["scores"].items():
            p = score["precision"]
            check(0.0 <= p <= 1.0 + 1e-9, f"ablation[{combo}].scores[{m}].precision = {p} out of [0,1]")

    # 3. Generalization ladder: uniqueness-in-directory is non-increasing in g.
    rungs = results["attack_schema_uniqueness"]["generalization_ladder"]
    for a, b in itertools.pairwise(rungs):
        check(
            b["unique_in_directory_pct"] <= a["unique_in_directory_pct"] + 1e-6,
            f"generalization_ladder uniqueness increased from g={a['g']} to g={b['g']}",
        )
        check(
            b["groups_addressable"] <= a["groups_addressable"],
            f"generalization_ladder groups_addressable increased from g={a['g']} to g={b['g']}",
        )

    # 4. Isolation (set-difference) is flat in k while k+1 <= ledger size, and
    #    isolation (conjunction-only) is non-increasing in k.
    setdiff = results["attack_differential_inference"]["isolation"]["set_difference_expressible"]
    n_ledger = results["corpus"]["ledger_size"]
    flat_region = [row for row in setdiff if row["k"] + 1 <= n_ledger]
    if flat_region:
        base = flat_region[0]["isolable_pct"]
        for row in flat_region:
            check(
                abs(row["isolable_pct"] - base) < 1e-6,
                f"set-difference isolability not flat in k: k={row['k']} -> {row['isolable_pct']} vs {base}",
            )
    conj = results["attack_differential_inference"]["isolation"]["conjunction_only"]
    for a, b in itertools.pairwise(conj):
        check(
            b["isolable_pct"] <= a["isolable_pct"] + 1e-6,
            f"conjunction-only isolability increased from k={a['k']} to k={b['k']}",
        )

    # 5. D2 generalization defense: re-id non-increasing in g; groups
    #    addressable non-increasing in g.
    d2 = results["defenses"]["D2_generalization"]
    for a, b in itertools.pairwise(d2):
        check(b["reidentified_pct"] <= a["reidentified_pct"] + 1e-6, f"D2 re-id increased from g={a['g']} to g={b['g']}")
        check(
            b["groups_addressable_pct"] <= a["groups_addressable_pct"] + 1e-6,
            f"D2 groups_addressable increased from g={a['g']} to g={b['g']}",
        )

    # 6. D1 epoch sweep: cross-session links preserved is non-decreasing in E.
    d1 = results["defenses"]["D1_epoch_scoped_tokens"]
    for a, b in itertools.pairwise(d1):
        check(
            b["cross_session_links_preserved_pct"] >= a["cross_session_links_preserved_pct"] - 1e-6,
            f"D1 links_preserved decreased from E={a['epoch_length']} to E={b['epoch_length']}",
        )

    # 7. Claim 1 must hold -- this is a proof-checked property, not a sweep.
    check(results["budget"]["beta_agg"]["claim1"]["holds"] is True, "Claim 1 proof check failed")

    # 8. beta_schema bits_per_row is in [0, log2(|U|)].
    max_bits = np.log2(max(1, results["corpus"]["directory_size"]))
    for profile, payload in results["budget"]["beta_schema"].items():
        b = payload["bits_per_row"]
        check(-1e-6 <= b <= max_bits + 1e-6, f"beta_schema[{profile}] = {b} out of [0, {max_bits}]")

    # 9. Bulk reconstruction: below the q=n threshold the system is
    #    underdetermined and the minimum-norm least-squares solution is not
    #    guaranteed to improve monotonically point-to-point (Section 7.2's
    #    claim is about a *threshold*, not monotonicity below it). What must
    #    hold is the threshold itself: once q/n >= 1, essentially every
    #    account is recovered exactly, and that should stay true as q/n
    #    grows further.
    bulk = results["attack_differential_inference"]["bulk_reconstruction"]
    at_or_above_threshold = [row for row in bulk if row["q_over_n"] >= 1.0 - 1e-9]
    for row in at_or_above_threshold:
        check(
            row["exact_within5_pct"] >= 99.0,
            f"bulk reconstruction at q/n={row['q_over_n']} >= 1 only recovered {row['exact_within5_pct']}% exactly (expected >= 99%)",
        )

    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--paper-scale",
        action="store_true",
        help="Run once at the paper's own sizes (slow; skips the determinism double-run).",
    )
    parser.add_argument(
        "--skip-determinism-check",
        action="store_true",
        help="Run the pipeline once only (for quick manual inspection; CI should not use this).",
    )
    args = parser.parse_args()

    sizes = corpus_mod.CorpusSizes.paper_scale() if args.paper_scale else corpus_mod.CorpusSizes.ci_scale()
    scale_name = "paper_scale" if args.paper_scale else "ci_scale"
    print(f"Running P3 leakage-quantification pipeline (sizes={scale_name}) ...")

    t0 = time.time()
    results_run1 = run_full_pipeline(sizes)
    t1 = time.time()
    print(f"  first run:  {t1 - t0:.2f}s")

    write_results(results_run1)

    determinism_ok = True
    if not args.paper_scale and not args.skip_determinism_check:
        results_run2 = run_full_pipeline(sizes)
        t2 = time.time()
        print(f"  second run: {t2 - t1:.2f}s")
        json1 = canonical_json(results_run1)
        json2 = canonical_json(results_run2)
        determinism_ok = json1 == json2
        if determinism_ok:
            print("DETERMINISM CHECK: PASS (two independent runs from the same seeds produced byte-identical JSON)")
        else:
            print("DETERMINISM CHECK: FAIL -- runs diverged; the pipeline is not fully seeded")
    else:
        print("DETERMINISM CHECK: skipped (--paper-scale or --skip-determinism-check)")

    headline = build_headline_numbers(results_run1)
    print_headline_numbers(headline)

    failures = sanity_checks(results_run1)
    print()
    if failures:
        print(f"SANITY CHECKS: FAIL ({len(failures)} violation(s))")
        for f in failures:
            print(f"  - {f}")
    else:
        print("SANITY CHECKS: PASS")

    print()
    print(f"Results written to: {RESULTS_DIR}")
    print()
    print(
        "Reminder: these are internally-consistent, deterministic outputs of a "
        "faithful re-implementation of the paper's *described* method on a "
        "synthetic corpus -- not a numeric reproduction of the paper's own "
        "published percentages. See README.md and corpus.py's module "
        "docstring for what is published / calibrated / invented / computed."
    )

    ok = determinism_ok and not failures
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
