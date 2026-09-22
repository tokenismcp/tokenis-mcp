# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Matplotlib reproductions of paper Figures 1-9.

This module is optional: `matplotlib` is listed under this repository's
`[project.optional-dependencies].research` extra, not a hard dependency, so
importing the rest of `research/p3_leakage/` must never require it. The
import is therefore guarded, and `main()` prints a clear message and exits
cleanly (rather than raising) if matplotlib is unavailable.

Usage:
    python research/p3_leakage/figures.py

Writes PNGs to `research/p3_leakage/results/`. Uses `corpus.CorpusSizes.
ci_scale()` by default (pass `--paper-scale` for the paper's own, much
slower, sizing) so a plain run stays fast; the shapes of the curves are what
matters here, not their absolute wall-clock cost. See `corpus.py` and
`verify_claims.py` for the standing honesty note: these figures reproduce
the paper's described *method*, not its published numbers.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    HAVE_MATPLOTLIB = True
except ImportError:  # pragma: no cover - exercised only when matplotlib absent
    HAVE_MATPLOTLIB = False

import attack_differential_inference as adi
import attack_schema_uniqueness as asu
import attack_token_linkage as atl
import corpus as corpus_mod
import defenses as defenses_mod

RESULTS_DIR = Path(__file__).parent / "results"


def _save(fig, name: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{name}.png"
    fig.savefig(path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {path}")


def figure1_subset_uniqueness(results: dict) -> None:
    rows = results["subset_size"]
    t = [r["t"] for r in rows]
    most = [r["most_informative_fraction_pct"] for r in rows]
    median = [r["median_fraction_pct"] for r in rows]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(t, most, marker="o", label="most informative subset")
    ax.plot(t, median, marker="s", label="median subset")
    ax.set_xlabel("public attributes known to the adversary (t)")
    ax.set_ylabel("uniquely identified (%)")
    ax.set_title("Fig. 1 (reproduction): attribute-combination uniqueness")
    ax.legend()
    _save(fig, "fig1_subset_uniqueness")


def figure2_generalization_ladder(results: dict) -> None:
    rows = results["generalization_ladder"]
    g = [r["g"] for r in rows]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(g, [r["unique_in_directory_pct"] for r in rows], marker="o", label="unique in public directory")
    ax.plot(g, [r["isolable_in_ledger_pct"] for r in rows], marker="s", label="isolable in ledger")
    max_groups = rows[0]["groups_addressable"] if rows else 1
    ax.plot(
        g,
        [100.0 * r["groups_addressable"] / max_groups for r in rows],
        marker="^",
        label="groups addressable (% of finest level)",
    )
    ax.set_xlabel("generalization level (g)")
    ax.set_ylabel("percent")
    ax.set_title("Fig. 2 (reproduction): generalization ladder")
    ax.legend()
    _save(fig, "fig2_generalization_ladder")


def figure3_ablation(results: dict) -> None:
    ablation = results["ablation"]
    order = ["S", "A", "T", "S+A", "S+T", "A+T", "S+A+T"]
    values = [ablation[name]["scores"]["2"]["pct_of_ledger"] for name in order]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(order, values, color="#4472C4")
    for i, v in enumerate(values):
        ax.text(i, v + 0.5, f"{v:.1f}", ha="center")
    ax.set_ylabel("ledger re-identified (%)")
    ax.set_title("Fig. 3 (reproduction): non-additive composition, m=2")
    _save(fig, "fig3_ablation")


def figure4_disclosure_profiles(results: dict) -> None:
    sweep = results["disclosure_profile_sweep"]
    order = ["P0_token_only", "P1_coarse", "P2_typical", "P3_rich"]
    schema_only = [sweep[p]["schema_only_pct_of_ledger"] for p in order]
    full = [sweep[p]["full_pipeline_pct_of_ledger"] for p in order]
    x = range(len(order))
    fig, ax = plt.subplots(figsize=(7, 4))
    width = 0.35
    ax.bar([i - width / 2 for i in x], schema_only, width, label="disclosed columns alone")
    ax.bar([i + width / 2 for i in x], full, width, label="+ aggregates + co-occurrence")
    ax.set_xticks(list(x))
    ax.set_xticklabels(order)
    ax.set_ylabel("ledger re-identified (%)")
    ax.set_title("Fig. 4 (reproduction): disclosure profile dominates")
    ax.legend()
    _save(fig, "fig4_disclosure_profiles")


def figure5_observation_growth(results: dict) -> None:
    rows = results["observation_growth_sweep"]
    sessions = [r["sessions_observed"] for r in rows]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(sessions, [r["accounts_reidentified"] for r in rows], marker="o", label="accounts re-identified")
    ax.plot(sessions, [r["amounts_recovered_exactly"] for r in rows], marker="s", label="amounts recovered exactly")
    ax.set_xlabel("sessions observed")
    ax.set_ylabel("accounts")
    ax.set_xscale("log")
    ax.set_title("Fig. 5 (reproduction): exposure grows with observation")
    ax.legend()
    _save(fig, "fig5_observation_growth")


def figure6_isolation(results: dict) -> None:
    setdiff = results["isolation"]["set_difference_expressible"]
    conj = results["isolation"]["conjunction_only"]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot([r["k"] for r in setdiff], [r["isolable_pct"] for r in setdiff], marker="o", label="set difference expressible")
    ax.plot([r["k"] for r in conj], [r["isolable_pct"] for r in conj], marker="s", label="conjunction-only")
    ax.set_xscale("log")
    ax.set_xlabel("minimum aggregate size (k)")
    ax.set_ylabel("accounts isolable (%)")
    ax.set_title("Fig. 6 (reproduction): isolability vs. k")
    ax.legend()
    _save(fig, "fig6_isolation")


def figure7_bulk_reconstruction(results: dict) -> None:
    rows = results["bulk_reconstruction"]
    ratios = [r["q_over_n"] for r in rows]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    axes[0].plot(ratios, [r["exact_determined_pct"] for r in rows], marker="o", label="exactly determined")
    axes[0].plot(ratios, [r["exact_within5_pct"] for r in rows], marker="s", label="within 5%")
    axes[0].set_xlabel("aggregate queries per account (q/n)")
    axes[0].set_ylabel("accounts recovered (%)")
    axes[0].set_title("exact answers: threshold at q=n")
    axes[0].legend()

    for sigma in sorted({s for r in rows for s in r["noisy_within5_pct"]}):
        axes[1].plot(ratios, [r["noisy_within5_pct"][sigma] for r in rows], marker="o", label=f"sigma={sigma}")
    axes[1].set_xlabel("aggregate queries per account (q/n)")
    axes[1].set_ylabel("accounts within 5% (%)")
    axes[1].set_title("noisy answers still reconstruct in bulk")
    axes[1].legend()

    fig.suptitle("Fig. 7 (reproduction): bulk reconstruction")
    _save(fig, "fig7_bulk_reconstruction")


def figure8_defenses(results: dict) -> None:
    d1, d2, d3, d5 = (
        results["D1_epoch_scoped_tokens"],
        results["D2_generalization"],
        results["D3_min_aggregate_size"],
        results["D5_cached_noise"],
    )
    fig, axes = plt.subplots(2, 2, figsize=(11, 8))

    axes[0, 0].plot([r["reidentified_pct"] for r in d1], [r["cross_session_links_preserved_pct"] for r in d1], marker="o")
    axes[0, 0].set_xlabel("re-identified (%)")
    axes[0, 0].set_ylabel("cross-session links kept (%)")
    axes[0, 0].set_title("D1 epoch-scoped tokens")

    axes[0, 1].plot([r["reidentified_pct"] for r in d2], [r["groups_addressable_pct"] for r in d2], marker="o")
    axes[0, 1].set_xlabel("re-identified (%)")
    axes[0, 1].set_ylabel("groups addressable (%)")
    axes[0, 1].set_title("D2 generalization")

    axes[1, 0].plot([r["amounts_recovered"] for r in d3], [r["pct_workload_answered"] for r in d3], marker="o")
    axes[1, 0].set_xlabel("amounts recovered")
    axes[1, 0].set_ylabel("sessions answered (%)")
    axes[1, 0].set_title("D3 minimum aggregate size")

    axes[1, 1].plot([r["adversary_cached_success_rate_pct"] for r in d5], [100 - r["analyst_median_relative_error_pct"] for r in d5], marker="o")
    axes[1, 1].set_xlabel("adversary success (%)")
    axes[1, 1].set_ylabel("100 - analyst median rel. error (%)")
    axes[1, 1].set_title("D5 cached noise")

    fig.suptitle("Fig. 8 (reproduction): security/utility frontiers")
    _save(fig, "fig8_defenses")


def figure9_gaussian_pricing(results: dict) -> None:
    sweep = results["beta_agg"]["gaussian_mechanism_sweep"]
    sigmas = [r["sigma_multiple_of_mean"] for r in sweep]
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    axes[0].plot(sigmas, [r["epsilon_per_query"] for r in sweep], marker="o")
    axes[0].set_xscale("log")
    axes[0].set_yscale("log")
    axes[0].set_xlabel("noise sigma (multiples of the mean account)")
    axes[0].set_ylabel("epsilon per query")
    axes[0].set_title("what the noise actually buys")

    axes[1].plot([r["epsilon_per_query"] for r in sweep], [r["analyst_median_relative_error_pct"] for r in sweep], marker="o")
    axes[1].set_xscale("log")
    axes[1].set_yscale("log")
    axes[1].set_xlabel("epsilon per query")
    axes[1].set_ylabel("analyst median error (%)")
    axes[1].set_title("what that noise costs the analyst")

    fig.suptitle("Fig. 9 (reproduction): Gaussian-mechanism pricing")
    _save(fig, "fig9_gaussian_pricing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper-scale", action="store_true", help="Use CorpusSizes.paper_scale() (slow).")
    args = parser.parse_args()

    if not HAVE_MATPLOTLIB:
        print(
            "matplotlib is not installed -- figures.py is optional and part of "
            "the 'research' extra (pip install '.[research]'). Skipping."
        )
        return 0

    sizes = corpus_mod.CorpusSizes.paper_scale() if args.paper_scale else corpus_mod.CorpusSizes.ci_scale()
    print("Building corpus ...")
    c = corpus_mod.build_corpus(sizes=sizes)

    print("Running attacks and defenses ...")
    schema_results = asu.run(c)
    linkage_results = atl.run(c)
    inference_results = adi.run(c)
    defense_results = defenses_mod.run(c)

    import budget as budget_mod

    budget_results = budget_mod.run(c)

    print("Rendering figures ...")
    figure1_subset_uniqueness(schema_results)
    figure2_generalization_ladder(schema_results)
    figure3_ablation(linkage_results)
    figure4_disclosure_profiles(linkage_results)
    figure5_observation_growth(linkage_results)
    figure6_isolation(inference_results)
    figure7_bulk_reconstruction(inference_results)
    figure8_defenses(defense_results)
    figure9_gaussian_pricing(budget_results)

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
