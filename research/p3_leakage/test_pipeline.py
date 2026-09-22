# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fast pytest tests for the P3 reproduction package.

These are deliberately small and fast (a handful of seconds total, run on a
much smaller corpus than even `verify_claims.py`'s CI profile) -- they check
that each module runs without error and returns structurally/qualitatively
sane output, not that any number matches the published paper. The slower,
full-pipeline determinism/consistency check lives in `verify_claims.py` and
is not re-run here.

Discovered automatically by pytest via this repository's `pyproject.toml`
`[tool.pytest.ini_options] testpaths`, which already lists
`research/p3_leakage`.
"""

from __future__ import annotations

import attack_differential_inference as adi
import attack_schema_uniqueness as asu
import attack_token_linkage as atl
import budget as budget_mod
import corpus as corpus_mod
import defenses as defenses_mod
import numpy as np
import pytest

TINY_SIZES = corpus_mod.CorpusSizes(directory_size=800, ledger_size=60, n_sessions=40)


@pytest.fixture(scope="module")
def tiny_corpus() -> corpus_mod.Corpus:
    return corpus_mod.build_corpus(sizes=TINY_SIZES)


# ---------------------------------------------------------------------------
# corpus.py
# ---------------------------------------------------------------------------


def test_published_constants_are_exact():
    # Section 4.1: these must never drift from the cited official values.
    assert corpus_mod.N_SUBCLASS == 1196
    assert corpus_mod.N_CLASS == 495
    assert corpus_mod.N_GROUP == 232
    assert corpus_mod.N_DIVISION == 77
    assert corpus_mod.N_SECTION == 21
    assert corpus_mod.N_LOCALITY == 229
    assert corpus_mod.INDUSTRY_CELLS == 1196 * 229


def test_corpus_generates_requested_sizes(tiny_corpus):
    c = tiny_corpus
    assert c.directory.size == TINY_SIZES.directory_size
    assert c.ledger.size == TINY_SIZES.ledger_size
    assert len(c.workload.sessions) == TINY_SIZES.n_sessions
    # Every ledger account must point at a real directory row.
    assert c.ledger.directory_index.min() >= 0
    assert c.ledger.directory_index.max() < c.directory.size
    # Ledger accounts are drawn without replacement.
    assert len(set(c.ledger.directory_index.tolist())) == c.ledger.size


def test_corpus_is_deterministic_under_fixed_seeds():
    c1 = corpus_mod.build_corpus(sizes=TINY_SIZES)
    c2 = corpus_mod.build_corpus(sizes=TINY_SIZES)
    assert np.array_equal(c1.directory.industry_subclass, c2.directory.industry_subclass)
    assert np.array_equal(c1.ledger.amount, c2.ledger.amount)
    assert np.array_equal(c1.public_graph.edges, c2.public_graph.edges)
    assert [s.members for s in c1.workload.sessions] == [s.members for s in c2.workload.sessions]


def test_private_amount_relation_matches_spec(tiny_corpus):
    # log(amount) = 0.95*log(revenue) + N(0, 0.35); check the fitted slope is
    # close to 0.95 across the whole ledger (a statistical, not exact, check).
    c = tiny_corpus
    log_amount = np.log(c.ledger.amount)
    log_revenue = np.log(c.directory.revenue[c.ledger.directory_index])
    slope = np.polyfit(log_revenue, log_amount, 1)[0]
    assert 0.7 < slope < 1.2


# ---------------------------------------------------------------------------
# attack_schema_uniqueness.py
# ---------------------------------------------------------------------------


def test_schema_uniqueness_runs_and_is_bounded(tiny_corpus):
    result = asu.run(tiny_corpus)
    for row in result["subset_size"]:
        assert 0.0 <= row["most_informative_fraction_pct"] <= 100.0
        assert 0.0 <= row["median_fraction_pct"] <= 100.0
        assert row["most_informative_fraction_pct"] >= row["median_fraction_pct"] - 1e-9

    # Adding an attribute can never decrease the *best* achievable uniqueness.
    most_informative = [r["most_informative_fraction_pct"] for r in result["subset_size"]]
    for a, b in zip(most_informative, most_informative[1:]):
        assert b >= a - 1e-6


def test_generalization_ladder_is_monotone(tiny_corpus):
    rungs = asu.generalization_ladder(tiny_corpus)
    assert len(rungs) == 6
    for a, b in zip(rungs, rungs[1:]):
        assert b.unique_in_directory_pct <= a.unique_in_directory_pct + 1e-6
        assert b.groups_addressable <= a.groups_addressable


# ---------------------------------------------------------------------------
# attack_token_linkage.py
# ---------------------------------------------------------------------------


def test_linkage_ablation_runs_without_error(tiny_corpus):
    ablation = atl.run_ablation(tiny_corpus)
    assert set(ablation.keys()) == {"S", "A", "T", "S+A", "S+T", "A+T", "S+A+T"}
    for payload in ablation.values():
        for score in payload["scores"].values():
            assert 0.0 <= score["pct_of_ledger"] <= 100.0
            assert 0.0 <= score["precision"] <= 1.0

    # A and T alone should not out-perform the schema channel (Section 6.2:
    # two of the three marginals re-identify nobody without an anchor).
    assert ablation["A"]["scores"]["2"]["pct_of_ledger"] == 0.0
    assert ablation["T"]["scores"]["2"]["pct_of_ledger"] == 0.0


def test_disclosure_profile_sweep_is_monotone_ish(tiny_corpus):
    sweep = atl.run_disclosure_profile_sweep(tiny_corpus)
    order = ["P0_token_only", "P1_coarse", "P2_typical", "P3_rich"]
    values = [sweep[p]["full_pipeline_pct_of_ledger"] for p in order]
    # P0 (token-only) must never beat P3 (full attribute row): richer
    # disclosure can only narrow candidates further, never widen them.
    assert values[0] <= values[-1] + 1e-6
    assert values[-1] >= max(values) - 1e-9


def test_stage2_peeling_recovers_only_true_amounts(tiny_corpus):
    known = atl.stage2_peel_amounts(tiny_corpus)
    for token, amount in known.items():
        assert amount == pytest.approx(tiny_corpus.ledger.amount[token], rel=1e-6)


# ---------------------------------------------------------------------------
# attack_differential_inference.py
# ---------------------------------------------------------------------------


def test_isolation_setdiff_is_flat_in_k(tiny_corpus):
    rows = adi.isolation_setdiff(tiny_corpus, [1, 2, 5, 10, 25])
    values = {r["isolable_pct"] for r in rows if r["k"] + 1 <= tiny_corpus.ledger.size}
    assert len(values) == 1  # flat, per the Section 7.1 proof


def test_isolation_conjunction_only_is_non_increasing(tiny_corpus):
    rows = adi.isolation_conjunction_only(tiny_corpus, [1, 2, 5, 10, 25])
    for a, b in zip(rows, rows[1:]):
        assert b["isolable_pct"] <= a["isolable_pct"] + 1e-6


def test_bulk_reconstruction_threshold(tiny_corpus):
    rng = np.random.default_rng(1)
    points = adi.bulk_reconstruction_sweep(
        tiny_corpus, rng, recon_n=40, q_over_n_values=[0.5, 1.0, 1.5], sigmas=[0.5]
    )
    by_ratio = {p.q_over_n: p for p in points}
    assert by_ratio[1.0].exact_determined_pct >= 99.0
    assert by_ratio[0.5].exact_determined_pct <= 1.0


# ---------------------------------------------------------------------------
# defenses.py
# ---------------------------------------------------------------------------


def test_d2_generalization_sweep_is_monotone(tiny_corpus):
    rows = defenses_mod.d2_generalization_sweep(tiny_corpus)
    for a, b in zip(rows, rows[1:]):
        assert b["reidentified_pct"] <= a["reidentified_pct"] + 1e-6
        assert b["groups_addressable_pct"] <= a["groups_addressable_pct"] + 1e-6


def test_d1_epoch_sweep_links_preserved_is_non_decreasing(tiny_corpus):
    rows = defenses_mod.d1_epoch_sweep(tiny_corpus, [1, 5, 20, 40])
    for a, b in zip(rows, rows[1:]):
        assert b["cross_session_links_preserved_pct"] >= a["cross_session_links_preserved_pct"] - 1e-6
    assert rows[-1]["cross_session_links_preserved_pct"] == pytest.approx(100.0)


def test_d3_min_aggregate_size_sweep_is_non_increasing(tiny_corpus):
    rows = defenses_mod.d3_min_aggregate_size_sweep(tiny_corpus, [1, 3, 5, 10])
    for a, b in zip(rows, rows[1:]):
        assert b["amounts_recovered"] <= a["amounts_recovered"]
        assert b["pct_workload_answered"] <= a["pct_workload_answered"] + 1e-6


# ---------------------------------------------------------------------------
# budget.py -- Claim 1 as a proof-checked property
# ---------------------------------------------------------------------------


def test_claim1_disjoint_support_holds():
    rng = np.random.default_rng(42)
    evidence = budget_mod.verify_claim1(rng)
    assert evidence.holds is True
    assert evidence.output_pairs_disjoint is True
    assert evidence.x_i != evidence.x_i_prime
    assert evidence.q_diff_on_D == pytest.approx(evidence.x_i)
    assert evidence.q_diff_on_D_prime == pytest.approx(evidence.x_i_prime)


def test_claim1_holds_for_many_independent_draws():
    # The proof does not depend on the particular x_i, x_i' chosen -- check
    # a handful of independent seeds all witness disjoint support.
    for seed in range(10):
        rng = np.random.default_rng(seed)
        evidence = budget_mod.verify_claim1(rng)
        assert evidence.holds is True


def test_beta_schema_is_between_zero_and_log2_universe(tiny_corpus):
    profiles = atl.disclosure_profiles(tiny_corpus)
    max_bits = np.log2(tiny_corpus.directory.size)
    for profile in profiles.values():
        bs = budget_mod.beta_schema(tiny_corpus, profile)
        assert -1e-6 <= bs["bits_per_row"] <= max_bits + 1e-6


def test_richer_profile_never_discloses_fewer_bits(tiny_corpus):
    profiles = atl.disclosure_profiles(tiny_corpus)
    bits = {
        name: budget_mod.beta_schema(tiny_corpus, profile)["bits_per_row"]
        for name, profile in profiles.items()
    }
    assert bits["P0_token_only"] <= bits["P3_rich"] + 1e-6
