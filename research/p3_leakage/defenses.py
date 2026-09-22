# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Defenses D1-D5 and their security/utility frontiers, reproducing paper
Section 8 ("Defences and what they cost") and Figure 8.

  D1 epoch-scoped tokens: sweep epoch length E. Within an epoch, a ledger
     account keeps one stable (opaque) token; across epochs its token is
     assumed unlinkable by A_host. We measure re-identification as the union,
     over epoch blocks, of what the S+A+T pipeline recovers using *only*
     that block's sessions -- and cross-session link preservation as the
     fraction of same-account session pairs that fall inside one epoch.

  D2 generalization: sweep ladder level g (reuses
     `attack_schema_uniqueness.generalization_ladder`).

  D3 minimum aggregate size: sweep k, report amounts the peeling adversary
     (Stage 2 of `attack_token_linkage`) recovers vs. the fraction of the
     workload whose sessions still meet the size floor.

  D4 query budget B: sweep B, report the averaging adversary's achievable
     relative error (via `attack_differential_inference.budget_relative_error`)
     against a simple model of what fraction of the legitimate workload a
     budget of B queries per principal can still serve.

  D5 cached/deterministic noise: sweep sigma, report the analyst's one-shot
     relative error on real workload aggregates against the deterministic-
     noise adversary's cached success rate.

See `corpus.py`'s docstring for the standing honesty note.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

import numpy as np

from corpus import Corpus, rebuild_workload
import attack_schema_uniqueness as asu
import attack_token_linkage as atl
import attack_differential_inference as adi


# ---------------------------------------------------------------------------
# D1: epoch-scoped tokens
# ---------------------------------------------------------------------------


def d1_epoch_sweep(corpus: Corpus, epoch_lengths: Sequence[int]) -> List[Dict[str, float]]:
    sessions = corpus.workload.sessions
    n_sessions = len(sessions)
    profile = atl.disclosure_profiles(corpus)["P2_typical"]
    ledger = corpus.ledger

    # Precompute, for every ledger account, which sessions (ids) it appears in.
    account_sessions: Dict[int, List[int]] = {}
    for s in sessions:
        for m in s.members:
            account_sessions.setdefault(m, []).append(s.id)

    out: List[Dict[str, float]] = []
    for E in epoch_lengths:
        E = max(1, min(E, n_sessions))
        n_epochs = (n_sessions + E - 1) // E

        ever_identified = np.zeros(ledger.size, dtype=bool)
        for epoch in range(n_epochs):
            block = sessions[epoch * E: (epoch + 1) * E]
            if not block:
                continue
            block_tokens = sorted({m for s in block for m in s.members})
            if not block_tokens:
                continue
            result = atl.run_pipeline(
                corpus, profile, True, True, True, sessions=block, only_tokens=block_tokens
            )
            for t in block_tokens:
                cand = result.candidates.get(t)
                asserted = None
                if cand is not None and len(cand) == 1:
                    asserted = int(cand[0])
                elif t in result.propagation.mapped_image and result.propagation.support.get(t, 0) >= 2:
                    asserted = result.propagation.mapped_image[t]
                if asserted is not None and asserted == int(ledger.directory_index[t]):
                    ever_identified[t] = True

        reid_pct = float(ever_identified.mean() * 100.0)

        total_pairs = 0
        within_epoch_pairs = 0
        for sids in account_sessions.values():
            if len(sids) < 2:
                continue
            epochs = [sid // E for sid in sids]
            n = len(sids)
            total_pairs += n * (n - 1) // 2
            for i in range(n):
                for j in range(i + 1, n):
                    if epochs[i] == epochs[j]:
                        within_epoch_pairs += 1

        links_preserved_pct = (
            100.0 * within_epoch_pairs / total_pairs if total_pairs else 100.0
        )
        out.append(
            {
                "epoch_length": E,
                "reidentified_pct": reid_pct,
                "cross_session_links_preserved_pct": links_preserved_pct,
            }
        )
    return out


# ---------------------------------------------------------------------------
# D2: generalization
# ---------------------------------------------------------------------------


def d2_generalization_sweep(corpus: Corpus) -> List[Dict[str, float]]:
    rungs = asu.generalization_ladder(corpus)
    max_groups = rungs[0].groups_addressable if rungs else 1
    out = []
    for r in rungs:
        out.append(
            {
                "g": r.g,
                "reidentified_pct": r.unique_in_directory_pct,
                "groups_addressable_pct": 100.0 * r.groups_addressable / max_groups if max_groups else 0.0,
            }
        )
    return out


# ---------------------------------------------------------------------------
# D3: minimum aggregate size
# ---------------------------------------------------------------------------


def d3_min_aggregate_size_sweep(corpus: Corpus, k_values: Sequence[int]) -> List[Dict[str, float]]:
    sessions = corpus.workload.sessions
    n_sessions = len(sessions)
    out = []
    for k in k_values:
        known = atl.stage2_peel_amounts(corpus, active=True, min_aggregate_size=k)
        n_answered = sum(1 for s in sessions if len(s.members) >= k)
        out.append(
            {
                "k": k,
                "amounts_recovered": len(known),
                "pct_workload_answered": 100.0 * n_answered / n_sessions if n_sessions else 0.0,
            }
        )
    return out


# ---------------------------------------------------------------------------
# D4: query budget
# ---------------------------------------------------------------------------


def d4_query_budget_sweep(
    corpus: Corpus, rng: np.random.Generator, budgets: Sequence[int], sigma_mult: float = 0.5
) -> List[Dict[str, float]]:
    total_workload = len(corpus.workload.sessions)
    rows = adi.budget_relative_error(
        corpus, rng, sigma_mult=sigma_mult, budgets=budgets, n_targets=min(80, corpus.ledger.size)
    )
    out = []
    for row in rows:
        B = row["budget"]
        out.append(
            {
                "budget": B,
                "adversary_median_relative_error_pct": row["median_relative_error_pct"],
                # Simple model: a per-principal budget of B queries can serve
                # at most B of the legitimate workload's queries; the rest go
                # unanswered. Documented as an explicit simplification (the
                # real bound depends on how many principals share a budget).
                "pct_legitimate_workload_served": 100.0 * min(1.0, B / total_workload) if total_workload else 0.0,
            }
        )
    return out


# ---------------------------------------------------------------------------
# D5: cached / deterministic noise
# ---------------------------------------------------------------------------


def d5_cached_noise_sweep(
    corpus: Corpus, rng: np.random.Generator, sigmas: Sequence[float]
) -> List[Dict[str, float]]:
    sessions = [s for s in corpus.workload.sessions if len(s.members) >= 1]
    aggregates = np.array([s.aggregate for s in sessions])
    small_set_mask = np.array([len(s.members) <= 5 for s in sessions])

    adversary = adi.noise_averaging_vs_deterministic(
        corpus, rng, sigmas=sigmas, n_targets=min(80, corpus.ledger.size)
    )
    adversary_by_sigma = {row["sigma"]: row["one_shot_success_rate_pct"] for row in adversary["deterministic_cache"]}

    out = []
    for sigma_mult in sigmas:
        sigma_abs = sigma_mult * float(corpus.ledger.amount.mean())
        noisy = aggregates + rng.normal(0, sigma_abs, size=len(aggregates))
        rel_err = np.abs(noisy - aggregates) / np.maximum(np.abs(aggregates), 1e-9)
        overall_median = float(np.median(rel_err) * 100.0)
        small_median = (
            float(np.median(rel_err[small_set_mask]) * 100.0) if small_set_mask.any() else float("nan")
        )
        out.append(
            {
                "sigma": sigma_mult,
                "analyst_median_relative_error_pct": overall_median,
                "analyst_median_relative_error_small_sets_pct": small_median,
                "adversary_cached_success_rate_pct": adversary_by_sigma.get(sigma_mult, float("nan")),
            }
        )
    return out


def run(corpus: Corpus, rng_seed: int = 20260922) -> Dict[str, object]:
    rng = np.random.default_rng(rng_seed)
    n_sessions = len(corpus.workload.sessions)

    epoch_lengths = sorted(set(
        min(n_sessions, x) for x in (1, 2, 5, 10, max(10, n_sessions // 8), n_sessions)
    ))
    d1 = d1_epoch_sweep(corpus, epoch_lengths)
    d2 = d2_generalization_sweep(corpus)
    d3 = d3_min_aggregate_size_sweep(corpus, [1, 3, 5, 10, 25, 50])
    d4 = d4_query_budget_sweep(corpus, rng, budgets=[2, 10, 50, 200, 1000])
    d5 = d5_cached_noise_sweep(corpus, rng, sigmas=[0.01, 0.1, 0.5, 1.0, 2.0])

    return {"D1_epoch_scoped_tokens": d1, "D2_generalization": d2, "D3_min_aggregate_size": d3,
            "D4_query_budget": d4, "D5_cached_noise": d5}
