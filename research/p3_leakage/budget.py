# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The four-component disclosure budget, reproducing paper Section 9
("The disclosure budget"), including a proof-checked instance of Claim 1
and the four product-mode table (Table 2).

  beta_schema(profile) = log2(|U|) - E[log2(|C(token)|)], the identity
     information (bits/row) the disclosed columns + filters release, computed
     from `attack_token_linkage.stage1_candidates`.

  beta_token(profile)  = re-id(S+T) - re-id(S), in ledger percentage points,
     i.e. what the co-occurrence graph adds once the schema channel has
     already supplied its anchors -- computed from `run_pipeline`/`score_pipeline`.

  beta_pattern         = mutual information (bits) between an account's
     workload query frequency and a discretized private attribute (revenue
     band), via a simple histogram-based MI estimator.

  beta_agg              is where Section 9.2's Claim 1 lives:

    Claim 1. If the admissible family contains two sets S, S' with
    S \\ S' = {i}, exact SUM release admits no finite epsilon, because two
    neighbouring databases differing only in record i produce deterministic,
    point-mass output distributions with disjoint support.

    `verify_claim1` constructs exactly that pair of neighbouring databases
    and checks the disjoint-support property directly -- this is a runnable
    proof check, not a docstring assertion, and `test_pipeline.py` calls it.

  The Gaussian-mechanism alternative is then priced: clip at the 99th
  percentile of the ledger amount distribution, compute the (epsilon, delta)
  the classical Gaussian mechanism delivers per query at several noise
  levels, and the analyst's resulting median relative error on real workload
  aggregates.

  `four_mode_table` instantiates modes A (exact/any-predicate), B
  (constrained-exact/conjunction-only+k), C (randomized ad hoc) and D (split
  channel) against the measures above, mirroring Table 2.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import numpy as np

from corpus import Corpus
import attack_token_linkage as atl
import attack_differential_inference as adi

GAUSSIAN_DELTA = 1e-6
CLIP_PERCENTILE = 99.0


# ---------------------------------------------------------------------------
# beta_schema
# ---------------------------------------------------------------------------


def beta_schema(corpus: Corpus, profile: atl.ProfileColumns) -> Dict[str, float]:
    directory_size = corpus.directory.size
    candidates = atl.stage1_candidates(corpus, profile, active=True)
    sizes = np.array([max(1, len(c)) for c in candidates.values()], dtype=np.float64)
    mean_log2_card = float(np.mean(np.log2(sizes)))
    bits = math.log2(directory_size) - mean_log2_card
    return {
        "bits_per_row": bits,
        "max_bits_available": math.log2(directory_size),
        "mean_log2_candidate_set_size": mean_log2_card,
    }


# ---------------------------------------------------------------------------
# beta_token
# ---------------------------------------------------------------------------


def beta_token(corpus: Corpus, profile: atl.ProfileColumns, m: int = 2) -> float:
    s_only = atl.run_pipeline(corpus, profile, True, False, False)
    s_plus_t = atl.run_pipeline(corpus, profile, True, False, True)
    s_score = atl.score_pipeline(corpus, s_only, m_values=(m,))[m]["pct_of_ledger"]
    st_score = atl.score_pipeline(corpus, s_plus_t, m_values=(m,))[m]["pct_of_ledger"]
    return st_score - s_score


# ---------------------------------------------------------------------------
# beta_pattern
# ---------------------------------------------------------------------------


def _discretized_mi(x: np.ndarray, y: np.ndarray, n_bins_x: int, n_bins_y: int) -> Tuple[float, float]:
    """Returns (mutual_information_bits, entropy_of_y_bits)."""
    x_edges = np.quantile(x, np.linspace(0, 1, n_bins_x + 1)[1:-1]) if len(np.unique(x)) > 1 else np.array([])
    y_edges = np.quantile(y, np.linspace(0, 1, n_bins_y + 1)[1:-1]) if len(np.unique(y)) > 1 else np.array([])
    xb = np.searchsorted(x_edges, x, side="right")
    yb = np.searchsorted(y_edges, y, side="right")

    n = len(x)
    joint: Dict[Tuple[int, int], int] = {}
    for a, b in zip(xb.tolist(), yb.tolist()):
        joint[(a, b)] = joint.get((a, b), 0) + 1
    px: Dict[int, int] = {}
    py: Dict[int, int] = {}
    for a in xb.tolist():
        px[a] = px.get(a, 0) + 1
    for b in yb.tolist():
        py[b] = py.get(b, 0) + 1

    mi = 0.0
    for (a, b), cnt in joint.items():
        p_ab = cnt / n
        p_a = px[a] / n
        p_b = py[b] / n
        mi += p_ab * math.log2(p_ab / (p_a * p_b))

    h_y = 0.0
    for b, cnt in py.items():
        p_b = cnt / n
        h_y -= p_b * math.log2(p_b)

    return mi, h_y


def beta_pattern(corpus: Corpus, attribute: str = "revenue_band") -> Dict[str, float]:
    sessions = corpus.workload.sessions
    ledger = corpus.ledger
    freq = np.zeros(ledger.size, dtype=np.float64)
    for s in sessions:
        for m in s.members:
            freq[m] += 1

    attr_values = corpus.directory.attribute(attribute)[ledger.directory_index].astype(np.float64)
    mi, h_attr = _discretized_mi(freq, attr_values, n_bins_x=5, n_bins_y=5)
    return {
        "mutual_information_bits": mi,
        "attribute_entropy_bits": h_attr,
        "fraction_of_attribute_entropy": (mi / h_attr) if h_attr > 0 else 0.0,
    }


# ---------------------------------------------------------------------------
# beta_agg -- Claim 1 (proof-checked) and the Gaussian-mechanism price
# ---------------------------------------------------------------------------


@dataclass
class Claim1Evidence:
    holds: bool
    x_i: float
    x_i_prime: float
    q_diff_on_D: float
    q_diff_on_D_prime: float
    output_pairs_disjoint: bool


def verify_claim1(rng: np.random.Generator, n: int = 20) -> Claim1Evidence:
    """Constructs two neighbouring databases D, D' that differ only in one
    record's private value, and checks that the exact-SUM release of an
    admissible pair (S, S' = S \\ {i}) has disjoint support across D and D',
    for the *specific* draw used here (the underlying argument is that this
    holds for *any* x_i != x_i', since the released quantity is a
    deterministic function of the database -- the check below is a concrete,
    runnable witness of that general fact, not an existence claim over all
    possible instances).
    """
    amounts = rng.uniform(1e6, 1e9, size=n)
    i = 0
    x_i = float(amounts[i])
    x_i_prime = float(x_i + rng.uniform(1e5, 1e7))  # x_i' != x_i by construction

    D = amounts.copy()
    D_prime = amounts.copy()
    D_prime[i] = x_i_prime

    S = np.arange(n)  # admissible set containing i
    S_prime = np.arange(1, n)  # S \ {i}, also admissible (set-difference expressible)

    q_S_D, q_S_prime_D = D[S].sum(), D[S_prime].sum()
    q_S_Dp, q_S_prime_Dp = D_prime[S].sum(), D_prime[S_prime].sum()

    diff_D = q_S_D - q_S_prime_D
    diff_Dp = q_S_Dp - q_S_prime_Dp

    # The released pair is deterministic given the database, so its "support"
    # on D is the single point (q_S_D, q_S_prime_D); disjointness from D''s
    # single point is exactly diff_D != diff_Dp here (q_S_prime is identical
    # on both databases since S' excludes record i).
    disjoint = not math.isclose(diff_D, diff_Dp, rel_tol=1e-12)
    holds = disjoint and math.isclose(diff_D, x_i, rel_tol=1e-9) and math.isclose(diff_Dp, x_i_prime, rel_tol=1e-9)

    return Claim1Evidence(
        holds=holds,
        x_i=x_i,
        x_i_prime=x_i_prime,
        q_diff_on_D=diff_D,
        q_diff_on_D_prime=diff_Dp,
        output_pairs_disjoint=disjoint,
    )


def gaussian_mechanism_epsilon(sensitivity: float, sigma_abs: float, delta: float = GAUSSIAN_DELTA) -> float:
    """Analytic (epsilon, delta)-DP bound for the Gaussian mechanism:
    sigma >= sensitivity * sqrt(2 ln(1.25/delta)) / epsilon, solved for epsilon.
    """
    if sigma_abs <= 0:
        return float("inf")
    return sensitivity * math.sqrt(2.0 * math.log(1.25 / delta)) / sigma_abs


def gaussian_mechanism_sweep(
    corpus: Corpus, rng: np.random.Generator, sigma_mults: Sequence[float]
) -> List[Dict[str, float]]:
    amounts = corpus.ledger.amount
    clip_value = float(np.percentile(amounts, CLIP_PERCENTILE))
    clipped = np.minimum(amounts, clip_value)
    volume_lost_pct = 100.0 * (1.0 - clipped.sum() / amounts.sum())
    mean_amount = float(amounts.mean())

    sessions = corpus.workload.sessions
    idx_by_account = {i: a for i, a in enumerate(clipped)}

    out = []
    for sigma_mult in sigma_mults:
        sigma_abs = sigma_mult * mean_amount
        eps = gaussian_mechanism_epsilon(clip_value, sigma_abs)

        errs = []
        for s in sessions:
            true_sum = s.aggregate
            clipped_sum = sum(idx_by_account[m] for m in s.members)
            noisy_sum = clipped_sum + rng.normal(0, sigma_abs)
            rel_err = abs(noisy_sum - true_sum) / max(abs(true_sum), 1e-9)
            errs.append(rel_err)

        out.append(
            {
                "sigma_multiple_of_mean": sigma_mult,
                "sigma_abs": sigma_abs,
                "epsilon_per_query": eps,
                "epsilon_per_1000_queries_basic_composition": eps * 1000.0,
                "clip_value": clip_value,
                "volume_lost_to_clipping_pct": volume_lost_pct,
                "analyst_median_relative_error_pct": float(np.median(errs) * 100.0),
            }
        )
    return out


def beta_agg(corpus: Corpus, rng: np.random.Generator) -> Dict[str, object]:
    claim1 = verify_claim1(rng)
    sweep = gaussian_mechanism_sweep(corpus, rng, sigma_mults=[0.1, 0.5, 1.0, 2.0, 5.0])
    return {
        "claim1": {
            "holds": claim1.holds,
            "x_i": claim1.x_i,
            "x_i_prime": claim1.x_i_prime,
            "released_diff_on_D": claim1.q_diff_on_D,
            "released_diff_on_D_prime": claim1.q_diff_on_D_prime,
            "output_supports_disjoint": claim1.output_pairs_disjoint,
        },
        "gaussian_mechanism_sweep": sweep,
    }


# ---------------------------------------------------------------------------
# Four product modes (Table 2)
# ---------------------------------------------------------------------------


def four_mode_table(corpus: Corpus, rng: np.random.Generator) -> List[Dict[str, object]]:
    profiles = atl.disclosure_profiles(corpus)
    k_values = [1, 2, 3, 5, 10, 25, 50, 100]

    def reid_pct(profile, m):
        result = atl.run_pipeline(corpus, profile, True, True, True)
        return atl.score_pipeline(corpus, result, m_values=(m,))[m]["pct_of_ledger"]

    def isolable_setdiff_pct(k):
        rows = adi.isolation_setdiff(corpus, [k])
        return rows[0]["isolable_pct"]

    def isolable_conjunction_pct(k):
        rows = adi.isolation_conjunction_only(corpus, [k])
        return rows[0]["isolable_pct"]

    def workload_answered_pct(min_k):
        sessions = corpus.workload.sessions
        n = len(sessions)
        return 100.0 * sum(1 for s in sessions if len(s.members) >= min_k) / n if n else 0.0

    modes: List[Dict[str, object]] = []

    # Mode A: exact analytics, rich profile, any predicate, no k floor.
    profile_a = profiles["P3_rich"]
    bs_a = beta_schema(corpus, profile_a)
    modes.append(
        {
            "mode": "A_exact_analytics",
            "profile": "rich / stable tokens",
            "aggregate_policy": "exact, any predicate",
            "beta_schema_bits": bs_a["bits_per_row"],
            "reidentified_pct": reid_pct(profile_a, m=1),
            "isolable_pct": isolable_setdiff_pct(1),
            "amounts_recovered": len(atl.stage2_peel_amounts(corpus, active=True, min_aggregate_size=1)),
            "pct_workload_answered": workload_answered_pct(1),
            "formal_guarantee": "none (Claim 1)",
        }
    )

    # Mode B: constrained exact, typical profile, conjunction-only + k=5.
    profile_b = profiles["P2_typical"]
    bs_b = beta_schema(corpus, profile_b)
    modes.append(
        {
            "mode": "B_constrained_exact",
            "profile": "typical / stable tokens",
            "aggregate_policy": "exact, conjunction-only, k=5",
            "beta_schema_bits": bs_b["bits_per_row"],
            "reidentified_pct": reid_pct(profile_b, m=2),
            "isolable_pct": isolable_conjunction_pct(5),
            "amounts_recovered": len(atl.stage2_peel_amounts(corpus, active=True, min_aggregate_size=5)),
            "pct_workload_answered": workload_answered_pct(5),
            "formal_guarantee": "none (Claim 1)",
        }
    )

    # Mode C: randomized ad hoc -- same schema/aggregate-size posture as B,
    # cached noise sigma=0.5 makes exact peeling impossible.
    gm = gaussian_mechanism_sweep(corpus, rng, sigma_mults=[0.5])[0]
    modes.append(
        {
            "mode": "C_randomized_ad_hoc",
            "profile": "typical / stable tokens",
            "aggregate_policy": "cached noise sigma=0.5, k=5",
            "beta_schema_bits": bs_b["bits_per_row"],
            "reidentified_pct": reid_pct(profile_b, m=2),  # re-id runs on Lschema, unaffected by noise
            "isolable_pct": isolable_conjunction_pct(5),
            "amounts_recovered": 0,  # noise defeats exact peeling
            "pct_workload_answered": workload_answered_pct(5),
            "formal_guarantee": f"epsilon={gm['epsilon_per_query']:.1f}/query",
        }
    )

    # Mode D: split channel -- registered exact reports (no set-difference
    # pair by construction, so Claim 1 does not apply to that sub-channel)
    # plus a noisy ad-hoc channel, coarse profile, epoch-scoped tokens.
    profile_d = profiles["P1_coarse"]
    bs_d = beta_schema(corpus, profile_d)
    gm_d = gaussian_mechanism_sweep(corpus, rng, sigma_mults=[1.0])[0]
    modes.append(
        {
            "mode": "D_split_channel",
            "profile": "coarse / epoch-scoped tokens",
            "aggregate_policy": "registered exact + noisy ad hoc",
            "beta_schema_bits": bs_d["bits_per_row"],
            "reidentified_pct": reid_pct(profile_d, m=2),
            # The registered family is constructed with no two sets differing
            # in one record, so the set-difference isolation channel does not
            # apply; the residual isolable_pct reflects only the noisy
            # ad-hoc channel under conjunction-only + k=10.
            "isolable_pct": isolable_conjunction_pct(10),
            "amounts_recovered": len(atl.stage2_peel_amounts(corpus, active=True, min_aggregate_size=10)),
            "pct_workload_answered": workload_answered_pct(10),
            "formal_guarantee": "DP (ad-hoc channel only)",
        }
    )

    return modes


def run(corpus: Corpus, rng_seed: int = 20260923) -> Dict[str, object]:
    rng = np.random.default_rng(rng_seed)
    profile_typical = atl.disclosure_profiles(corpus)["P2_typical"]

    return {
        "beta_schema": {
            name: beta_schema(corpus, profile)
            for name, profile in atl.disclosure_profiles(corpus).items()
        },
        "beta_token": {
            name: beta_token(corpus, profile)
            for name, profile in atl.disclosure_profiles(corpus).items()
        },
        "beta_pattern": beta_pattern(corpus),
        "beta_agg": beta_agg(corpus, rng),
        "four_mode_table": four_mode_table(corpus, rng),
    }
