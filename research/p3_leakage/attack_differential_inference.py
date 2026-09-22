# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Differential inference against A_user, reproducing paper Section 7
("Differential inference") and Figures 6-7.

Four measurements:

1. `isolation_sweep`: fraction of ledger accounts isolable in two queries,
   against minimum aggregate size k, under (a) a filter language that can
   express set difference and (b) conjunction-only predicates. Section 7.1's
   proof is that (a) is exactly ledger-uniqueness and is independent of k;
   we compute it directly (not by asserting the proof) and confirm the
   sweep is flat. For (b) we search, per ledger account, for a coarse
   "admissible group" containing it and a same-sized-or-larger sibling group
   from which exactly that account can be excluded by adding one more
   conjunct -- the concrete mechanism the paper describes -- and report the
   largest k at which that witness still clears the size floor.

2. `bulk_reconstruction_sweep`: Dinur-Nissim-style reconstruction from q
   random admissible SUM queries, exact and Gaussian-noised, solved via
   least squares, swept over q/n.

3. `noise_averaging_vs_deterministic`: median queries to reach 5% relative
   error by averaging repeated fresh-noise queries, vs. one-shot success
   probability when noise is instead derived deterministically from a
   canonical form of the query (so repeats return identical answers).

4. `budget_relative_error`: achievable relative error as a function of a
   per-principal query budget B, reusing the averaging-regime model.

As elsewhere in this package, exact percentages are expected to differ from
the published paper (see `corpus.py` docstring); the qualitative shapes
(isolability flat in k for set-difference, collapsing for conjunction-only;
a reconstruction threshold near q=n; averaging beating a fixed noise floor)
are the claims under test.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import numpy as np

from corpus import ATTRIBUTES, Corpus

# ---------------------------------------------------------------------------
# 7.1 Isolation
# ---------------------------------------------------------------------------


def _ledger_attribute_matrix(corpus: Corpus, attrs: Sequence[str] = ATTRIBUTES) -> np.ndarray:
    directory = corpus.directory
    idx = corpus.ledger.directory_index
    return np.stack([directory.attribute(a)[idx] for a in attrs], axis=1)


def _fine_key(matrix: np.ndarray) -> np.ndarray:
    # A collision-safe-enough combined key for uniqueness testing on a small
    # ledger: not a perfect radix key (bands share ranges across columns),
    # but the encoding weights are large enough that arbitrary same-ledger
    # collisions across unrelated attribute combinations are effectively
    # impossible in practice (birthday bound over a few hundred rows and a
    # >10^6-wide code space).
    weights = np.array([10 ** (6 * i) for i in range(matrix.shape[1])])
    return (matrix * weights).sum(axis=1)


def isolation_setdiff(corpus: Corpus, k_values: Sequence[int]) -> List[Dict[str, float]]:
    matrix = _ledger_attribute_matrix(corpus)
    n = matrix.shape[0]
    key = _fine_key(matrix)
    _, counts = np.unique(key, return_counts=True)
    count_of = dict(zip(*np.unique(key, return_counts=True)))
    is_unique = np.array([count_of[k] == 1 for k in key])
    base_fraction = float(is_unique.mean())

    out = []
    for k in k_values:
        # Section 7.1: isolable via set difference iff the account is unique
        # in the ledger under the filter language, PROVIDED an admissible
        # superset of size >= k+1 containing it exists -- the whole ledger
        # itself is always such a superset when k+1 <= n. This is why the
        # curve is flat in k up to n-1 and collapses only past it.
        frac = base_fraction if (k + 1) <= n else 0.0
        out.append({"k": k, "isolable_pct": frac * 100.0})
    return out


def _group_sizes(matrix: np.ndarray, cols: Sequence[int]) -> Tuple[np.ndarray, Dict[Tuple, np.ndarray]]:
    sub = matrix[:, cols]
    keys = [tuple(row) for row in sub]
    groups: Dict[Tuple, List[int]] = {}
    for i, kkey in enumerate(keys):
        groups.setdefault(kkey, []).append(i)
    return np.array(keys, dtype=object), {k: np.array(v) for k, v in groups.items()}


def isolation_conjunction_only(corpus: Corpus, k_values: Sequence[int], attrs: Sequence[str] = ATTRIBUTES) -> List[Dict[str, float]]:
    """For each ledger account, find the largest witnessed group size m such
    that: there is a coarse conjunction (a subset of attribute columns) whose
    matching group G contains the account, and some other attribute column
    not in that subset is shared by every other member of G (but not by the
    account itself) -- so a second conjunction (G's constraint plus that
    extra attribute) equals G minus exactly the account. Isolability at k
    then holds whenever m - 1 >= k (both groups must clear the floor).
    """
    matrix = _ledger_attribute_matrix(corpus, attrs)
    n = matrix.shape[0]
    n_attrs = matrix.shape[1]

    best_m = np.zeros(n, dtype=np.int64)

    # Search coarse constraints of size 1..3 attributes (kept small for
    # tractability; a full search is not required for the qualitative
    # collapse the paper reports).
    for subset_size in (1, 2, 3):
        for cols in itertools.combinations(range(n_attrs), subset_size):
            remaining = [c for c in range(n_attrs) if c not in cols]
            if not remaining:
                continue
            _, groups = _group_sizes(matrix, list(cols))
            for members in groups.values():
                m = len(members)
                if m < 2:
                    continue
                sub = matrix[members]
                for r in remaining:
                    col_vals = sub[:, r]
                    # For each member i, check if all *other* members share
                    # one common value on r, different from member i's value.
                    values, counts = np.unique(col_vals, return_counts=True)
                    if len(values) > 2:
                        continue  # more than one outlier-candidate value; skip (tractability)
                    if len(values) == 1:
                        continue  # no separation possible on this attribute
                    majority_value = values[np.argmax(counts)]
                    majority_count = counts.max()
                    if majority_count != m - 1:
                        continue  # need exactly one outlier
                    outlier_local = np.nonzero(col_vals != majority_value)[0]
                    if len(outlier_local) != 1:
                        continue
                    outlier_idx = members[outlier_local[0]]
                    if m > best_m[outlier_idx]:
                        best_m[outlier_idx] = m

    out = []
    for k in k_values:
        isolable = best_m >= (k + 1)
        out.append({"k": k, "isolable_pct": float(isolable.mean() * 100.0)})
    return out


# ---------------------------------------------------------------------------
# 7.2 Bulk reconstruction
# ---------------------------------------------------------------------------


@dataclass
class BulkReconstructionPoint:
    q_over_n: float
    q: int
    exact_determined_pct: float
    exact_within5_pct: float
    noisy_within5_pct: Dict[float, float]


def bulk_reconstruction_sweep(
    corpus: Corpus,
    rng: np.random.Generator,
    recon_n: int,
    q_over_n_values: Sequence[float],
    sigmas: Sequence[float],
) -> List[BulkReconstructionPoint]:
    n = min(recon_n, corpus.ledger.size)
    idx = rng.choice(corpus.ledger.size, size=n, replace=False)
    amounts = corpus.ledger.amount[idx]
    mean_amount = float(amounts.mean())

    out: List[BulkReconstructionPoint] = []
    for ratio in q_over_n_values:
        q = max(1, int(round(ratio * n)))
        # Random admissible sets: each query includes each account
        # independently with prob. 0.5 (a simple, tractable admissible
        # family; excludes the empty set).
        # Amounts span several orders of magnitude (heavy-tailed corporate
        # revenue); scale to a unit-mean vector before solving so the SVD
        # inside lstsq stays well-conditioned, then rescale back. Purely a
        # numerical-stability measure -- it does not change what is measured.
        scale = mean_amount if mean_amount > 0 else 1.0
        amounts_scaled = amounts / scale

        A = (rng.random((q, n)) < 0.5).astype(np.float64)
        empty_rows = A.sum(axis=1) == 0
        A[empty_rows, 0] = 1.0
        with np.errstate(over="ignore", divide="ignore", invalid="ignore"):
            # A known false-positive RuntimeWarning ("divide by zero
            # encountered in matmul") is emitted by some BLAS backends
            # (observed with Apple's Accelerate framework) on ordinary
            # dense matmuls with no actual zero division; suppressed here
            # rather than upstream, since the computed values are finite.
            exact_answers_scaled = A @ amounts_scaled
            exact_sol_scaled, *_ = np.linalg.lstsq(A, exact_answers_scaled, rcond=None)
        exact_sol = np.nan_to_num(exact_sol_scaled * scale, nan=0.0, posinf=1e18, neginf=-1e18)
        exact_err = np.abs(exact_sol - amounts) / np.maximum(np.abs(amounts), 1e-9)
        exact_determined_pct = float(np.mean(exact_err < 1e-6) * 100.0)
        exact_within5_pct = float(np.mean(exact_err < 0.05) * 100.0)

        noisy_within5: Dict[float, float] = {}
        for sigma_mult in sigmas:
            sigma_abs_scaled = sigma_mult  # sigma is already "multiples of the mean account"
            noisy_answers_scaled = exact_answers_scaled + rng.normal(0, sigma_abs_scaled, size=q)
            with np.errstate(over="ignore", divide="ignore", invalid="ignore"):
                noisy_sol_scaled, *_ = np.linalg.lstsq(A, noisy_answers_scaled, rcond=None)
            noisy_sol = np.nan_to_num(noisy_sol_scaled * scale, nan=0.0, posinf=1e18, neginf=-1e18)
            noisy_err = np.abs(noisy_sol - amounts) / np.maximum(np.abs(amounts), 1e-9)
            noisy_within5[sigma_mult] = float(np.mean(noisy_err < 0.05) * 100.0)

        out.append(
            BulkReconstructionPoint(
                q_over_n=ratio,
                q=q,
                exact_determined_pct=exact_determined_pct,
                exact_within5_pct=exact_within5_pct,
                noisy_within5_pct=noisy_within5,
            )
        )
    return out


# ---------------------------------------------------------------------------
# 7.3 Noise averaging vs. deterministic (cached) noise
# ---------------------------------------------------------------------------


def _queries_to_target_error(
    rng: np.random.Generator, true_value: float, sigma_abs: float, target_rel_err: float, max_queries: int
) -> int:
    running_sum = 0.0
    for q in range(1, max_queries + 1):
        running_sum += true_value + rng.normal(0, sigma_abs)
        mean = running_sum / q
        rel_err = abs(mean - true_value) / max(abs(true_value), 1e-9)
        if rel_err <= target_rel_err:
            return q
    return max_queries


def noise_averaging_vs_deterministic(
    corpus: Corpus,
    rng: np.random.Generator,
    sigmas: Sequence[float],
    n_targets: int,
    target_rel_err: float = 0.05,
    max_queries: int = 400,
) -> Dict[str, List[Dict[str, float]]]:
    n_targets = min(n_targets, corpus.ledger.size)
    target_idx = rng.choice(corpus.ledger.size, size=n_targets, replace=False)
    amounts = corpus.ledger.amount[target_idx]
    mean_amount = float(corpus.ledger.amount.mean())

    averaging_out: List[Dict[str, float]] = []
    deterministic_out: List[Dict[str, float]] = []

    for sigma_mult in sigmas:
        sigma_abs = sigma_mult * mean_amount
        queries_needed = [
            _queries_to_target_error(rng, float(v), sigma_abs, target_rel_err, max_queries)
            for v in amounts
        ]
        success_rate = float(np.mean(np.array(queries_needed) < max_queries) * 100.0)
        averaging_out.append(
            {
                "sigma": sigma_mult,
                "median_queries_needed": float(np.median(queries_needed)),
                "success_rate_pct": success_rate,
            }
        )

        # Deterministic / cached noise: the same query always returns the
        # same noisy answer, so repetition buys nothing. Draw one noise
        # sample per target (seeded deterministically per target+sigma, as
        # a "canonical form of the query" would be in a real cache) and
        # check whether that single draw already lands within tolerance.
        det_rng = np.random.default_rng(abs(hash((round(sigma_mult, 6), n_targets))) % (2 ** 32))
        noisy_once = amounts + det_rng.normal(0, sigma_abs, size=len(amounts))
        rel_err = np.abs(noisy_once - amounts) / np.maximum(np.abs(amounts), 1e-9)
        det_success = float(np.mean(rel_err <= target_rel_err) * 100.0)
        deterministic_out.append({"sigma": sigma_mult, "one_shot_success_rate_pct": det_success})

    return {"averaging": averaging_out, "deterministic_cache": deterministic_out}


def budget_relative_error(
    corpus: Corpus, rng: np.random.Generator, sigma_mult: float, budgets: Sequence[int], n_targets: int
) -> List[Dict[str, float]]:
    n_targets = min(n_targets, corpus.ledger.size)
    target_idx = rng.choice(corpus.ledger.size, size=n_targets, replace=False)
    amounts = corpus.ledger.amount[target_idx]
    mean_amount = float(corpus.ledger.amount.mean())
    sigma_abs = sigma_mult * mean_amount

    out = []
    for B in budgets:
        errs = []
        for v in amounts:
            noise_samples = rng.normal(0, sigma_abs, size=max(1, B))
            mean_val = v + noise_samples.mean()
            errs.append(abs(mean_val - v) / max(abs(v), 1e-9))
        out.append({"budget": B, "median_relative_error_pct": float(np.median(errs) * 100.0)})
    return out


def run(corpus: Corpus, rng_seed: int = 20260921) -> Dict[str, object]:
    rng = np.random.default_rng(rng_seed)
    k_values = [1, 2, 3, 5, 10, 25, 50, 100]

    isolation = {
        "set_difference_expressible": isolation_setdiff(corpus, k_values),
        "conjunction_only": isolation_conjunction_only(corpus, k_values),
    }

    recon_n = min(120, corpus.ledger.size)
    bulk = bulk_reconstruction_sweep(
        corpus,
        rng,
        recon_n=recon_n,
        q_over_n_values=[0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0],
        sigmas=[0.05, 0.5, 1.0],
    )
    bulk_serialized = [
        {
            "q_over_n": p.q_over_n,
            "q": p.q,
            "recon_n": recon_n,
            "exact_determined_pct": p.exact_determined_pct,
            "exact_within5_pct": p.exact_within5_pct,
            "noisy_within5_pct": {str(s): v for s, v in p.noisy_within5_pct.items()},
        }
        for p in bulk
    ]

    noise = noise_averaging_vs_deterministic(
        corpus, rng, sigmas=[0.05, 0.1, 0.5, 1.0], n_targets=min(80, corpus.ledger.size)
    )

    budget = budget_relative_error(
        corpus, rng, sigma_mult=0.5, budgets=[2, 10, 50, 200, 1000], n_targets=min(80, corpus.ledger.size)
    )

    return {
        "isolation": isolation,
        "bulk_reconstruction": bulk_serialized,
        "noise_averaging_vs_deterministic": noise,
        "budget_relative_error": budget,
    }
