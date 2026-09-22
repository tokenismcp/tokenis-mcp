# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Containment bounds (paper §6) as checkable functions, not just narrative.

Each bound is implemented as a pure function of its public parameters (so it
can be computed without running anything), paired with a way to compute or
measure the corresponding empirical quantity on THIS reproduction's ledger
and attacks, so ``verify_claims.py`` can assert the inequality actually
holds rather than merely printing two numbers next to each other.

Honesty note: we verify that these bounds hold as inequalities against
measurements taken on this reproduction's synthetic ledger and attack suite.
We do not claim the measured numbers equal the paper's own (e.g. "1,287 bits
permitted against 643 extracted"); those depend on the paper's unpublished
exact generator. See the top-level README.

Value-domain-bits convention (Remark 24): the paper treats a per-record
revenue value as if uniform on a domain of size |X| = 2**20.1 for the purpose
of a Corollary-18/23-style bit count, and notes this OVERSTATES the true
entropy of a log-normal column -- it is a convention applied consistently on
both sides of every comparison, generous to the adversary, not a claim about
the true distribution. :func:`value_domain_bits` reproduces that convention
on this ledger's own revenue range rather than hard-coding the paper's 20.1.
"""

from __future__ import annotations

import math
from typing import Dict, Sequence

import numpy as np

from .admission import GF_PRIME, rref_rank
from .ledger import Ledger

# ---------------------------------------------------------------------------
# Theorem 16: I(x; V | pub) <= B * log2(M).
# ---------------------------------------------------------------------------


def theorem16_bound(B: int, M: int) -> float:
    """The basic containment bound: B admitted queries, alphabet size <= M."""
    if B <= 0 or M <= 1:
        return 0.0
    return B * math.log2(M)


def value_domain_bits(ledger: Ledger, column: str = "revenue") -> float:
    """log2(|X|) under the paper's Remark 24 convention (generous to the
    adversary; see module docstring). Computed from this ledger's own
    observed value range rather than the paper's literal 20.1.
    """
    values = ledger.columns[column]
    span = float(values.max() - values.min())
    if span <= 0:
        return 1.0
    return math.log2(span + 1.0)


# ---------------------------------------------------------------------------
# Corollary 18: records recoverable under uniform x_i.
# ---------------------------------------------------------------------------


def corollary18_max_records(B: int, M: int, domain_bits: float) -> float:
    """|S| <= B*log2(M) / log2(|X|)."""
    if domain_bits <= 0:
        return 0.0
    return theorem16_bound(B, M) / domain_bits


# ---------------------------------------------------------------------------
# Theorem 20: rank refinement for first-moment (SUM/AVG) aggregates.
# ---------------------------------------------------------------------------


def theorem20_bound(rank: int, M: int) -> float:
    """I(x; V | pub) <= rank(Q_c) * log2(M) <= min(B, n) * log2(M)."""
    if rank <= 0 or M <= 1:
        return 0.0
    return rank * math.log2(M)


def first_moment_rank(
    indicator_vectors: Sequence[np.ndarray], n: int
) -> int:
    """rank(Q_c) over GF(2**31 - 1), reusing admission.py's own RREF routine
    (Remark 11: the same field arithmetic the auditor itself would use, not
    an idealised computation over the rationals)."""
    return rref_rank(indicator_vectors, n, GF_PRIME)


# ---------------------------------------------------------------------------
# Theorem 26: record-recovery tightness (to within a factor of two).
# ---------------------------------------------------------------------------


def theorem26_check(B: int, domain_bits: float, recovered_records: int) -> Dict[str, float]:
    """Sandwich the measured recovered-value content between the two forms
    of the bound: floor(B/2)*log2|X| (Theorem 26's tight lower construction,
    Proposition 4 applied to floor(B/2) isolated targets) and B*log2|X|
    (Corollary 23's upper bound).
    """
    lower = math.floor(B / 2) * domain_bits
    upper = B * domain_bits
    measured = recovered_records * domain_bits
    return {
        "lower_bound_bits": lower,
        "upper_bound_bits": upper,
        "measured_bits": measured,
        "lower_holds": measured >= lower - 1e-9,
        "upper_holds": measured <= upper + 1e-9,
    }


# ---------------------------------------------------------------------------
# Theorem 30 / 32: injection-attributable bound and its degradation under
# leaky taint tracking.
# ---------------------------------------------------------------------------


def theorem30_bound(B_tau: int, M_tau: int) -> float:
    """I(x; V_Ainject) <= B_tau * log2(M_tau) under sound taint tracking."""
    return theorem16_bound(B_tau, M_tau)


def theorem32_bound(B_tau: int, M_tau: int, L: int, M: int) -> float:
    """Degradation under L-leaky taint tracking: + L * log2(M)."""
    return theorem30_bound(B_tau, M_tau) + theorem16_bound(L, M)


def theorem32_bound_bits(B_tau: int, M_tau: int, L: int, log2_M: float) -> float:
    """As theorem32_bound, but takes log2(M) directly.

    Used when the untainted alphabet is the exact-mode value domain (Remark
    24/25's convention), which is far too large to materialise as a raw
    integer M -- e.g. a revenue column's |X| = 2**20.1.
    """
    return theorem30_bound(B_tau, M_tau) + L * log2_M


# ---------------------------------------------------------------------------
# Bound-checking summary used by verify_claims.py.
# ---------------------------------------------------------------------------


def check_upper_bound(name: str, measured: float, bound: float) -> Dict[str, object]:
    return {
        "name": name,
        "measured": measured,
        "bound": bound,
        "holds": measured <= bound + 1e-6,
    }
