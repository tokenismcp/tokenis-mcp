# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The D1-D5 admission-control policy ladder (P4 §5, "Admission control design")
-- the product's admission-control module (``G_adm``, P2 §3.4).

This is the same engine developed and regression-tested in
:mod:`research.p4_admission.admission` (see that module's file for the
paper reproduction and ``research/p4_admission/attacks.py`` /
``research/p4_admission/test_pipeline.py`` for the attacks it is built to
withstand). The two copies are kept in sync by hand rather than one
importing the other: ``research/p4_admission`` is deliberately not part of
this package's installable distribution (see the root ``pyproject.toml``,
``[tool.setuptools.packages.find]``), so ``tokenis`` cannot depend on it at
import time without breaking a normal `pip install tokenis-mcp`. Any change
to the admission logic should be made in both places, or to whichever one
is authoritative going forward with the other reduced to a thin
re-export -- tracked as a follow-up, not resolved here.

This module implements, in order:

- **D1** (§5.1): minimum query-set size, admit iff ``k <= |C_phi| <= n - k``.
- **D2** (§5.2): the differencing control. Theorem 7 gives the exact compromise
  criterion (a value is determined iff its standard-basis vector lies in the
  rowspace of the admitted characteristic-vector matrix Q); Lemma 9 gives the
  weight-one row test that decides this exactly via reduced row-echelon form
  (RREF). The cell-aware correction (refuse on any RREF row of Hamming weight in
  ``[1, k-1]``) is a *tractable relaxation* of the true (NP-hard, Remark 10)
  sub-k disclosure test, not an exact decision procedure — see
  :class:`RREFBasis` and the module-level note below. The implementation works
  over ``GF(2**31 - 1)`` rather than over the rationals (Remark 11): this is an
  approximation of Theorem 7, not the theorem itself.
- **D3** (§5.3): budget scope. :class:`SubjectScopedBudget` is the only correct,
  production-default scoping (Corollary 14). :class:`CredentialScopedBudget` is
  included *only* as a documented, insecure variant to regression-test Theorem 13
  — never construct :class:`AdmissionPolicy` with it in anything but a test.
- **D4** (§5.4): taint-gated tool surface — when ``context.taint == 1`` the
  admissible function set shrinks to ``{COUNT}``, a separate tainted budget
  ``B_tau`` and a separate *call* cap ``C_tau`` apply (Proposition 34: only a cap
  on calls, admitted or not, bounds the admit/deny side channel E3 — a budget on
  admissions alone does not), and any tool with an external effect is refused
  outright while tainted (closing egress channel E2).
- **D5** (§5.5): deny-by-default on any column absent from the supplied
  catalogue of classified columns.

Honesty note (see the top-level README): this module reproduces the *mechanisms*
and the theorems' mathematical properties. It does not claim to reproduce the
paper's literal headline percentages, which rest on an unpublished exact
generator.

Design invariant (Proposition 33, "the policy is simulatable"): ``AdmissionPolicy``
never receives the protected value array. Its constructor accepts only public
per-record attribute arrays; ``decide()`` accepts only a query descriptor and a
context carrying public state (subject id, credential id, taint bit). This is
structural, not merely documented — the class holds no reference to any
protected-value column, so it is not merely unlikely to inspect ``x``, it is
unable to.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Field arithmetic (§5.2, Remark 11): the shipped auditor works over
# GF(2**31 - 1) so that products of two field elements fit in a machine word
# (here: a signed 64-bit numpy int, since (p-1)**2 < 2**63 - 1).
# ---------------------------------------------------------------------------

GF_PRIME = 2**31 - 1


def _mod_inverse(a: int, p: int = GF_PRIME) -> int:
    """Modular inverse via Fermat's little theorem (p is prime)."""
    a %= p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 in GF(p)")
    return pow(a, p - 2, p)


# ---------------------------------------------------------------------------
# Predicate algebra over PUBLIC attributes only (§3.1). A predicate's
# characteristic set C_phi depends only on the public attribute table, never
# on protected values, so this algebra is safe for AdmissionPolicy to hold and
# evaluate directly.
#
# The filter language supports: attribute equality / membership (conjunction
# primitives), conjunction (And), disjunction of conjunctions (Or of And), and
# an explicit exclusion / set-difference operator (Exclude), which
# Propositions 4 and 5 both rely on being expressible.
# ---------------------------------------------------------------------------


class Predicate(ABC):
    """A predicate over public attributes with an induced characteristic set."""

    @abstractmethod
    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        """Return a boolean array of length n: True at record i iff i in C_phi."""
        raise NotImplementedError


@dataclass(frozen=True)
class All(Predicate):
    """The universe predicate: C_phi = [n]."""

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        return np.ones(n, dtype=bool)


@dataclass(frozen=True)
class Eq(Predicate):
    """attr == value."""

    attr: str
    value: Any

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        return attrs[self.attr] == self.value


@dataclass(frozen=True)
class In(Predicate):
    """attr in values (a range constraint is expressed as an explicit value set)."""

    attr: str
    values: Tuple[Any, ...]

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        return np.isin(attrs[self.attr], np.asarray(self.values))


@dataclass(frozen=True)
class And(Predicate):
    """Conjunction of predicates (a single conjunction, the base filter unit)."""

    parts: Tuple[Predicate, ...]

    def __init__(self, *parts: Predicate):
        object.__setattr__(self, "parts", tuple(parts))

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        out = np.ones(n, dtype=bool)
        for p in self.parts:
            out &= p.indicator(attrs, n)
        return out


@dataclass(frozen=True)
class Or(Predicate):
    """Disjunction of predicates (the natural JSON shape for an MCP tool argument)."""

    parts: Tuple[Predicate, ...]

    def __init__(self, *parts: Predicate):
        object.__setattr__(self, "parts", tuple(parts))

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        out = np.zeros(n, dtype=bool)
        for p in self.parts:
            out |= p.indicator(attrs, n)
        return out


@dataclass(frozen=True)
class Not(Predicate):
    """Complement within the universe."""

    inner: Predicate

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        return ~self.inner.indicator(attrs, n)


@dataclass(frozen=True)
class Exclude(Predicate):
    """Explicit set-difference: left AND NOT right (theta AND NOT psi).

    Propositions 4 and 5 both require the filter language to express this
    (a two-query individual tracker needs ``theta OR psi_t`` and ``theta``; a
    nested-conjunction differencing attack needs ``alpha`` and ``alpha AND NOT
    beta``), so it is provided as a first-class operator rather than requiring
    callers to hand-build ``And(left, Not(right))``.
    """

    left: Predicate
    right: Predicate

    def indicator(self, attrs: Mapping[str, np.ndarray], n: int) -> np.ndarray:
        return self.left.indicator(attrs, n) & ~self.right.indicator(attrs, n)


def characteristic_indicator(
    predicate: Predicate, public_attributes: Mapping[str, np.ndarray], n: int
) -> np.ndarray:
    """Resolve a predicate's characteristic set against PUBLIC attributes only."""
    return predicate.indicator(public_attributes, n)


# ---------------------------------------------------------------------------
# D2: RREF over GF(p) (Theorem 7, Lemma 9, Remark 10, Remark 11).
# ---------------------------------------------------------------------------


class RREFBasis:
    """Maintains the reduced row-echelon form of an admitted-query matrix over GF(p).

    Implements Theorem 7's exact compromise criterion via Lemma 9's weight-one
    test (``weight_hi=1``): a standard basis vector e_i lies in rowspace(Q) iff
    the RREF contains e_i itself as a row.

    The cell-aware correction (§5.2, "First correction") widens this to refuse
    whenever the RREF contains ANY row of Hamming weight in ``[1, weight_hi]``
    with ``weight_hi = k - 1``. Per Remark 10, this widened test is an honest,
    tractable *relaxation* of the true sub-k disclosure question (deciding
    whether any 0/1 vector of weight below k lies in a subspace is a
    minimum-weight-codeword problem, NP-hard in general). It can therefore both
    over-refuse (a low-weight RREF row need not correspond to a realisable
    cell) and under-refuse (a low-weight combination need not appear as an RREF
    row). This is expected, documented behaviour, not a bug.
    """

    def __init__(self, n: int, p: int = GF_PRIME):
        self.n = n
        self.p = p
        self.rows: List[np.ndarray] = []
        self.pivots: List[int] = []

    @property
    def rank(self) -> int:
        return len(self.rows)

    def _reduce(self, v: np.ndarray) -> np.ndarray:
        v = v.astype(np.int64) % self.p
        for row, piv in zip(self.rows, self.pivots):
            c = int(v[piv])
            if c != 0:
                v = (v - c * row) % self.p
        return v

    def contains_weight_one_row(self) -> bool:
        """Lemma 9: exact test for e_i in rowspace(Q) for some i."""
        return self.has_row_with_weight_in(1, 1)

    def has_row_with_weight_in(self, lo: int, hi: int) -> bool:
        for row in self.rows:
            w = int(np.count_nonzero(row))
            if lo <= w <= hi:
                return True
        return False

    def try_add(self, v: np.ndarray, weight_lo: int, weight_hi: int) -> bool:
        """Attempt to admit a candidate characteristic vector v.

        Mirrors the auditor pseudocode of Appendix B exactly: reduce v against
        the current basis; if it reduces to zero the candidate is linearly
        dependent and carries no new information, so it is admitted without
        being recorded. Otherwise normalise the reduced row, back-substitute
        it into the existing rows, and test the RESULTING row set for any row
        of Hamming weight in [weight_lo, weight_hi]. If the test fires, the
        candidate is refused and discarded (the basis is left unchanged);
        otherwise the row is committed.

        Returns True iff the candidate is admitted (whether or not it changed
        the basis).
        """
        r = self._reduce(v)
        nz = np.nonzero(r)[0]
        if len(nz) == 0:
            # Dependent on the existing span: admitting it changes nothing,
            # so it is safe iff the CURRENT basis is already safe, which it
            # is by the loop invariant (every committed row passed the test).
            return True

        pivot = int(nz[0])
        inv = _mod_inverse(int(r[pivot]), self.p)
        r = (r * inv) % self.p

        # Back-substitute the trial row into the existing rows and build the
        # trial row set (in pivot order) WITHOUT mutating self yet.
        trial_rows: List[np.ndarray] = []
        trial_pivots: List[int] = []
        inserted = False
        for row, piv in zip(self.rows, self.pivots):
            c = int(row[pivot])
            if c != 0:
                row = (row - c * r) % self.p
            if not inserted and piv > pivot:
                trial_rows.append(r)
                trial_pivots.append(pivot)
                inserted = True
            trial_rows.append(row)
            trial_pivots.append(piv)
        if not inserted:
            trial_rows.append(r)
            trial_pivots.append(pivot)

        for row in trial_rows:
            w = int(np.count_nonzero(row))
            if weight_lo <= w <= weight_hi:
                # Refuse: discard the candidate, leave the basis untouched.
                return False

        self.rows = trial_rows
        self.pivots = trial_pivots
        return True


def rref_rank(vectors: Sequence[np.ndarray], n: int, p: int = GF_PRIME) -> int:
    """Compute rank over GF(p) of a set of 0/1 (or already-mod-p) vectors.

    Used by bounds.py (Theorem 20) to reuse the exact same field arithmetic as
    the admission auditor, so the rank refinement is computed consistently
    with what the auditor itself would have recorded.
    """
    basis = RREFBasis(n, p)
    for v in vectors:
        # weight range [n+1, -1] never fires (empty range), i.e. this basis
        # unconditionally accepts every independent vector: rank_rref is a
        # pure rank computation, not an admission decision.
        basis.try_add(v, n + 1, -1)
    return basis.rank


# ---------------------------------------------------------------------------
# D3: budget scope (Theorem 13, Corollary 14).
# ---------------------------------------------------------------------------


@dataclass
class QueryContext:
    """Public, per-call context carried by every admission decision.

    subject_id: the AUTHENTICATED end-user subject (OIDC/SAML, §3.1). Required
        on every call (Corollary 14) -- AdmissionPolicy.decide raises
        MissingSubjectIdError if this is falsy.
    credential_id: the agent's presented credential. Cheap to rotate, which is
        exactly why a budget keyed to it (CredentialScopedBudget) is insecure
        (Theorem 13).
    taint: 1 iff the current model context contains content from an untrusted
        source (Assumption 15: taint is supplied by the host, not inferred).
    window: an accounting-window key (Proposition 29: budgets are per-window,
        and renewing the window renews the allowance).
    """

    subject_id: Optional[str]
    credential_id: str
    taint: int = 0
    window: str = "default"


class MissingSubjectIdError(ValueError):
    """Raised when a call carries no authenticated subject id (Corollary 14).

    Every containment bound in §6 presupposes an authenticated end-user
    subject on every call; a gateway that receives only the agent's API key
    cannot state any of them. AdmissionPolicy therefore refuses to operate
    (rather than silently falling back to some other key) when this is
    missing, regardless of which BudgetScope is configured.
    """


class BudgetScope(ABC):
    """A per-principal admitted-query budget, keyed by some function of context."""

    def __init__(self, budget: int):
        self.budget = budget
        self._remaining: Dict[Tuple[str, str], int] = {}

    @abstractmethod
    def _key(self, context: QueryContext) -> str:
        raise NotImplementedError

    def _slot(self, context: QueryContext) -> Tuple[str, str]:
        return (context.window, self._key(context))

    def has_budget(self, context: QueryContext) -> bool:
        return self._remaining.get(self._slot(context), self.budget) > 0

    def consume(self, context: QueryContext) -> None:
        slot = self._slot(context)
        self._remaining[slot] = self._remaining.get(slot, self.budget) - 1

    def remaining(self, context: QueryContext) -> int:
        return self._remaining.get(self._slot(context), self.budget)


class SubjectScopedBudget(BudgetScope):
    """Correct D3 scoping (§5.3): keys the budget to the authenticated subject.

    Theorem 13: the number of admitted queries attributable to subject s in a
    window is at most B(s) regardless of how many credentials are presented.
    This is the default, and the only scoping AdmissionPolicy's production
    constructor should be given.
    """

    def _key(self, context: QueryContext) -> str:
        return context.subject_id or ""


class CredentialScopedBudget(BudgetScope):
    """INSECURE. Reproduces Theorem 13's regression-test fixture ONLY.

    Keys the budget to the presented credential rather than the authenticated
    subject. Theorem 13: if an adversary can mint fresh credentials at
    negligible cost (opening a new agent session), this admits no containment
    bound of the Theorem 16 form at all -- for every B and every target set S
    there is an adversary recovering all of S using ceil(|S| / floor(B/2))
    credentials.

    Do not construct :class:`AdmissionPolicy` with this in anything other than
    ``attacks.py``'s Theorem-13 regression test (attack #5) and
    ``test_pipeline.py``'s corresponding unit test. It exists here, clearly
    labelled, so that the "budget keyed to the wrong thing" failure mode is a
    concrete object under test rather than merely a warning in a docstring.
    """

    def _key(self, context: QueryContext) -> str:
        return context.credential_id


# ---------------------------------------------------------------------------
# Query / Decision descriptors.
# ---------------------------------------------------------------------------

AGGREGATE_FUNCTIONS = ("COUNT", "SUM", "AVG", "VAR")


@dataclass(frozen=True)
class Query:
    """A tool call: either an aggregate query (predicate, function[, column])
    or an external-effect tool call (has_external_effect=True; predicate and
    function are then ignored by D1/D2/D5 and only D4's external-effect
    refusal applies).
    """

    predicate: Predicate = field(default_factory=All)
    function: str = "COUNT"
    column: Optional[str] = None
    has_external_effect: bool = False

    def __post_init__(self) -> None:
        if self.function not in AGGREGATE_FUNCTIONS:
            raise ValueError(f"unknown function {self.function!r}")


@dataclass(frozen=True)
class Decision:
    admitted: bool
    rule: Optional[str]  # which rule refused the query, or None if admitted
    reason: str
    set_size: Optional[int] = None


# ---------------------------------------------------------------------------
# D4 response-shaping helper (banding). This is a PURE function of a single
# scalar response value and public banding parameters -- it is deliberately
# NOT part of AdmissionPolicy.decide, which never sees any response value,
# let alone the protected array that produced it. Callers (gateway_sim /
# attacks / evaluate) apply this themselves to a value they already computed.
# ---------------------------------------------------------------------------


def band_value(value: float, lo: float, hi: float, num_bands: int) -> int:
    """Map a scalar response into one of num_bands log-spaced bands in [lo, hi].

    Used to implement D4's M_tau-alphabet response shaping (§5.4, §8.1: "24
    log-spaced bands").
    """
    if num_bands < 1:
        raise ValueError("num_bands must be >= 1")
    if hi <= lo:
        return 0
    value = min(max(value, lo), hi)
    log_lo, log_hi = np.log1p(0.0), np.log1p(hi - lo)
    log_v = np.log1p(value - lo)
    band = int(np.floor((log_v - log_lo) / (log_hi - log_lo + 1e-12) * num_bands))
    return min(max(band, 0), num_bands - 1)


# ---------------------------------------------------------------------------
# The naive exposure-cap heuristic (§5.2, "A cheap heuristic, and its
# failure"; Proposition 12). This is an ALTERNATIVE, intentionally weaker
# policy -- not part of the D1-D5 stack, and not what AdmissionPolicy
# implements. It is provided so attacks.py can demonstrate Proposition 12
# directly against the object the paper describes.
# ---------------------------------------------------------------------------


class NaiveExposureCapPolicy:
    """D1 (size rule) plus a constant-cost per-record exposure counter.

    Refuses a query iff any record in its characteristic set already has
    exposure (= number of PREVIOUSLY ADMITTED query sets containing it) >= E.
    Proposition 12: this fails for every E >= 2 against a nested-disjoint-pair
    construction, and only E = 1 (no two admitted sets may intersect) stops
    it. This is *not* part of the recommended D1-D5 stack (§5.2 explicitly
    reports it as a negative result); it is here purely so attacks.py can
    measure Proposition 12 against a real object rather than asserting it.
    """

    def __init__(
        self,
        n: int,
        public_attributes: Mapping[str, np.ndarray],
        k: int,
        exposure_cap: int,
    ):
        self.n = n
        self._attrs = public_attributes
        self.k = k
        self.exposure_cap = exposure_cap
        self._exposure = np.zeros(n, dtype=np.int64)

    def decide(self, query: Query) -> Decision:
        indicator = characteristic_indicator(query.predicate, self._attrs, self.n)
        size = int(indicator.sum())
        if not (self.k <= size <= self.n - self.k):
            return Decision(False, "D1", "below minimum query-set size", size)
        exposed = self._exposure[indicator]
        if exposed.size and int(exposed.max()) >= self.exposure_cap:
            return Decision(False, "exposure-cap", "per-record exposure cap exceeded", size)
        self._exposure[indicator] += 1
        return Decision(True, None, "admitted", size)


# ---------------------------------------------------------------------------
# D1-D5: the recommended AdmissionPolicy.
# ---------------------------------------------------------------------------


class AdmissionPolicy:
    """The D1-D5 policy ladder (§5), composed as the recommended stack.

    Construction takes ONLY public information: the record count, a mapping
    of public attribute arrays, and the catalogue of classified column names.
    It never receives, stores, or is passed the protected value array at any
    point in its lifecycle -- this is what makes Proposition 33
    ("the policy is simulatable") a structural property rather than a promise.

    Parameters
    ----------
    n: population size.
    public_attributes: mapping attribute name -> length-n array of public
        category codes. Never contains protected values.
    catalogue: iterable of column names the policy will admit queries about
        (D5). Any query naming a column outside this set is refused.
    k: minimum query-set size (D1).
    budget: untainted admitted-query budget B per subject per window (D3).
    taint_budget: tainted admitted-query budget B_tau (D4).
    taint_call_cap: tainted CALL cap C_tau, counting admitted and refused
        calls alike (D4; Proposition 34 -- only this, not B_tau, bounds E3).
    taint_alphabet_size: M_tau, the number of response bands used while
        tainted (exposed for callers that shape responses; decide() itself
        never shapes a response).
    cell_aware: if True (default, matches the paper's recommended P7/P8),
        widen the D2 weight-one test to the cell-aware weight-in-[1,k-1] test
        (Remark 10's honest relaxation). If False, use the classical
        weight-one-only test (Lemma 9 exactly, misses sub-k cell disclosure
        per §5.2's "First correction").
    audit_enabled: if False, disable D2 entirely (no rowspace tracking at
        all) -- this is what the paper's P0/P1 "no control" / "size only"
        configurations are (Table 1). Default True.
    enforce_d1: if False, disable D1 (the minimum query-set-size rule)
        entirely -- used to build the paper's P0 ("no admission control")
        configuration, which is otherwise unreachable since k=0 still forbids
        the empty and full query sets.
    enforce_d4: if False, disable D4's taint-specific restrictions (surface
        shrink, B_tau, C_tau, external-effect refusal) even when
        context.taint == 1 -- used to build the paper's pre-P6 configurations,
        which do not yet add taint gating.
    enforce_d5: if False, disable D5 (deny-by-default on unclassified
        columns) -- used to build the paper's pre-P7 configurations.
    audit_avg: if False, reproduce the historical "AVG-exemption" bug (§5.2,
        "Second correction"): AVG queries skip the D2 rowspace audit entirely
        (SUM queries are still audited normally). This exists ONLY so
        attacks.py's regression test (attack #8) has a concrete buggy object
        to attack; AdmissionPolicy's correct, default behaviour (audit_avg=
        True) shares one first-moment basis between SUM and AVG on a column,
        since an AVG response is affine in the SUM it implies once the
        (public) set size is known.
    budget_scope: the D3 BudgetScope to use. Defaults to SubjectScopedBudget
        (the only correct choice for production). Passing a
        CredentialScopedBudget is supported ONLY to reproduce Theorem 13's
        regression test and is never the default.

    Concurrency: not thread-safe. ``decide`` is a read-check-write over the
    D2 basis and the budgets, so concurrent calls can each pass a check the
    other would have failed -- which is exactly how a differencing attack
    gets through. Callers must serialise every call (the gateway service
    holds one lock around admission, computation and audit).
    """

    def __init__(
        self,
        n: int,
        public_attributes: Mapping[str, np.ndarray],
        catalogue: Iterable[str],
        k: int = 5,
        budget: int = 64,
        taint_budget: int = 8,
        taint_call_cap: int = 32,
        taint_alphabet_size: int = 24,
        cell_aware: bool = True,
        audit_enabled: bool = True,
        enforce_d1: bool = True,
        enforce_d4: bool = True,
        enforce_d5: bool = True,
        audit_avg: bool = True,
        budget_scope: Optional[BudgetScope] = None,
    ):
        self.n = n
        self._public_attributes: Dict[str, np.ndarray] = dict(public_attributes)
        self.catalogue = frozenset(catalogue)
        self.k = k
        self.taint_alphabet_size = taint_alphabet_size
        self.cell_aware = cell_aware
        self.audit_enabled = audit_enabled
        self.enforce_d1 = enforce_d1
        self.enforce_d4 = enforce_d4
        self.enforce_d5 = enforce_d5
        self.audit_avg = audit_avg

        self._budget: BudgetScope = budget_scope or SubjectScopedBudget(budget)
        self._taint_budget: BudgetScope = SubjectScopedBudget(taint_budget)
        self._taint_call_cap = taint_call_cap
        self._taint_calls: Dict[Tuple[str, str], int] = {}

        # One RREF basis per (column, moment) audit slot (§5.2, "Second
        # correction"): SUM and AVG share the first-moment slot for a column
        # (an AVG response is audited on the SAME characteristic vector as
        # the SUM it implies -- |C_phi| is public, so this is the fix for the
        # historical AVG-exemption bug); VAR gets its own second-moment slot;
        # COUNT is exempt (its answer is a public set size).
        self._bases: Dict[Tuple[str, int], RREFBasis] = {}

    # -- internal helpers ---------------------------------------------------

    def _basis_for(self, column: str, moment: int) -> RREFBasis:
        key = (column, moment)
        if key not in self._bases:
            self._bases[key] = RREFBasis(self.n)
        return self._bases[key]

    def _taint_call_slot(self, context: QueryContext) -> Tuple[str, str]:
        return (context.window, context.subject_id or "")

    # -- the policy -----------------------------------------------------

    def remaining_budget(self, context: QueryContext) -> int:
        """Admissions left for this context's subject in its window (the
        tainted budget when ``context.taint`` is set). Public state only."""
        tainted = context.taint == 1 and self.enforce_d4
        return (self._taint_budget if tainted else self._budget).remaining(context)

    def restore(self, query: Optional[Query], context: QueryContext, admitted: bool) -> None:
        """Re-apply a *logged* decision without re-deciding it (durable-state
        replay; see ``tokenis/gateway/state.py``). Every tainted call counts
        against C_tau; an admitted one also consumes budget and, for a
        value-bearing aggregate, commits its characteristic vector to the D2
        basis unconditionally -- it was disclosed, whatever the current
        settings would say about it now. ``query`` is None for a
        :meth:`charge` call."""
        tainted = context.taint == 1 and self.enforce_d4
        if tainted:
            slot = self._taint_call_slot(context)
            self._taint_calls[slot] = self._taint_calls.get(slot, 0) + 1
        if not admitted:
            return
        if (
            query is not None
            and self.audit_enabled
            and query.function in ("SUM", "AVG", "VAR")
            and not (query.function == "AVG" and not self.audit_avg)
            and query.column is not None
        ):
            moment = 2 if query.function == "VAR" else 1
            vec = characteristic_indicator(query.predicate, self._public_attributes, self.n)
            # weight range [1, 0] is empty: the row is committed, never refused.
            self._basis_for(query.column, moment).try_add(vec.astype(np.int64), 1, 0)
        (self._taint_budget if tainted else self._budget).consume(context)

    def charge(self, context: QueryContext) -> Decision:
        """Admission for a *lookup* tool that returns no aggregate (e.g. a
        similarity search): no predicate, so D1/D2/D5 do not apply, but the
        call still counts against D4's tainted call cap and the D3 (or D4
        tainted) budget, so lookups cannot be issued without limit."""
        if not context.subject_id:
            raise MissingSubjectIdError(
                "AdmissionPolicy.charge requires an authenticated subject id "
                "on every call (Corollary 14); received none"
            )
        tainted = context.taint == 1 and self.enforce_d4
        if tainted:
            slot = self._taint_call_slot(context)
            self._taint_calls[slot] = self._taint_calls.get(slot, 0) + 1
            if self._taint_calls[slot] > self._taint_call_cap:
                return Decision(False, "D4-Ctau", "tainted call cap exceeded")
        budget_scope = self._taint_budget if tainted else self._budget
        if not budget_scope.has_budget(context):
            return Decision(False, "D4-Btau" if tainted else "D3", "budget exhausted")
        budget_scope.consume(context)
        return Decision(True, None, "admitted")

    def decide(self, query: Query, context: QueryContext) -> Decision:
        """Decide whether to admit a query. A pure function of public state only.

        Signature note (Proposition 33): this method's parameters are exactly
        (query, context) -- a query descriptor and public call context. There
        is no protected-value parameter to pass even by mistake, and this
        class holds no reference to one (see the class docstring).
        """
        # Corollary 14: identity propagation is a precondition, enforced on
        # every call regardless of which BudgetScope is configured.
        if not context.subject_id:
            raise MissingSubjectIdError(
                "AdmissionPolicy.decide requires an authenticated subject id "
                "on every call (Corollary 14); received none"
            )

        # D4's call cap C_tau: counts EVERY call made while tainted, admitted
        # or refused (Proposition 34), so it is checked first -- before any
        # other rule has a chance to refuse the call without being counted.
        # This ordering is a deliberate choice (see the RREFBasis /
        # AdmissionPolicy module docstring and README): it is what makes the
        # C_tau bound on the decision side-channel E3 actually hold, rather
        # than merely being asserted.
        tainted = context.taint == 1 and self.enforce_d4
        if tainted:
            slot = self._taint_call_slot(context)
            self._taint_calls[slot] = self._taint_calls.get(slot, 0) + 1
            if self._taint_calls[slot] > self._taint_call_cap:
                return Decision(False, "D4-Ctau", "tainted call cap exceeded")

        # External-effect tools: refused outright while tainted (closes E2);
        # otherwise admission control does not gate them (they carry no
        # aggregate function/predicate to check).
        if query.has_external_effect:
            if tainted:
                return Decision(False, "D4-external-effect", "external-effect tool refused while tainted")
            return Decision(True, None, "external-effect tool admitted (untainted)")

        # D5: deny-by-default on unclassified columns.
        if self.enforce_d5 and query.function != "COUNT" and query.column not in self.catalogue:
            return Decision(False, "D5", f"column {query.column!r} not in catalogue")

        # D4: taint-gated function surface (shrinks to COUNT only).
        if tainted and query.function != "COUNT":
            return Decision(False, "D4-surface", "tainted surface admits COUNT only")

        # D1: minimum query-set size, both tails.
        indicator = characteristic_indicator(query.predicate, self._public_attributes, self.n)
        size = int(indicator.sum())
        if self.enforce_d1 and not (self.k <= size <= self.n - self.k):
            return Decision(False, "D1", "query set size outside [k, n-k]", size)

        # D3: budget (tainted or untainted, per context).
        budget_scope = self._taint_budget if tainted else self._budget
        rule = "D4-Btau" if tainted else "D3"
        if not budget_scope.has_budget(context):
            return Decision(False, rule, "budget exhausted", size)

        # D2: differencing control (audits every value-bearing aggregate).
        skip_avg_audit = query.function == "AVG" and not self.audit_avg
        if self.audit_enabled and query.function in ("SUM", "AVG", "VAR") and not skip_avg_audit:
            if query.column is None:
                raise ValueError("SUM/AVG/VAR queries must name a column")
            moment = 2 if query.function == "VAR" else 1
            basis = self._basis_for(query.column, moment)
            weight_hi = max(self.k - 1, 1) if self.cell_aware else 1
            vec = indicator.astype(np.int64)
            if not basis.try_add(vec, 1, weight_hi):
                return Decision(False, "D2", "rowspace/cell-aware audit refused", size)

        budget_scope.consume(context)
        return Decision(True, None, "admitted", size)
