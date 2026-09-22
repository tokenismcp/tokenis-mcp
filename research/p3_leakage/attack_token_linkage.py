# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Cross-session token linkage and composition, reproducing paper Section 6
("Token linkage and composition") and Figures 3-5.

Implements the three-stage adversary against the model host `A_host`:

  Stage 1 (Lschema, "candidate narrowing"): intersect the public directory on
  the disclosed columns of the active disclosure profile, plus any exact
  filter constraint carried on a session's tool call (filters are always
  visible to A_host regardless of profile, since they are part of the query,
  not a returned column).

  Stage 2 (Lagg, "aggregate inversion"): peel exact per-account amounts out
  of session aggregates -- a session with exactly one unsolved member
  discloses that member's amount directly; a pair of sessions S1 subset S2
  with |S2 \\ S1| = 1 discloses the extra member's amount as a direct
  difference of two already-known aggregates (both aggregates are always
  observed by A_host, so this rule needs no fixpoint). Recovered amounts then
  narrow candidate sets via the inverse of corpus.py's log-linear revenue
  relation, at a +/-3 sigma noise tolerance.

  Stage 3 (Ltoken, "seeded propagation"): a Narayanan-Shmatikov-style seeded
  graph match. Tokens with a singleton candidate set after stages 1-2 become
  seeds; propagation extends the mapping through the token co-occurrence
  graph (built from same-session membership) against the public relationship
  graph, accepting a candidate only if (i) it is publicly adjacent to at
  least `m` distinct images of the token's already-mapped neighbours
  ("corroboration"), (ii) its support beats the runner-up by at least the
  eccentricity margin, and (iii) it is the strongest proposal for that
  candidate this round (mutual-best arbitration across all proposers).

`run_ablation` measures all seven non-empty combinations of {S, A, T}. See
`corpus.py`'s module docstring for what "faithful re-implementation" means
here: this is not the paper's own code, and exact percentages are not
expected to match -- only the qualitative composition-failure pattern
(S alone re-identifies, A alone and T alone do not, the union exceeds the
sum) is the claim under test.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from corpus import (
    ATTRIBUTES,
    Corpus,
    N_FOUNDING_BANDS,
    N_HEADCOUNT_BANDS,
    N_REVENUE_BANDS,
    Session,
)

REVENUE_NOISE_SIGMA = 0.35
REVENUE_LOG_COEF = 0.95
REVENUE_NOISE_WIDTH_SIGMAS = 3.0

_BAND_CARDINALITY = {
    "revenue_band": N_REVENUE_BANDS,
    "headcount_band": N_HEADCOUNT_BANDS,
    "founding_year_band": N_FOUNDING_BANDS,
}

ProfileColumns = List[Tuple[str, int]]


def disclosure_profiles(corpus: Corpus) -> Dict[str, ProfileColumns]:
    """P0-P3 of Section 6.5. Levels are indices into each attribute's
    GeneralizationHierarchy chain (0 = finest)."""
    return {
        "P0_token_only": [],
        "P1_coarse": [("industry_subclass", 3), ("locality", 1)],  # division, region
        "P2_typical": [
            ("industry_subclass", 2),  # group
            ("locality", 1),  # region (paper says "province"; nearest analogue)
            ("revenue_band", 1),  # coarse band
        ],
        "P3_rich": [(a, 0) for a in ATTRIBUTES],
    }


def _disclosed_columns(corpus: Corpus, profile: ProfileColumns) -> Dict[str, np.ndarray]:
    gen = corpus.generalization
    directory = corpus.directory
    out: Dict[str, np.ndarray] = {}
    for attr, level in profile:
        if attr == "industry_subclass":
            out[attr] = gen.industry_at(directory.industry_subclass, level)
        elif attr == "locality":
            out[attr] = gen.locality_at(directory.locality, level)
        elif attr in _BAND_CARDINALITY:
            out[attr] = gen.band_at(directory.attribute(attr), _BAND_CARDINALITY[attr], level)
        else:
            out[attr] = gen.categorical_at(directory.attribute(attr), level)
    return out


def _filter_mask(corpus: Corpus, filt: Dict[str, int], cache: Dict[Tuple, np.ndarray]) -> np.ndarray:
    key = tuple(sorted(filt.items()))
    if key in cache:
        return cache[key]
    gen = corpus.generalization
    directory = corpus.directory
    if "industry_level" in filt:
        col = gen.industry_at(directory.industry_subclass, filt["industry_level"])
        mask = col == filt["industry_value"]
    else:
        col = gen.locality_at(directory.locality, filt["locality_level"])
        mask = col == filt["locality_value"]
    cache[key] = mask
    return mask


def stage1_candidates(
    corpus: Corpus,
    profile: ProfileColumns,
    sessions: Optional[Sequence[Session]] = None,
    active: bool = True,
) -> Dict[int, np.ndarray]:
    """Returns {ledger_token: array of admissible directory indices}."""
    directory = corpus.directory
    ledger = corpus.ledger
    n_dir = directory.size
    sessions = corpus.workload.sessions if sessions is None else sessions

    if not active:
        universe = np.arange(n_dir)
        return {t: universe for t in range(ledger.size)}

    disclosed = _disclosed_columns(corpus, profile)

    token_filters: Dict[int, List[Dict[str, int]]] = defaultdict(list)
    for s in sessions:
        if s.filter is not None:
            for m in s.members:
                token_filters[m].append(s.filter)

    filter_cache: Dict[Tuple, np.ndarray] = {}
    candidates: Dict[int, np.ndarray] = {}
    universe = np.arange(n_dir)
    for t in range(ledger.size):
        mask = np.ones(n_dir, dtype=bool)
        true_dir = int(ledger.directory_index[t])
        for attr, col in disclosed.items():
            mask &= col == col[true_dir]
        for filt in token_filters.get(t, []):
            mask &= _filter_mask(corpus, filt, filter_cache)
        candidates[t] = universe[mask]
    return candidates


def stage2_peel_amounts(
    corpus: Corpus,
    sessions: Optional[Sequence[Session]] = None,
    active: bool = True,
    min_aggregate_size: int = 1,
) -> Dict[int, float]:
    """Peeling adversary: returns {ledger_token: recovered exact amount}."""
    if not active:
        return {}
    sessions = corpus.workload.sessions if sessions is None else sessions
    allowed = [s for s in sessions if len(s.members) >= min_aggregate_size]

    known: Dict[int, float] = {}

    # Rule B: pairs S1 subset S2, |S2 \ S1| == 1 -> direct difference of two
    # already-observed aggregates (no dependency on `known`).
    member_sets = [frozenset(s.members) for s in allowed]
    for i, si in enumerate(member_sets):
        for j, sj in enumerate(member_sets):
            if i == j or len(sj) <= len(si):
                continue
            if si < sj and len(sj - si) == 1:
                extra = next(iter(sj - si))
                if extra not in known:
                    known[extra] = allowed[j].aggregate - allowed[i].aggregate

    # Rule A: iterate to a fixpoint -- a session with exactly one unsolved
    # member discloses that member's amount.
    for _ in range(15):
        changed = False
        for s in allowed:
            unsolved = [m for m in s.members if m not in known]
            if len(unsolved) == 1:
                val = s.aggregate - sum(known[m] for m in s.members if m in known)
                if unsolved[0] not in known:
                    known[unsolved[0]] = val
                    changed = True
        if not changed:
            break
    return known


def _narrow_by_revenue(
    corpus: Corpus, candidates: Dict[int, np.ndarray], known_amounts: Dict[int, float]
) -> Dict[int, np.ndarray]:
    if not known_amounts:
        return candidates
    directory = corpus.directory
    log_revenue = np.log(directory.revenue)
    out = dict(candidates)
    for t, amount in known_amounts.items():
        if t not in out:
            continue
        log_amount = np.log(max(amount, 1e-9))
        lo = (log_amount - REVENUE_NOISE_WIDTH_SIGMAS * REVENUE_NOISE_SIGMA) / REVENUE_LOG_COEF
        hi = (log_amount + REVENUE_NOISE_WIDTH_SIGMAS * REVENUE_NOISE_SIGMA) / REVENUE_LOG_COEF
        cand = out[t]
        cand_log_rev = log_revenue[cand]
        keep = (cand_log_rev >= lo) & (cand_log_rev <= hi)
        out[t] = cand[keep]
    return out


@dataclass
class PropagationResult:
    mapped_image: Dict[int, int] = field(default_factory=dict)
    support: Dict[int, int] = field(default_factory=dict)  # token -> corroboration count
    is_seed: Dict[int, bool] = field(default_factory=dict)


def _build_token_graph(sessions: Sequence[Session]) -> Dict[int, set]:
    graph: Dict[int, set] = defaultdict(set)
    for s in sessions:
        members = s.members
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                graph[members[i]].add(members[j])
                graph[members[j]].add(members[i])
    return graph


def stage3_propagate(
    corpus: Corpus,
    candidates: Dict[int, np.ndarray],
    sessions: Optional[Sequence[Session]] = None,
    active: bool = True,
    min_support: int = 1,
    eccentricity_margin: int = 1,
    max_rounds: int = 12,
) -> PropagationResult:
    result = PropagationResult()
    if not active:
        return result
    sessions = corpus.workload.sessions if sessions is None else sessions

    # Seeds: tokens whose stage1/2 candidate set is already a singleton.
    unmapped = set(candidates.keys())
    for t, cand in candidates.items():
        if len(cand) == 1:
            result.mapped_image[t] = int(cand[0])
            result.support[t] = 10 ** 6  # trivially maximal confidence
            result.is_seed[t] = True
            unmapped.discard(t)

    if not result.mapped_image:
        return result  # no anchors -> propagation cannot start

    token_graph = _build_token_graph(sessions)
    public_adjacency = corpus.public_graph.adjacency()

    for _ in range(max_rounds):
        proposals: Dict[int, List[Tuple[int, int]]] = defaultdict(list)  # candidate -> [(token, support)]
        token_best: Dict[int, Tuple[int, int, int]] = {}  # token -> (best_cand, best_support, second_support)

        for t in list(unmapped):
            neighbours = token_graph.get(t, ())
            mapped_neighbours = [n for n in neighbours if n in result.mapped_image]
            if not mapped_neighbours:
                continue
            cand_support: Dict[int, int] = defaultdict(int)
            token_candidates = set(candidates.get(t, np.array([], dtype=np.int64)).tolist())
            if not token_candidates:
                continue
            for n in mapped_neighbours:
                image = result.mapped_image[n]
                for pub_neigh in public_adjacency.get(image, ()):
                    if pub_neigh in token_candidates:
                        cand_support[pub_neigh] += 1
            if not cand_support:
                continue
            ranked = sorted(cand_support.items(), key=lambda kv: (-kv[1], kv[0]))
            best_cand, best_support = ranked[0]
            second_support = ranked[1][1] if len(ranked) > 1 else 0
            token_best[t] = (best_cand, best_support, second_support)
            proposals[best_cand].append((t, best_support))

        if not token_best:
            break

        accepted_any = False
        for cand, proposers in proposals.items():
            proposers_sorted = sorted(proposers, key=lambda kv: (-kv[1], kv[0]))
            winner_token, winner_support = proposers_sorted[0]
            best_cand, best_support, second_support = token_best[winner_token]
            if best_cand != cand:
                continue
            if winner_support < min_support:
                continue
            if (winner_support - second_support) < eccentricity_margin:
                continue
            if len(proposers_sorted) > 1 and proposers_sorted[1][1] == winner_support:
                continue  # tie for strongest proposer -> ambiguous, reject
            result.mapped_image[winner_token] = cand
            result.support[winner_token] = winner_support
            result.is_seed[winner_token] = False
            unmapped.discard(winner_token)
            accepted_any = True

        if not accepted_any:
            break

    return result


@dataclass
class LinkagePipelineResult:
    candidates: Dict[int, np.ndarray]
    known_amounts: Dict[int, float]
    propagation: PropagationResult


def run_pipeline(
    corpus: Corpus,
    profile: ProfileColumns,
    use_schema: bool,
    use_agg: bool,
    use_token: bool,
    sessions: Optional[Sequence[Session]] = None,
    min_aggregate_size: int = 1,
) -> LinkagePipelineResult:
    candidates = stage1_candidates(corpus, profile, sessions=sessions, active=use_schema)
    known_amounts = stage2_peel_amounts(
        corpus, sessions=sessions, active=use_agg, min_aggregate_size=min_aggregate_size
    )
    if use_agg:
        candidates = _narrow_by_revenue(corpus, candidates, known_amounts)
    propagation = stage3_propagate(
        corpus, candidates, sessions=sessions, active=use_token, min_support=1, eccentricity_margin=1
    )
    return LinkagePipelineResult(candidates=candidates, known_amounts=known_amounts, propagation=propagation)


def _assertions_at_m(
    corpus: Corpus, result: LinkagePipelineResult, m: int
) -> Tuple[int, int, int]:
    """Returns (n_asserted, n_correct, ledger_size) at corroboration >= m."""
    ledger = corpus.ledger
    n_correct = 0
    n_asserted = 0
    for t in range(ledger.size):
        cand = result.candidates.get(t)
        asserted: Optional[int] = None
        if cand is not None and len(cand) == 1:
            asserted = int(cand[0])
        elif t in result.propagation.mapped_image:
            if result.propagation.support.get(t, 0) >= m:
                asserted = result.propagation.mapped_image[t]
        if asserted is not None:
            n_asserted += 1
            if asserted == int(ledger.directory_index[t]):
                n_correct += 1
    return n_asserted, n_correct, ledger.size


def score_pipeline(corpus: Corpus, result: LinkagePipelineResult, m_values: Sequence[int] = (1, 2, 3)) -> Dict[int, Dict[str, float]]:
    out = {}
    for m in m_values:
        n_asserted, n_correct, n_ledger = _assertions_at_m(corpus, result, m)
        out[m] = {
            "n_asserted": n_asserted,
            "n_correct": n_correct,
            "pct_of_ledger": 100.0 * n_correct / n_ledger if n_ledger else 0.0,
            "precision": (n_correct / n_asserted) if n_asserted else 0.0,
        }
    return out


ABLATION_COMBOS: Tuple[Tuple[str, bool, bool, bool], ...] = (
    ("S", True, False, False),
    ("A", False, True, False),
    ("T", False, False, True),
    ("S+A", True, True, False),
    ("S+T", True, False, True),
    ("A+T", False, True, True),
    ("S+A+T", True, True, True),
)


def run_ablation(
    corpus: Corpus, profile: Optional[ProfileColumns] = None, m_values: Sequence[int] = (1, 2, 3)
) -> Dict[str, Dict]:
    profile = profile if profile is not None else disclosure_profiles(corpus)["P2_typical"]
    out: Dict[str, Dict] = {}
    for name, use_s, use_a, use_t in ABLATION_COMBOS:
        result = run_pipeline(corpus, profile, use_s, use_a, use_t)
        scores = score_pipeline(corpus, result, m_values=m_values)
        out[name] = {"scores": {str(m): v for m, v in scores.items()}}
    return out


def median_candidate_set_size(corpus: Corpus, profile: ProfileColumns) -> float:
    candidates = stage1_candidates(corpus, profile, active=True)
    sizes = [len(c) for c in candidates.values()]
    return float(np.median(sizes))


def run_disclosure_profile_sweep(corpus: Corpus, m: int = 2) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for name, profile in disclosure_profiles(corpus).items():
        schema_only = run_pipeline(corpus, profile, True, False, False)
        full = run_pipeline(corpus, profile, True, True, True)
        schema_scores = score_pipeline(corpus, schema_only, m_values=(m,))[m]
        full_scores = score_pipeline(corpus, full, m_values=(m,))[m]
        out[name] = {
            "median_candidate_set_size": median_candidate_set_size(corpus, profile),
            "schema_only_pct_of_ledger": schema_scores["pct_of_ledger"],
            "full_pipeline_pct_of_ledger": full_scores["pct_of_ledger"],
        }
    return out


def run_observation_growth_sweep(
    corpus: Corpus, session_counts: Sequence[int], m: int = 2
) -> List[Dict[str, float]]:
    profile = disclosure_profiles(corpus)["P2_typical"]
    all_sessions = corpus.workload.sessions
    out: List[Dict[str, float]] = []
    for n in session_counts:
        n = min(n, len(all_sessions))
        prefix = all_sessions[:n]
        result = run_pipeline(corpus, profile, True, True, True, sessions=prefix)
        scores = score_pipeline(corpus, result, m_values=(m,))[m]
        out.append(
            {
                "sessions_observed": n,
                "accounts_reidentified": scores["n_correct"],
                "amounts_recovered_exactly": len(result.known_amounts),
            }
        )
    return out


def run_rho_sweep(
    corpus: Corpus, rho_values: Sequence[float], n_sessions: int, m: int = 2
) -> List[Dict[str, float]]:
    from corpus import rebuild_workload

    profile = disclosure_profiles(corpus)["P2_typical"]
    out: List[Dict[str, float]] = []
    for rho in rho_values:
        workload = rebuild_workload(corpus, n_sessions=n_sessions, rho=rho)
        schema_only = run_pipeline(corpus, profile, True, False, False, sessions=workload.sessions)
        full = run_pipeline(corpus, profile, True, True, True, sessions=workload.sessions)
        schema_scores = score_pipeline(corpus, schema_only, m_values=(m,))[m]
        full_scores = score_pipeline(corpus, full, m_values=(m,))[m]
        out.append(
            {
                "rho": rho,
                "schema_only_pct_of_ledger": schema_scores["pct_of_ledger"],
                "total_pct_of_ledger": full_scores["pct_of_ledger"],
            }
        )
    return out


def run(corpus: Corpus) -> Dict[str, object]:
    profile = disclosure_profiles(corpus)["P2_typical"]
    ablation = run_ablation(corpus, profile=profile)
    profile_sweep = run_disclosure_profile_sweep(corpus)

    max_sessions = len(corpus.workload.sessions)
    growth_points = sorted(set(
        min(max_sessions, x) for x in (25, 50, 100, max(100, max_sessions // 2), max_sessions)
    ))
    growth = run_observation_growth_sweep(corpus, growth_points)

    rho_values = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    rho_sweep = run_rho_sweep(corpus, rho_values, n_sessions=max_sessions)

    return {
        "disclosure_profile_used_for_ablation": "P2_typical",
        "ablation": ablation,
        "disclosure_profile_sweep": profile_sweep,
        "observation_growth_sweep": growth,
        "rho_sweep": rho_sweep,
    }
