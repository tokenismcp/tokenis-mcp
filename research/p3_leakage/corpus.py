# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic corpus generator reproducing Section 4 of the P3 paper.

"What a Token Does Not Hide: Leakage Quantification and Disclosure Budgets
for LLM Gateways over Corporate Ledgers" (J1729Labs, 2026), `papers/p3-leakage-
quantification/paper.pdf`, Section 4 ("Corpus").

HONESTY NOTE (read this before trusting a number out of this module)
----------------------------------------------------------------------
The paper's Availability section (App. B) commits its authors to releasing a
corpus generator with fixed seeds (corpus seed 20260920, workload seed 7), but
the paper does not publish the literal source of that generator -- only the
seeds, the published constants it must use, and a description in prose of the
calibrated marginal shapes. This module is therefore a **faithful
re-implementation of the described method**, not a byte-for-byte reproduction
of the paper's own pipeline. Concretely:

  * PUBLISHED (verbatim, hardcoded, cited to Section 4.1): the Korean Standard
    Industrial Classification level cardinalities (1,196 / 495 / 232 / 77 /
    21) and the 229 si/gun/gu locality codes. These numbers are not ours; we
    do not invent them and do not fit anything to them.
  * CALIBRATED (shape chosen to match a *qualitative* published property, not
    a published joint distribution -- because no joint distribution at this
    resolution is public): capital-area concentration (~50%), heavy-tailed
    industry popularity (Dirichlet/Zipf-style), log-normal revenue, headcount
    correlated with revenue, listing/audit status monotone in size, ledger
    sampling biased toward larger/audited/capital-area firms.
  * INVENTED (ours, not calibrated to anything): which firms exist, which of
    them are on the vendor's ledger, what they transact, which firms meet in
    public procurement records, what an analyst asks on a given day. The
    *hierarchical bucketing* used to assign e.g. subclass -> class -> group is
    also invented (contiguous, deterministic) since only the level counts are
    published, not the assignment.

Every one of the above categories mirrors the spirit of the paper's own
Table 1 ("Provenance of every class of number in this paper", Section 4.4).
Because the joint distribution is generated rather than calibrated, computed
downstream percentages (re-identification rates, isolability, etc.) are
expected to land in the *same qualitative range and exhibit the same
qualitative effects* as the paper's headline numbers -- not be numerically
identical to them. See `verify_claims.py` for the standard this repository
holds itself to (internal determinism and consistency, not numeric parity
with the published paper).

All randomness in this module flows from two seeded `numpy.random.Generator`
instances (corpus_seed=20260920, workload_seed=7 by default, matching the
paper's App. B) -- never from a bare, unseeded `numpy.random` call.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Published constants (Section 4.1). Do not "tune" these -- they are the
# Korean Standard Industrial Classification (11th revision) level cardinalities
# and the count of si/gun/gu administrative locality codes. Source: Statistics
# Korea (KSIC 11th revision); Ministry of the Interior and Safety locality
# code table (226 basic local governments + Jeju's 2 administrative cities +
# Sejong = 229).
# ---------------------------------------------------------------------------
N_SUBCLASS = 1196   # 5-digit KSIC subclasses
N_CLASS = 495        # 4-digit KSIC classes
N_GROUP = 232         # 3-digit KSIC groups
N_DIVISION = 77        # 2-digit KSIC divisions
N_SECTION = 21          # KSIC sections
N_LOCALITY = 229        # si/gun/gu codes (226 + Jeju x2 + Sejong)
N_REGION = 17           # invented coarsening of locality -> province-like region

INDUSTRY_CELLS = N_SUBCLASS * N_LOCALITY  # 273,884, cited in Section 4.1

DEFAULT_CORPUS_SEED = 20260920
DEFAULT_WORKLOAD_SEED = 7

# Analyst workload templates (Section 4.3).
TEMPLATE_SINGLE = "single_account_lookup"
TEMPLATE_RECEIVABLES = "receivables_review"
TEMPLATE_INDUSTRY_ROLLUP = "industry_rollup"
TEMPLATE_REGIONAL_ROLLUP = "regional_rollup"
TEMPLATE_SUPPLY_CHAIN = "supply_chain_trace"
TEMPLATE_CHURN = "churn_watchlist"
TEMPLATES = (
    TEMPLATE_SINGLE,
    TEMPLATE_RECEIVABLES,
    TEMPLATE_INDUSTRY_ROLLUP,
    TEMPLATE_REGIONAL_ROLLUP,
    TEMPLATE_SUPPLY_CHAIN,
    TEMPLATE_CHURN,
)

# The seven public/quasi-identifying attributes used throughout Sections 5-9.
ATTRIBUTES: Tuple[str, ...] = (
    "industry_subclass",
    "locality",
    "revenue_band",
    "headcount_band",
    "founding_year_band",
    "listing_status",
    "main_bank",
)


def _contiguous_hierarchy(n_children: int, n_parents: int) -> np.ndarray:
    """Deterministic, invented (not published) child->parent bucketing.

    Published sources give only the level *cardinalities*; the specific
    assignment of e.g. which of the 1,196 subclasses fall under which of the
    495 classes is not something we reproduce (nor could we, without the
    actual KSIC concordance table). We instead bucket contiguously and
    evenly, which preserves the cardinalities exactly and is deterministic
    (no randomness), documented here as INVENTED per the module docstring.
    """
    idx = np.arange(n_children)
    return np.minimum(n_parents - 1, (idx * n_parents) // n_children)


@dataclass(frozen=True)
class IndustryHierarchy:
    """subclass -> class -> group -> division -> section, contiguous buckets."""

    subclass_to_class: np.ndarray
    class_to_group: np.ndarray
    group_to_division: np.ndarray
    division_to_section: np.ndarray

    @staticmethod
    def build() -> "IndustryHierarchy":
        return IndustryHierarchy(
            subclass_to_class=_contiguous_hierarchy(N_SUBCLASS, N_CLASS),
            class_to_group=_contiguous_hierarchy(N_CLASS, N_GROUP),
            group_to_division=_contiguous_hierarchy(N_GROUP, N_DIVISION),
            division_to_section=_contiguous_hierarchy(N_DIVISION, N_SECTION),
        )

    def class_of(self, subclass: np.ndarray) -> np.ndarray:
        return self.subclass_to_class[subclass]

    def group_of(self, subclass: np.ndarray) -> np.ndarray:
        return self.class_to_group[self.class_of(subclass)]

    def division_of(self, subclass: np.ndarray) -> np.ndarray:
        return self.group_to_division[self.group_of(subclass)]

    def section_of(self, subclass: np.ndarray) -> np.ndarray:
        return self.division_to_section[self.division_of(subclass)]


LOCALITY_TO_REGION = _contiguous_hierarchy(N_LOCALITY, N_REGION)
# First third of locality codes (by our own deterministic ordering) are
# treated as "capital area" -- an invented stand-in for Seoul/Incheon/
# Gyeonggi, calibrated only in that it yields the ~50% concentration the
# paper describes when combined with per-firm capital-area weighting below.
N_CAPITAL_LOCALITIES = max(1, N_LOCALITY // 5)
CAPITAL_LOCALITIES = np.arange(N_CAPITAL_LOCALITIES)
NONCAPITAL_LOCALITIES = np.arange(N_CAPITAL_LOCALITIES, N_LOCALITY)

N_BANKS = 20  # invented count of "main bank" codes


@dataclass
class GeneralizationHierarchy:
    """Per-attribute chains of coarsenings used by the g=0..5 ladder (Fig. 2)
    and by the P0-P3 disclosure profiles (Section 6.5).

    Level 0 is always the finest (raw) encoding. Each subsequent level is a
    coarser grouping. `n_levels[attr]` is how many rungs that attribute has
    before it bottoms out (stays constant thereafter).
    """

    hierarchy: IndustryHierarchy

    def industry_at(self, subclass: np.ndarray, level: int) -> np.ndarray:
        level = min(level, 4)
        if level == 0:
            return subclass
        if level == 1:
            return self.hierarchy.class_of(subclass)
        if level == 2:
            return self.hierarchy.group_of(subclass)
        if level == 3:
            return self.hierarchy.division_of(subclass)
        return self.hierarchy.section_of(subclass)

    @staticmethod
    def locality_at(locality: np.ndarray, level: int) -> np.ndarray:
        level = min(level, 2)
        if level == 0:
            return locality
        if level == 1:
            return LOCALITY_TO_REGION[locality]
        return np.zeros_like(locality)

    @staticmethod
    def band_at(band: np.ndarray, n_fine: int, level: int) -> np.ndarray:
        level = min(level, 2)
        if level == 0:
            return band
        if level == 1:
            coarse_bins = max(2, n_fine // 4)
            return np.minimum(coarse_bins - 1, band * coarse_bins // n_fine)
        return np.zeros_like(band)

    @staticmethod
    def categorical_at(value: np.ndarray, level: int) -> np.ndarray:
        # listing_status / main_bank: one coarsening step down to "dropped".
        if level <= 0:
            return value
        return np.zeros_like(value)

    def levels_available(self, attr: str) -> int:
        return {
            "industry_subclass": 5,
            "locality": 3,
            "revenue_band": 3,
            "headcount_band": 3,
            "founding_year_band": 3,
            "listing_status": 2,
            "main_bank": 2,
        }[attr]


N_REVENUE_BANDS = 20
N_HEADCOUNT_BANDS = 20
N_FOUNDING_BANDS = 12  # decade-ish buckets from 1960..2025+


@dataclass
class Directory:
    """The public directory U of |U| firms (Section 3.3)."""

    size: int
    industry_subclass: np.ndarray
    locality: np.ndarray
    capital_area: np.ndarray
    revenue: np.ndarray
    headcount: np.ndarray
    founding_year: np.ndarray
    listing_status: np.ndarray
    audited: np.ndarray
    main_bank: np.ndarray
    revenue_band: np.ndarray
    headcount_band: np.ndarray
    founding_year_band: np.ndarray

    def attribute(self, name: str) -> np.ndarray:
        return getattr(self, name)

    def attribute_matrix(self, attrs: Sequence[str] = ATTRIBUTES) -> np.ndarray:
        return np.stack([self.attribute(a) for a in attrs], axis=1)


@dataclass
class Ledger:
    """The vendor's book D: `size` accounts drawn from the directory."""

    directory_index: np.ndarray  # ledger row -> directory row, shape (size,)
    amount: np.ndarray  # private quantity x_i, shape (size,)
    size: int = field(init=False)

    def __post_init__(self) -> None:
        self.size = int(self.directory_index.shape[0])


@dataclass
class PublicGraph:
    """Public relationship graph over the directory (Section 4.2)."""

    edges: np.ndarray  # shape (m, 2), directory indices, i < j
    n_firms: int
    _adjacency_cache: Optional[Dict[int, set]] = field(default=None, repr=False, compare=False)

    def adjacency(self) -> Dict[int, set]:
        # Memoized: this is rebuilt on first call and reused thereafter. The
        # attack/defense pipelines call `stage3_propagate` (and therefore
        # this method) many times per sweep point -- rebuilding an O(edges)
        # dict from scratch every call was the dominant cost of the D1 epoch
        # sweep before this cache was added.
        if self._adjacency_cache is None:
            adj: Dict[int, set] = {}
            for a, b in self.edges:
                adj.setdefault(int(a), set()).add(int(b))
                adj.setdefault(int(b), set()).add(int(a))
            self._adjacency_cache = adj
        return self._adjacency_cache


@dataclass
class Session:
    id: int
    template: str
    members: Tuple[int, ...]  # ledger indices
    filter: Optional[Dict[str, int]]  # exact attribute constraints, or None
    aggregate: float
    is_cluster_echo: bool  # True if drawn from the public graph (rho branch)


@dataclass
class Workload:
    sessions: List[Session]
    rho: float


@dataclass
class Corpus:
    seed_corpus: int
    seed_workload: int
    hierarchy: IndustryHierarchy
    generalization: GeneralizationHierarchy
    directory: Directory
    ledger: Ledger
    public_graph: PublicGraph
    workload: Workload


def _quantile_bands(values: np.ndarray, n_bands: int) -> np.ndarray:
    edges = np.quantile(values, np.linspace(0, 1, n_bands + 1)[1:-1])
    return np.searchsorted(edges, values, side="right").astype(np.int64)


def _logistic(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


def generate_directory(rng: np.random.Generator, size: int, hierarchy: IndustryHierarchy) -> Directory:
    # Heavy-tailed industry popularity: Dirichlet draw over subclasses gives a
    # skewed probability vector (CALIBRATED shape, not a published
    # distribution) which we then sample from -- a standard way to produce a
    # Zipf-like heavy tail without hardcoding an arbitrary exponent.
    industry_weights = rng.dirichlet(np.full(N_SUBCLASS, 0.25))
    industry_subclass = rng.choice(N_SUBCLASS, size=size, p=industry_weights)

    capital_area = rng.random(size) < 0.5  # calibrated: ~50% capital-area concentration
    locality = np.empty(size, dtype=np.int64)
    n_capital = int(capital_area.sum())
    locality[capital_area] = rng.choice(CAPITAL_LOCALITIES, size=n_capital)
    locality[~capital_area] = rng.choice(NONCAPITAL_LOCALITIES, size=size - n_capital)

    log_revenue = rng.normal(loc=np.log(3e9), scale=1.6, size=size)  # calibrated log-normal shape
    revenue = np.exp(log_revenue)

    headcount = np.exp(0.6 * log_revenue - 4.0 + rng.normal(0, 0.5, size=size))
    headcount = np.clip(np.round(headcount), 1, None)

    founding_year = rng.integers(1960, 2026, size=size)

    # Listing status: monotone in size (logistic in log-revenue), calibrated shape.
    listing_score = _logistic((log_revenue - np.log(5e10)) / 1.2)
    listing_status = (rng.random(size) < listing_score).astype(np.int64)

    audit_score = _logistic((log_revenue - np.log(1e10)) / 1.0)
    audited = rng.random(size) < audit_score

    main_bank = rng.integers(0, N_BANKS, size=size)

    revenue_band = _quantile_bands(revenue, N_REVENUE_BANDS)
    headcount_band = _quantile_bands(headcount, N_HEADCOUNT_BANDS)
    founding_year_band = np.minimum(
        N_FOUNDING_BANDS - 1, (founding_year - 1960) // 6
    ).astype(np.int64)

    return Directory(
        size=size,
        industry_subclass=industry_subclass,
        locality=locality,
        capital_area=capital_area,
        revenue=revenue,
        headcount=headcount,
        founding_year=founding_year,
        listing_status=listing_status,
        audited=audited,
        main_bank=main_bank,
        revenue_band=revenue_band,
        headcount_band=headcount_band,
        founding_year_band=founding_year_band,
    )


def generate_ledger(rng: np.random.Generator, directory: Directory, size: int) -> Ledger:
    size = min(size, directory.size)
    weight = (
        (directory.revenue / directory.revenue.mean())
        * np.where(directory.audited, 2.0, 1.0)
        * np.where(directory.capital_area, 1.5, 1.0)
    )
    p = weight / weight.sum()
    idx = rng.choice(directory.size, size=size, replace=False, p=p)

    log_revenue = np.log(directory.revenue[idx])
    log_amount = 0.95 * log_revenue + rng.normal(0, 0.35, size=size)
    amount = np.exp(log_amount)

    return Ledger(directory_index=idx, amount=amount)


def generate_public_graph(
    rng: np.random.Generator, directory: Directory, n_institutions: Optional[int] = None
) -> PublicGraph:
    """Bipartite firm<->procuring-institution graph, projected to firm-firm
    edges (Section 4.2: "firms co-occur via shared procuring institution").

    Participation probability rises with firm size, per the paper. We model
    only the institution axis (not a separate item-class axis) for
    tractability; this is an explicit simplification of the paper's
    "institution or item class" mechanism, documented here rather than
    silently. It preserves the qualitative property the attacks rely on: a
    sparse public graph whose density scales with firm size and whose
    ledger-restricted edge count is a small fraction of the full graph.
    """
    n = directory.size
    if n_institutions is None:
        n_institutions = max(20, n // 60)

    size_score = _logistic((np.log(directory.revenue) - np.log(directory.revenue).mean()) / 0.8)
    # Expected number of institution-memberships per firm, rising with size.
    lam = 0.2 + 2.5 * size_score
    n_memberships = rng.poisson(lam=lam)
    n_memberships = np.clip(n_memberships, 0, 8)

    institution_weights = rng.dirichlet(np.full(n_institutions, 0.5))

    institution_members: Dict[int, List[int]] = {i: [] for i in range(n_institutions)}
    for firm in range(n):
        k = int(n_memberships[firm])
        if k == 0:
            continue
        insts = rng.choice(n_institutions, size=k, replace=False, p=institution_weights)
        for inst in insts:
            institution_members[int(inst)].append(firm)

    edge_set = set()
    max_pairs_per_institution = 400  # cap to keep projection tractable
    for members in institution_members.values():
        if len(members) < 2:
            continue
        members_arr = np.array(members)
        if len(members) > 60:
            # Large institutions (e.g. a major public buyer) are subsampled
            # when projecting pairs, rather than producing a near-complete
            # subgraph -- an explicit tractability simplification.
            n_pairs = min(max_pairs_per_institution, len(members) * 3)
            ai = rng.integers(0, len(members), size=n_pairs)
            bi = rng.integers(0, len(members), size=n_pairs)
            for a, b in zip(ai, bi):
                if a == b:
                    continue
                fa, fb = int(members_arr[a]), int(members_arr[b])
                if fa == fb:
                    continue
                edge_set.add((min(fa, fb), max(fa, fb)))
        else:
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    fa, fb = members[i], members[j]
                    edge_set.add((min(fa, fb), max(fa, fb)))

    if edge_set:
        edges = np.array(sorted(edge_set), dtype=np.int64)
    else:
        edges = np.empty((0, 2), dtype=np.int64)
    return PublicGraph(edges=edges, n_firms=n)


def _zipf_probabilities(rng: np.random.Generator, n: int, s: float = 1.3) -> np.ndarray:
    order = rng.permutation(n)
    ranks = np.empty(n, dtype=np.float64)
    ranks[order] = np.arange(1, n + 1)
    weights = 1.0 / np.power(ranks, s)
    return weights / weights.sum()


def generate_workload(
    rng: np.random.Generator,
    directory: Directory,
    ledger: Ledger,
    public_graph: PublicGraph,
    n_sessions: int,
    rho: float,
) -> Workload:
    """Section 4.3: 1,600 analyst sessions over six templates."""
    pop_weights = _zipf_probabilities(rng, ledger.size)
    adjacency = public_graph.adjacency()
    ledger_dir_idx = ledger.directory_index
    dir_to_ledger = {int(d): l for l, d in enumerate(ledger_dir_idx)}

    template_weights = np.array([0.30, 0.15, 0.15, 0.15, 0.15, 0.10])
    templates = rng.choice(len(TEMPLATES), size=n_sessions, p=template_weights)

    sessions: List[Session] = []
    for sid in range(n_sessions):
        template = TEMPLATES[templates[sid]]
        is_echo = False
        filt: Optional[Dict[str, int]] = None

        if template == TEMPLATE_SINGLE:
            member = int(rng.choice(ledger.size, p=pop_weights))
            members = (member,)

        elif template == TEMPLATE_RECEIVABLES:
            seed = int(rng.choice(ledger.size, p=pop_weights))
            k = int(rng.integers(2, 5))
            extra = rng.choice(ledger.size, size=k, replace=False)
            members = tuple(sorted(set([seed, *extra.tolist()])))

        elif template == TEMPLATE_INDUSTRY_ROLLUP:
            level = int(rng.integers(1, 4))  # class/group/division constraint
            seed_dir = int(rng.choice(ledger_dir_idx))
            value = int(
                GeneralizationHierarchy(hierarchy=IndustryHierarchy.build()).industry_at(
                    np.array([directory.industry_subclass[seed_dir]]), level
                )[0]
            )
            gen = GeneralizationHierarchy(hierarchy=IndustryHierarchy.build())
            coarse = gen.industry_at(directory.industry_subclass[ledger_dir_idx], level)
            members = tuple(np.nonzero(coarse == value)[0].tolist())
            filt = {"industry_level": level, "industry_value": value}
            if not members:
                members = (int(rng.choice(ledger.size, p=pop_weights)),)

        elif template == TEMPLATE_REGIONAL_ROLLUP:
            level = int(rng.integers(1, 3))
            seed_dir = int(rng.choice(ledger_dir_idx))
            value = int(
                GeneralizationHierarchy.locality_at(
                    np.array([directory.locality[seed_dir]]), level
                )[0]
            )
            coarse = GeneralizationHierarchy.locality_at(directory.locality[ledger_dir_idx], level)
            members = tuple(np.nonzero(coarse == value)[0].tolist())
            filt = {"locality_level": level, "locality_value": value}
            if not members:
                members = (int(rng.choice(ledger.size, p=pop_weights)),)

        elif template == TEMPLATE_SUPPLY_CHAIN:
            seed_ledger = int(rng.choice(ledger.size, p=pop_weights))
            if rng.random() < rho:
                seed_dir = int(ledger_dir_idx[seed_ledger])
                neigh = adjacency.get(seed_dir, set())
                neigh_ledger = [dir_to_ledger[n] for n in neigh if n in dir_to_ledger]
                if neigh_ledger:
                    k = min(len(neigh_ledger), int(rng.integers(1, 4)))
                    chosen = rng.choice(neigh_ledger, size=k, replace=False)
                    members = tuple(sorted(set([seed_ledger, *chosen.tolist()])))
                    is_echo = True
                else:
                    members = (seed_ledger,)
            else:
                k = int(rng.integers(1, 4))
                extra = rng.choice(ledger.size, size=k, replace=False)
                members = tuple(sorted(set([seed_ledger, *extra.tolist()])))

        else:  # TEMPLATE_CHURN
            k = int(rng.integers(2, 6))
            if rng.random() < rho:
                seed_ledger = int(rng.choice(ledger.size, p=pop_weights))
                seed_dir = int(ledger_dir_idx[seed_ledger])
                neigh = adjacency.get(seed_dir, set())
                neigh_ledger = [dir_to_ledger[n] for n in neigh if n in dir_to_ledger]
                if neigh_ledger:
                    kk = min(len(neigh_ledger), k)
                    chosen = rng.choice(neigh_ledger, size=kk, replace=False)
                    members = tuple(sorted(set([seed_ledger, *chosen.tolist()])))
                    is_echo = True
                else:
                    members = tuple(sorted(set(rng.choice(ledger.size, size=k, replace=False).tolist())))
            else:
                members = tuple(sorted(set(rng.choice(ledger.size, size=k, replace=False).tolist())))

        aggregate = float(ledger.amount[list(members)].sum())
        sessions.append(
            Session(
                id=sid,
                template=template,
                members=members,
                filter=filt,
                aggregate=aggregate,
                is_cluster_echo=is_echo,
            )
        )

    return Workload(sessions=sessions, rho=rho)


@dataclass
class CorpusSizes:
    """Sizing profile. The paper's own defaults are `paper_scale()`; a much
    smaller `ci_scale()` profile is used by `verify_claims.py` and the test
    suite so the whole pipeline finishes in well under the 2-minute budget.
    Every attack/defense/budget module is parameterized off `Corpus`, so
    swapping the profile changes nothing about the method being exercised --
    only its wall-clock cost. See `README.md`.
    """

    directory_size: int
    ledger_size: int
    n_sessions: int
    rho: float = 0.60

    @staticmethod
    def paper_scale() -> "CorpusSizes":
        return CorpusSizes(directory_size=40_000, ledger_size=4_000, n_sessions=1_600)

    @staticmethod
    def ci_scale() -> "CorpusSizes":
        return CorpusSizes(directory_size=8_000, ledger_size=500, n_sessions=300)


def build_corpus(
    sizes: Optional[CorpusSizes] = None,
    corpus_seed: int = DEFAULT_CORPUS_SEED,
    workload_seed: int = DEFAULT_WORKLOAD_SEED,
    rho: Optional[float] = None,
) -> Corpus:
    """Build the full synthetic corpus: directory, ledger, public graph, workload.

    Two independent `numpy.random.Generator`s are used, seeded from
    `corpus_seed` and `workload_seed` respectively (Section 4/App. B), so that
    re-running the workload generation alone (e.g. for the rho sweep) never
    perturbs the directory/ledger/graph draw, and vice versa.
    """
    sizes = sizes or CorpusSizes.ci_scale()
    rho = sizes.rho if rho is None else rho

    corpus_rng = np.random.default_rng(corpus_seed)
    workload_rng = np.random.default_rng(workload_seed)

    hierarchy = IndustryHierarchy.build()
    generalization = GeneralizationHierarchy(hierarchy=hierarchy)

    directory = generate_directory(corpus_rng, sizes.directory_size, hierarchy)
    ledger = generate_ledger(corpus_rng, directory, sizes.ledger_size)
    public_graph = generate_public_graph(corpus_rng, directory)
    workload = generate_workload(
        workload_rng, directory, ledger, public_graph, sizes.n_sessions, rho
    )

    return Corpus(
        seed_corpus=corpus_seed,
        seed_workload=workload_seed,
        hierarchy=hierarchy,
        generalization=generalization,
        directory=directory,
        ledger=ledger,
        public_graph=public_graph,
        workload=workload,
    )


def rebuild_workload(corpus: Corpus, n_sessions: int, rho: float, workload_seed: Optional[int] = None) -> Workload:
    """Regenerate only the workload (used by the rho / observation-growth sweeps)."""
    seed = corpus.seed_workload if workload_seed is None else workload_seed
    rng = np.random.default_rng(seed)
    return generate_workload(
        rng, corpus.directory, corpus.ledger, corpus.public_graph, n_sessions, rho
    )
