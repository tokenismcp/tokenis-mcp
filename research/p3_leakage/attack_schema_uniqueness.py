# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Attribute-combination re-identification, reproducing paper Section 5
("Attribute-combination re-identification") and Figures 1-2.

Two measurements, both against the public directory `U` as the search
population and the ledger `D` as the set of rows whose exposure is reported:

1. `uniqueness_by_subset_size`: for `t = 1..7` attributes drawn from the
   7-attribute quasi-identifier space, the fraction of ledger accounts that
   are uniquely determined inside `U`, for (a) the most-informative subset of
   each size and (b) the median subset of that size (median taken over the
   distribution of per-subset fractions, matching the paper's framing that
   the exposure depends on *which* columns, not how many).

2. `generalization_ladder`: a six-rung ladder (g=0..5) that coarsens every
   attribute simultaneously, tracking uniqueness within `U`, isolability
   within the ledger (unique combination within `D` itself -- the quantity
   Section 7 shows governs differential isolation), and the count of distinct
   occupied attribute-combinations ("groups still addressable").

See `corpus.py`'s module docstring for the honesty note: exact percentages
are not expected to match the paper's published 41.4%/91.5%/etc. -- only the
qualitative shape (industry+locality being highly informative, uniqueness
falling steeply with generalization, etc.) is expected to transfer.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import numpy as np

from corpus import ATTRIBUTES, Corpus, GeneralizationHierarchy

# Cardinality upper bounds for each attribute's *finest* encoding, used to
# build a collision-free combined key via mixed-radix ravel. Must match the
# actual value ranges produced by corpus.generate_directory.
from corpus import (
    N_SUBCLASS,
    N_LOCALITY,
    N_REVENUE_BANDS,
    N_HEADCOUNT_BANDS,
    N_FOUNDING_BANDS,
    N_BANKS,
)

_ATTR_CARDINALITY = {
    "industry_subclass": N_SUBCLASS,
    "locality": N_LOCALITY,
    "revenue_band": N_REVENUE_BANDS,
    "headcount_band": N_HEADCOUNT_BANDS,
    "founding_year_band": N_FOUNDING_BANDS,
    "listing_status": 2,
    "main_bank": N_BANKS,
}


def _combined_key(columns: Sequence[np.ndarray], cardinalities: Sequence[int]) -> np.ndarray:
    """Collision-free integer key for a tuple of attribute columns."""
    key = np.zeros_like(columns[0], dtype=np.int64)
    for col, card in zip(columns, cardinalities):
        key = key * card + col.astype(np.int64)
    return key


def _fraction_unique_in_population(
    directory_cols: Sequence[np.ndarray],
    cardinalities: Sequence[int],
    ledger_directory_index: np.ndarray,
) -> float:
    key = _combined_key(directory_cols, cardinalities)
    values, counts = np.unique(key, return_counts=True)
    count_of = dict(zip(values.tolist(), counts.tolist()))
    ledger_keys = key[ledger_directory_index]
    unique_flags = np.array([count_of[k] == 1 for k in ledger_keys.tolist()])
    return float(unique_flags.mean())


@dataclass
class SubsetSizeResult:
    t: int
    most_informative_fraction: float
    most_informative_attrs: Tuple[str, ...]
    median_fraction: float
    n_subsets: int


def uniqueness_by_subset_size(corpus: Corpus, attributes: Sequence[str] = ATTRIBUTES) -> List[SubsetSizeResult]:
    directory = corpus.directory
    ledger_idx = corpus.ledger.directory_index
    cols = {a: directory.attribute(a) for a in attributes}
    cards = {a: _ATTR_CARDINALITY[a] for a in attributes}

    results: List[SubsetSizeResult] = []
    for t in range(1, len(attributes) + 1):
        fractions: List[float] = []
        best_frac = -1.0
        best_subset: Tuple[str, ...] = ()
        for subset in itertools.combinations(attributes, t):
            frac = _fraction_unique_in_population(
                [cols[a] for a in subset], [cards[a] for a in subset], ledger_idx
            )
            fractions.append(frac)
            if frac > best_frac:
                best_frac = frac
                best_subset = subset
        results.append(
            SubsetSizeResult(
                t=t,
                most_informative_fraction=best_frac,
                most_informative_attrs=best_subset,
                median_fraction=float(np.median(fractions)),
                n_subsets=len(fractions),
            )
        )
    return results


@dataclass
class LadderRung:
    g: int
    unique_in_directory_pct: float
    isolable_in_ledger_pct: float
    groups_addressable: int


def _coarsened_columns(corpus: Corpus, g: int, subject: str) -> Dict[str, np.ndarray]:
    gen = corpus.generalization
    directory = corpus.directory
    out: Dict[str, np.ndarray] = {}
    industry_level = min(g, gen.levels_available("industry_subclass") - 1)
    out["industry_subclass"] = gen.industry_at(directory.industry_subclass, industry_level)

    locality_level = min(g, gen.levels_available("locality") - 1)
    out["locality"] = gen.locality_at(directory.locality, locality_level)

    for band_attr, n_fine in (
        ("revenue_band", N_REVENUE_BANDS),
        ("headcount_band", N_HEADCOUNT_BANDS),
        ("founding_year_band", N_FOUNDING_BANDS),
    ):
        level = min(g, gen.levels_available(band_attr) - 1)
        out[band_attr] = gen.band_at(directory.attribute(band_attr), n_fine, level)

    for cat_attr in ("listing_status", "main_bank"):
        level = min(g, gen.levels_available(cat_attr) - 1)
        out[cat_attr] = gen.categorical_at(directory.attribute(cat_attr), level)

    return out


def generalization_ladder(corpus: Corpus, attributes: Sequence[str] = ATTRIBUTES) -> List[LadderRung]:
    ledger_idx = corpus.ledger.directory_index
    rungs: List[LadderRung] = []
    for g in range(0, 6):
        coarse = _coarsened_columns(corpus, g, subject="ladder")
        cols = [coarse[a] for a in attributes]
        # Cardinalities after coarsening are bounded by the finest cardinality
        # (coarsening only maps into a smaller or equal range), which keeps
        # the combined key collision-free.
        cards = [_ATTR_CARDINALITY[a] for a in attributes]

        key_dir = _combined_key(cols, cards)
        values, counts = np.unique(key_dir, return_counts=True)
        count_in_dir = dict(zip(values.tolist(), counts.tolist()))
        ledger_keys_dir = key_dir[ledger_idx]
        unique_in_dir = np.array([count_in_dir[k] == 1 for k in ledger_keys_dir.tolist()])

        ledger_cols = [c[ledger_idx] for c in cols]
        key_ledger = _combined_key(ledger_cols, cards)
        lv, lc = np.unique(key_ledger, return_counts=True)
        count_in_ledger = dict(zip(lv.tolist(), lc.tolist()))
        isolable_in_ledger = np.array([count_in_ledger[k] == 1 for k in key_ledger.tolist()])

        rungs.append(
            LadderRung(
                g=g,
                unique_in_directory_pct=float(unique_in_dir.mean() * 100.0),
                isolable_in_ledger_pct=float(isolable_in_ledger.mean() * 100.0),
                groups_addressable=int(len(values)),
            )
        )
    return rungs


def industry_locality_cell_occupancy(corpus: Corpus) -> Dict[str, float]:
    """Section 4.1's cell-occupancy arithmetic, computed on this corpus."""
    directory = corpus.directory
    key = _combined_key(
        [directory.industry_subclass, directory.locality], [N_SUBCLASS, N_LOCALITY]
    )
    values, counts = np.unique(key, return_counts=True)
    occupied_cells = int(len(values))
    singleton_cells = int((counts == 1).sum())
    firms_alone = int(counts[counts == 1].sum())
    return {
        "total_cells": float(N_SUBCLASS * N_LOCALITY),
        "occupied_cells": float(occupied_cells),
        "singleton_cell_share_pct": float(100.0 * singleton_cells / occupied_cells) if occupied_cells else 0.0,
        "firms_alone_in_cell_pct": float(100.0 * firms_alone / directory.size),
    }


def run(corpus: Corpus) -> Dict[str, object]:
    subset_results = uniqueness_by_subset_size(corpus)
    ladder_results = generalization_ladder(corpus)
    occupancy = industry_locality_cell_occupancy(corpus)
    return {
        "subset_size": [
            {
                "t": r.t,
                "most_informative_fraction_pct": r.most_informative_fraction * 100.0,
                "most_informative_attrs": list(r.most_informative_attrs),
                "median_fraction_pct": r.median_fraction * 100.0,
                "n_subsets": r.n_subsets,
            }
            for r in subset_results
        ],
        "generalization_ladder": [
            {
                "g": r.g,
                "unique_in_directory_pct": r.unique_in_directory_pct,
                "isolable_in_ledger_pct": r.isolable_in_ledger_pct,
                "groups_addressable": r.groups_addressable,
            }
            for r in ladder_results
        ],
        "cell_occupancy": occupancy,
    }
