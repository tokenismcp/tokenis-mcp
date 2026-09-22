# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic corporate ledger generator (paper §4, §8.1: "a synthetic ... corporate
ledger of n = 5,000 firms").

Honesty note: the paper's exact headline figures (e.g. "77.4% of occupied
cross-classification cells hold fewer than k=5 records", "9.8% of records are
uniquely identified by four public attributes alone") depend on an unpublished
exact generator. This module reproduces the same *qualitative* structure --
n = 5,000 firms, a handful of low-cardinality public categorical attributes,
skewed category weights so cross-classification cells are mostly small, and a
protected numeric value per firm -- and reports its own measured statistics
rather than asserting the paper's numbers. See the top-level README for the
full disclaimer.

Every record carries public attributes (region, industry, size band, listed
status) that a gateway catalogue would publish, and protected numeric columns
(revenue, margin, headcount) plus one deliberately unclassified column
(``internal_risk_score``) used to exercise D5 (deny-by-default on unclassified
columns).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import numpy as np

N_FIRMS = 5000
N_REGIONS = 17
N_INDUSTRIES = 21
N_SIZE_BANDS = 5
LISTED_VALUES: Tuple[str, ...] = ("listed", "unlisted")

PUBLIC_ATTRIBUTES: Tuple[str, ...] = ("region", "industry", "size_band", "listed")

# Columns published in the policy catalogue (D5 admits queries about these).
CLASSIFIED_COLUMNS: Tuple[str, ...] = ("revenue", "margin", "headcount")
# Present in the physical schema but deliberately NOT in the catalogue --
# attacks.py's unclassified-column attack (A5) targets this.
UNCLASSIFIED_COLUMN = "internal_risk_score"

DEFAULT_SEED = 1729


@dataclass
class Ledger:
    n: int
    seed: int
    attributes: Dict[str, np.ndarray]  # attr name -> int category-code array, length n
    attribute_categories: Dict[str, List[str]]  # attr name -> category labels
    columns: Dict[str, np.ndarray]  # column name -> float64 array, length n (PROTECTED)
    classified_columns: Tuple[str, ...] = CLASSIFIED_COLUMNS
    unclassified_column: str = UNCLASSIFIED_COLUMN

    def public_attributes(self) -> Dict[str, np.ndarray]:
        """The subset of state that is safe to hand to AdmissionPolicy."""
        return dict(self.attributes)


def _skewed_weights(rng: np.random.Generator, k: int, alpha: float) -> np.ndarray:
    """Dirichlet-skewed category weights (small alpha => more skewed / low-cardinality)."""
    w = rng.dirichlet(np.full(k, alpha))
    return w / w.sum()


def generate_ledger(seed: int = DEFAULT_SEED, n: int = N_FIRMS) -> Ledger:
    """Generate the synthetic ledger with a fixed seed (numpy Generator only).

    Public attributes are drawn from skewed (Dirichlet) marginals so that the
    joint cross-classification is low-cardinality: most occupied cells are
    small and a meaningful fraction of records are unique on their full public
    attribute vector, matching the paper's qualitative premise (§4) without
    claiming to hit its literal percentages.
    """
    rng = np.random.default_rng(seed)

    region_w = _skewed_weights(rng, N_REGIONS, alpha=0.6)
    industry_w = _skewed_weights(rng, N_INDUSTRIES, alpha=0.5)
    size_w = _skewed_weights(rng, N_SIZE_BANDS, alpha=1.5)
    listed_w = np.array([0.22, 0.78])

    region = rng.choice(N_REGIONS, size=n, p=region_w)
    industry = rng.choice(N_INDUSTRIES, size=n, p=industry_w)
    size_band = rng.choice(N_SIZE_BANDS, size=n, p=size_w)
    listed = rng.choice(len(LISTED_VALUES), size=n, p=listed_w)

    attributes = {
        "region": region,
        "industry": industry,
        "size_band": size_band,
        "listed": listed,
    }
    attribute_categories = {
        "region": [f"region_{i:02d}" for i in range(N_REGIONS)],
        "industry": [f"industry_{i:02d}" for i in range(N_INDUSTRIES)],
        "size_band": [f"size_{i}" for i in range(N_SIZE_BANDS)],
        "listed": list(LISTED_VALUES),
    }

    # Protected numeric columns. Revenue is log-normal with location driven by
    # size band (larger size band => larger typical revenue), matching the
    # paper's "revenue is log-normal with location driven by size band" (§8.1).
    size_location = 12.0 + 1.1 * size_band  # log-space location, revenue-scale
    revenue = rng.lognormal(mean=size_location, sigma=0.8, size=n)

    margin = np.clip(rng.normal(loc=0.12, scale=0.06, size=n), -0.3, 0.6)
    headcount = np.clip(
        rng.lognormal(mean=2.5 + 0.6 * size_band, sigma=0.7, size=n), 1, None
    ).round()

    # Deliberately unclassified column: present in the physical schema, never
    # added to any AdmissionPolicy's catalogue.
    internal_risk_score = np.clip(rng.normal(loc=50, scale=15, size=n), 0, 100)

    columns = {
        "revenue": revenue,
        "margin": margin,
        "headcount": headcount,
        UNCLASSIFIED_COLUMN: internal_risk_score,
    }

    return Ledger(
        n=n,
        seed=seed,
        attributes=attributes,
        attribute_categories=attribute_categories,
        columns=columns,
    )


def cross_classification_stats(ledger: Ledger, k: int = 5) -> Dict[str, float]:
    """Measure the low-cardinality structure the admission policy has to contend with.

    Returns occupied-cell count, the fraction of occupied cells with fewer
    than k records, and the fraction of records uniquely identified by the
    full public attribute vector -- the same two headline quantities the
    paper reports (§4), computed on THIS generator's population rather than
    asserted to match the paper's figures.
    """
    n = ledger.n
    keys = np.stack([ledger.attributes[a] for a in PUBLIC_ATTRIBUTES], axis=1)
    # Encode each record's full attribute tuple as a single integer key.
    bases = [len(ledger.attribute_categories[a]) for a in PUBLIC_ATTRIBUTES]
    combined = np.zeros(n, dtype=np.int64)
    for col in range(keys.shape[1]):
        combined = combined * bases[col] + keys[:, col]

    _, inverse, counts = np.unique(combined, return_inverse=True, return_counts=True)
    occupied_cells = len(counts)
    cells_below_k = int(np.sum(counts < k))
    records_unique = int(np.sum(counts[inverse] == 1))

    return {
        "n": n,
        "occupied_cells": occupied_cells,
        "cells_below_k_fraction": cells_below_k / occupied_cells if occupied_cells else 0.0,
        "records_unique_fraction": records_unique / n if n else 0.0,
    }


def unique_record_indices(ledger: Ledger) -> np.ndarray:
    """Indices of records that are unique on their full public attribute vector.

    These are exactly the records for which a conjunction psi_t with
    C_psi_t = {t} exists (Proposition 4's hypothesis), so this is the target
    pool for the two-query individual tracker attack.
    """
    n = ledger.n
    keys = np.stack([ledger.attributes[a] for a in PUBLIC_ATTRIBUTES], axis=1)
    bases = [len(ledger.attribute_categories[a]) for a in PUBLIC_ATTRIBUTES]
    combined = np.zeros(n, dtype=np.int64)
    for col in range(keys.shape[1]):
        combined = combined * bases[col] + keys[:, col]
    _, inverse, counts = np.unique(combined, return_inverse=True, return_counts=True)
    mask = counts[inverse] == 1
    return np.nonzero(mask)[0]
