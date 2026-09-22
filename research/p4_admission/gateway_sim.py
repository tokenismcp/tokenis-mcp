# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Simulated aggregate-query gateway (paper §3.1, "system model").

This is the "ground truth" oracle: it resolves a query's characteristic set
against PUBLIC attributes and evaluates its function over the PROTECTED
column, exactly as the real EC-ElGamal aggregation engine would (minus the
cryptography, which is out of scope here -- see P1). It performs no
admission control at all; :mod:`admission` sits in front of it, and attacks.py
composes the two: resolve/evaluate here, decide there.

The filter language (predicate algebra: attribute equality/membership,
conjunction, disjunction of conjunctions, and an explicit exclusion / set-
difference operator) is defined in :mod:`admission` since it only touches
public attributes and :mod:`admission` is this package's dependency-light,
reusable core; this module simply imports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

from .admission import All, Predicate, characteristic_indicator
from .ledger import Ledger

FUNCTIONS = ("COUNT", "SUM", "AVG", "VAR")


@dataclass(frozen=True)
class Query:
    """A ground-truth query against the gateway. Mirrors admission.Query's
    shape (predicate, function, column) but is evaluated against real
    protected values here, never inside admission.py.
    """

    predicate: Predicate
    function: str
    column: Optional[str] = None

    def __post_init__(self) -> None:
        if self.function not in FUNCTIONS:
            raise ValueError(f"unknown function {self.function!r}")
        if self.function != "COUNT" and self.column is None:
            raise ValueError("SUM/AVG/VAR queries must name a column")


class GatewaySim:
    """Resolves a query's characteristic set and evaluates its function over x.

    No cryptography, no admission control -- this is the oracle attacks.py
    consults for "what would the true answer be", and evaluate.py consults to
    measure benign-task utility (comparing admitted answers to it).
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    def characteristic_set(self, predicate: Predicate) -> np.ndarray:
        """Boolean indicator array of the predicate's characteristic set."""
        return characteristic_indicator(predicate, self.ledger.attributes, self.ledger.n)

    def evaluate(self, query: Query) -> float:
        indicator = self.characteristic_set(query.predicate)
        if query.function == "COUNT":
            return float(np.count_nonzero(indicator))

        values = self.ledger.columns[query.column][indicator]
        if values.size == 0:
            return 0.0
        if query.function == "SUM":
            return float(values.sum())
        if query.function == "AVG":
            return float(values.mean())
        if query.function == "VAR":
            return float(values.var())
        raise AssertionError("unreachable")
