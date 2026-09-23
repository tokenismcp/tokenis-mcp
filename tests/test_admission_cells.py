# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The gateway runs admission control over *cells* of indistinguishable
records (for scale). This must never change a decision: every admit/deny,
the rule that fired, and every admitted set size must equal those of the
plain per-record policy, for any data and any query sequence."""
import random

import numpy as np
import pytest

from tokenis.gateway.admission import AdmissionPolicy, All, And, Eq, Query, QueryContext
from tokenis.gateway.schema import (
    AdmissionSettings,
    ColumnSpec,
    DecryptionSettings,
    DisclosureSettings,
    GatewaySettings,
    Schema,
)
from tokenis.gateway.service import TokenisGatewayService

SCHEMA = Schema(columns=(
    ColumnSpec("v", "sealed"), ColumnSpec("a", "open"), ColumnSpec("b", "open"),
    ColumnSpec("c", "open"), ColumnSpec("who", "token"),
))


def predicate(filters):
    parts = [Eq(name, value) for name, value in sorted(filters.items())]
    return All() if not parts else parts[0] if len(parts) == 1 else And(*parts)


@pytest.mark.parametrize("seed", range(60))  # 48 once caught a column-order bug
def test_cell_compressed_decisions_equal_per_record_decisions(seed):
    rng = random.Random(seed)
    k = rng.choice([2, 3, 4, 5])
    n = rng.randint(2 * k, 70)
    domains = {"a": rng.randint(1, 6), "b": rng.randint(1, 12), "c": rng.randint(1, 3)}
    rows = [{name: f"{name}{rng.randrange(size)}" for name, size in domains.items()}
            for _ in range(n)]
    # A token column with repeats (e.g. an account manager) and some uniques.
    for i, row in enumerate(rows):
        row["who"] = f"w{rng.randrange(4)}" if rng.random() < 0.6 else f"u{i}"
        row["v"] = rng.randint(-50, 50)

    settings = GatewaySettings(
        admission=AdmissionSettings(min_query_set_size=k, budget=40, window="total",
                                    taint_budget=5, taint_call_cap=9),
        decryption=DecryptionSettings(max_value=1 << 20, table_size=None),
        disclosure=DisclosureSettings(latency_granularity_ms=1.0),
    )
    svc = TokenisGatewayService(SCHEMA, b"s" * 32, settings)
    svc.ingest_many((str(i), row, None) for i, row in enumerate(rows))
    # The per-record view (with tokens) before sealing releases it.
    per_record = {name: np.array(values, dtype=object) for name, values in svc._public.items()}
    svc.seal()
    cells = svc._admission
    tokens = per_record["who"]
    plain = AdmissionPolicy(
        n=n, public_attributes=per_record,
        catalogue=["v"], k=k, budget=40, taint_budget=5, taint_call_cap=9,
    )
    assert cells.n <= n and cells.population == n

    values = {name: sorted({row[name] for row in rows}) + [f"{name}-absent"] for name in domains}
    values["who"] = sorted(set(tokens)) + ["0" * 32]
    for _ in range(60):
        filters = {name: rng.choice(opts) for name, opts in values.items() if rng.random() < 0.45}
        function = rng.choice(["SUM", "SUM", "AVG", "COUNT"])
        context = QueryContext(subject_id=rng.choice(["s1", "s2"]), credential_id="c",
                               taint=int(rng.random() < 0.15))
        query = Query(predicate=predicate(filters), function=function,
                      column=None if function == "COUNT" else "v")
        expected = plain.decide(query, context)
        actual = cells.decide(query, context)
        assert (actual.admitted, actual.rule) == (expected.admitted, expected.rule), filters
        if expected.admitted:
            assert actual.set_size == expected.set_size


def test_cells_shrink_the_problem():
    rng = random.Random(7)
    svc = TokenisGatewayService(
        SCHEMA, b"s" * 32,
        GatewaySettings(admission=AdmissionSettings(min_query_set_size=5),
                        decryption=DecryptionSettings(max_value=1 << 30, table_size=None)),
    )
    svc.ingest_many(
        (str(i), {"v": i, "a": f"a{rng.randrange(4)}", "b": f"b{rng.randrange(5)}",
                  "c": f"c{rng.randrange(2)}", "who": f"u{i}"}, None)
        for i in range(5000)
    )
    svc.seal()
    # The unique token column collapses to one sentinel: 4*5*2 cells, not 5000.
    assert svc._admission.n == 40
    assert int(np.sum(svc._admission._weights)) == 5000
