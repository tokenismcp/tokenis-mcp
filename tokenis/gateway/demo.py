# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""A small, entirely fictional dataset for examples, tests and
``tokenis-mcp serve --demo``.

Sized so every tool has an admitted and a refused path with k = 3:
``finance`` and ``tech`` have 3 rows each, ``retail`` only 2 (below the
minimum query-set size).
"""
from __future__ import annotations

import secrets
from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from tokenis.gateway.schema import (
    AdmissionSettings,
    ColumnSpec,
    DecryptionSettings,
    DisclosureSettings,
    GatewaySettings,
    RevealPurpose,
    Schema,
)
from tokenis.gateway.service import TokenisGatewayService

DEMO_SCHEMA = Schema(
    columns=(
        ColumnSpec("revenue_2024", "sealed", "Annual revenue, fiscal 2024", unit="KRW"),
        ColumnSpec("revenue_2025", "sealed", "Annual revenue, fiscal 2025", unit="KRW"),
        ColumnSpec("industry", "open", "Industry sector"),
        ColumnSpec("region", "open", "Registered region (city-district)"),
        ColumnSpec("customer_name", "token", "Customer legal name", entity=True),
    ),
    id_column="id",
    embedding_column="embedding",
)

DEMO_PURPOSE = RevealPurpose(
    name="demo_review",
    description="Demonstration of a gated, audited disclosure",
    principals=("*",),
)

DEMO_SETTINGS = GatewaySettings(
    tenant="demo",
    admission=AdmissionSettings(min_query_set_size=3, budget=1000, window="total"),
    decryption=DecryptionSettings(max_value=1 << 28, table_size=1 << 15),
    disclosure=DisclosureSettings(latency_granularity_ms=50.0),
    purposes=(DEMO_PURPOSE,),
    notice="FICTIONAL demonstration data: these companies and figures are made up.",
)

#: (id, industry, region, revenue_2024, revenue_2025, customer_name, embedding)
DEMO_ROWS: List[Tuple[str, str, str, int, int, str, Tuple[float, ...]]] = [
    ("r1", "finance", "Seoul-Gangnam", 900_000, 1_000_000, "Acme Corp", (1.0, 0.0, 0.0)),
    ("r2", "finance", "Busan-Haeundae", 2_100_000, 2_000_000, "Beta LLC", (0.9, 0.1, 0.0)),
    ("r3", "retail", "Seoul-Gangnam", 450_000, 500_000, "Gamma Inc", (0.0, 1.0, 0.0)),
    ("r4", "retail", "Seoul-Jongno", 700_000, 750_000, "Delta Co", (0.0, 0.9, 0.1)),
    ("r5", "finance", "Seoul-Gangnam", 1_000_000, 1_250_000, "Epsilon Ltd", (0.95, 0.05, 0.0)),
    ("r6", "tech", "Seoul-Gangnam", 2_000_000, 3_000_000, "Zeta AI", (0.0, 0.0, 1.0)),
    ("r7", "tech", "Seoul-Jongno", 1_200_000, 1_500_000, "Eta Systems", (0.05, 0.0, 0.95)),
    ("r8", "tech", "Busan-Haeundae", 1_900_000, 2_500_000, "Theta Labs", (0.0, 0.05, 0.95)),
]


def demo_rows() -> List[Dict[str, Any]]:
    return [
        {"id": rid, "industry": ind, "region": reg, "revenue_2024": r24, "revenue_2025": r25,
         "customer_name": name, "embedding": list(emb)}
        for rid, ind, reg, r24, r25, name, emb in DEMO_ROWS
    ]


def demo_service(
    settings: Optional[GatewaySettings] = None,
    *,
    latency_granularity_ms: Optional[float] = None,
    tokenizer_key: Optional[bytes] = None,
    **service_kwargs: Any,
) -> TokenisGatewayService:
    """The demo dataset loaded into a gateway. The tokenizer key is random
    per call unless given, so demo tokens are not stable across runs."""
    settings = settings or DEMO_SETTINGS
    if latency_granularity_ms is not None:
        settings = replace(
            settings,
            disclosure=replace(settings.disclosure, latency_granularity_ms=latency_granularity_ms),
        )
    service = TokenisGatewayService(
        DEMO_SCHEMA, tokenizer_key or secrets.token_bytes(32), settings, **service_kwargs
    )
    service.ingest_many(
        (row.pop("id"), row, row.pop("embedding")) for row in demo_rows()
    )
    return service
