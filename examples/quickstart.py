#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""A five-minute tour of the Tokenis reference SDK, in-process (no real MCP
client/transport needed -- :meth:`MCPServer.call_tool` is called directly,
which is exactly what a stdio/HTTP transport does under the hood).

Run it:

    pip install -e ".[server]"   # needs Python >=3.10
    python examples/quickstart.py

To actually connect a real MCP client (Claude Desktop, an SDK client,
etc.), run ``python -m tokenis.mcp_server.server`` instead, which speaks
stdio, and point your client at that command.
"""
from __future__ import annotations

import asyncio
import json

from tokenis.gateway.service import TokenisGatewayService, load_demo_ledger
from tokenis.mcp_server.server import create_server


def _print_result(label: str, result) -> None:
    payload = result.content[0].text if result.content else "<no content>"
    print(f"\n--- {label} ---")
    print(payload)


async def main() -> None:
    print("Loading a five-row demo ledger (industry/region public, revenue sealed)...")
    service = TokenisGatewayService()
    load_demo_ledger(service)
    server = create_server(service=service)

    tools = await server.list_tools()
    print(f"\nRegistered tools: {[t.name for t in tools]}")

    catalogue = await server.read_resource("tokenis://catalogue")
    print("\n--- catalogue resource (no row values) ---")
    print(json.dumps(json.loads(catalogue[0].content), indent=2))

    _print_result(
        "aggregate: SUM(revenue) where industry=finance",
        await server.call_tool("aggregate", {"function": "sum", "industry": "finance"}),
    )

    _print_result(
        "aggregate: SUM(revenue) where industry=retail  (2 rows, below the "
        "demo catalogue's minimum aggregate size of 3 -- expect a denial, "
        "not silence: P2 Remark 18 says a denial is disclosure too, and "
        "it's logged to the trace exactly like a successful call)",
        await server.call_tool("aggregate", {"function": "sum", "industry": "retail"}),
    )

    _print_result(
        "group_by: industry (retail's group is suppressed for the same reason)",
        await server.call_tool("group_by", {"key": "industry"}),
    )

    _print_result(
        "disclose_ratio without an authorized purpose -- denied",
        await server.call_tool(
            "disclose_ratio",
            {"numerator_industry": "finance", "denominator_industry": "retail", "purpose": "just curious"},
        ),
    )

    _print_result(
        "disclose_ratio with an authorized purpose -- crosses the boundary, gated and audited",
        await server.call_tool(
            "disclose_ratio",
            {
                "numerator_industry": "finance",
                "denominator_industry": "retail",
                "purpose": "authorized_quarterly_review",
            },
        ),
    )

    print(f"\nDisclosure trace: {len(service.trace)} entries, chain valid = {service.trace.verify_chain()}")
    for entry in service.trace:
        print(f"  [{entry.index}] {entry.kind:9s} {entry.audit.decision:6s} purpose={entry.audit.purpose!r}")


if __name__ == "__main__":
    asyncio.run(main())
