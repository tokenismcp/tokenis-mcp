#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""A five-minute tour of Tokenis, in-process: the same tool calls an MCP
client (or an LLM through ``tokenis.llm``) would make, against the built-in
fictional demo dataset.

    pip install -e ".[server]"      # Python >= 3.10
    python examples/quickstart.py

To connect a real client instead, run ``tokenis-mcp serve --demo`` (stdio);
see the README's "Connect an LLM" section.
"""
from __future__ import annotations

import json

from tokenis.gateway.demo import demo_service
from tokenis.llm import TokenisToolkit


def show(label: str, toolkit: TokenisToolkit, tool: str, arguments: dict) -> None:
    outcome = toolkit.call(tool, arguments)
    print(f"\n--- {label} ---")
    print(("DENIED: " if outcome.is_error else "") + outcome.content)


def main() -> None:
    service = demo_service()
    toolkit = TokenisToolkit(service, principal="analyst@example.com")
    print("Tools:", [d.name for d in toolkit.definitions()])

    show("describe_dataset (call this first)", toolkit, "describe_dataset", {})
    show("SUM(revenue_2025) for finance (3 records, admitted)", toolkit, "aggregate",
         {"function": "sum", "column": "revenue_2025", "filters": {"industry": "finance"}})
    show("SUM(revenue_2025) for retail (2 records < k=3: denied, reason not disclosed)", toolkit,
         "aggregate", {"function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}})
    show("group_by industry (retail suppressed)", toolkit, "group_by",
         {"key": "industry", "column": "revenue_2024"})
    show("compare_periods for tech: direction and ratio band only", toolkit, "compare_periods",
         {"column_a": "revenue_2024", "column_b": "revenue_2025", "filters": {"industry": "tech"}})
    show("exists: at least k records?", toolkit, "exists", {"filters": {"region": "Seoul-Gangnam"}})
    show("disclose_ratio under an authorised purpose (audited Reveal)", toolkit, "disclose_ratio",
         {"column": "revenue_2025", "numerator_filters": {"industry": "finance"},
          "denominator_filters": {"industry": "tech"}, "purpose": "demo_review"})

    print(f"\nDisclosure trace: {len(service.trace)} entries, chain valid = "
          f"{service.trace.verify_chain()}")
    for entry in service.trace:
        detail = f" rule={entry.audit.detail}" if entry.audit.detail else ""
        print(f"  [{entry.index}] {entry.kind:9s} {entry.audit.obj_ref}{detail}")
    print("\nAnthropic tool schema for `aggregate`:")
    print(json.dumps(toolkit.anthropic_tools()[1], indent=2)[:800], "...")


if __name__ == "__main__":
    main()
