#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Claude answers questions about confidential data through Tokenis.

    pip install -e ".[llm]"
    export ANTHROPIC_API_KEY=...            # never hard-code it
    python examples/anthropic_agent.py "Which industry grew fastest from 2024 to 2025?"

    # against your own data instead of the built-in demo:
    export TOKENIS_TOKENIZER_KEY=$(tokenis-mcp keygen-secret)
    export TOKENIS_AUDIT_KEY=$(tokenis-mcp keygen-secret)
    python examples/anthropic_agent.py --config examples/tokenis.toml "..."

Claude sees only tool results -- aggregates over groups of at least k
records, bands, and generic denials -- never a row. Every call it makes is
admission-checked and written to the disclosure trace under the principal
given here, which in a real application is your authenticated end user.
"""
from __future__ import annotations

import argparse
import json
import sys

from tokenis.llm import TokenisToolkit, ToolOutcome, ask_anthropic


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("question", nargs="?",
                        default="Which industry grew fastest from 2024 to 2025, and by roughly how much?")
    parser.add_argument("--config", help="tokenis.toml (default: built-in demo data)")
    parser.add_argument("--model", default="claude-opus-5-5")
    parser.add_argument("--principal", default="analyst@example.com",
                        help="the authenticated end user the queries are charged to")
    args = parser.parse_args()

    if args.config:
        from tokenis.config import build_service, load_config

        service = build_service(load_config(args.config))
    else:
        from tokenis.gateway.demo import demo_service

        service = demo_service()

    toolkit = TokenisToolkit(service, principal=args.principal)

    def trace(name: str, arguments: object, outcome: ToolOutcome) -> None:
        status = "denied" if outcome.is_error else "ok"
        print(f"  tool {name} {json.dumps(arguments, ensure_ascii=False)} -> {status}",
              file=sys.stderr)

    print(ask_anthropic(toolkit, args.question, model=args.model, on_tool=trace))
    print(f"\n[{len(service.trace)} disclosure-trace entries, chain valid: "
          f"{service.trace.verify_chain()}]", file=sys.stderr)


if __name__ == "__main__":
    main()
