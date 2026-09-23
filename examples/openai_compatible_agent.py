#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Any OpenAI-compatible chat model answers questions through Tokenis:
OpenAI itself, Azure OpenAI, or a local/self-hosted model served by vLLM,
Ollama, LM Studio or LiteLLM -- anything with tool calling.

    pip install -e ".[llm]"

    # OpenAI
    export OPENAI_API_KEY=...
    python examples/openai_compatible_agent.py --model gpt-5 "Which region is largest?"

    # A local model (no data leaves the machine at all), e.g. Ollama:
    export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=unused
    python examples/openai_compatible_agent.py --model qwen3 "Which region is largest?"

Tool-calling quality varies a lot between models; Tokenis enforces its
policy either way, but weaker models may need more turns or give up.
"""
from __future__ import annotations

import argparse
import json
import sys

from tokenis.llm import TokenisToolkit, ToolOutcome, ask_openai


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("question", nargs="?",
                        default="Compare total 2025 revenue across industries.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--config", help="tokenis.toml (default: built-in demo data)")
    parser.add_argument("--principal", default="analyst@example.com")
    args = parser.parse_args()

    if args.config:
        from tokenis.config import build_service, load_config

        service = build_service(load_config(args.config))
    else:
        from tokenis.gateway.demo import demo_service

        service = demo_service()

    toolkit = TokenisToolkit(service, principal=args.principal)

    def trace(name: str, arguments: object, outcome: ToolOutcome) -> None:
        print(f"  tool {name} {json.dumps(arguments, ensure_ascii=False)}", file=sys.stderr)

    print(ask_openai(toolkit, args.question, model=args.model, on_tool=trace))


if __name__ == "__main__":
    main()
