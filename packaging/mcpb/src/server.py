# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Entry point for the Claude Desktop extension: the Tokenis MCP server over
stdio, with the arguments Claude Desktop passes from the extension settings."""
import sys

from tokenis.cli import main

if __name__ == "__main__":
    main(["--log-level", "WARNING", "serve", *sys.argv[1:]])
