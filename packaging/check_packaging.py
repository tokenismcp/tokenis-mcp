#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check every way users install Tokenis, the way they actually launch it.

    python packaging/check_packaging.py --wheel-dir dist            # launchers + manifests
    python packaging/check_packaging.py --wheel-dir dist --docker-image tokenis-mcp:test

- **Versions**: pyproject, Cargo, npm, the Claude Code plugin (and its uvx
  pin), the marketplace entry, the MCP Registry ``server.json`` and the MCPB
  bundle (and its dependency pin) must all name the same version.
- **Manifests**: ``server.json`` validates against the MCP Registry schema.
- **Launchers**, each started exactly as its host starts it and driven by a
  real MCP client over stdio: the Claude Code plugin command (``uvx``), the
  Claude Desktop bundle (``uv run --directory``), and optionally the Docker
  image. ``--wheel-dir`` is published through a local copy of the GitHub
  Pages package index (``packaging/build_index.py``), substituted for the
  real index URL, so this runs before a release exists.
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
PAGES_INDEX = "https://tokenismcp.github.io/tokenis-mcp/simple/"
EXPECTED_TOOLS = {"describe_dataset", "aggregate", "group_by", "compare_periods",
                  "similarity_search", "exists", "disclose_ratio", "disclose_bucket"}


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def ok(message: str) -> None:
    print(f"ok    {message}")


def load(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def check_versions() -> str:
    import tomllib

    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    plugin = load("plugins/tokenis/.claude-plugin/plugin.json")
    uvx_pin = next(a for a in plugin["mcpServers"]["tokenis"]["args"] if a.startswith("tokenis-mcp@"))
    server = load("server.json")
    mcpb_pin = tomllib.loads((ROOT / "packaging/mcpb/pyproject.toml").read_text())["project"]["dependencies"]
    found = {
        "Cargo.toml": tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"],
        "sdk/typescript/package.json": load("sdk/typescript/package.json")["version"],
        "plugin.json": plugin["version"],
        "plugin uvx pin": uvx_pin.split("@", 1)[1],
        "marketplace.json": load(".claude-plugin/marketplace.json")["plugins"][0]["version"],
        "server.json": server["version"],
        **{f"server.json {p['registryType']}": p.get("version") or p["identifier"].rsplit(":", 1)[1]
           for p in server["packages"]},
        "mcpb manifest": load("packaging/mcpb/manifest.json")["version"],
        "mcpb dependency pin": next(d for d in mcpb_pin if d.startswith("tokenis-mcp")).split("==")[1],
    }
    wrong = {k: v for k, v in found.items() if v != version}
    if wrong:
        fail(f"versions disagree with pyproject.toml ({version}): {wrong}")
    ok(f"all {len(found) + 1} version declarations are {version}")
    return version


def check_server_json() -> None:
    import jsonschema

    with urllib.request.urlopen(SCHEMA_URL, timeout=30) as response:
        schema = json.load(response)
    server = load("server.json")
    errors = list(jsonschema.validators.validator_for(schema)(schema).iter_errors(server))
    if errors:
        fail("server.json: " + "; ".join(e.message for e in errors))
    oci = [p for p in server["packages"] if p["registryType"] == "oci"]
    label = f'io.modelcontextprotocol.server.name="{server["name"]}"'
    if oci and label not in (ROOT / "Dockerfile").read_text():
        fail("the Dockerfile lacks the label the registry uses to verify the image")
    ok("server.json matches the MCP Registry schema; the image carries its ownership label")


async def drive(command: str, args: List[str], env: Dict[str, str], label: str) -> None:
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(command=command, args=args, env=env)
    async with Client(params, read_timeout_seconds=900) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        if tools != EXPECTED_TOOLS:
            fail(f"{label}: unexpected tools {sorted(tools)}")
        described = json.loads((await client.call_tool("describe_dataset", {})).content[0].text)
        grouped = json.loads((await client.call_tool(
            "group_by", {"key": "industry", "column": "revenue_2025"})).content[0].text)
        denied = await client.call_tool("aggregate", {
            "function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}})
    if "FICTIONAL" not in described.get("notice", ""):
        fail(f"{label}: the demo dataset was not announced as fictional")
    suppressed = {g["group"] for g in grouped["groups"] if g["suppressed"]}
    if suppressed != {"retail"} or not denied.is_error:
        fail(f"{label}: admission control did not behave as expected")
    ok(f"{label}: 8 tools, demo announced, small group suppressed, narrow query denied")


def serve_index(wheel_dir: Path, root: Path) -> str:
    """Publish the wheels the way a release does -- files plus a Pages-style
    index pointing at them -- on a local port. Returns the index URL."""
    sys.path.insert(0, str(ROOT / "packaging"))
    import build_index

    files = root / "files"
    shutil.copytree(wheel_dir, files)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    dists = sorted(files.glob("tokenis_mcp-*"))
    build_index.write_index(root / "site", build_index.from_files(dists, f"{base}/files"))
    shutil.move(str(root / "site" / "simple"), str(root / "simple"))
    return f"{base}/simple/"


def launch_env(cache: Path) -> Dict[str, str]:
    return {"UV_CACHE_DIR": str(cache), "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "")}


def check_plugin(index: str, cache: Path) -> None:
    spec = load("plugins/tokenis/.claude-plugin/plugin.json")["mcpServers"]["tokenis"]
    if PAGES_INDEX not in spec["args"]:
        fail("the plugin does not install from the GitHub Pages index")
    args = [a.replace("${user_config.config_file}", "").replace(PAGES_INDEX, index)
            for a in spec["args"]]
    env = {k: "" for k in spec.get("env", {})} | launch_env(cache)
    asyncio.run(drive(spec["command"], args, env, "Claude Code plugin (uvx)"))


def check_mcpb(index: str, cache: Path) -> None:
    manifest = load("packaging/mcpb/manifest.json")
    config = manifest["server"]["mcp_config"]
    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "bundle"
        shutil.copytree(ROOT / "packaging/mcpb", bundle,
                        ignore=shutil.ignore_patterns(".venv", "uv.lock", "__pycache__", "*.mcpb"))
        pyproject = bundle / "pyproject.toml"
        if PAGES_INDEX not in pyproject.read_text():
            fail("the Desktop bundle does not install from the GitHub Pages index")
        pyproject.write_text(pyproject.read_text().replace(PAGES_INDEX, index))
        args = [a.replace("${__dirname}", str(bundle)).replace("${user_config.config_file}", "")
                for a in config["args"]]
        env = {k: "" for k in config.get("env", {})} | launch_env(cache)
        asyncio.run(drive(config["command"], args, env, "Claude Desktop bundle (uv run)"))


def check_docker(image: str) -> None:
    asyncio.run(drive("docker", ["run", "-i", "--rm", image], {"PATH": os.environ.get("PATH", "")},
                      f"Docker image {image}"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel-dir", type=Path, required=True,
                        help="directory holding the built tokenis-mcp wheel (and optionally sdist)")
    parser.add_argument("--docker-image")
    args = parser.parse_args()
    if not any(args.wheel_dir.glob("tokenis_mcp-*.whl")):
        fail(f"no tokenis_mcp wheel in {args.wheel_dir}")
    check_versions()
    check_server_json()
    with tempfile.TemporaryDirectory() as cache, tempfile.TemporaryDirectory() as site:
        index = serve_index(args.wheel_dir.resolve(), Path(site))
        ok(f"package index served at {index} (stands in for GitHub Pages)")
        check_plugin(index, Path(cache))
        check_mcpb(index, Path(cache))
    if args.docker_image:
        check_docker(args.docker_image)
    print("all packaging checks passed")


if __name__ == "__main__":
    sys.exit(main())
