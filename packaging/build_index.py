#!/usr/bin/env python3
# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Build the package index Tokenis is installed from: a static PEP 503
"simple" index, served by GitHub Pages, whose links point at the wheels and
sdists attached to GitHub Releases. This is what makes

    uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp serve

work without any third-party package registry.

    python packaging/build_index.py --out site --files dist/*          # links to local files
    python packaging/build_index.py --out site --github-releases       # links to every release

With ``--github-releases`` it lists the assets of every published release
through the ``gh`` CLI (the release workflow's GITHUB_TOKEN), so older
versions stay installable.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path
from typing import List, Tuple

PROJECT = "tokenis-mcp"
REQUIRES_PYTHON = ">=3.10"
DIST = re.compile(r"^tokenis_mcp-[^/]+\.(whl|tar\.gz)$")


def sha256_of_url(url: str) -> str:
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response:
        for chunk in iter(lambda: response.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def from_releases(repo: str) -> List[Tuple[str, str, str]]:
    """(filename, url, sha256) for every distribution in every release."""
    tags = json.loads(subprocess.run(
        ["gh", "release", "list", "--repo", repo, "--json", "tagName", "--limit", "1000"],
        check=True, capture_output=True, text=True).stdout)
    files = []
    for tag in (t["tagName"] for t in tags):
        assets = json.loads(subprocess.run(
            ["gh", "release", "view", tag, "--repo", repo, "--json", "assets"],
            check=True, capture_output=True, text=True).stdout)["assets"]
        for asset in assets:
            if DIST.match(asset["name"]):
                url = asset["url"]
                digest = (asset.get("digest") or "").removeprefix("sha256:") or sha256_of_url(url)
                files.append((asset["name"], url, digest))
    return files


def from_files(paths: List[Path], base_url: str) -> List[Tuple[str, str, str]]:
    files = []
    for path in paths:
        if DIST.match(path.name):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append((path.name, f"{base_url.rstrip('/')}/{path.name}", digest))
    return files


def write_index(out: Path, files: List[Tuple[str, str, str]]) -> None:
    if not files:
        raise SystemExit("no tokenis-mcp distributions found")
    if out.exists():
        shutil.rmtree(out)
    project_dir = out / "simple" / PROJECT
    project_dir.mkdir(parents=True)
    rows = "\n".join(
        f'    <a href="{html.escape(url)}#sha256={digest}" '
        f'data-requires-python="{html.escape(REQUIRES_PYTHON)}">{html.escape(name)}</a><br>'
        for name, url, digest in sorted(files)
    )
    (project_dir / "index.html").write_text(
        f"<!DOCTYPE html>\n<html>\n  <head><title>Links for {PROJECT}</title></head>\n"
        f"  <body>\n    <h1>Links for {PROJECT}</h1>\n{rows}\n  </body>\n</html>\n")
    (out / "simple" / "index.html").write_text(
        f'<!DOCTYPE html>\n<html>\n  <body>\n    <a href="{PROJECT}/">{PROJECT}</a>\n'
        "  </body>\n</html>\n")
    (out / "index.html").write_text(
        "<!DOCTYPE html>\n<html>\n  <head><title>Tokenis package index</title></head>\n  <body>\n"
        "    <h1>Tokenis package index</h1>\n"
        "    <p><code>uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ "
        "tokenis-mcp serve --demo</code></p>\n"
        '    <p><a href="simple/">simple/</a> &middot; '
        '<a href="https://github.com/tokenismcp/tokenis-mcp">source</a></p>\n'
        "  </body>\n</html>\n")
    (out / ".nojekyll").write_text("")
    print(f"wrote {out}/simple/{PROJECT}/ with {len(files)} files")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--files", type=Path, nargs="+")
    source.add_argument("--github-releases", action="store_true")
    parser.add_argument("--repo", default="tokenismcp/tokenis-mcp")
    parser.add_argument("--base-url", default="",
                        help="with --files: URL the files are served from (default: file URLs)")
    args = parser.parse_args()
    if args.github_releases:
        files = from_releases(args.repo)
    else:
        base = args.base_url or args.files[0].resolve().parent.as_uri()
        files = from_files(args.files, base)
    write_index(args.out, files)


if __name__ == "__main__":
    main()
