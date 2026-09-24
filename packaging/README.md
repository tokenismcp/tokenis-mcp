# Distribution

Tokenis is distributed from GitHub alone. Every channel installs the same
`tokenis-mcp` Python package; each is a thin launcher that starts
`tokenis-mcp serve` the way its host expects.

| Channel | Files | Launch command |
|---|---|---|
| GitHub Releases + Pages index (`uv`, `pip`) | `pyproject.toml`, `packaging/build_index.py` | `uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp serve ...` |
| Claude Code plugin | `.claude-plugin/marketplace.json`, `plugins/tokenis/` | `uvx --index <index> tokenis-mcp@<version> serve --config-or-demo <file>` |
| Claude Desktop extension | `packaging/mcpb/` (MCPB manifest 0.4, `uv` server type; its `pyproject.toml` pins the index for `tokenis-mcp` only) | `uv run --directory <bundle> src/server.py --config-or-demo <file>` |
| GitHub Container Registry | `Dockerfile` | `docker run -i --rm ghcr.io/tokenismcp/tokenis-mcp` |
| MCP Registry (optional) | `server.json` (the image; its label is in `Dockerfile`) | points at the GHCR image |
| npm (`@tokenis/crypto`, optional) | `sdk/typescript/` | the TypeScript crypto SDK, not the server |

The index is a static PEP 503 page on GitHub Pages whose links point at the
wheels attached to every GitHub Release, with their SHA-256 hashes.
`uv` consults an index given with `--index` before the default one and stops
at the first index that has the package, so a package of the same name on
another registry cannot be substituted.

`--config-or-demo` exists for launchers that always pass a path: an empty
path serves the fictional demo data, and `describe_dataset` says so.

## Checking it

```bash
maturin build --release --out wheels && maturin sdist --out wheels
python packaging/check_packaging.py --wheel-dir wheels [--docker-image tokenis-mcp:test]
```

The checker confirms every version declaration agrees, validates
`server.json` against the registry schema, publishes the wheels through a
local copy of the Pages index, and launches the plugin command, the Desktop
bundle and (optionally) the image exactly as their hosts do, driving each
with a real MCP client. CI runs this on every push, together with
`claude plugin validate --strict` and `mcpb validate`.

## Releasing

1. Bump the version everywhere the checker lists (it fails on any mismatch),
   update `CHANGELOG.md`, and push a `vX.Y.Z` tag.
2. The release workflow builds wheels for every platform, the sdist, the npm
   tarball and `tokenis.mcpb`; attaches them, with build provenance, to a
   GitHub Release; rebuilds and deploys the Pages index; pushes the
   multi-arch image to GHCR; and finally installs the release with the same
   `uvx` one-liner users type.
3. Optional: `PUBLISH_REGISTRY=true` lists it in the MCP Registry,
   `PUBLISH_NPM=true` publishes the TypeScript SDK to npm.

One-time setup (repository settings):

- Make the repository public: GitHub Pages, anonymous Release downloads,
  `/plugin marketplace add` and GHCR pulls all need it.
- Settings -> Pages -> Build and deployment -> Source: **GitHub Actions**.
- After the first image push, set the GHCR package's visibility to public.
