# Distribution

Every channel installs the same `tokenis-mcp` Python package; each is a
thin launcher that starts `tokenis-mcp serve` the way its host expects.

| Channel | Files | Launch command |
|---|---|---|
| PyPI (`pip`, `uvx`) | `pyproject.toml` | `uvx tokenis-mcp serve ...` |
| Claude Code plugin | `.claude-plugin/marketplace.json`, `plugins/tokenis/` | `uvx --python 3.12 tokenis-mcp@<version> serve --config-or-demo <file>` |
| Claude Desktop extension | `packaging/mcpb/` (MCPB manifest 0.4, `uv` server type) | `uv run --directory <bundle> src/server.py --config-or-demo <file>` |
| Docker / OCI | `Dockerfile` | `docker run -i --rm ghcr.io/tokenismcp/tokenis-mcp` |
| MCP Registry | `server.json` (+ the `mcp-name` marker in `README.md`) | points at the PyPI package (add the OCI image once it is public; the `Dockerfile` already carries the label) |
| npm (`@tokenis/crypto`) | `sdk/typescript/` | the TypeScript crypto SDK, not the server |

`--config-or-demo` exists for launchers that always pass a path: an empty
path serves the fictional demo data, and `describe_dataset` says so.

## Checking it

```bash
maturin build --release --out wheels
python packaging/check_packaging.py --wheel-dir wheels [--docker-image tokenis-mcp:test]
```

The checker confirms that every version declaration agrees, validates
`server.json` against the registry schema, then launches the plugin
command, the Desktop bundle and (optionally) the image exactly as their
hosts do. `--wheel-dir` stands in for PyPI. Each launch is driven by a real
MCP client: list the tools, `describe_dataset`, a suppressed group, a
denied narrow query. CI runs this on every push, together with
`claude plugin validate --strict` and `mcpb validate`.

## Releasing

1. Bump the version everywhere the checker lists (it fails on any mismatch),
   update `CHANGELOG.md`, and tag `vX.Y.Z`.
2. The release workflow builds wheels for every platform, the sdist, the npm
   tarball and `tokenis.mcpb`, and attaches them to a GitHub release.
3. With the repository variable `PUBLISH=true`, it also publishes to PyPI
   (trusted publishing), GHCR (multi-arch, with provenance), and then the
   MCP Registry (GitHub OIDC). npm has its own switch, `PUBLISH_NPM=true`.

One-time setup only the owner can do:

- Reserve `tokenis-mcp` on PyPI (it is unclaimed as of this writing, so
  anyone could take it) and add this repository as its Trusted Publisher,
  environment `pypi`.
- Confirm ownership of the `@tokenis` npm scope; create the `npm`
  environment with an `NPM_TOKEN` secret.
- After the first image push, make `ghcr.io/tokenismcp/tokenis-mcp` public
  (the MCP Registry must be able to pull its label).
- Make the repository public before relying on npm provenance or listing
  the plugin marketplace publicly: `/plugin marketplace add` and the
  registry both read it anonymously.
