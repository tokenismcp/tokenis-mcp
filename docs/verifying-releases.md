# Verifying a release

Every release is built by GitHub Actions from a tagged commit, in the open,
and published only to GitHub (Releases, Pages and the Container Registry).
No long-lived signing key exists. Each artifact carries four independent
pieces of evidence:

| Evidence | What it proves | Verify with |
|---|---|---|
| `SHA256SUMS` | The files are the ones listed | `sha256sum -c` |
| Build provenance attestation | The file was built by this repository's release workflow, from a specific commit | `gh attestation verify` |
| Sigstore signature (`<file>.sigstore.json`) | The same, checkable without the GitHub CLI; logged in the public Rekor transparency log | `cosign verify-blob` |
| CycloneDX SBOM | What is inside: every Python, Rust and npm dependency, and the image contents | Any SBOM tool (`grype`, `osv-scanner`, Dependency-Track) |

Replace `0.1.0` below with the version you are checking.

## Release files (wheels, sdist, bundles)

```bash
gh release download v0.1.0 --repo tokenismcp/tokenis-mcp --dir tokenis-release
```

```bash
cd tokenis-release && sha256sum -c SHA256SUMS
```

Provenance (requires the GitHub CLI):

```bash
gh attestation verify tokenis_mcp-0.1.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl --repo tokenismcp/tokenis-mcp
```

Signature (requires `cosign` 2.x):

```bash
cosign verify-blob tokenis.mcpb --bundle tokenis.mcpb.sigstore.json --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github.com/tokenismcp/tokenis-mcp/\.github/workflows/release\.yml@refs/tags/v'
```

A valid signature proves the file was produced by `release.yml` running on a
`v*` tag of this repository, and by nothing else.

## Container image

```bash
cosign verify ghcr.io/tokenismcp/tokenis-mcp:0.1.0 --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp '^https://github.com/tokenismcp/tokenis-mcp/\.github/workflows/release\.yml@refs/tags/v'
```

```bash
gh attestation verify oci://ghcr.io/tokenismcp/tokenis-mcp:0.1.0 --repo tokenismcp/tokenis-mcp
```

Pin the image by digest in production (the `cosign verify` output prints
it), for example in the Helm chart: `image.tag: 0.1.0@sha256:...`.

The image SBOM is attached to the image as an attestation:

```bash
gh attestation verify oci://ghcr.io/tokenismcp/tokenis-mcp:0.1.0 --repo tokenismcp/tokenis-mcp --predicate-type https://cyclonedx.org/bom --format json
```

## SBOMs

Each release includes:

| File | Covers |
|---|---|
| `tokenis-mcp-<v>-python.cdx.json` | The Python package as installed with every runtime extra (database drivers, KMS SDKs) |
| `tokenis-core-<v>-rust.cdx.json`, `tokenis-py-...`, `tokenis-wasm-...` | Each Rust crate and its dependency tree |
| `tokenis-crypto-<v>-npm.cdx.json` | The TypeScript SDK (no runtime dependencies) |

Scan one for known vulnerabilities:

```bash
osv-scanner scan --sbom tokenis-mcp-0.1.0-python.cdx.json
```

## Installing from the Pages index

`uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp`
downloads wheels from the GitHub Release, and the index pins each file's
SHA-256. `uv` checks those hashes, and it consults this index first for
`tokenis-mcp`, so a same-named package on another registry cannot be
substituted.
