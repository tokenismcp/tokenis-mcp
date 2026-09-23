# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No tagged
release yet: everything below is `[Unreleased]` and describes the current
state; "History" records how the crypto layer got here.

## [Unreleased]

### Added
- **One-command installs, like other popular MCP servers:** `uvx tokenis-mcp`
  (the server now installs by default on Python 3.10+, no extra needed); a
  Claude Code plugin marketplace (`/plugin marketplace add
  tokenismcp/tokenis-mcp`) whose plugin bundles the server and an analysis
  skill; a Claude Desktop extension (`tokenis.mcpb`, MCPB 0.4, uv runtime);
  a non-root Docker image with the MCP Registry label; and an MCP Registry
  `server.json`. `packaging/check_packaging.py` launches each exactly as its
  host does and drives it with a real MCP client, in CI.
- **Benchmarks** (`benchmarks/bench.py`, `BENCHMARKS.md`): crypto primitives,
  the gateway at 10k-1M records, server-side W6 under concurrency, and an
  authenticated end-to-end HTTP load test with a restart.
- **LLM integration.** `tokenis-mcp` CLI (`serve`, `check`, `tools`, `ask`,
  `keys`, `keygen-secret`, `audit verify`); a TOML configuration with a
  CSV/JSON-lines loader for your own data (`tokenis/config.py`,
  `examples/tokenis.toml`); the Streamable HTTP transport with mandatory
  authentication by API key (hashed, revocable without restart) or IdP JWT
  (`tokenis/server_auth.py`); and `tokenis.llm`, which exposes the tools to
  the Anthropic Messages API and any OpenAI-compatible API (OpenAI, Azure,
  vLLM, Ollama, LiteLLM) through the same code path as the MCP server, with
  ready-made agent loops. Examples for Claude Code/Desktop, Claude via the
  API, and OpenAI-compatible models.
- **Schema-driven gateway.** Any number of open, token and sealed columns
  (decimal `scale`, banded results, optional VAR), filters over open and
  token columns, a real `compare_periods` over two sealed columns,
  `describe_dataset`, configurable admission budgets and windows, and
  server-side Reveal purposes authorised per principal. Tool schemas carry
  the real column names and filter values as enums, plus MCP tool
  annotations, server instructions and an analysis prompt.
- **Rust cryptographic core** (`crates/tokenis-core`): EC-ElGamal over
  secp256k1 (RustCrypto `k256`, audited by NCC Group in 2023) and the
  no-key delegation protocol. It is the only implementation of any
  cryptographic operation in the repository. `unsafe` is forbidden and
  `unwrap`/`expect`/`panic`/slice indexing are denied, so malformed input
  from a binding returns an error instead of aborting the host process.
  Unit and property tests, including arbitrary-bytes fuzzing of every
  parser.
- **Python SDK** (`tokenis/`) over the core via PyO3 (`crates/tokenis-py`,
  `tokenis._core`, abi3 — one build per platform serves CPython 3.9+), built
  with maturin. Also: the gateway (ciphertext compute, D1-D5 admission
  control, gated/audited Reveal, hash-chained disclosure trace, W6 latency
  quantization), a scope-confined tokenizer, and an MCP server exposing the
  tools in `tokenis/spec/tool-surface.md`.
- **TypeScript SDK** (`sdk/typescript`, `@tokenis/crypto`) over the same
  core compiled to WebAssembly (`crates/tokenis-wasm`), for Node 20+.
- `tokenis/crypto/no_key_delegation.py` / `Owner` in both SDKs: an
  interactive protocol (one-time-pad masking + Beaver triples) that lets an
  untrusted server evaluate affine functions and products while provably
  learning nothing about the plaintext, from "No-Key Delegation of
  Elliptic-Curve Fully Homomorphic Encryption" (J1729 Labs, 2026).
- Versioned, validated wire formats for ciphertexts, public keys, masked
  values and multiplication openings, identical across Rust, Python and
  TypeScript; `tests/test_interop.py` has Python and TypeScript exchange
  real keys, ciphertexts and masked values (TypeScript acting as the
  untrusted delegation server for a Python owner).
- `tokenis/conformance/`: all six well-formedness conditions (W1-W6, P2
  Definition 17) tested against the SDK.
- The J1729Labs paper series (P2, P3, P4) with per-paper navigation pages;
  `research/p3_leakage/` and `research/p4_admission/` reproduction code,
  each with a `verify_claims.py` that checks determinism and internal
  consistency (not the papers' literal published percentages — see their
  READMEs).
- `reports/SUMMARY.md` (excerpts of R1/R2, excluding confidential and
  customer-identifying content), `examples/quickstart.py`.
- Release workflow: wheels for Linux (glibc x86_64/aarch64, musl), macOS
  (arm64, x86_64) and Windows, an sdist, and the npm tarball on each
  version tag; PyPI trusted publishing and npm publishing with build
  provenance, gated behind the `PUBLISH` repository variable.
- Project files: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  issue/PR templates, `py.typed` + `_core.pyi` (PEP 561).

### Security
- Findings from an internal audit of every layer, all fixed:
  - Concurrent tool calls could both pass the D2 differencing check (the
    MCP SDK runs tools on worker threads), recovering a single record; the
    trace chain and budgets also raced. Admission, computation and auditing
    of a call now run under one lock, and the trace locks its own appends.
  - A restart reset the admission history and budgets. The history is now
    an fsync'd log replayed on start-up, keyed to a fingerprint of the data;
    changed data requires an explicit `--reset-admission-state`.
  - Denials said which rule fired and how many records matched, turning
    `exists` into a membership oracle. Every denial now returns one fixed
    message; `exists` answers "at least k" and cannot distinguish 0 from 1.
  - The tokenizer key had a public default; it is now required from the
    environment. `similarity_search` is budgeted and bounded. Decryption
    failures are traced denials instead of leaking a range bit. The Reveal
    gate was a model-chosen string prefix; purposes are now configured
    server-side per principal. `compare_periods` no longer takes caller
    multipliers, and `disclose_bucket` inputs are bounded.
  - The disclosure trace is persisted (0600, fsync'd), optionally
    HMAC-signed, verified on load, and repairs only a torn final line.
  - Rust core: decryption memory is bounded (a packed table of at most 2^24
    entries and a constant-size search buffer; the maximum range is now
    2^40 — previously 2^48 could need ~12 GB); one-time secrets live behind
    heap pointers so moving them leaves no copy; a secret offered to the
    wrong owner is rejected before it is consumed; randomness failures are
    errors instead of panics; the plaintext sign is handled branch-free;
    remaining temporaries are zeroed; the owner tracks only outstanding
    triples. The "constant work" claim is narrowed to what holds: a
    constant step count, not constant-time memory access.
  - WebAssembly: 64-bit integer arguments are range-checked instead of
    silently wrapping; exported key bytes no longer leave a copy in linear
    memory.
- Private keys, one-time masks, affine corrections and Beaver triples live
  only in Rust memory that is zeroed on drop; Python and JavaScript hold
  opaque handles that are redacted from `repr`/`toString` and (in Python)
  refuse pickling and copying. Key export is one explicit, named call.
- Masks, corrections and triples are consumed by the operation that uses
  them and bound to the owner that created them; reuse (which would reveal
  `s1 - s2` to the server) or cross-owner use raises.
- Randomness is drawn inside Rust from the OS CSPRNG (or
  `crypto.getRandomValues` under WebAssembly); no API accepts a caller RNG.
- Every point parsed from bytes must be a canonical compressed encoding on
  secp256k1.
- Decryption takes the same number of baby-step-giant-step steps whatever
  the plaintext (pinned by a Rust test), and releases the Python GIL.
- An `assert` guarding the admission policy in `tokenis/gateway/service.py`
  became an explicit check (asserts vanish under `python -O`).
- CI: `cargo fmt`/`clippy -D warnings`, `ruff` (incl. flake8-bandit),
  `mypy`, strict `tsc`, and `cargo audit` + `pip-audit` + `npm audit` on
  every push and weekly; Dependabot for Cargo, pip, npm and Actions.

### Changed
- **Performance.** A single `sum` over 10k records went from ~300 ms to under
  1 ms, and `group_by` from 9.3 s to ~20 ms. Three changes did it:
  - Each sealed column's decryptor is sized to that column's own hard bound
    (the sum of absolute values, which no aggregate can exceed) instead of the
    configured worst case. The step count stays fixed per column.
  - Ciphertext columns and masked sums moved into Rust (`CiphertextVector`),
    with batch encryption on all cores.
  - Encryption uses k256's constant-time precomputed-table and
    linear-combination paths.

  Loading is batched (`ingest_many`). The D2 audit now runs over *cells* of
  records no admissible query can separate. Values held by fewer than k
  records are merged, and cells are ordered by first record. This keeps
  memory and time independent of the record count, with decisions verified
  identical to the per-record policy on 180,000 randomised decisions. A
  column-ordering bug that this differential test caught is fixed before
  release.
- Breaking, pre-1.0: `TokenisGatewayService(schema, tokenizer_key,
  settings)` replaces the hard-coded demo service (`tokenis.gateway.demo`
  has the demo data); tool arguments are `column` / `filters` objects.
  `create_server` requires an explicit `principal_resolver`. In Rust,
  `PrivateKey::generate`, `encrypt`, `Owner::new`, `blind` and
  `prepare_triple` return `Result`, and delegation values are a `Value`
  newtype instead of `k256::Scalar`.
- `Decryptor` accepts an optional table size (Python `table_size=`,
  TypeScript `Decryptor.withTableSize`).
- TypeScript SDK requires Node 22+; the `mcp` dependency floor is 2.2.

### Fixed
- The npm tarball shipped without its WebAssembly (wasm-pack's nested
  `.gitignore`); CI now installs the packed tarball into a fresh project.
- LICENSE was missing from the sdist, wheels built from it, the npm package
  and the Rust crate; `THIRD-PARTY-NOTICES.md` now covers the statically
  linked Rust crates.
- The release workflow used the retired `macos-13` runner; actions moved to
  their current majors; release tags must match every manifest's version;
  npm provenance is requested only for a public repository.
- Project URLs pointed at the wrong GitHub organisation.
- k256 0.13's batch point normalisation panics when a point equal to the
  identity was produced by arithmetic (an unnormalised zero `z`); decrypting
  a zero plaintext hit it. The core swaps identities for the generator
  branch-free before normalising.
- WebAssembly bindings originally took some handles by value, which
  silently invalidated the caller's JavaScript object (e.g. the public key
  passed to `Ciphertext.fromBytes`); they now borrow or take bytes, with a
  regression test.
- `disclose_ratio`/`disclose_bucket` had no minimum-query-set-size check on
  their underlying sums: an authorised Reveal purpose alone could read an
  aggregate over an arbitrarily small group.

### History (crypto layer)
1. Hand-rolled additive ElGamal over pure-Python point arithmetic (`ecdsa`).
2. Briefly Paillier (`phe`) — reverted: it abandoned the EC architecture
   the paper series specifies without that being discussed.
3. EC-ElGamal matching the "EC-FHE" / "elliptic rational number" source
   papers as literally as possible. `tokenis/crypto/ec_fhe.py` documents
   the papers' three problems (a core map that cancels to a no-op, a
   multiplication construction that doesn't type-check, a "bootstrap" that
   needs the private key); capability is additive homomorphism only.
4. Curve arithmetic moved to libsecp256k1 (`coincurve`) after `pip-audit`
   flagged `ecdsa` 0.19.2 (PYSEC-2026-1325: Minerva timing attack on key
   generation and ECDH-style scalar multiplication, which its maintainers
   will not fix).
5. Everything moved into the Rust core, adding memory zeroisation,
   consumable one-time values, and a TypeScript SDK on the same code.
