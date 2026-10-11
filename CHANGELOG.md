# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). "History" at
the end records how the crypto layer got here.

## [Unreleased]

### Added
- **`tokenis-mcp init FILE`**: a starting `tokenis.toml` and generated keys
  from a CSV or JSON-lines file. It guesses each column's protection
  conservatively (personal-looking or high-cardinality text: pseudonym; numbers:
  sealed; few distinct values: open; unique `id`/`*_id`: record id;
  numeric lists: embedding), leaves out columns with empty cells, writes
  `.env` (mode 600, git-ignored) and loads every row to prove the result
  works. `[data.rename]` maps file headers that are not valid column names.
- **Any AI app, any model.** [docs/clients.md](docs/clients.md): settings for
  Claude Code, Claude Desktop, ChatGPT, Codex, Gemini CLI, Cursor, VS Code and
  Windsurf, with what is tested and what follows vendor documentation. The
  console's Connect AI apps page covers them too. ChatGPT (OAuth only) works
  through `[auth] mode = "jwt"`; the gateway's OAuth discovery is tested.
  `tokenis.llm` gains `responses_tools()` / `responses_tool_outputs()` for the
  OpenAI Responses API and `PROVIDER_PRESETS` (Gemini, Ollama);
  `ask_openai(base_url=, api_key=)`; `tokenis-mcp ask --provider
  gemini|ollama --base-url`; `tokenis-mcp tools --format responses`;
  `[ask] provider = "gemini" | "ollama"`.
- **Tokenis Ask** (`[ask]`): a chat screen at `/ask` for people without an
  MCP client. Single sign-on; the person's identity is the admission
  principal, so Ask shares their budget, refusals and audit trail. Claude
  (Messages API) or any OpenAI-compatible model (vLLM, Ollama, SARA,
  OpenAI); a JSON tool protocol for models without function calling.
  Answers with figures no lookup returned are withheld; Korean questions get
  Korean answers. Suggested questions, a plain-language description of what
  can be asked, each lookup shown in plain words, refusals explained
  without naming the rule, and the remaining allowance. Per-person rate
  limit. Helm values `ask.*`.
- **A `user` role** (`[ops.oidc] users`): Ask only, no console. Role
  members may also be e-mail domains (`"@example.com"`, verified addresses).
- **Korean console**: the admin console and the sign-in pages are in Korean
  and English (browser language, or the switch in the top bar), with
  refusal reasons and protections explained in plain words and column
  display names from `[ask.labels]`.
- **Connect AI apps** page in the console: copy-ready settings for Claude
  Code, Claude Desktop, Cursor and VS Code with the gateway's address; a
  newly issued key can be copied straight into them.
- **Key management:** `[keys]` keeps the gateway's four secrets (ElGamal
  key, tokenizer key, audit key, ledger key) in a keystore wrapped by AWS KMS,
  HashiCorp Vault Transit, Google Cloud KMS, Azure Key Vault or a local
  passphrase, each bound to the tenant. `tokenis-mcp secrets init | status |
  rewrap`.
- **Encrypted ledger:** `tokenis-mcp ingest` reads the source once and writes
  an AES-256-GCM ledger; serving hosts load it and never see the source.
- **Database sources:** `[data] url_env` + `table`/`query` streams rows from
  PostgreSQL, MySQL/MariaDB, Oracle, SQL Server, Snowflake or BigQuery
  through SQLAlchemy; passwords are refused in the file.
- **Several replicas:** `[state] backend = "postgres"` shares the admission
  history, the hash-chained audit trail and API keys between gateway
  processes. Each call runs in one transaction under a per-tenant advisory
  lock after replaying the other replicas' decisions, so a differencing pair
  split across replicas is refused. A replica whose database call fails
  rebuilds its admission state from the shared log before answering again.
- **Integrity across replicas:** the shared admission log is hash-chained.
  A replica whose history was restored from an older backup, edited, or
  reset by another replica refuses every call and reports not ready, until
  an operator restarts it.
- **Operations:** `/healthz`, `/readyz` and Prometheus `/metrics` on every
  HTTP replica; JSON logs (`--log-format json`); stateless HTTP mode for load
  balancers (`[server] stateless`).
- **Admin console** at `/admin` (`[ops] admin_token_env`): health, traffic,
  denials by rule, per-tool outcomes, a searchable audit trail, API keys and
  the policy in force. It is read-only, has light and dark themes, works on
  mobile, and makes no external requests (strict nonce-based CSP).
- **Deployment:** a Docker Compose stack (replicas, nginx, PostgreSQL,
  Prometheus, Grafana); a hardened Helm chart (Ingress, HPA, PDB,
  NetworkPolicy, ServiceMonitor, PrometheusRule, Grafana dashboard);
  alert rules. The Docker image now includes the database and KMS drivers.
- New guides: tools, deployment, LLM integration, troubleshooting.
- The audit trail streams from its storage instead of being held in memory.
- CI runs the database tests against real PostgreSQL and MySQL servers, and
  lints, renders and schema-validates the Helm chart and alert rules.

- **Audit readiness:** coverage-guided fuzzing of the Rust core (four
  libFuzzer targets in `fuzz/`) and property-based fuzzing of every
  tamperable input (`tests/test_fuzz_inputs.py`), run on pull requests and
  nightly; a threat model, a guide for auditors and release-verification
  instructions; `cargo deny` license and source policy.
- **Signed releases with SBOMs:** every release file gets a Sigstore
  (cosign, keyless) signature bundle, a `SHA256SUMS` file and build
  provenance. CycloneDX SBOMs cover the Python package with every runtime
  extra, each Rust crate and the npm SDK. The container image is signed,
  and its SBOM and provenance are attested in the registry.

### Added (admin console)
- **Single sign-on and roles:** people sign in to the console with the
  organisation's identity provider (OpenID Connect, PKCE) and get the role
  the configuration gives them (viewer, auditor, admin), enforced by the
  server. Every admin activity entry names the person. Sessions are signed
  cookies shared by all replicas. The admin token remains as a break-glass
  credential. Helm: `admin.oidc`.
- **Cluster-wide, persistent statistics:** every call (tool, principal,
  outcome, rule, time, replica; never an argument or a value) is recorded
  in the shared database (or SQLite for one server), written in the
  background. The console shows the same numbers on every replica over
  1 hour, 24 hours, 7 days or 30 days, compared with the previous period,
  and nothing resets on restart. Latency percentiles are exact.
- **Users page:** calls, refusals, top refusal rule and remaining budget
  per principal. **Replicas** and **top users** panels on the overview.
- **Key management in the console:** issue a key (shown once) and revoke
  one, with CSRF protection, and an **admin activity log** of every issue,
  revocation and export.
- **CSV exports** of calls and of the audit trail (no values; spreadsheet
  formulas neutralised).
- `[ops] stats_retention_days` (default 90).

### Security
- Shared state: a replica rebuilding after a database error now checks
  that the last committed record is still there, so a failover to a
  lagging standby or a restore is refused (before, it was accepted). The
  admission log is a chain keyed with the audit key and verified on every
  replay.
- Open `/metrics` no longer breaks denials down by rule (that told callers
  why they were refused); set `[ops] metrics_token_env` to get the
  breakdown.
- Azure Key Vault: each wrapped secret carries a signature made inside the
  vault, since RSA-OAEP alone can be produced with the public key.
  **Keystores wrapped with Azure must be recreated** (`secrets init`, or
  `secrets rewrap` from another provider); the key needs sign and verify
  permissions.
- `disclose_ratio` and `disclose_bucket` refuse band-mode columns
  (thresholds could bisect the exact total).
- The admin console enforces the Host allow-list; Compose passes each
  container only its own secrets; stricter Vault address and URL password
  checks; driver errors never echo a password.

### Fixed (stability)
- Deadlock between a tool call and `/metrics` or the dashboard with the
  postgres backend.
- A connection lost mid-call left the replica's state unmarked; database
  restarts are now absorbed by replacing dead connections before a call.
- Database connections have connect, statement and lock timeouts; waits for
  the gateway lock are bounded; `/readyz` answers within 2.5 s; requests
  that cannot be authenticated during an outage get 503 with `Retry-After`.
- The history fingerprint no longer depends on row order, and database
  sources are read in `id_column` order. **The fingerprint changed: restart
  existing deployments once with `--reset-admission-state`.**
- A failed audit-trail write no longer leaves a partial line behind.
- Reading the newest trail entries no longer scans the whole file, and a
  torn final line is repaired without reading the file into memory.
- The API-key check no longer blocks the event loop.

### Fixed
- `tokenis-core`: `elgamal::to_bytes_many` panicked on an empty slice (found
  by fuzzing). The Python `CiphertextVector.to_bytes` now raises instead of
  writing a short encoding if a worker thread fails.
- Damaged state files (audit trail, admission log, keystore, ledger
  manifest) and unusual config paths now raise the component's own error
  instead of `UnicodeDecodeError`, `KeyError` or `AttributeError` (found by
  fuzzing).
- Startup failures (history mismatch, a trail that fails verification, too
  few records) print one clear line instead of a Python traceback.
- Unexpected errors during a tool call (for example a database outage) no
  longer pass driver messages to the caller. They are logged for the
  operator, and the caller sees "temporarily unavailable".
- The `group_by` limit message now gives advice that works (filters do not
  reduce a key's distinct values).

## [0.1.0] - 2026-09-24

First release, distributed from GitHub alone:
`uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp serve --demo`.

### Distribution
- Every version tag publishes to GitHub only:
  - a GitHub Release with wheels for Linux, macOS and Windows, the sdist,
    the npm tarball and the Claude Desktop bundle, all with build provenance;
  - a PEP 503 package index on GitHub Pages pointing at those wheels
    (`packaging/build_index.py`);
  - a multi-arch image on the GitHub Container Registry.

  `uv` consults that index first for `tokenis-mcp`, so a same-named package
  on another registry cannot be substituted. The release then installs itself
  with the published one-liner as a final check.
- The minimum Python version is now 3.10 (3.9 reached end of life in October
  2025), so `uvx` picks a suitable interpreter on its own, and the server
  dependencies are unconditional.

### Added
- **One-command installs, like other popular MCP servers:** `uvx` from the
  GitHub Pages index (the server installs by default, no extra needed); a
  Claude Code plugin marketplace (`/plugin marketplace add
  tokenismcp/tokenis-mcp`) whose plugin bundles the server and an analysis
  skill; a Claude Desktop extension (`tokenis.mcpb`, MCPB 0.4, uv runtime);
  a non-root Docker image with the MCP Registry label; and an MCP Registry
  `server.json` pointing at that image (published only with PUBLISH_REGISTRY). `packaging/check_packaging.py` launches each exactly as its
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
  version tag (see Distribution above); npm publishing with build
  provenance, behind the `PUBLISH_NPM` repository variable.
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
