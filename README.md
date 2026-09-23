# Tokenis

![CI](https://github.com/tokenismcp/tokenis-mcp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Docs license](https://img.shields.io/badge/docs%20license-CC--BY--4.0-lightgrey.svg)
![Rust](https://img.shields.io/badge/core-Rust-orange.svg)
![Python](https://img.shields.io/badge/python-3.9%2B%20(core)%20%7C%203.10%2B%20(server)-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-Node%2022%2B-blue.svg)

**A cryptographic disclosure-boundary gateway between an enterprise's
protected data and a large language model: the model gets a small set of
tools that answer aggregate questions over encrypted data, under admission
control and a signed audit trail, and never sees a row.** Plus the research
papers and measurement code the design is accountable to.

A model connected to Tokenis can ask "total 2025 revenue for tech companies
in Seoul?" and get `7,000,000 KRW over 12 records`. It cannot ask for one
company's revenue, cannot get it by differencing two overlapping groups, and
cannot learn *why* a question was refused. Every answer and every refusal is
recorded, under the authenticated user's identity, in a tamper-evident log.

## Connect an LLM

Install (Python 3.10+; prebuilt wheels for Linux, macOS and Windows):

```bash
pip install "tokenis-mcp[server]"        # add [llm] for the Anthropic/OpenAI clients
tokenis-mcp tools --demo                  # the tool schemas a model will see
```

Everything below works with the built-in fictional dataset (`--demo`);
[Use your own data](#use-your-own-data) swaps in yours.

**Claude Code / Claude Desktop (local, stdio).**

```bash
claude mcp add tokenis -- tokenis-mcp serve --demo
```

For Claude Desktop, add the server to `claude_desktop_config.json`
([example](https://github.com/tokenismcp/tokenis-mcp/blob/main/examples/claude_desktop_config.json)).
Over stdio the caller is the local OS user (`local:<user>`), which is who the
query budget and audit trail are charged to.

**Any MCP client, remote (Streamable HTTP + authentication).** HTTP always
requires authentication — API keys or your identity provider's JWTs:

```bash
tokenis-mcp keys create alice@example.com --config tokenis.toml   # prints the key once
tokenis-mcp serve --config tokenis.toml --transport http
claude mcp add --transport http tokenis https://tokenis.example.com/mcp \
  --header "Authorization: Bearer $TOKENIS_KEY"
```

The principal is the key's (or token subject's) identity; a model cannot
choose it. The same URL and key work with Anthropic's MCP connector in the
Messages API and with any other MCP client.

**Straight from an LLM API (no MCP client needed).** `tokenis.llm` turns the
tools into Anthropic or OpenAI-compatible tool definitions and runs the
calls, through exactly the same code path as the MCP server:

```python
import anthropic
from tokenis.gateway.demo import demo_service
from tokenis.llm import TokenisToolkit, ask_anthropic

toolkit = TokenisToolkit(demo_service(), principal=current_user_id)  # your authenticated user
print(ask_anthropic(toolkit, "Which industry grew fastest from 2024 to 2025?",
                    client=anthropic.Anthropic()))                    # reads ANTHROPIC_API_KEY
```

`toolkit.anthropic_tools()` / `toolkit.openai_tools()` and
`toolkit.anthropic_tool_results(...)` / `toolkit.openai_tool_messages(...)`
plug into a tool loop you already have; `ask_openai` works with OpenAI,
Azure OpenAI and local models behind vLLM, Ollama or LiteLLM
(`OPENAI_BASE_URL`). Runnable versions:
[`examples/anthropic_agent.py`](https://github.com/tokenismcp/tokenis-mcp/blob/main/examples/anthropic_agent.py),
[`examples/openai_compatible_agent.py`](https://github.com/tokenismcp/tokenis-mcp/blob/main/examples/openai_compatible_agent.py).
Or from the shell: `tokenis-mcp ask --demo "Which region is largest?"`.

Pass `taint=1` (or, over HTTP, have your agent host set the configured
`X-Tokenis-Taint` header) when the conversation contains untrusted content
such as retrieved documents or e-mail: the gateway then narrows the tools to
counts and applies a much smaller budget (P4's D4).

## The tools

| Tool | What it answers | What leaves the gateway |
|---|---|---|
| `describe_dataset` | Columns, protection classes, filterable values, k, remaining budget, allowed purposes | Schema and public values only; uses no budget |
| `aggregate` | SUM / AVG / COUNT (VAR where enabled) of a sealed column over filtered records | The value (or a 1-2-5 band, per column) and the group size |
| `group_by` | The same, per value of a filterable column | Per-group values; groups the policy refuses are just "suppressed" |
| `compare_periods` | Two sealed columns over the same records | Direction and a ratio band only |
| `similarity_search` | Entities most like a given one | Entity tokens and a coarse similarity level |
| `exists` | Whether at least k records match | A boolean that never distinguishes 0 from a handful |
| `disclose_ratio` | Ratio of a column's totals over two groups | The ratio — an audited Reveal, only for a configured purpose |
| `disclose_bucket` | Which named bucket a group's total falls in | The label — an audited Reveal, only for a configured purpose |

Arguments are schema-checked against the actual dataset (column names and
filter values are enums), so a malformed call never reaches the gateway.
Every refusal returns one fixed message whatever the reason.

## Use your own data

1. Describe the data in a TOML file — which columns are `open` (released
   verbatim, filterable), `token` (released only as keyed pseudonyms), and
   `sealed` (encrypted at load; only aggregates leave). The annotated
   [`examples/tokenis.toml`](https://github.com/tokenismcp/tokenis-mcp/blob/main/examples/tokenis.toml)
   covers every option: admission budgets, decryption range, Reveal
   purposes, state directory, transport and authentication.
2. Provide the secrets through the environment (never in the file):

   ```bash
   export TOKENIS_TOKENIZER_KEY=$(tokenis-mcp keygen-secret)   # keep stable: it defines every token
   export TOKENIS_AUDIT_KEY=$(tokenis-mcp keygen-secret)       # signs the audit trail
   ```

3. Validate, then serve:

   ```bash
   tokenis-mcp check --config tokenis.toml     # every row, every setting; changes nothing
   tokenis-mcp serve --config tokenis.toml
   tokenis-mcp audit verify --config tokenis.toml
   ```

Data is CSV (with a header) or JSON lines. Money and other decimals are
stored exactly (`scale = 2` keeps cents). With `[state] dir` set, the
admission history and the disclosure trace survive restarts; a restart with
different data refuses to start until you explicitly pass
`--reset-admission-state` (see
[SECURITY.md](https://github.com/tokenismcp/tokenis-mcp/blob/main/SECURITY.md)
for why that matters).

## Security model

What the gateway enforces, rather than asks the model to respect:

- **Identity from credentials, never from arguments.** stdio: the OS user.
  HTTP: API keys (stored as hashes, revocable without restart) or JWTs from
  your IdP (asymmetric algorithms only; `exp`/`iss`/`aud` required).
- **Admission control (P4 D1-D5)** on every value-bearing call: minimum
  group size k, a differencing audit that refuses any query that would
  combine with earlier ones to isolate a record, per-user budgets per
  window, a restricted surface while the context is tainted, and
  deny-by-default on unclassified columns. Admission, computation and
  auditing of a call are atomic, so concurrent calls cannot race past the
  differencing audit.
- **Refusals disclose nothing extra.** One message for every denial; the
  rule that fired is recorded for auditors only.
- **Durable, signed audit trail.** Every answer and refusal is appended,
  fsync'd and HMAC-signed before the result is returned
  (`tokenis-mcp audit verify`).
- **Uniform latency (W6).** Every call takes a multiple of a declared
  quantum, so timing does not reveal which path ran.
- **Cryptography in Rust.** Sealed values are EC-ElGamal ciphertexts from
  the moment they are loaded; keys and one-time secrets live in memory that
  is zeroed when freed.

What it does not do, stated plainly: plaintext exists inside the gateway
process at load time and at decryption (it is the trusted boundary; run it
on a host you control); embeddings for `similarity_search` are held in the
clear inside that process; decryption is not constant-time against a
co-located cache-timing attacker; the private key is generated per process
rather than held in an HSM; and neither this code nor its integration has
had an independent audit. Details and deployment guidance:
[SECURITY.md](https://github.com/tokenismcp/tokenis-mcp/blob/main/SECURITY.md).

## Why

Vendors of "privacy gateways" for LLMs routinely say the provider never sees
your data. [P2](https://github.com/tokenismcp/tokenis-mcp/blob/main/papers/p2-disclosure-boundaries/paper.md)
shows that sentence names one adversary where there are three, and gets the
capabilities of the one it does name wrong: the model host is not a passive
query executor, it *proposes the next query*.
[P3](https://github.com/tokenismcp/tokenis-mcp/blob/main/papers/p3-leakage-quantification/paper.md)
then measures what a tokenizing gateway actually leaks against a realistic
Korean corporate ledger — two public attributes alone re-identify 41.4% of
accounts inside a 40,000-firm public directory, and the three leakage
channels compose non-additively.
[P4](https://github.com/tokenismcp/tokenis-mcp/blob/main/papers/p4-admission-control/paper.md)
takes the same rigor to admission control once the querier is a language
model that can be steered by content it merely reads.

This repository exists so those aren't just claims in a PDF: every
percentage in P3, every containment bound in P4, and the disclosure-boundary
architecture of P2 has runnable code next to it.

## Architecture

```
   LLM / agent host  ──MCP (stdio | HTTP+auth)──▶  tokenis/mcp_server
   (untrusted query planner)        or tokenis.llm ─┘        │ principal from credentials
                                                             ▼
                         tokenis/gateway/service  ── one lock per call ──┐
                          │ admission (P4 D1-D5)   │ reveal (purposes)    │
                          │ + durable history      │                      │
                          ▼                        ▼                      ▼
                  ciphertext compute        Rust core (EC-ElGamal)   audit trace
                  over sealed columns       crates/tokenis-core      (hash-chained,
                                                                      HMAC, fsync)
```

```
            crates/tokenis-core  (Rust)  ── every cryptographic operation
                 │                     │
     PyO3 ───────┘                     └─────── wasm-bindgen / WebAssembly
        │                                                    │
 tokenis/ (Python)                                 sdk/typescript (TypeScript)
 gateway, admission, MCP server,                   @tokenis/crypto for Node 22+
 LLM toolkit, research reproduction
```

One Rust core, three languages, one wire format: Python and TypeScript are
thin bindings, and `tests/test_interop.py` has them exchange real keys,
ciphertexts and masked values in CI.

Every plaintext value that reaches the model is one of exactly four things
(P2 Definition 14, well-formedness condition W1 —
[`tokenis/spec/well-formedness.md`](https://github.com/tokenismcp/tokenis-mcp/blob/main/tokenis/spec/well-formedness.md)):
an open-class literal, a deterministic token, a ciphertext handle, or the
output of a gated, audited Reveal.
[`tokenis/conformance/`](https://github.com/tokenismcp/tokenis-mcp/tree/main/tokenis/conformance)
checks this and five other conditions.

## Repository layout

| Path | What it is |
|---|---|
| `tokenis/gateway/` | The gateway service, schema/settings, admission control (D1-D5), durable state, demo dataset |
| `tokenis/mcp_server/` | The MCP server (schema-driven tools, auth, async latency padding) |
| `tokenis/llm.py` | Direct Anthropic / OpenAI-compatible integration |
| `tokenis/cli.py`, `tokenis/config.py`, `tokenis/server_auth.py` | `tokenis-mcp` CLI, TOML config and data loader, API-key and JWT authentication |
| `tokenis/crypto/`, `tokenis/audit/`, `tokenis/semantic/` | Crypto (via the Rust core), disclosure trace, scoped tokenizer |
| `crates/` | Rust core (`tokenis-core`) and its PyO3 / WebAssembly bindings |
| `sdk/typescript/` | `@tokenis/crypto`, the TypeScript SDK |
| `tokenis/spec/`, `tokenis/conformance/` | The tool-surface and well-formedness specification, and its test suite |
| `papers/`, `research/` | The J1729Labs paper series (P2, P3, P4) and their reproduction code |
| `reports/SUMMARY.md` | Excerpts of the R1 (utility) and R2 (performance) reports — not the confidential originals |
| `examples/` | Quickstart, LLM agents, annotated config, fictional dataset, Claude Desktop config |

## Development

Needs a Rust toolchain ([rustup.rs](https://rustup.rs)); for the TypeScript
SDK also Node 22.18+ and [wasm-pack](https://rustwasm.github.io/wasm-pack/).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,research,server]"   # compiles the Rust core; drop `server` on Python 3.9
pytest                                     # everything the current interpreter can run
python examples/quickstart.py

cd sdk/typescript && npm ci && npm run build:wasm && npm run build && npm test
cargo test -p tokenis-core --release
```

See [CONTRIBUTING.md](https://github.com/tokenismcp/tokenis-mcp/blob/main/CONTRIBUTING.md)
for the full pre-PR checklist.

## What's open, what's closed

Mirroring R2 §1.4: the specification, this SDK and gateway, and the
conformance suite are Apache-2.0. What stays closed is 4Chains Inc.'s
product: an audited, HSM/KMS-integrated production engine, the
appliance/multi-tenancy layer, and the confidential performance benchmark.

The encryption here is additive EC-ElGamal over secp256k1
(`tokenis/crypto/ec_fhe.py`), built to match a set of "EC-FHE" / "elliptic
rational number" source papers as literally as possible. Those papers have
specific problems — a core map that cancels to a no-op, a multiplication
construction that does not type-check, a "bootstrap" that needs the private
key — and the module's docstring documents each one rather than quietly
working around it. Capability is additive homomorphism, which is all the
gateway's aggregates need. `tokenis/crypto/no_key_delegation.py` adds a
genuinely sound interactive protocol (one-time pads plus Beaver triples) for
letting an untrusted party compute affine functions and products on masked
values without any key.

**Why Rust for the crypto?** Python cannot zeroise a secret, cannot promise
constant-time arithmetic, and cannot make a one-time pad unusable after its
one use. In the Rust core, curve arithmetic is RustCrypto's `k256` (audited
by NCC Group in 2023); keys, masks and Beaver triples are zeroed on drop and
never become Python or JavaScript numbers; one-time values are consumed by
use and checked against their owner before they are touched; points read
from bytes are validated; randomness failures are errors, not panics; and
decryption runs in bounded memory with a constant step count.

## Quality signal

Checked by CI on every push (`.github/workflows/ci.yml`), not just claimed:

- **Rust:** `fmt`, `clippy -D warnings` with `unsafe`/`unwrap`/`expect`/
  `panic`/indexing denied in the core (host and `wasm32`), unit and property
  tests including arbitrary-byte fuzzing of every parser, an MSRV (1.85)
  build, and a freshness check of the bundled third-party license notices.
- **Python:** `ruff` (including flake8-bandit) and `mypy` clean; tests for
  the security properties at the binding boundary, the gateway's denial
  uniformity and admission semantics, a deterministic check that admission
  decisions never overlap under concurrency, restart durability, audit-trail
  tamper detection, JWT algorithm-confusion and `alg: none` rejection, and
  real stdio and authenticated-HTTP MCP sessions through the CLI.
- **TypeScript:** strict `tsc` and `node:test` on Node 22 and 24, 64-bit
  overflow rejected rather than wrapped, and the packed npm tarball
  installed into a fresh project and exercised from ESM and CommonJS.
- **Interop:** Python and TypeScript exchange real keys, ciphertexts and
  masked values.
- **Supply chain:** `cargo audit`, `pip-audit`, `npm audit` on every push and
  weekly; Dependabot for Cargo, pip, npm and Actions.
- All six well-formedness conditions (W1-W6) have passing conformance tests;
  `research/*/verify_claims.py` rerun each pipeline and fail on
  non-determinism.

## Status

Pre-1.0: interfaces may still change (see
[CHANGELOG.md](https://github.com/tokenismcp/tokenis-mcp/blob/main/CHANGELOG.md)).
Issues and PRs welcome. Found a security issue? Follow
[SECURITY.md](https://github.com/tokenismcp/tokenis-mcp/blob/main/SECURITY.md)
rather than opening a public issue.

## License

Code is Apache-2.0 (`LICENSE`); bundled third-party Rust crates are listed
in `THIRD-PARTY-NOTICES.md`. Papers and other documentation are CC BY 4.0
(`papers/LICENSE-CC-BY-4.0`).
