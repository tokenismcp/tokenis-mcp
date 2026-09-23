# Tokenis

![CI](https://github.com/tokenismcp/tokenis-mcp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Docs license](https://img.shields.io/badge/docs%20license-CC--BY--4.0-lightgrey.svg)
![Rust](https://img.shields.io/badge/core-Rust-orange.svg)
![Python](https://img.shields.io/badge/python-3.9%2B%20(core)%20%7C%203.10%2B%20(MCP%20server)-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-Node%2020%2B-blue.svg)

**A cryptographic disclosure-boundary gateway between an enterprise's protected
data and a large language model, exposed to the model as an MCP (Model
Context Protocol) server — plus the research paper series and measurement
pipeline this repository's design is accountable to.**

Tokenis sells access to *operations* over encrypted data, not access to the
data itself. A model gets a small, named tool surface (aggregate, compare,
search, check existence) instead of a general query interface; every value
that crosses from ciphertext into the model's view does so through a typed,
audited path. This repository is the open layer of that design — the
specification, the reference SDK, the conformance suite, and the papers and
measurement code behind the claims — while the product's optimised
cryptographic engine, key management, appliance and multi-tenancy stay
closed (see [What's open, what's closed](#whats-open-whats-closed) below).

## Why

Vendors of "privacy gateways" for LLMs routinely say the provider never sees
your data. [P2](papers/p2-disclosure-boundaries/paper.md) shows that
sentence names one adversary where there are three, and gets the
capabilities of the one it does name wrong: the model host is not a passive
query executor, it *proposes the next query*. [P3](papers/p3-leakage-quantification/paper.md)
then measures what a tokenizing gateway actually leaks against a realistic
Korean corporate ledger — two public attributes alone re-identify 41.4% of
accounts inside a 40,000-firm public directory, and the three leakage
channels compose non-additively, not additively. [P4](papers/p4-admission-control/paper.md)
takes the same rigor to the admission-control layer once the querier is a
language model that can be steered by content it merely reads.

This repository exists so those aren't just claims in a PDF: every
percentage in P3, every containment bound in P4, and the disclosure-boundary
architecture of P2 has runnable code next to it.

## Architecture

```
                    ┌─────────────────────────────────────────┐
   model host  ────▶│  tokenis/mcp_server   (MCP tool surface) │
  (untrusted,       └───────────────┬───────────────────────┬─┘
   query planner)                   │                       │
                     ┌───────────────▼──────────┐  ┌─────────▼─────────┐
                     │ tokenis/gateway/admission │  │ tokenis/semantic  │
                     │  D1-D5 policy ladder (P4) │  │  scope-confined   │
                     └───────────────┬───────────┘  │  tokenizer (P2)   │
                                     │               └────────────────────┘
                     ┌───────────────▼───────────┐
                     │  tokenis/gateway/compute   │  ciphertext SUM/COUNT/
                     │  (EC-FHE, additive HE)     │  AVG/VAR — no plaintext
                     └───────────────┬────────────┘  ever stored (P2 Thm 29)
                                     │
                     ┌───────────────▼───────────┐
                     │  tokenis/gateway/reveal    │  gated + audited
                     │  + tokenis/audit/trace     │  boundary crossings
                     └────────────────────────────┘  (P2 Definitions 15-16)
```

### Languages

```
            crates/tokenis-core  (Rust)  ── every cryptographic operation
                 │                     │
     PyO3 ───────┘                     └─────── wasm-bindgen / WebAssembly
        │                                                    │
 tokenis/ (Python)                                 sdk/typescript (TypeScript)
 gateway, admission, MCP server,                   @tokenis/crypto for Node
 research reproduction                             MCP clients and servers
```

One Rust core, three languages, one wire format. The cryptography —
EC-ElGamal over secp256k1 and the no-key delegation protocol — exists only
in [`crates/tokenis-core`](crates/tokenis-core); Python and TypeScript are
thin bindings over it, so they cannot drift apart, and
[`tests/test_interop.py`](tests/test_interop.py) has the two exchange real
keys, ciphertexts and masked values in CI. Everything above the crypto layer
(the gateway, admission control, MCP server, research code) stays in Python.

Every plaintext value that reaches the model is one of exactly four things
(P2 Definition 14, the "well-formedness" condition W1 —
[`tokenis/spec/well-formedness.md`](tokenis/spec/well-formedness.md)): an
open-class literal, a deterministic token, a ciphertext handle, or the
output of a gated, audited `Reveal`. [`tokenis/conformance/`](tokenis/conformance)
checks this and five other conditions against the reference SDK.

## Repository layout

| Path | What it is |
|---|---|
| [`papers/`](papers) | The J1729Labs paper series (P2 disclosure boundaries, P3 leakage quantification, P4 admission control) — abstract, key results and full PDF per paper |
| [`research/p3_leakage/`](research/p3_leakage) | P3's corpus generator, three attacks, five defenses, and disclosure-budget computation — the code release P3 itself commits to |
| [`research/p4_admission/`](research/p4_admission) | P4's D1-D5 admission-control engine, eight evaluation attacks, and containment-bound checks |
| [`crates/tokenis-core/`](crates/tokenis-core) | The Rust cryptographic core: EC-ElGamal and no-key delegation, shared by every SDK |
| [`crates/tokenis-py/`](crates/tokenis-py), [`crates/tokenis-wasm/`](crates/tokenis-wasm) | PyO3 and WebAssembly bindings over the core |
| [`tokenis/`](tokenis) | The Python SDK: crypto (via the Rust core), tokenizer, ciphertext compute, admission, reveal, audit trace, and the MCP server that exposes all of it |
| [`sdk/typescript/`](sdk/typescript) | `@tokenis/crypto`, the TypeScript SDK (same core compiled to WebAssembly) |
| [`tokenis/spec/`](tokenis/spec) | The tool-surface and well-formedness specification any gateway implementation (this one, or a future closed engine) should satisfy |
| [`tokenis/conformance/`](tokenis/conformance) | pytest suite checking the reference SDK against that spec |
| [`reports/SUMMARY.md`](reports/SUMMARY.md) | Excerpted findings from the R1 (utility) and R2 (performance) technical reports — not the full confidential reports themselves |
| [`examples/quickstart.py`](examples/quickstart.py) | A five-minute, in-process tour of all seven tools |

## Quickstart

**Python.** Released wheels are prebuilt for Linux, macOS and Windows (one
wheel per platform covers CPython 3.9+). Building from source needs a Rust
toolchain ([rustup.rs](https://rustup.rs)); `pip` compiles the core
automatically. The MCP server needs Python 3.10+ (the `mcp` package's own
floor):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,research,server]"   # builds crates/tokenis-core; drop `server` on Python <3.10

pytest                                     # everything the current interpreter can run
python research/p3_leakage/verify_claims.py
python research/p4_admission/verify_claims.py
python examples/quickstart.py              # needs the `server` extra
```

To connect a real MCP client instead of the in-process quickstart:

```bash
python -m tokenis.mcp_server.server        # speaks stdio
```

**TypeScript** (Node 20+; building needs Rust and
[wasm-pack](https://rustwasm.github.io/wasm-pack/)):

```bash
cd sdk/typescript
npm ci && npm run build:wasm && npm run build && npm test
```

```ts
import { keygen, encrypt, decrypt } from "@tokenis/crypto";

const { privateKey, publicKey } = keygen();
const sum = encrypt(publicKey, 40n).add(encrypt(publicKey, 2n));
decrypt(privateKey, sum); // 42n
```

**Rust:** `cargo test -p tokenis-core`.

## What's open, what's closed

Mirroring R2 §1.4 (summarized in [`reports/SUMMARY.md`](reports/SUMMARY.md)):
the specification, this reference SDK, and the conformance suite are
distributed freely under Apache-2.0. What stays closed is 4Chains Inc.'s
product: an audited, key-management/HSM-integrated production engine, the
appliance/multi-tenancy layer, and the full confidential performance
benchmark (R2). The [`tokenis/crypto`](tokenis/crypto) module in this
repository is explicitly **not** that engine: it is an elliptic-curve
additive-ElGamal construction (`tokenis/crypto/ec_fhe.py`), built to match a
set of "EC-FHE" / "elliptic rational number" source papers as literally as
possible. Those papers have real, specific problems — a core function that
cancels to a no-op, a multiplicative-homomorphism construction that does
not type-check, a "bootstrap" that requires the private key — and this
module's own docstring documents each one rather than quietly working
around it, because implementing broken cryptography and presenting it as
solid is a worse outcome than implementing it faithfully and saying so.
Read that docstring before using anything in this package for more than
running this repository's own examples and tests.

**Why Rust for the crypto?** Python cannot zeroise a secret from memory,
cannot guarantee constant-time execution, and has no compile-time way to
make a one-time pad unusable after its one use. The core therefore lives in
Rust, where: curve arithmetic is RustCrypto's `k256` (audited by NCC Group
in 2023, constant-time by design); private keys, masks and Beaver triples
are zeroed on drop and never become Python `int`s or JavaScript numbers;
masks and triples are consumed by the operation that uses them; every
point read from bytes is validated on-curve; decryption does the same work
whatever the plaintext; and the crate forbids `unsafe` and every panicking
construct, so malformed input from Python or JavaScript returns an error
instead of crashing the process. (An earlier revision did its curve
arithmetic in the pure-Python `ecdsa` package, which `pip-audit` flags for
a key-recovering timing attack its maintainers will not fix.) What remains
for the closed engine is hardware-backed key storage (HSM/KMS) and an
independent audit of this integration.

`tokenis/crypto/no_key_delegation.py` is a separate, genuinely sound
addition on the same foundation: an interactive delegation protocol
(one-time-pad masking + Beaver triples, standard secure-computation
technique, not something this repository invented) that lets an untrusted
party evaluate affine functions and products over masked values while
provably learning nothing about the plaintext — including against a
quantum adversary — without ever holding key material. It does not make
the underlying scheme post-quantum, and it is not wired into the gateway's
trust model; see that module's docstring for exactly what it proves and
what it doesn't.

## Quality signal

Every claim below is something CI (`.github/workflows/ci.yml`) actually
checks on every push, not just documentation:

- **Rust:** `cargo fmt --check`, `cargo clippy -D warnings` with
  `unsafe`, `unwrap`, `expect`, `panic` and slice indexing denied in the
  core, unit and property tests (including one that pins decryption work as
  independent of the plaintext, and one feeding arbitrary bytes to every
  parser), and a `wasm32` build.
- **Python:** `ruff check .` (including flake8-bandit security rules on the
  SDK) and `mypy tokenis` clean; `tests/test_crypto_security.py` pins each
  claimed security property at the Python boundary (no secret attribute,
  redacted `repr`, unpicklable key handles, one-time masks, off-curve points
  rejected, no injectable RNG) and `tests/test_properties.py` checks the
  homomorphic identities on hypothesis-generated inputs.
- **TypeScript:** strict `tsc` (including `noUncheckedIndexedAccess` and
  `exactOptionalPropertyTypes`) and `node:test` suites; the built package is
  also loaded on the oldest supported Node.
- **Interop:** Python and TypeScript exchange real keys, ciphertexts and
  masked values (`tests/test_interop.py`), including bit-identical
  fixed-point rounding.
- **Supply chain:** `cargo audit`, `pip-audit` and `npm audit` on every push
  and weekly on schedule; Dependabot for Cargo, pip, npm and Actions.
- All six well-formedness conditions (W1-W6,
  [`tokenis/spec/well-formedness.md`](tokenis/spec/well-formedness.md)) have
  passing conformance tests — none are stubbed, skipped, or marked `xfail`.
- The Python suite passes on 3.9, 3.11 and 3.13 (one abi3 extension build
  serves all of them), and the MCP server on 3.10, 3.12 and 3.13.
- `research/p3_leakage/verify_claims.py` and
  `research/p4_admission/verify_claims.py` each run their full pipeline
  twice from the same seeds and hard-fail on any non-determinism.

## Status

Early-stage but no longer a rough sketch: see
[CHANGELOG.md](CHANGELOG.md) for what's landed, and each package's
docstrings for the specific, named simplifications that remain (e.g.
`tokenis/gateway/service.py`'s notes on `principal` not being real
authentication, or `credential_id == principal`) — these are stated
deliberately rather than silently assumed away. Issues and PRs welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Found a security issue? See
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Code is [Apache-2.0](LICENSE). Papers and other documentation are
[CC BY 4.0](papers/LICENSE-CC-BY-4.0). See also
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
