# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No tagged
release yet: everything below is `[Unreleased]` and describes the current
state; "History" records how the crypto layer got here.

## [Unreleased]

### Added
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
  quantization), a scope-confined tokenizer, and an MCP server exposing all
  seven tools in `tokenis/spec/tool-surface.md`.
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
- Decryption walks its whole baby-step-giant-step search whatever the
  plaintext (pinned by a Rust test), and releases the Python GIL.
- An `assert` guarding the admission policy in `tokenis/gateway/service.py`
  became an explicit check (asserts vanish under `python -O`).
- CI: `cargo fmt`/`clippy -D warnings`, `ruff` (incl. flake8-bandit),
  `mypy`, strict `tsc`, and `cargo audit` + `pip-audit` + `npm audit` on
  every push and weekly; Dependabot for Cargo, pip, npm and Actions.

### Fixed
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
