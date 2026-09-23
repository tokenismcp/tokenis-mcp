# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project has not yet made a tagged release, so everything so far is under
`[Unreleased]`.

## [Unreleased]

### Added
- The J1729Labs paper series (P2 Disclosure Boundaries, P3 Leakage
  Quantification, P4 Admission Control) with per-paper navigation pages.
- `research/p3_leakage/`: corpus generator, three leakage attacks, D1-D5
  defense frontiers, and the four-component disclosure budget from P3,
  each with a `verify_claims.py` that checks determinism and internal
  consistency rather than claiming to reproduce the paper's literal
  published percentages (see that directory's README for why).
- `research/p4_admission/`: the D1-D5 admission-control ladder, an exact
  GF(2^31-1) RREF auditor, eight evaluation attacks, and the containment
  bounds from P4, with the same verify_claims.py pattern.
- `tokenis/`: the reference SDK — a Paillier-based additively homomorphic
  compute engine, a scope-confined tokenizer, the D1-D5 admission engine
  (adopted from `research/p4_admission`), a gated/audited Reveal
  operation with a hash-chained disclosure trace, and an MCP server
  exposing all seven tools from `tokenis/spec/tool-surface.md`.
- `tokenis/conformance/`: a pytest suite checking all six well-formedness
  conditions (W1-W6, P2 Definition 17) against the reference SDK.
- `tokenis/gateway/latency.py`: response-latency quantization (W6) so an
  admission denial and a permitted call are observationally identical in
  timing.
- `reports/SUMMARY.md`: excerpted findings from the R1 (utility) and R2
  (performance) technical reports, with customer-identifying and
  not-yet-measured confidential figures excluded per those reports' own
  classification markings.
- `examples/quickstart.py`: an in-process, seven-tool tour of the SDK.
- Standard OSS project files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this changelog, and a two-track CI workflow
  (Python 3.9+ for the core/research code, 3.10+ for the MCP server).

### Changed
- Replaced a hand-rolled additive-ElGamal construction over raw
  elliptic-curve point arithmetic with `tokenis/crypto/paillier.py`, built
  on `phe` (python-paillier) — the Paillier cryptosystem (1999) rather
  than an in-repository EC construction, with direct/unbounded decryption
  in place of a range-limited baby-step-giant-step search.

### Fixed
- A Python 3.11+ `dataclasses` incompatibility in the (now-removed)
  EC-ElGamal module: `field(default=...)` with an unhashable default
  raised `ValueError` on Python 3.12 while silently working on 3.9.
- A baby-step-giant-step sign-handling bug in the same (now-removed)
  module that made negative-plaintext decryption fail.
- An admission-control gap where `disclose_ratio`/`disclose_bucket`'s
  underlying aggregate sums had no minimum-query-set-size check at all —
  an authorized Reveal purpose was, before this fix, sufficient by itself
  to read out an aggregate over an arbitrarily small group.
