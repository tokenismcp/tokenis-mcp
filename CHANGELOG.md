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
- `tokenis/`: the reference SDK — an EC-FHE-based additively homomorphic
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
- `tokenis/crypto/no_key_delegation.py`: an interactive delegation
  protocol (one-time-pad masking of `tokenis.crypto.ec_fhe`'s
  plaintext-domain group elements, plus Beaver-triple masked
  multiplication and blinded bootstrapping) letting an untrusted party
  evaluate affine functions and products while provably learning nothing
  about the plaintext, including against a quantum adversary that fully
  compromises it — see that module's docstring for what this does and
  does not provide, and for why (unlike the three papers `ec_fhe.py`
  documents problems in) its source paper is sound: it avoids the broken
  Weil-pairing multiplication entirely, and never lets an untrusted party
  bootstrap without the key.
- Standard OSS project files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, this changelog, and a two-track CI workflow
  (Python 3.9+ for the core/research code, 3.10+ for the MCP server).

### Changed
- The crypto backend went through two revisions before settling on its
  current form, `tokenis/crypto/ec_fhe.py`:
  1. A hand-rolled additive-ElGamal construction over raw elliptic-curve
     point arithmetic (the original).
  2. A brief replacement with `tokenis/crypto/paillier.py`, built on `phe`
     (python-paillier) — a well-established non-EC scheme, chosen at the
     time to get unbounded/direct decryption and offload the arithmetic to
     a purpose-built library instead of this repository's own point-adding
     code. This was reverted after the maintainer pointed out it silently
     abandoned the EC-based architecture the paper series specifies,
     without that tradeoff being discussed first.
  3. `tokenis/crypto/ec_fhe.py`, the current module: EC-based again, and
     built to match a set of "EC-FHE" / "elliptic rational number" source
     papers as literally as possible. Those papers have three specific,
     documented problems (a core "isomorphism" function that cancels to a
     no-op in every formula that uses it, a ciphertext-times-ciphertext
     multiplicative-homomorphism construction that doesn't type-check, and
     a "bootstrap" operation that requires the private key and so isn't
     usable by an untrusted evaluator) — see that module's docstring for
     the full explanation. The scheme's actual capability is the same
     class as both predecessors: additive homomorphism only.

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
