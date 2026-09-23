# Security Policy

## Scope

This repository contains:

- **A reference SDK** (`tokenis/`) demonstrating the disclosure-boundary
  architecture described in the [J1729Labs paper series](papers/). Its
  crypto module (`tokenis/crypto/ec_fhe.py`) is explicitly documented as
  a reference integration, not an independently audited implementation —
  see that module's docstring for exactly what that does and doesn't mean.
- **Research reproduction code** (`research/`) for measuring leakage (P3)
  and admission-control containment (P4) on synthetic corpora.

Vulnerability reports are welcome for both, but please weigh severity
accordingly: a flaw in `tokenis/gateway/admission.py`'s D1-D5 logic or in
the crypto integration is more consequential than a bug in a
research-reproduction script's synthetic-data generator.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Email **director@j1729labs.online** with:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a minimal example against this repository's
  reference SDK or research code is ideal).
- Which file(s)/function(s) you believe are affected.

We aim to acknowledge reports within 5 business days. This is a small,
early-stage open-source project without a dedicated security team or a
paid bug-bounty program — please set expectations accordingly, and thank
you for reporting responsibly rather than disclosing publicly first.

## What we consider in scope

- Logic errors in `tokenis/gateway/admission.py` that let a query bypass
  D1-D5 (e.g., a filter-language construction that evades the minimum
  query-set-size or rowspace-audit checks).
- Logic errors in `tokenis/gateway/reveal.py` or `tokenis/audit/trace.py`
  that let a value cross the disclosure boundary without being logged, or
  let a logged entry be altered without `verify_chain()` detecting it.
- Bugs in `tokenis/crypto/ec_fhe.py` or `tokenis/crypto/no_key_delegation.py`
  (not in libsecp256k1/`coincurve` themselves — report those upstream) that
  break the stated `Dec(Enc(x) (+) Enc(y)) = x + y` property, leak key
  material or masks, accept a point that is not on secp256k1, or make
  decryption work depend on the plaintext value. Each of those properties
  has a pinning test in `tests/test_crypto_security.py`; a report that one
  of them doesn't hold in practice despite the test is exactly what we
  want to hear about.
- Any `tokenis/mcp_server` code path that lets a tool argument reach a
  place principal/subject identity should have gated it instead (see the
  "`principal` is not authentication" note in
  `tokenis/gateway/service.py`'s module docstring — a report that this
  reference-implementation simplification exists is not new information,
  but a report that a *specific deployment pattern* built on this SDK
  inherits a real bypass is welcome).

## What is explicitly out of scope

- The absence of a formal third-party security audit of the crypto
  module, or the specific, already-documented problems in the "EC-FHE"
  source papers that module's docstring describes (a decorative core
  function, a multiplicative-homomorphism construction that doesn't
  type-check, a "bootstrap" that needs the private key) — these are known,
  stated limitations, not vulnerabilities to report (see
  `tokenis/crypto/ec_fhe.py`'s docstring).
- Findings against `research/` code that only affect the synthetic,
  fabricated corpora those scripts generate — there is no real data to
  expose there.
- The known, documented `TokenisGatewayService`/`ReferenceGateway`
  simplifications already called out in module docstrings (e.g.,
  `credential_id == principal`, in-memory-only key storage) — these are
  reference-implementation choices, not undisclosed bugs.
