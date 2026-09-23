# Tokenis

![CI](https://github.com/tokenismcp/tokenis-mcp/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Docs license](https://img.shields.io/badge/docs%20license-CC--BY--4.0-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.9%2B%20(core)%20%7C%203.10%2B%20(MCP%20server)-blue.svg)

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
| [`tokenis/`](tokenis) | The reference SDK: crypto, tokenizer, ciphertext compute, admission, reveal, audit trace, and the MCP server that exposes all of it |
| [`tokenis/spec/`](tokenis/spec) | The tool-surface and well-formedness specification any gateway implementation (this one, or a future closed engine) should satisfy |
| [`tokenis/conformance/`](tokenis/conformance) | pytest suite checking the reference SDK against that spec |
| [`reports/SUMMARY.md`](reports/SUMMARY.md) | Excerpted findings from the R1 (utility) and R2 (performance) technical reports — not the full confidential reports themselves |
| [`examples/quickstart.py`](examples/quickstart.py) | A five-minute, in-process tour of all seven tools |

## Quickstart

The crypto/semantic/gateway/audit core and the research reproduction code
run on Python 3.9+. The MCP server needs Python 3.10+ (the `mcp` package's
own floor):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,research,server]"   # drop `server` if you're on Python <3.10

pytest                                     # everything the current interpreter can run
python research/p3_leakage/verify_claims.py
python research/p4_admission/verify_claims.py
python examples/quickstart.py              # needs the `server` extra
```

To connect a real MCP client instead of the in-process quickstart:

```bash
python -m tokenis.mcp_server.server        # speaks stdio
```

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

**Is Python enough for this?** For the gateway, admission control and MCP
server, yes. For the cryptography, not on its own — which is why none of
the elliptic-curve arithmetic here runs in Python. It is delegated to
libsecp256k1 (the C library Bitcoin Core uses) via `coincurve`, so every
operation on a secret scalar uses that library's constant-time code. An
earlier revision used the pure-Python `ecdsa` package; `pip-audit` now flags
that package for a key-recovering timing attack its maintainers consider
out of scope, which is the concrete reason for the change. What Python
still cannot give you — zeroising secrets from memory, and hardware-backed
key storage — is listed in `tokenis/crypto/ec_fhe.py`'s docstring and is
the part R2 assigns to the closed engine.

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

- `ruff check .` — zero lint findings across the whole repository,
  including flake8-bandit security rules on the shipped SDK.
- `mypy tokenis` — zero type errors on the product SDK.
- `pip-audit` — no known vulnerabilities in the resolved dependency set,
  re-run weekly by schedule so a newly published advisory fails CI even
  without a push; Dependabot proposes the upgrades.
- `tests/test_crypto_security.py` pins each security property the crypto
  module claims (secrets absent from `repr` and unpicklable, off-curve
  points rejected, decryption work independent of the plaintext, seeded
  RNGs flagged), and `tests/test_properties.py` checks the homomorphic
  identities on hypothesis-generated inputs rather than hand-picked ones.
- All six well-formedness conditions (W1-W6,
  [`tokenis/spec/well-formedness.md`](tokenis/spec/well-formedness.md)) have
  passing conformance tests — none are stubbed, skipped, or marked `xfail`.
- The full test suite (100+ tests) passes on Python 3.9, 3.11 and 3.13 for
  the core SDK/research code, and 3.10, 3.12 and 3.13 for the MCP server.
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
