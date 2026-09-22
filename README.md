# Tokenis

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
                     │  (EC-ElGamal, additive HE) │  AVG/VAR — no plaintext
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
product: an optimised, audited cryptographic engine, key management and HSM
integration, the appliance/multi-tenancy layer, and the full confidential
performance benchmark (R2). The [`tokenis/crypto`](tokenis/crypto) module in
this repository is explicitly **not** that engine — see its module
docstring for the reference-implementation disclaimer before using it for
anything beyond running this repository's own examples and tests.

## Status

Early — see each paper's page and each package's docstrings for what's
implemented versus what's a documented, deliberate gap (e.g.
[`tokenis/spec/well-formedness.md`](tokenis/spec/well-formedness.md)'s note
on W6/latency quantization). Issues and PRs welcome.

## License

Code is [Apache-2.0](LICENSE). Papers and other documentation are
[CC BY 4.0](papers/LICENSE-CC-BY-4.0).
