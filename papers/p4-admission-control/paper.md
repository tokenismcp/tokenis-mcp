# Admission Control for Probabilistic Callers: Bounding Disclosure When the Query Planner Is a Language Model

**Eunice Lee, Sophia Shim, Caleb Lee — J1729Labs**
September 2026 · [paper.pdf](./paper.pdf) · License: [CC BY 4.0](../LICENSE-CC-BY-4.0)
Reproduction code: [`research/p4_admission/`](../../research/p4_admission/)

> The full paper is in [`paper.pdf`](./paper.pdf). This page is a navigation aid.

## Abstract

A gateway that answers aggregate queries over an encrypted store for a language-model
agent — an MCP server, typically — is a statistical database whose querier has changed
character: it is *generated*, not motivated; it is *steerable* by untrusted content that
reaches the model's context (indirect prompt injection); and its queries are cheap enough
to issue in bulk. The disclosure controls built for human analysts between 1977 and 1990
therefore transfer in form and fail in force.

This paper defines the resulting adversary (𝒜inject), enumerates the channels through
which a *tool's return value* — not the tool call — reaches it, and gives an exact
linear-algebraic criterion for compromise together with three corrections to its naive
application. On a synthetic corporate ledger of 5,000 firms, a minimum-query-set-size
rule alone leaves every value-recovery attack at a 1.00 success rate, an individual
record falling to two admitted queries. It proves a containment bound of B·log₂M bits per
subject per window, sharpens it by the rank of the admitted queries, shows the
record-recovery form is tight to within a factor of two, and proves that a budget keyed
to the *agent's credential* (rather than the authenticated end user) admits no bound of
this form at all. The claim is **containment, not prevention**: no swept configuration
reaches zero attack success at full analyst utility.

## Why this paper matters for Tokenis

This paper *is* the admission-control layer shipped in this repository:

- [`research/p4_admission/admission.py`](../../research/p4_admission/admission.py)
  implements the D1–D5 policy ladder (minimum query-set size, GF(p)-RREF differencing
  control, subject-scoped budget, taint-gated tool surface, deny-by-default on
  unclassified columns) exactly as specified in §5, and is adopted **unchanged** as
  [`tokenis/gateway/admission.py`](../../tokenis/gateway/admission.py) — the paper's
  own research artifact is the product's admission engine, not a separate reference.
- [`research/p4_admission/attacks.py`](../../research/p4_admission/attacks.py)
  reproduces the eight evaluation attacks of §8, which
  [`tokenis/conformance`](../../tokenis/conformance) runs as **regression tests**: a
  future change to the admission engine that reopens the two-query tracker, the AVG/SUM
  exemption hole, or the credential-rotation bypass fails CI.
- **Theorem 13 (credential-scoped budgets admit no bound)** is why
  [`tokenis/gateway/admission.py`](../../tokenis/gateway/admission.py) refuses to operate
  without an authenticated end-user subject on every call — this is enforced, not merely
  documented.
- **§3.4 (egress channels E1/E2/E3)** is why the MCP tool catalogue in
  [`tokenis/mcp_server/server.py`](../../tokenis/mcp_server/server.py) refuses
  external-effect tools (fetch/send/write) whenever the taint bit is set, and why the
  admission decision itself is only ever a function of public state (Proposition 33,
  "the policy is simulatable").

## Table of contents (paper.pdf)

| § | Title |
|---|---|
| 1 | Introduction — three assumptions the classical literature made that MCP breaks |
| 2 | Background (statistical-database inference control, prompt injection, MCP security, encrypted-store leakage) |
| 3 | System and threat model (𝒜host, 𝒜infra, 𝒜user, 𝒜inject; egress channels E1–E3; non-goals) |
| 4 | What the classical controls do and do not buy (two-query tracker, general tracker, query economics) |
| 5 | Admission control design (D1 min query-set size, D2 differencing control, D3 budget scope, D4 taint-gated surface, D5 deny-by-default) |
| 6 | Containment bounds (basic bound, rank refinement, injection-attributable refinement, simulatability) |
| 7 | Implementation |
| 8 | Evaluation (eight attacks × ten policy configurations) |
| 9 | Discussion |

## Key results

- **Proposition 4 / 5 (two-query & general tracker).** A minimum query-set size rule
  alone is defeated in exactly two admitted SUM queries per isolated record, and in four
  per sub-k cell, whenever the filter language admits a disjunction of conjunctions.
- **Theorem 7 / Lemma 9 (exact compromise criterion).** A value is determined by the
  admitted query matrix Q iff its standard-basis vector lies in `rowspace(Q)`; testing
  this is an exact, polynomial-time RREF computation — but it must be widened to a
  cell-aware weight-`[1, k-1]` test (an NP-hard relaxation, Remark 10) to catch sub-k
  aggregate disclosure, not just individual-record disclosure.
- **Theorem 13 (credential-scoped budgets admit no bound).** If an adversary can mint
  fresh credentials at negligible cost, a per-credential budget bounds nothing; the
  budget must be keyed to the authenticated end-user subject.
- **Theorem 16 / 20 / 26 (containment bounds).** `I(x; V | pub) ≤ B·log₂M`, sharpened to
  `rank(Q)·log₂M` for first-moment aggregates, and tight to within a factor of two for
  record recovery under exact responses.
- **Theorem 30 / 32 (injection-attributable bound).** Under taint gating,
  injection-attributable leakage is bounded by `Bτ·log₂Mτ`, degrading linearly in how
  many queries escape taint tracking untagged.
- **Proposition 33 / 34.** The admission policy's decisions are simulatable from public
  information alone (so refusals disclose nothing about protected values) — but the
  admit/deny sequence itself is an unclosable one-bit-per-call side channel, bounded only
  by a separate cap on *calls*, not on *admissions*.

## Citation

```bibtex
@techreport{lee2026admission,
  title       = {Admission Control for Probabilistic Callers: Bounding Disclosure When
                 the Query Planner Is a Language Model},
  author      = {Lee, Eunice and Shim, Sophia and Lee, Caleb},
  institution = {J1729Labs},
  year        = {2026},
  month       = {9},
  note        = {Companion paper P4, Tokenis deliverable programme}
}
```
