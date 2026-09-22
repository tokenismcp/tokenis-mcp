# Disclosure Boundaries: A Threat Model and Leakage Formalisation for Privacy Gateways in LLM Agent Systems

**Eunice Lee, Sophia Shim, Caleb Lee — J1729Labs**
September 2026 · [paper.pdf](./paper.pdf) · License: [CC BY 4.0](../LICENSE-CC-BY-4.0)

> The full paper, with all definitions, theorems and proofs, is in [`paper.pdf`](./paper.pdf).
> This page is a navigation aid, not a substitute for it.

## Abstract

Systems that place a cryptographic gateway between an enterprise data estate and a
third-party large language model are routinely described as protecting "the data" from
"the provider." That description names one adversary where there are three, and it
misses what is distinctive about the model host: it observes the interface *and also
proposes the queries that cross it*.

This paper separates the **model host**, the **infrastructure operator** and the
**legitimate tool caller**, characterising each by an observation function together with
an influence parameter *γ* — the worst-case probability that a call it proposes is
executed. It defines the **disclosure boundary** as a partition of system state whose
every plaintext crossing is a gated, audited operation; decomposes gateway leakage into
catalogue, token, disclosed-value and access-pattern components; and proves
simulation-based security statements for the host and the operator, independent of *γ*
— influence governs how fast an adversary steers the leakage, not what leaks.

The main results are negative and concern **composition**: total leakage is provably
sub-additive for deterministic views, so bit-counting disclosure budgets are unsound,
while *safety does not compose* — an instance is exhibited in which k-anonymity and
minimum-query-set-size control both hold, and each view alone leaves an adversary's
posterior on a target record unchanged, yet the joint view reconstructs that record
exactly in two admitted aggregate queries.

## Why this paper matters for Tokenis

This is the threat-model foundation the rest of the series (and the `tokenis/` reference
SDK in this repository) is built on:

- The **six-role trust model** (data owner, gateway, model host, infrastructure operator,
  end user, orchestrator) and the **three-module gateway split** (semantic / compute /
  admission) map directly onto [`tokenis/semantic`](../../tokenis/semantic),
  [`tokenis/gateway/compute.py`](../../tokenis/gateway/compute.py) and
  [`tokenis/gateway/admission.py`](../../tokenis/gateway/admission.py).
- The **well-formed gateway** conditions (W1–W6, Definition 17) are the requirements
  implemented and checked by [`tokenis/conformance`](../../tokenis/conformance).
- The **Reveal operation** and **disclosure trace** (Definitions 15–16) are implemented
  in [`tokenis/gateway/reveal.py`](../../tokenis/gateway/reveal.py) and
  [`tokenis/audit/trace.py`](../../tokenis/audit/trace.py).
- The composition-failure result (Theorem 41) is the reason [P3](../p3-leakage-quantification/paper.md)
  and [P4](../p4-admission-control/paper.md) exist as separate, empirical follow-ups
  rather than being derivable from this paper's bounds alone.

## Table of contents (paper.pdf)

| § | Title |
|---|---|
| 1 | Introduction — three adversaries, the host as query planner, why leakage doesn't add up |
| 2 | Background and related work (leakage-parameterised security, leakage-abuse attacks, inference control, anonymisation, LLM privacy tech, MCP/agent security) |
| 3 | System model (parties, data model, cryptographic components, gateway architecture, interface) |
| 4 | Adversaries (observation, γ-influence, the three adversaries + composite) |
| 5 | The disclosure boundary (state partition, Reveal, well-formed gateways, leakage decomposition, security definitions, Theorems 28/29) |
| 6 | Composition results (sub-additivity, the safety-separation construction, vocabulary-enabling theorem, row-space criterion, span condition) |
| 7 | Scope and limitations |
| App. A | Fourteen tool-schema constraints for a conforming gateway interface |
| App. B | Descriptive Korean/EU regulatory mapping |

## Key results

- **Definition 5 (γ-influence).** An adversary is characterised by *what it observes* and
  *how reliably a query it proposes is executed* — the classical searchable-encryption
  adversary sits at γ = 1; a passive server sits at γ = 0; a real gateway with an approval
  path sits strictly between.
- **Corollary 35.** Influence governs the *rate* at which an attack completes
  (expected proposals ≤ m/γ), not the leakage *profile* — human-in-the-loop confirmation
  is a rate limiter, not a confidentiality control.
- **Theorem 41.** A concrete two-adversary construction where k-anonymity and
  minimum-query-set-size control both hold throughout, yet the joint (token + aggregate)
  view determines a target record exactly.
- **Theorem 46.** The token channel is the *enabling condition* for the aggregate channel
  — a gateway's predicate language is written over tokens the adversary must first observe.
- **Theorems 49 & 51.** Minimum-query-set-size control bounds row *weights* of the
  released query matrix, but reconstruction is governed by its row *space*; weight-k rows
  can still span rank n. The control that actually works is a span condition
  (Definition 54), enforceable in polynomial time in the single-record case and NP-hard
  adjacent in general.

## Citation

```bibtex
@techreport{lee2026disclosure,
  title       = {Disclosure Boundaries: A Threat Model and Leakage Formalisation for
                 Privacy Gateways in LLM Agent Systems},
  author      = {Lee, Eunice and Shim, Sophia and Lee, Caleb},
  institution = {J1729Labs},
  year        = {2026},
  month       = {9},
  note        = {Companion paper P2, Tokenis deliverable programme}
}
```
