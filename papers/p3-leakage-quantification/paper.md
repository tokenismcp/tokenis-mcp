# What a Token Does Not Hide: Leakage Quantification and Disclosure Budgets for LLM Gateways over Corporate Ledgers

**Eunice Lee, Sophia Shim, Caleb Lee — J1729Labs**
September 2026 · [paper.pdf](./paper.pdf) · License: [CC BY 4.0](../LICENSE-CC-BY-4.0)
Reproduction code: [`research/p3_leakage/`](../../research/p3_leakage/)

> The full paper is in [`paper.pdf`](./paper.pdf). This page is a navigation aid.
> The paper's own "Availability" section commits to releasing the measurement code —
> [`research/p3_leakage/`](../../research/p3_leakage/) in this repository is that release.

## Abstract

Gateways that place a tokenizing layer between an enterprise database and a hosted
language model are usually justified by analogy to pseudonymization. This paper asks,
and answers by measurement, what that analogy is worth when the records describe
**corporations rather than natural persons** — sharpest in the Korean case, where a
firm's industry code, registered address, revenue band, headcount band, founding year
and listing status are all recoverable *by statute* from public filings, so an adversary
needs no auxiliary-knowledge acquisition step at all.

On a synthetic 4,000-account ledger calibrated to published Korean aggregates: two
public attributes single out 41.4% of accounts inside a 40,000-firm directory, four
single out 91.5%. Three attacks (attribute combination, cross-session token linkage,
differential inference) are measured and shown **not** to compose additively — disclosed
columns alone re-identify 7.3%, exact aggregates alone and the co-occurrence graph alone
re-identify *none* of the ledger, yet the three together reach 9.8%. The dominant
variable is not the tokenization scheme but which columns the gateway lets through beside
the token: 1.2% re-identified under a token-only profile vs. 86.3% under the profile an
analyst asks for unprompted. Exact aggregates over caller-chosen sets are shown to admit
no finite ε, independent of minimum aggregate size k.

## Why this paper matters for Tokenis

This is the paper that turns the abstract composition-failure result of
[P2](../p2-disclosure-boundaries/paper.md) into **numbers on a realistic corpus**, and
those numbers are what [`reports/SUMMARY.md`](../../reports/SUMMARY.md) and the
`tokenis/` reference SDK's default configuration are built to respect:

- [`research/p3_leakage/corpus.py`](../../research/p3_leakage/corpus.py) reproduces the
  synthetic 40,000-firm directory / 4,000-account ledger generator (§4).
- [`research/p3_leakage/attack_schema_uniqueness.py`](../../research/p3_leakage/attack_schema_uniqueness.py),
  [`attack_token_linkage.py`](../../research/p3_leakage/attack_token_linkage.py) and
  [`attack_differential_inference.py`](../../research/p3_leakage/attack_differential_inference.py)
  reproduce §§5–7.
- [`research/p3_leakage/defenses.py`](../../research/p3_leakage/defenses.py) reproduces
  the D1–D5 security/utility frontier of §8, which directly motivates why
  [`tokenis/gateway/admission.py`](../../tokenis/gateway/admission.py) defaults to
  generalization + predicate-language restriction rather than session-scoped tokens or a
  bare minimum-aggregate-size rule.
- [`research/p3_leakage/budget.py`](../../research/p3_leakage/budget.py) reproduces the
  four-component disclosure budget and the four product modes (A–D) of §9; Tokenis ships
  **Mode D (split channel)** as its default, per this paper's own recommendation.

**Note on reproduced figures:** the paper names its RNG seeds (corpus seed `20260920`,
workload seed `7`) but not the literal generator source. `research/p3_leakage/` is a
faithful re-implementation of the *described* method and calibrated statistics (Korean
industry-classification cardinalities, locality counts, etc. are taken verbatim from
official sources), but exact headline percentages may differ from the paper's own numbers
by construction — see `verify_claims.py` and its docstring for what is and isn't claimed.

## Table of contents (paper.pdf)

| § | Title |
|---|---|
| 1 | Introduction — five contributions |
| 2 | Background and related work |
| 3 | Setting (the gateway, adversaries and leakage components, the public directory) |
| 4 | Corpus (why corporations are not persons, construction, workload, provenance table) |
| 5 | Attribute-combination re-identification |
| 6 | Token linkage and composition (non-additivity, corroboration/precision, disclosure-profile dominance) |
| 7 | Differential inference (isolation and why k doesn't help, bulk reconstruction, noise averaging) |
| 8 | Defenses and what they cost (D1–D5 security/utility frontiers) |
| 9 | The disclosure budget (components, Claim 1 — no finite ε for exact aggregates, four product modes) |
| 10 | Limitations |
| 11 | Conclusion |
| App. A | Regulatory mapping (PIPA, Credit Information Act, electronic financial supervision, GDPR) |
| App. B | Reproduction |

## Key results

- **Corporate re-identification baseline (§5).** Industry × locality alone has 273,884
  cells against ~4×10⁴ publicly enumerable Korean firms — 75.3% of occupied cells hold a
  single firm, before any attack begins.
- **Non-additive composition (§6.2, Fig. 3).** Marginal re-identification sums to 7.3%;
  the joint reaches 9.8% — a 34% relative increase over the best marginal, because the
  schema channel is *generative* (produces anchors from nothing) while the token and
  aggregate channels are merely *amplifying*.
- **Disclosure profile dominates (§6.5, Fig. 4).** Same pipeline, same workload, same
  adversary: re-identification moves from 1.2% (token-only) to 86.3% (rich profile) — a
  factor of seventy — while session-scoped token rotation only moves it from 9.8% to
  7.9% and destroys 100% of legitimate cross-session analysis.
- **Isolability is independent of k (§7.1, Fig. 6).** When the filter language can
  express set difference, isolating a record costs exactly two queries regardless of the
  minimum aggregate size k; only *restricting the predicate language* (no exclusion
  clause) collapses isolability, and only in combination with k.
- **No finite ε for exact aggregates (§9.2, Claim 1).** Proven directly from two
  neighbouring databases producing disjoint output supports. Randomization prices badly
  against heavy-tailed corporate amounts: the noise an analyst tolerates buys ε ≈ 111 per
  query.

## Citation

```bibtex
@techreport{lee2026leakage,
  title       = {What a Token Does Not Hide: Leakage Quantification and Disclosure
                 Budgets for LLM Gateways over Corporate Ledgers},
  author      = {Lee, Eunice and Shim, Sophia and Lee, Caleb},
  institution = {J1729Labs},
  year        = {2026},
  month       = {9},
  note        = {Companion paper P3, Tokenis deliverable programme}
}
```
