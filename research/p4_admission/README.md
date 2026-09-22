# P4 — Admission Control for Probabilistic Callers

Reproduction code for **"Admission Control for Probabilistic Callers: Bounding
Disclosure When the Query Planner Is a Language Model"** (Lee, Shim, Lee;
J1729Labs, 2026). The full paper is at
[`papers/p4-admission-control/paper.pdf`](../../papers/p4-admission-control/paper.pdf);
a navigation aid is at
[`papers/p4-admission-control/paper.md`](../../papers/p4-admission-control/paper.md).

## What this reproduces

The paper defines an adversary (`Ainject`) who steers an LLM agent's tool
calls against an aggregate-query gateway through indirect prompt injection,
gives an exact linear-algebraic criterion for when a sequence of admitted
aggregate queries determines a protected value (Theorem 7), and builds a
five-rule admission-control ladder (D1-D5, §5) around it, together with
information-theoretic containment bounds (§6) and an eight-attack evaluation
(§8). This package reproduces:

- the D1-D5 policy ladder, as an importable, product-shaped
  `AdmissionPolicy` (`admission.py`);
- the exact GF(p) reduced-row-echelon-form auditor behind D2 (Theorem 7,
  Lemma 9, the cell-aware relaxation of Remark 10);
- the credential- vs. subject-scoped budget distinction behind D3
  (Theorem 13, Corollary 14);
- the eight evaluation attacks of §8 (`attacks.py`);
- the containment bounds of §6 as checkable functions, not narrative
  (`bounds.py`);
- a security/utility policy-ladder sweep in the shape of the paper's Table 4
  (`evaluate.py`);
- a synthetic corporate ledger with the paper's qualitative low-cardinality
  structure (`ledger.py`).

## Honesty disclaimer

**The paper's literal headline numbers depend on an unpublished exact
generator and an unpublished exact attack harness.** Figures like "77.4% of
occupied cross-classification cells hold fewer than k=5 records", "9.8% of
records are uniquely identified by four public attributes alone", the
specific §8 latencies, and the exact attack-success percentages in Table 2
cannot be reproduced bit-for-bit from the paper alone — they depend on
generator and harness internals the paper does not publish.

This package does **not** claim to hit those literal numbers. Instead,
`verify_claims.py` verifies:

1. **Internal determinism** — the same seed produces identical results
   across runs.
2. **The mathematical properties the theorems actually assert** —
   Theorem 7 / Lemma 9's exact compromise criterion behaves exactly as
   proved on this reproduction's own admitted-query matrices; Theorem 13's
   credential-budget bypass is exhibited and the subject-scoped fix is shown
   to bound it; the Theorem 16 / Corollary 18 / Theorem 20 / Theorem 26 /
   Theorem 30 / Theorem 32 bounds are computed as closed-form functions of
   public parameters and checked as upper bounds against measurements taken
   on this reproduction's own ledger and attack constructions.

Where a measured percentage differs from the paper's own (for example, our
classical-audit general-tracker success rate is not the paper's 0.77 — see
the note in `attacks.py`'s `attack_general_tracker` docstring on cross-cell
basis contamination and why each cell is evaluated against a fresh policy
instance), that is expected: the qualitative claim ("classical audit misses
some sub-k disclosure, cell-aware audit closes it") is verified; the literal
number is not asserted to match.

## Paper section → file map

| Paper section | File |
|---|---|
| §3.1 system model (queries, characteristic sets, catalogue) | `admission.py` (predicate algebra), `gateway_sim.py` |
| §4 (population, Propositions 4/5/6) | `ledger.py`, `attacks.py` |
| §5.1 D1 minimum query-set size | `admission.py: AdmissionPolicy.decide` |
| §5.2 D2 differencing control (Theorem 7, Lemma 9, Remark 10, Remark 11) | `admission.py: RREFBasis` |
| §5.3 D3 budget scope (Theorem 13, Corollary 14) | `admission.py: SubjectScopedBudget, CredentialScopedBudget` |
| §5.4 D4 taint-gated tool surface (Proposition 34) | `admission.py: AdmissionPolicy.decide` (taint branch) |
| §5.5 D5 deny-by-default on unclassified columns | `admission.py: AdmissionPolicy.decide` |
| §6 containment bounds (Theorems 16/20/26/30/32) | `bounds.py` |
| §8 evaluation, eight attacks | `attacks.py` |
| §8.5 security/utility frontier | `evaluate.py` |
| §7 implementation / §8 headline numbers | `verify_claims.py` |

## How to run

```bash
# Fast unit tests (seconds)
pytest research/p4_admission -q

# Full pipeline: ledger -> policy -> attacks -> bounds -> sweep -> JSON
python research/p4_admission/verify_claims.py
```

`verify_claims.py` writes `research/p4_admission/results/verify_claims.json`
and exits non-zero if determinism fails, if the full D1-D5 stack fails to
block the attacks a weaker/buggy variant does not block, or if any computed
bound fails to upper-bound its measurement. It runs in well under two
minutes (well under a second on a typical laptop).

## `AdmissionPolicy`'s public API is the product's admission engine

`admission.py`'s `AdmissionPolicy` (plus `QueryContext`, `Query`, `Decision`,
the `Predicate` algebra, `SubjectScopedBudget` / `CredentialScopedBudget`,
and `RREFBasis`) is the same engine a later milestone imports **unchanged**
as `tokenis/gateway/admission.py` — this research artifact is the product's
admission-control module, not a separate reference implementation the
product reimplements. `admission.py` therefore depends on nothing outside
the Python standard library and numpy (no `research/p3_leakage`, no
`tokenis/`), uses plain absolute-style imports so it works whether it is
exercised from inside this package or imported directly from
`tokenis/gateway/`, and keeps its public surface deliberately small and
stable: construct an `AdmissionPolicy` with public per-record attributes and
a column catalogue (never protected values — `decide()` is a pure function
of public state only, Proposition 33), and call `decide(query, context) ->
Decision` per tool call.
