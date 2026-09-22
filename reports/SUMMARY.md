# Benchmark summary (R1, R2)

4Chains Inc. issues two technical reports alongside the J1729Labs paper
series: **R1** (utility degradation) and **R2** (performance). Both are
internal/customer deliverables and are **not** included in this repository
in full — R2 is marked *Confidential, for the recipient's internal review
only, reproduction or disclosure to third parties is prohibited*, and R1 is
marked *External — may be shared with prospective customers*, which is not
the same as public. This page summarizes only the methodology and
already-public-facing headline findings; no customer names, internal
document-control metadata, or not-yet-measured confidential figures are
reproduced here.

## R1 — Utility Degradation of LLM Responses under Cryptographic Protection Layers

*4Chains Inc., TR-2026-R1 v1.0.* Answers one question: after Tokenis
removes information from the model's context, is the assistant still
useful? It deliberately does **not** answer whether the layer is secure
(that's [P2](../papers/p2-disclosure-boundaries/paper.md)/[P3](../papers/p3-leakage-quantification/paper.md)),
fast enough (that's R2, below), or resistant to prompt injection (that's
[P4](../papers/p4-admission-control/paper.md)).

The report separates two causes of utility loss that call for opposite
responses: information the protection layer removed (unrecoverable by any
model — the only fix is changing the protection mode) versus information
that's present but a model fails to use (recoverable — better prompt,
tool surface, or model). It measures the first directly as an
**information-availability ceiling** — the maximum accuracy an ideal
reasoner could reach from what a protection condition leaves in context —
on 500 synthetic-corpus task instances × 4 protection conditions, with a
20-instance LLM pilot for indicative (not statistically powered)
reference.

**Three findings:**

1. **Tokenizing identifiers costs nothing in utility.** Across all seven
   banking use cases measured, replacing direct identifiers with
   deterministic tokens left the relative accuracy ceiling unchanged from
   plaintext (100.0). Analysis depends on entity *identity*, not entity
   *names*, and a deterministic token preserves identity exactly.
2. **The entire utility cost sits in generalization and aggregation.**
   Generalizing quasi-identifiers drops the ceiling to 73 (relative to
   plaintext = 100); withdrawing row-level access entirely drops it to 11.
3. **The model does not reliably refuse when it should.** Of sixteen pilot
   items with no basis for an answer in context, the model answered four,
   asserting two without qualification — a confident-error rate that
   quadrupled between plaintext/tokenization and the generalized condition.
   This is why [`tokenis/gateway/admission.py`](../tokenis/gateway/admission.py)
   enforces refusal at the gateway (minimum-aggregation-size rejection,
   deny-by-default on unclassified columns, unanswerable query types
   removed from the tool surface) rather than delegating the decision to
   the model.

**Deployment verdict by use case** (SAFE / DEGRADED / NOT ADVISED, per a
verdict rule frozen before measurement — accuracy ≥ 95 *and*
confident-error rate within +2pp of baseline for SAFE; the rule gives
confident-error rate priority over raw accuracy, because in banking
operations an assistant that confidently asserts something false is worse
than one that says it doesn't know):

| Use case | Tokenized | Tokenized + Generalized | Aggregate only |
|---|---|---|---|
| Aggregate balance/volume queries | SAFE | SAFE | SAFE |
| Period comparison & trend reporting | SAFE | NOT ADVISED | NOT ADVISED |
| Segment profiling | SAFE | NOT ADVISED | NOT ADVISED |
| First-pass anomaly interpretation | SAFE | NOT ADVISED | NOT ADVISED |
| Contact-log summarization | SAFE | DEGRADED | NOT ADVISED |
| Causal attribution / hypothesis generation | SAFE | DEGRADED | NOT ADVISED |
| Entity-specific lookup | SAFE | NOT ADVISED | NOT ADVISED |

The practical reading: token-only deployments keep essentially every
workflow usable; generalization is where a real product-configuration
decision has to be made per use case, trading the [P3](../papers/p3-leakage-quantification/paper.md)
re-identification exposure against the utility this table quantifies.

## R2 — Tokenis MCP Gateway Performance Technical Report

*4Chains Inc., 4C-TR-2026-R2 v3.1, Confidential.* This report fixes the
**measurement specification** for gateway-added latency (written
`Δ_gw` — the latency Tokenis itself adds; end-to-end latency is dominated
by the model host, which Tokenis does not control, so end-to-end figures
are reported for context only and never appear in a service-level
objective) ahead of running the actual measurement campaign; at the time of
writing its result tables are formatted and awaiting values, so there are
no confidential customer or throughput figures to summarize here — only the
architecture and decision criteria, which are not confidential:

- **Product definition** (echoed by this repository's `tokenis/` package):
  Tokenis is model-independent middleware that sells access to *operations*
  over encrypted data, not access to the data itself — the same core
  behind five interchangeable host adapters (MCP server, an
  OpenAI-compatible endpoint, a Postgres extension, a 1U HSM-backed
  appliance, and a thin egress proxy for the pasted-text path an MCP tool
  surface structurally cannot see).
- **Decision criteria, fixed before measurement:** `Δ_gw` p95 ≤ 200 ms for
  in-call conversational use, ≤ 300 ms for agent screen lookups, ≤ 3 s for
  post-call processing.
- **The expected conclusion, stated in advance so measurement could falsify
  it:** single-attribute lookups and precomputed aggregate reads should sit
  inside the in-call budget; large live aggregations should not. Whichever
  way measurement lands, the product-mode-separation table is the
  deliverable that gets amended or confirmed by it — not a marketing claim
  made independent of measurement.
- **Tool surface is capped at five-to-seven tools.** Model tool-selection
  accuracy degrades sharply past roughly ten tools, and every additional
  tool description inflates the prompt token count on every inference turn
  — variety is absorbed through tool *arguments*, not through additional
  tools. This is why [`tokenis/mcp_server/server.py`](../tokenis/mcp_server/server.py)
  exposes exactly the seven tools this report and R1 both reference
  (`aggregate`, `group_by`, `compare_periods`, `similarity_search`,
  `exists`, `disclose_ratio`, `disclose_bucket`), not a general query
  interface.

## What's *not* here

Customer-identifying figures (e.g. a named proof-of-concept's throughput
numbers), internal document-control metadata, and any not-yet-measured
confidential figure from R2 are intentionally omitted. If you're a
prospective customer or partner and want the full reports, contact
4Chains Inc. directly.
