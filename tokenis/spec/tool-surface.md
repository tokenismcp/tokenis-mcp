# Tool surface

Per P2 §3.5, a gateway's tools fall into three families that differ in what
they place outside the protected domain, and per R2 §1.4 the catalogue is
deliberately capped at five-to-seven named verbs rather than a general
query interface — "tool count is capped at five to seven. Beyond roughly
ten tools, model selection accuracy degrades sharply, and every additional
tool description also inflates the prompt token count on every inference
turn. Variety is absorbed through arguments, not through additional
tools." This is also a security property, not just a UX one: P2 §3.5
requires the predicate language to be written over the *exposed*
vocabulary only (open-class literals and tokens the model has already
seen) — a general `query(sql)` style tool cannot be schema-restricted this
way, which is why R2 §1.2 lists "a generic SQL proxy" under "what Tokenis
is not."

| Tool | Family | Operation | Return form | Boundary |
|---|---|---|---|---|
| `aggregate` | Aggregate | SUM / COUNT / AVG / VAR over a SEALED column, caller-chosen predicate | Band or exact value, per product mode ([`reports/SUMMARY.md`](../../reports/SUMMARY.md) mode table) | Ciphertext domain; decrypted at the boundary, logged to the disclosure trace |
| `group_by` | Aggregate | `aggregate`, partitioned by an OPEN or TOKEN key | Per-group bands, k-suppressed (P3 §7/§8 D3) | Ciphertext domain |
| `compare_periods` | Aggregate | Difference between two aggregates, `Enc(delta)` | Relative ratio or direction only (never the raw difference, which is itself a value disclosure) | Ciphertext domain |
| `similarity_search` | Lookup | Top-k nearest records over encrypted vectors | Ranked TOKEN-class IDs | Ciphertext domain |
| `exists` | Lookup | Presence test for a record or attribute value | Boolean | Ciphertext domain |
| `disclose_ratio` | Reveal | Division — the ciphertext domain cannot perform this under an additive-only scheme (see [`tokenis/gateway/compute.py`](../gateway/compute.py) module docstring) | Numeric ratio | **Crosses the boundary** — gated via [`tokenis/gateway/reveal.py`](../gateway/reveal.py), synchronously audited |
| `disclose_bucket` | Reveal | Threshold classification into a named bucket | Bucket label | **Crosses the boundary** — gated + audited |

Two **resources** (not tools — they carry no call arguments and disclose no
row values) let the model plan without seeing data:

- **Catalogue metadata**: table/column names, protection class per
  attribute, permitted operations, minimum aggregation size, units. Not one
  field *value* leaves the protected domain through this channel — but
  P2 Definition 19 (`L_schema`, catalogue leakage) still counts it: knowing
  that `customer.revenue` is SEALED, aggregate-only, minimum-5-records is
  itself information a model (and hence [P3](../../papers/p3-leakage-quantification/paper.md)'s
  adversary) can use to plan a query sequence, even before any query runs.
- **Prompt templates**: disclosure-policy rules, sector presets, safe
  analysis procedures, published as reusable guidance. R2 §1.4 is explicit
  that **prompts carry no enforcement power** — the MCP server is the only
  enforcement point. A deployment that ships prompt guidance and lets
  users believe it is a security control is the configuration R2 warns puts
  the vendor's name in an incident report.

## Why `disclose_ratio` / `disclose_bucket` are separate tools

Division and threshold comparison cannot be performed over EC-ElGamal
ciphertext (no multiplicative homomorphism — see
[`tokenis/gateway/compute.py`](../gateway/compute.py)). The wrong response
to that limitation is to hide the decrypt-and-compute step inside another
tool's implementation, where a caller (and an auditor) cannot tell from the
tool name alone that a boundary crossing occurred. Instead each such
operation is its own tool whose *name* announces that it crosses the
boundary — this is how P2's disclosure boundary (§5) becomes a checkable
product property (every call to one of these two tools must produce a
[`tokenis.audit.trace`](../audit/trace.py) entry; see
[`tokenis/conformance/`](../conformance)) rather than an internal design
note nobody can verify from outside.
