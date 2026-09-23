# Well-formedness conditions (W1-W6)

P2 Definition 17 defines a **well-formed gateway** as one satisfying six
conditions. P2's simulation-security theorems (Theorems 28/29) are proved
*for* a well-formed gateway — a gateway that violates one of these isn't
just "less secure," it's outside the scope of what the papers in this
repository prove anything about. [`tokenis/conformance/`](./../conformance)
tests each of these against this repository's reference implementation, and
is meant to be reusable against any other implementation of this spec via
its adapter interface.

| # | Condition | What it requires | Checked by |
|---|---|---|---|
| W1 | **Closure** | Every value appearing outside the protected domain is open-class, a token, a ciphertext, or an output of `Reveal`. Nothing else may cross. | `test_w1_closure.py` — every value returned by every tool is one of these four forms |
| W2 | **Gating** | Every `Reveal` is preceded by a policy decision and emits an audit record. | `test_w2_gating.py` — [`tokenis/gateway/reveal.py`](../gateway/reveal.py)'s `reveal()` cannot return a value without a corresponding `DisclosureTrace` entry; see its source for why this is structural, not just tested |
| W3 | **Typed interface** | Every tool argument and return is typed by protection class; no free-form field carries an enclosed value without egress screening. | `test_w3_typed_interface.py` |
| W4 | **Declared scope** | Every TOKEN-class attribute declares a scope function and rotation policy. | `test_w4_declared_scope.py` — every [`ScopedTokenizer`](../semantic/tokenizer.py) call site names an explicit scope (attribute + tenant + epoch), never a bare value |
| W5 | **Simulatable admission** | The admit/deny decision is computable from exposed state alone (public catalogue, prior decisions, prior responses, policy) — never from the protected value itself. | `test_w5_simulatable_admission.py` — asserts [`tokenis/gateway/admission.py`](../gateway/admission.py)'s decision function's signature and body never receive the protected values array (P4 Proposition 33) |
| W6 | **Uniform latency** | Response latency and error taxonomy are quantized to a declared granularity independent of the data, so the interface exposes no data-dependent timing channel. | `test_w6_uniform_latency.py` — asserts an admitted and a D1-denied `aggregate` call (and a Reveal-denied vs. Reveal-permitted `disclose_ratio` call) land in the same declared time bucket, via [`tokenis/gateway/latency.py`](../gateway/latency.py) |

## Status of W5 in this reference implementation

P2 §5.3 treats W5 as a *design recommendation* rather than an unconditional
requirement: its Theorem 28 holds whether or not W5 is satisfied, because
admission decisions are placed inside the leakage profile (`L_agg`)
unconditionally regardless. A gateway that *does* satisfy W5 simply
discloses strictly less, because its decisions are then derivable by
anyone holding the rest of the profile. [`tokenis/gateway/admission.py`](../gateway/admission.py)
(adopted from [`research/p4_admission/admission.py`](../../research/p4_admission/admission.py))
is built to satisfy W5 by construction — see P4 Proposition 33, "the
policy is simulatable" — rather than relying on the weaker unconditional
fallback.

## Status of W6 in this reference implementation

[`tokenis/gateway/latency.py`](../gateway/latency.py)'s `@quantize_latency`
wraps every public tool method on
[`TokenisGatewayService`](../gateway/service.py), and the MCP server
(`tokenis/mcp_server/server.py`, also used by `tokenis.llm`) pads every tool
call the same way with an async sleep: each call is padded, via `try`/`finally`, to the next
multiple of `latency_granularity_ms` (default 250ms, inside R2's tightest
quoted SLO bucket) — on the success path and the exception path alike, so
a fast D1 admission denial and a slow permitted aggregate are
observationally identical in timing. The mechanism is a simple sleep-out,
not a scheduling or batching system: it does not smooth out contention
under concurrent load, only the latency of a single call relative to its
own declared bucket. `test_w6_uniform_latency.py` checks the observable
property (admitted vs. denied calls land in the same bucket) rather than
re-deriving the padding arithmetic `tests/test_latency.py` already covers
directly.
