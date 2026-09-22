# Tokenis gateway specification

This is the "distributed freely" layer R2 refers to: the tool surface a
conforming gateway exposes to a model host, and the well-formedness
conditions ([`well-formedness.md`](./well-formedness.md)) any implementation
of this spec — this repository's reference SDK, or a future closed,
optimised engine — must satisfy. [`tokenis/conformance/`](../conformance)
checks these conditions against this repository's own reference
implementation; a third party implementing the spec independently can run
the same suite against their own gateway by implementing the small adapter
interface documented there.

- [`tool-surface.md`](./tool-surface.md) — the seven tools and the two
  resource kinds (R2 §1.4), and which protection class each tool argument
  and return value carries.
- [`well-formedness.md`](./well-formedness.md) — conditions W1-W6
  (P2 Definition 17) a gateway must satisfy for the paper series'
  simulation-security theorems to apply to it.
