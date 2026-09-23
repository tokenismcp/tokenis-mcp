# Contributing to Tokenis

Thanks for considering a contribution. This is a small, early-stage
project (see the README's Status section), so please open an issue to
discuss anything beyond a small fix before investing significant time in
a PR — it saves everyone rework.

## Ground rules

- **Read the honesty disclaimers before changing what they describe.**
  Several modules carry an explicit, deliberate scope statement — e.g.
  `tokenis/crypto/paillier.py` ("reference integration, not audited"),
  `research/p3_leakage/README.md` and `research/p4_admission/README.md`
  ("verifies internal consistency, not the paper's literal numbers"). A
  PR that makes the code claim more than it can honestly claim (e.g. "this
  is now audited," "this reproduces the paper's exact published figures")
  will be asked to revise the claim, not just the code.
- **Don't weaken a well-formedness condition silently.** If a change
  touches `tokenis/gateway/admission.py`, `tokenis/gateway/reveal.py`, or
  `tokenis/audit/trace.py`, run the full conformance suite
  (`pytest tokenis/conformance`) and say in the PR description which of
  W1-W6 (`tokenis/spec/well-formedness.md`) the change affects, if any.
- **Match the honesty pattern in research code.** A change to
  `research/p3_leakage/` or `research/p4_admission/` that makes a measured
  number *more* impressive without a corresponding methodology change is
  the kind of thing `verify_claims.py`'s determinism/consistency checks
  exist to catch — make sure they still pass, and don't hand-tune a
  result to look better.

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,research,server]"   # drop `server` if you're on Python <3.10
```

Python 3.9+ is required for the core SDK and research code; the MCP
server (`tokenis/mcp_server`) needs Python 3.10+ (the `mcp` package's own
floor).

## Before opening a PR

```bash
ruff check .                                            # lint
pytest                                                    # everything the current interpreter can run
python research/p3_leakage/verify_claims.py               # ~1 minute on the default CI-sized profile
python research/p4_admission/verify_claims.py              # well under a second
python examples/quickstart.py                              # needs the `server` extra (Python >=3.10)
```

CI runs the same checks across Python 3.9/3.11/3.13 (core) and
3.10/3.12/3.13 (MCP server) — see `.github/workflows/ci.yml`.

## Commit messages

Explain *why*, not just *what* — this repository's own commit history is
written that way on purpose (`git log --oneline` gives a good sense of the
expected level of detail for anything touching security-relevant logic).
A one-line "fix bug" for a change to `admission.py` or `paillier.py` isn't
enough; say what the bug was and how you verified the fix.

## Scope of changes we're likely to accept

- Bug fixes with a regression test.
- Documentation corrections, including to the papers' navigation pages
  (`papers/*/paper.md`) — but not edits to the paper PDFs themselves,
  which are the authors' primary source.
- New conformance tests, or research-reproduction robustness
  improvements, that don't change what's claimed.
- New tool implementations or SDK features that follow the existing
  disclosure-boundary pattern (typed protection classes, admission-checked
  before touching ciphertext, audited on every boundary crossing).

Larger architectural changes (a new crypto backend, a new admission rule,
a new paper's reproduction code) should start as an issue describing the
approach.

## License

By contributing, you agree your contribution is licensed under this
repository's existing licenses: Apache-2.0 for code, CC BY 4.0 for
documentation and papers (see [LICENSE](LICENSE) and
[papers/LICENSE-CC-BY-4.0](papers/LICENSE-CC-BY-4.0)).
