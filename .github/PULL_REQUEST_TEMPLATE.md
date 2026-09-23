## What does this change?

<!-- One or two sentences. -->

## Why?

<!-- The motivation -- a bug, a missing feature, a paper section not yet
reproduced. Link an issue if there is one. -->

## Checklist

- [ ] `ruff check .` and `mypy tokenis --ignore-missing-imports` pass
- [ ] `pytest` passes for the paths this change touches (see CONTRIBUTING.md)
- [ ] If this touches `crates/`: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`
      and `cargo test -p tokenis-core --release` pass, and a dependency change is reflected in
      `THIRD-PARTY-NOTICES.md` (`python scripts/third_party_notices.py`)
- [ ] If this touches `sdk/typescript/` or the WebAssembly bindings: `npm run typecheck && npm test`
      and `npm run check:package` pass
- [ ] If this touches `tokenis/gateway/admission.py`, `tokenis/gateway/reveal.py`,
      or `tokenis/audit/trace.py`: `pytest tokenis/conformance` passes, and I've
      noted below which W1-W6 condition(s) this affects (if any)
- [ ] If this touches `research/p3_leakage/` or `research/p4_admission/`:
      both `python research/p3_leakage/verify_claims.py` and
      `python research/p4_admission/verify_claims.py` still exit 0, and I haven't
      changed what's claimed without updating that directory's README
- [ ] If this changes a public docstring's security claim (e.g. "reference,
      not audited"), I've kept the claim honest rather than just editing
      the wording — see CONTRIBUTING.md's "ground rules"

## Which W1-W6 condition(s) does this affect, if any?

<!-- e.g. "None" / "W2 -- adds a new Reveal-adjacent code path, covered by
a new test in tokenis/conformance/test_w2_gating.py" -->
