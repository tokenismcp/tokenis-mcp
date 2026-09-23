---
name: Bug report
about: Something in the SDK, research code, or docs doesn't work as documented
title: ""
labels: bug
assignees: ""
---

**Which part of the repository?**
- [ ] `tokenis/` reference SDK (say which module, e.g. `tokenis/gateway/admission.py`)
- [ ] `research/p3_leakage/`
- [ ] `research/p4_admission/`
- [ ] `papers/` (a documentation/navigation-page issue, not the PDF itself)
- [ ] Something else

**Describe the bug**
A clear description of what's wrong.

**To reproduce**
Steps, or ideally a minimal code snippet, to reproduce the behavior.

**Expected behavior**
What you expected to happen instead.

**Environment**
- Python version:
- OS:
- Installed with: `pip install -e ".[?]"` (which extras?)

**If this touches `tokenis/gateway/admission.py`, `tokenis/gateway/reveal.py`, or `tokenis/audit/trace.py`:**
Does `pytest tokenis/conformance` still pass? If not, which W1-W6 condition
(`tokenis/spec/well-formedness.md`) does it fail?

**If this is about a `research/` script producing an unexpected number:**
Please check `verify_claims.py`'s own honesty disclaimer first — this
repository does not claim to reproduce the papers' literal published
percentages, only internal determinism/consistency. If it's the latter
that's broken, please say which check failed.
