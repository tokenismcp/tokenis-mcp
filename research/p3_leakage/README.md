# P3: Leakage Quantification and Disclosure Budgets (reproduction)

This directory is the release referenced by the paper's own Availability
statement (`papers/p3-leakage-quantification/paper.pdf`, Appendix B):

> "The corpus generator, the three attacks, the defence evaluation, the
> budget computation, all result files, the figure scripts and a provenance
> checker are released with fixed seeds ... `verify_claims.py` prints each of
> the 65 headline numbers in this paper beside the result-file field that
> produced it."

## Honesty note -- read this before quoting a number out of this directory

The paper names its RNG seeds (corpus seed `20260920`, workload seed `7`)
but does not publish the literal source of its own corpus generator, attacks,
defenses or budget code -- only a prose description of the method, the
published constants it must use, and the seeds. **This directory is a
faithful re-implementation of that described method and its calibrated
statistics, not a byte-for-byte reproduction of the paper's own pipeline.**

Concretely:

- `verify_claims.py` verifies **internal determinism** (same seeds -> same
  output, byte-identical JSON across two independent runs) and **internal
  consistency** (sanity bounds: percentages in [0,100], isolability curves
  non-increasing where the underlying claim requires it, Claim 1's proof
  check passing, etc.).
- It does **not** claim, and its output does not assert, that any computed
  number equals a number printed in the paper (e.g. "41.4%", "9.8%",
  "epsilon ~ 111"). Because the joint distribution of the synthetic corpus is
  *generated* rather than *calibrated* (no such joint distribution is public
  at this resolution -- see `corpus.py`'s module docstring and the
  provenance table below), the numbers this code produces are expected to
  land in the **same qualitative range and exhibit the same qualitative
  effects** as the paper's -- non-additive composition, the disclosure
  profile dominating the token scheme, isolability flat in k for a
  set-difference-capable filter language, no finite epsilon for exact
  aggregates, etc. -- not to be numerically identical to it.

This mirrors the spirit of the paper's own Section 4.4 ("Provenance: measured,
calibrated, invented"), which draws exactly this distinction for its own
numbers:

| Provenance  | Meaning here                                                                 |
|-------------|-------------------------------------------------------------------------------|
| Published   | Verbatim from official sources: KSIC level cardinalities (1,196/495/232/77/21), the 229 si/gun/gu locality codes. `corpus.py`. |
| Calibrated  | Distributional *shape* chosen to match a described qualitative property (capital-area concentration, heavy-tailed industry popularity, log-normal revenue, etc.) -- not a published joint distribution, because none exists at this resolution. `corpus.py`. |
| Invented    | Which firms exist, ledger membership, transaction amounts, the public relationship graph, the analyst workload -- entirely synthetic, no real customer or firm data anywhere in this code or its output. `corpus.py`. |
| Computed    | Every attack/defense/budget result in this directory: an output of the code below run against the corpus above, deterministic under the recorded seeds. `attack_*.py`, `defenses.py`, `budget.py`. |
| Unmeasured  | `rho` (workload cohesion) -- reported only as a sweep, never a point value, exactly as the paper does. |

## How to run

```bash
# Fast path (CI-sized corpus, ~1 minute, runs the pipeline twice to check determinism):
python research/p3_leakage/verify_claims.py

# Paper-sized corpus (|U|=40,000, ledger=4,000, sessions=1,600; several minutes, single run):
python research/p3_leakage/verify_claims.py --paper-scale

# Figures (optional; needs `pip install '.[research]'` for matplotlib):
python research/p3_leakage/figures.py

# Unit tests (seconds, tiny corpus, separate from the full pipeline run):
pytest research/p3_leakage -q
```

`verify_claims.py` requires no arguments to run and writes one JSON file per
module to `results/`:

```
results/corpus.json
results/attack_schema_uniqueness.json
results/attack_token_linkage.json
results/attack_differential_inference.json
results/defenses.json
results/budget.json
```

then prints every headline number it computed next to the `(file, JSON path)`
that produced it, runs the whole pipeline a second time from the same seeds
and checks the two JSON outputs are byte-identical, checks a battery of
sanity bounds, and exits non-zero if either check fails.

### Why the default profile is smaller than the paper's

`corpus.py`'s `CorpusSizes.ci_scale()` (|U|=8,000, ledger=500, sessions=300)
is what `verify_claims.py` and `test_pipeline.py` use by default, so the full
pipeline -- run *twice*, for the determinism check -- finishes in well under
this repository's 2-minute budget on a laptop (observed: ~25-30s per run,
~55s total). `CorpusSizes.paper_scale()` (|U|=40,000, ledger=4,000,
sessions=1,600) reproduces the paper's own sizing and is available via
`--paper-scale`, but takes several minutes, dominated by the epoch-length
sweep in `defenses.py` (D1) and the linkage ablation, exactly as the paper's
own Appendix B describes for its pipeline. Every module is parameterized off
a `Corpus` object built from `CorpusSizes`, so nothing about the *method*
changes between profiles -- only wall-clock cost.

## Paper section -> file mapping

| Paper section | File |
|---|---|
| Section 4 (Corpus) | `corpus.py` |
| Section 5 (Attribute-combination re-identification), Figs. 1-2 | `attack_schema_uniqueness.py` |
| Section 6 (Token linkage and composition), Figs. 3-5 | `attack_token_linkage.py` |
| Section 7 (Differential inference), Figs. 6-7 | `attack_differential_inference.py` |
| Section 8 (Defences), Fig. 8 | `defenses.py` |
| Section 9 (Disclosure budget), Table 2, Fig. 9 | `budget.py` |
| All figures | `figures.py` (optional; needs matplotlib) |
| Appendix B (Reproduction) | `verify_claims.py` |
| -- | `test_pipeline.py` (fast unit tests, not part of the paper) |

## Dependencies

Core pipeline (`corpus.py`, `attack_*.py`, `defenses.py`, `budget.py`,
`verify_claims.py`): Python 3.9+ standard library and `numpy` only. No
network access and no external data downloads -- the entire corpus is
generated in-process from the two seeds above.

`figures.py` additionally needs `matplotlib` (declared under this
repository's `pyproject.toml` `[project.optional-dependencies].research`
extra); its import is guarded so importing any other module in this
directory never requires matplotlib to be installed.

All randomness flows from `numpy.random.default_rng(seed)` instances seeded
from the paper's own corpus/workload seeds (or a small number of other fixed
integer seeds local to individual sweeps, documented at each call site) --
never from a bare, unseeded `numpy.random` or `random` call.
