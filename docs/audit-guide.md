# Guide for auditors

This page is the starting point for an external security review of Tokenis:
what is in scope, how to build and test it, what evidence exists, what was
found during our own preparation, and where we would look first.

Read alongside:

- [threat-model.md](threat-model.md): assets, trust boundaries, adversaries,
  threats with code and test references, invariants, residual risks.
- [SECURITY.md](../SECURITY.md): reporting, deployment guidance, known
  limitations.
- `papers/` (P2-P4): the formal model the admission controls implement.

## 1. Scope, in priority order

| Priority | Component | Path | Why |
|---|---|---|---|
| 1 | Cryptographic core | `crates/tokenis-core/` (≈1.8k lines of Rust, including tests) | EC-ElGamal over secp256k1, bounded decryption, no-key delegation. Everything else relies on it |
| 1 | Admission control | `tokenis/gateway/admission.py` | D1-D5, the rowspace audit over GF(p). Its soundness is the product's main security claim |
| 1 | Gateway service | `tokenis/gateway/service.py` | Locking, cell compression, decryption bounds, tool semantics, denial handling |
| 2 | Shared state | `tokenis/gateway/pgstate.py`, `tokenis/gateway/state.py` | Serialisation across replicas, hash-chained history, fail-closed checks |
| 2 | Bindings | `crates/tokenis-py/`, `crates/tokenis-wasm/` | Parallel batch paths, parsing of untrusted encodings |
| 2 | Authentication | `tokenis/server_auth.py`, `tokenis/mcp_server/server.py` | Principal derivation, JWT verification, API keys |
| 2 | Keys and ledger | `tokenis/keystore.py`, `tokenis/ledger.py` | KMS wrapping with context binding; authenticated encryption of the ledger |
| 3 | Audit trail | `tokenis/audit/trace.py` | Hash chain + HMAC; storage back-ends |
| 3 | Operations | `tokenis/ops.py`, `tokenis/assets/admin.html` | Unauthenticated probes; token-protected dashboard |
| 3 | Configuration | `tokenis/config.py`, `tokenis/cli.py` | Operator-supplied, but parses paths, URLs and SQL sources |
| 3 | Release pipeline | `.github/workflows/release.yml`, `Dockerfile`, `deploy/` | Provenance, signing, SBOM, image and chart hardening |

Out of scope: `research/` (reproduction code for the papers, run on
synthetic data), `benchmarks/`, `examples/`, and `tokenis/crypto/ec_fhe.py`'s
analysis of the source papers (documentation, not a code path).

## 2. Build and run

Requirements: Rust 1.85+, Python 3.10+, Docker (for database tests).

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev,postgres,mysql]"
```

```bash
cargo test --workspace
```

```bash
.venv/bin/python -m pytest -q tests tokenis
```

Database tests run when a server is available:

```bash
docker run -d --rm --name pg -e POSTGRES_USER=tokenis -e POSTGRES_PASSWORD=tokenis -p 55432:5432 postgres:17-alpine
```

```bash
TOKENIS_TEST_POSTGRES_URL=postgresql://tokenis:tokenis@127.0.0.1:55432/tokenis .venv/bin/python -m pytest -q tests/test_pgstate.py tests/test_db_source.py
```

Fuzzing (Rust, coverage-guided; needs a nightly toolchain and `cargo install cargo-fuzz`):

```bash
cd fuzz && cargo +nightly fuzz run elgamal_arithmetic -O -- -max_total_time=600
```

Targets: `wire_formats`, `elgamal_arithmetic`, `decrypt_untrusted`,
`delegation`. Fuzzing (Python, property-based) scales with an environment
variable:

```bash
TOKENIS_FUZZ_EXAMPLES=20000 .venv/bin/python -m pytest -q tests/test_fuzz_inputs.py
```

A full multi-replica deployment (two gateways, PostgreSQL, nginx,
Prometheus, Grafana) is one command; see
[deployment.md](deployment.md#docker-compose).

## 3. Evidence

| Kind | What | Where |
|---|---|---|
| Unit and property tests | 33 Rust tests (proptest), about 300 Python tests including property-based tests (Hypothesis) | `crates/*/src`, `tests/`, `tokenis/conformance/` |
| Differential test | Cell-compressed admission decisions equal per-record decisions over 3,000 random ledgers | `tests/test_admission_cells.py` |
| Concurrency tests | A differencing pair raced from many threads is never both admitted; budgets are exact under contention | `tests/test_service.py` |
| Real databases | Shared state and data sources against PostgreSQL 17 and MySQL 8.4 | `tests/test_pgstate.py`, `tests/test_db_source.py`; CI `databases` job |
| Coverage-guided fuzzing | Four libFuzzer targets; about 6 million executions in the preparation runs, no open crash | `fuzz/`; nightly CI (`.github/workflows/fuzz.yml`) |
| Input fuzzing | Tampered ledger, keystore, trail, admission log, ciphertext encodings, configuration; 5,000 examples each, clean | `tests/test_fuzz_inputs.py` |
| Deployment | Helm chart installed on a real Kubernetes (k3s): hardened pod spec, cross-pod differencing refused, restore divergence detected | [deployment.md](deployment.md) |
| Supply chain | `cargo audit`, `cargo deny`, `pip-audit`, `npm audit`; SBOMs, provenance and Sigstore signatures on every release | `.github/workflows/`, `deny.toml`, [verifying-releases.md](verifying-releases.md) |
| Static rules | `unsafe` forbidden; `unwrap`, `expect`, `panic` and slice indexing denied in the Rust workspace; `mypy` and `ruff` on Python | `Cargo.toml`, `pyproject.toml` |

## 4. Findings fixed during preparation

Our own review, testing and fuzzing before engaging auditors found the
following; each fix has a regression test. Earlier history is in
[CHANGELOG.md](../CHANGELOG.md).

| # | Found by | Issue | Severity (our estimate) | Fix |
|---|---|---|---|---|
| P-1 | Rust fuzzing (`elgamal_arithmetic`, within seconds) | `to_bytes_many(&[])` panicked inside `k256`'s batch inversion, breaking the crate's no-panic contract | Low (not reachable from the gateway; aborts a WebAssembly caller) | Early return; `batched_encoding_of_nothing_is_nothing` |
| P-2 | Code review of P-1's call sites | `CiphertextVector.to_bytes` dropped a chunk silently if a worker thread failed, producing an encoding whose count no longer matched | Low (only after a panic, now unreachable) | Worker failure raises |
| P-3 | Python fuzzing | Damaged audit trail, admission log, keystore, ledger manifest or config paths raised `UnicodeDecodeError`, `KeyError`, `AttributeError` or `ValueError` instead of the component's error; startup crashed with a traceback | Low (failed closed, but unclear) | Byte-safe parsing; structure validation; errors wrapped |
| P-4 | Kubernetes test (database restore under running pods) | After the state database was rolled back, a replica that had not seen the lost records continued. It wrote new records under the same sequence numbers, which other replicas would skip | Medium (admission history could silently diverge between replicas) | Hash-chained admission log; per-call check of the last seen record; fail closed, `/readyz` 503, alert |
| P-5 | Review | Unexpected tool errors (e.g. a database outage) could return driver messages, including host names, to callers | Low | Generic message to callers; details in the operator log |
| P-6 | Documentation audit | Docs said the differencing audit was per principal; it is (correctly) shared across all principals | Documentation | Docs corrected |

## 5. Where we would look first

1. **D2 soundness.** The cell-aware rowspace audit (`admission.py`) and the
   cell-compression argument (`service.py::_cells` docstring): is every
   combination that isolates fewer than *k* records refused? P4 Remark 10
   notes the relaxation may under-refuse some low-weight combinations; how
   exploitable is that in practice?
2. **Tool semantics as side channels.** `group_by` suppression,
   `compare_periods` returning only a direction, `exists`, `disclose_bucket`
   thresholds, band mode. Can combinations of these tools emulate a refused
   aggregate?
3. **Timing.** Latency padding covers the gateway path (`server.py::run`),
   but schema-validation failures are answered by the MCP SDK before the
   padding. They depend only on the arguments, not on data; confirm that
   nothing data-dependent escapes the padding.
4. **Decryption.** Bounded baby-step giant-step (`elgamal.rs::Decryptor`):
   range handling at the edges, and the memory-access side channel
   documented as residual risk R2.
5. **Shared-state transactions.** Commit-on-exception semantics in
   `pgstate.py::transaction`, the advisory-lock key (the first 64 bits of
   SHA-256 of the tenant), and behaviour under connection loss mid-call.
6. **KMS context binding.** Each provider binds tenant and slot differently
   (EncryptionContext, AAD, or a digest prefix for Azure's RSA-OAEP). Can a
   wrapped secret be replayed into another slot or tenant?
7. **Tokenizer.** The keyed pseudonym construction in
   `tokenis/semantic/tokenizer.py`: key separation by tenant and epoch, and
   collision behaviour at 128 bits.
8. **Admin console.** CSP, token handling, and whether the summary API can
   be coaxed into revealing values.

## 6. Engagement logistics

- Reports: director@j1729labs.online (see [SECURITY.md](../SECURITY.md)).
- We can provide a dedicated test deployment (Compose or Kubernetes) with
  synthetic data, and API keys for any number of principals.
- Commit to review: the tag of the release under audit. Findings will be
  published with the fix, crediting the auditor unless asked otherwise.
