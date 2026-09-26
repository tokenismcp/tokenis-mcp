# Threat model

This document states what Tokenis protects, from whom, and how, with each
mitigation tied to the code that implements it and the test that checks it.
It is written for security reviewers and external auditors. A shorter
summary is in [SECURITY.md](../SECURITY.md); the guide for auditors is
[audit-guide.md](audit-guide.md).

Version: 0.1.x (September 2026). Update this file whenever a boundary, an
asset or a mitigation changes.

## 1. System

```
                          TB1 (tool calls)                    TB3
 LLM / agent ──▶ MCP client ──HTTPS──▶ ┌────────────────────┐ ◀──────▶ PostgreSQL
 (untrusted:     (API key / JWT)       │  gateway replica   │          admission log (hash chain)
  chooses                              │  - admission D1-D5 │          audit trail (HMAC chain)
  queries)       operator ──TB6──▶     │  - EC-ElGamal sums │          API key hashes
                 /admin, /metrics      │  - audit trail     │
                                       └────────────────────┘
                                         ▲ TB4        ▲ TB5
                                   KMS (unwraps   source DB, or
                                   the keystore)  encrypted ledger
```

The **gateway process** is the trusted computing base. It holds the
ElGamal private key and, at load time, the plaintext data. Everything a
caller can influence is untrusted. That includes the language model: it
chooses queries and may be steered by content it has read (prompt
injection).

What may cross TB1 to a caller: schema metadata; aggregates over at least
*k* records that admission control allows (possibly coarsened into bands);
keyed 128-bit pseudonyms for `token` columns; Reveal answers for configured
purposes; and one fixed denial message. Every crossing and every refusal is
recorded in the audit trail under an authenticated principal.

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Sealed values (e.g. individual revenues) | The data the product exists to protect |
| A2 | Which record belongs to which subject | Re-identification defeats pseudonymisation (see P3 in `papers/`) |
| A3 | Secrets: ElGamal private key, tokenizer key, audit (HMAC) key, ledger key | A3 leaks give A1 (ElGamal, ledger), A2 (tokenizer) or undetectable audit edits (audit key) |
| A4 | Admission history (who was told what) | D2 and the budgets are only as good as this memory |
| A5 | Audit trail | Accountability, and after-the-fact detection |
| A6 | Caller credentials (API keys, JWT trust) | Identity is what budgets and audit attach to |
| A7 | Availability | Secondary; the design prefers failing closed |

## 3. Trust boundaries

| ID | Boundary | Crossing data | Controls |
|---|---|---|---|
| TB1 | Caller ↔ gateway (MCP over stdio or HTTP) | Tool calls, results | Authentication, schema validation, admission D1-D5, uniform denials, latency quantisation |
| TB2 | Network | TLS-terminated HTTP | TLS at the proxy; Host/Origin validation (DNS rebinding) |
| TB3 | Gateway ↔ state database | Admission records, audit entries, API key hashes | Transaction + advisory lock; hash chain; HMAC on audit entries; fail closed |
| TB4 | Gateway ↔ KMS | Wrapped secrets | KMS policy; tenant-bound encryption context / AAD |
| TB5 | Gateway ↔ data source or ledger | Plaintext rows (source) or ciphertexts (ledger) | Read-only DB role; AES-GCM with the manifest as AAD |
| TB6 | Operator ↔ ops endpoints | Health, metrics, dashboard | Admin token; read-only; no values; strict CSP |
| TB7 | Build and distribution | Wheels, image, bundles | Provenance attestations, Sigstore signatures, SBOMs, dependency audits |

## 4. Adversaries

| ID | Adversary | Capabilities assumed |
|---|---|---|
| ADV1 | Curious or malicious analyst | Valid credentials; issues any sequence of well-formed tool calls, concurrently, to any replica, over any time span |
| ADV2 | Prompt-injected model | Chooses tool arguments to exfiltrate, possibly encoding data into later queries |
| ADV3 | Colluding principals | Several ADV1s who pool their answers |
| ADV4 | Network attacker | Sees and alters traffic outside TLS; can make a victim's browser send requests (DNS rebinding) |
| ADV5 | Storage reader | Reads the ledger, keystore, database backups or trail files, without KMS access |
| ADV6 | State tamperer | Writes to the state database or state files (a compromised DB account, a careless restore) |
| ADV7 | Operator with admin token | Views the dashboard and metrics |
| ADV8 | Co-located attacker | Shares hardware with the gateway (cache timing) |
| ADV9 | Supply-chain attacker | Tampers with a dependency or a release artifact |

Out of scope: an attacker who controls the gateway process or its host
(root on the host can read memory); the LLM provider seeing answers the
gateway released (by design, released answers are public to the caller).

## 5. Threats and mitigations

Code references are to this repository; tests are in `tests/` unless stated.

### Disclosure through queries (ADV1-ADV3)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T1 | Aggregate over a tiny group, or over all but a tiny group | D1: query-set size must lie in [k, n-k] | `gateway/admission.py` (D1) | `test_service.py::test_every_denial_has_the_same_message_and_the_rule_is_traced` |
| T2 | Differencing / tracker: combine answers so their difference isolates a record or a group smaller than k | D2: rowspace audit over GF(p), cell-aware; history is **shared by all principals**, so colluders (ADV3) are covered | `admission.py` (D2), `service.py::_cells` | `test_differencing_is_refused`; `test_admission_cells.py` checks cell compression against per-record decisions (3,000 seeds) |
| T3 | Race two halves of a pair concurrently | One lock around decide, compute and audit | `service.py::_locked` | `test_concurrent_differencing_pair_is_never_both_admitted`, `test_admission_decisions_never_overlap` |
| T4 | Split the pair across replicas | Postgres transaction + per-tenant advisory lock; replay other replicas' records first | `gateway/pgstate.py`, `service.py::_sync_shared` | `test_pgstate.py::test_a_differencing_pair_split_across_replicas_is_refused`; also run on k3s across two pods |
| T5 | Ask the second half after a restart | Durable log, replayed at start; changed data refuses to start without an explicit reset | `gateway/state.py`, `pgstate.py::open` | `test_service_state.py::test_differencing_across_a_restart_is_refused`, `test_changed_data_needs_an_explicit_reset` |
| T6 | Harvest through sheer volume | D3 budget per principal per window; persisted | `admission.py` (D3) | `test_budget_is_enforced_per_principal`, `test_budget_survives_a_restart` |
| T7 | Prompt-injected model exfiltrates (ADV2) | D4 while tainted: separate budget, call cap, COUNT-only surface; taint comes from the host, never from arguments | `admission.py` (D4-*), `mcp_server/server.py::header_taint` | `test_tainted_context_admits_count_only`, `mcp_server/test_server.py::test_taint_comes_from_the_host` |
| T8 | Query a column nobody approved | D5 catalogue (deny by default) and schema enums | `admission.py` (D5), `server.py::_filters_model` | `test_schema_validation_happens_before_the_gateway` |
| T9 | Learn from the denial itself (which rule, group size) | One constant message; the rule goes only to the trail and operator log | `service.py::DENIED_MESSAGE`, `_deny` | `test_calls_and_generic_denials` |
| T10 | Learn from timing which path ran | Every call is padded to a multiple of a quantum | `gateway/latency.py`, `server.py::run` | `test_every_call_is_padded_to_the_quantum` |
| T11 | `exists` or `group_by` reveals small groups | `exists` never separates zero from a few; small groups suppressed | `service.py` | `test_exists_never_distinguishes_zero_from_a_few`, `test_group_by_suppresses_small_groups` |
| T12 | Link records through pseudonyms | Keyed, tenant- and epoch-scoped tokens; epoch bump rotates all | `semantic/tokenizer.py` | `test_tokenizer.py` |

### Identity and access (ADV1, ADV4)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T13 | Choose someone else's principal | Principal comes only from the credential or the OS user; never an argument | `server.py` resolvers, `server_auth.py` | `test_principal_comes_from_the_resolver_only` |
| T14 | Forge or confuse a JWT | Asymmetric algorithms only; `exp`/`iss`/`aud` required; `none`/HMAC refused | `server_auth.py::JwtVerifier` | `test_server_auth.py::test_algorithm_confusion_and_alg_none_are_rejected`, `test_invalid_jwts_are_rejected` |
| T15 | Steal API keys from storage | Stored as SHA-256 hashes; compared in constant time; revocable without restart | `server_auth.py`, `pgstate.py::PostgresApiKeyStore` | `test_api_key_lifecycle`, `test_pgstate.py::test_api_keys_are_shared` |
| T16 | Unauthenticated HTTP | HTTP refuses to start without `[auth]` | `config.py` | `test_config.py` |
| T17 | DNS rebinding from a victim's browser (ADV4) | Host/Origin allow-list on `/mcp` and the admin console whenever not bound to localhost | `cli.py::cmd_serve`, `ops.py::install_routes` | `test_ops.py::test_admin_console_answers_only_its_own_host` |

### Secrets and stored data (ADV5)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T18 | Read or substitute secrets in the keystore file | Every secret wrapped by a KMS (or scrypt + AES-GCM locally), with the tenant and slot as encryption context, so one blob cannot be swapped for another. Azure's RSA-OAEP needs only the public key, so each Azure-wrapped secret also carries a signature made inside the vault | `keystore.py` | `test_keystore_ledger.py` (including a forged Azure entry); `test_fuzz_inputs.py::test_a_tampered_keystore_never_yields_other_secrets` |
| T19 | Read or alter the ledger | Sealed values are ciphertexts; the whole payload is AES-256-GCM under the ledger key with the manifest as AAD | `ledger.py` | `test_fuzz_inputs.py::test_a_tampered_ledger_never_loads_different_data` |
| T20 | Credentials in config files | A password in `[data] url` is refused; URLs come from the environment | `config.py` | `test_db_source.py::test_credentials_stay_out_of_the_config` |
| T21 | Secrets in logs, reprs or errors | Redacted reprs; driver errors are never returned to callers | `keystore.py::Secrets`, `server.py::run` | `test_crypto_security.py::test_secrets_not_in_repr` |

### Integrity of history and audit (ADV6)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T22 | Edit or reorder the audit trail | Hash chain + HMAC per entry; verified end to end on open and by `audit verify` | `audit/trace.py` | `test_tampered_or_rekeyed_trace_refuses_to_load`; fuzzed by `test_a_tampered_audit_trail_is_detected` |
| T23 | Roll back or edit the shared admission log (restore from an old backup, failover to a lagging standby, or a DB account) | The log is a chain keyed with the audit key and verified link by link on every replay. Each replica checks, inside every transaction, that the last record it saw is unchanged, and after a failed call that the last record it knows was committed is still there. Otherwise it refuses all calls and reports not ready | `pgstate.py::check`, `records_after`, `service.py::_sync_shared` | `test_pgstate.py`: restored backup, rewritten record, edited record, failover after an error, keyed chain; verified on k3s |
| T24 | Reset history from another replica with different data | Fingerprint check on every call | `pgstate.py::check` | `test_a_reset_elsewhere_stops_old_replicas` |
| T25 | Corrupt state files to crash or confuse startup | Every parser rejects damage with its own error type | `state.py`, `trace.py`, `keystore.py`, `ledger.py` | `test_fuzz_inputs.py` (all properties) |

### Cryptographic core

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T26 | Invalid-curve or malformed points | Every decoded point validated on-curve and canonical | `crates/tokenis-core/src/encoding.rs::decode_point` | `test_crypto_security.py::test_off_curve_points_rejected`; `fuzz/wire_formats` |
| T27 | Wrong homomorphic results or panics | Lints forbid `unsafe`, `unwrap`, `panic` and indexing; property tests; coverage-guided fuzzing | `crates/tokenis-core` | 33 Rust tests; `fuzz/elgamal_arithmetic`, `fuzz/decrypt_untrusted`, `fuzz/delegation` |
| T28 | Secret material lingers in memory | Zeroize-on-drop types; secrets behind heap pointers | `elgamal.rs`, `delegation.rs` | `moving_a_secret_moves_only_a_pointer` |
| T29 | Reused one-time pads or Beaver triples | Owner-bound, single-use handles | `delegation.rs` | `test_no_key_delegation.py` |

### Operations and supply chain (ADV7, ADV9)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T30 | Dashboard leaks values or is scriptable | No values in the summary API; nonce CSP; `textContent` only; constant-time token check; no-store | `ops.py`, `assets/admin.html` | `test_ops.py::test_admin_dashboard_requires_the_token_and_hides_values` |
| T31 | Metrics leak data, or tell a caller why they were refused | Only counts by tool and outcome; the per-rule breakdown only when `/metrics` requires a token | `ops.py::Metrics` | `test_metrics_count_outcomes_and_rules_without_values`, `test_open_metrics_do_not_reveal_denial_rules` |
| T32 | Tampered release artifact | Build provenance attestations, Sigstore keyless signatures, SHA256SUMS, CycloneDX SBOMs | `.github/workflows/release.yml` | [verifying-releases.md](verifying-releases.md) |
| T33 | Vulnerable dependency | `cargo audit`, `cargo deny`, `pip-audit`, `npm audit` in CI | `.github/workflows/ci.yml` | CI |

### Availability and failure behaviour (A7)

| # | Threat | Mitigation | Code | Evidence |
|---|---|---|---|---|
| T34 | Deadlock between tool calls and readers (metrics, dashboard) | One lock order: shared trace storage lends its connection lock to the trace | `pgstate.py::PostgresTraceStorage.lock`, `trace.py` | `test_pgstate.py::test_tool_calls_and_readers_never_deadlock` (fails on the old code) |
| T35 | A frozen or restarting database hangs the cluster | Connect, statement and lock timeouts; the server ends sessions idle in a transaction (releasing the tenant lock); dead connections are replaced before a call; waits for the gateway lock are bounded; readiness answers within 2.5 s on its own connection; callers get 503 with `Retry-After` | `pgstate.py::CONNECT_OPTIONS`, `service.py::_hold`, `ops.py` | Failure-injection runs (database paused 25 s, restarted, replica killed) in [audit-guide.md](audit-guide.md) |
| T36 | A failed trail write (disk full) corrupts the trail | The partial line is cut back and the call fails closed | `trace.py::FileTraceStorage.append` | `test_service_state.py::test_a_failed_trail_write_leaves_a_valid_trail` |
| T37 | Replicas disagree because rows arrive in a different order | Database sources are read in `id_column` order; the history fingerprint is independent of row order | `config.py::_iter_sql`, `service.py::_fingerprint` | `test_service_state.py::test_row_order_does_not_change_the_history_fingerprint` |

## 6. Security invariants

These are the properties the tests and fuzzers check. An auditor who
disproves one has found a vulnerability.

1. No sequence of admitted calls, from any set of principals, lets a caller
   compute a sealed value of fewer than *k* records exactly. This holds
   modulo D2's documented relaxation; see residual risk R3.
2. Admission decisions are serialised per tenant: across threads, across
   processes and across restarts.
3. A caller cannot tell which rule refused a call, or how long the refused
   path took, beyond the latency quantum.
4. Every released value and every refusal is in the audit trail before the
   caller receives the result. Any edit to the trail short of cutting its
   tail is detected.
5. A replica never answers on an admission history that differs from the
   one it has already counted.
6. No secret leaves the process except wrapped by the KMS. No plaintext
   sealed value is written to disk by the gateway.
7. Decoders never panic and accept only canonical encodings.

## 7. Assumptions

- The gateway host, its memory and its service account are trusted. TLS is
  terminated by a proxy the operator controls.
- The KMS and its access policy are correctly configured. Only the gateway's
  identity may unwrap.
- The state database is reachable only by the gateway's role. Backups are
  restored only with the procedure in [deployment.md](deployment.md#backups).
- `k256` (RustCrypto; audited by NCC Group in 2023) is correct. The CPU has
  constant-time integer multiplication.
- The operator's choice of *k*, budgets, open columns and bands follows a
  re-identification analysis of their own data (P3 explains the method).

## 8. Residual risks

| # | Risk | Why it remains | Recommendation |
|---|---|---|---|
| R1 | Plaintext and the private key are in process memory | Needed to compute; no enclave support | Harden the host; restrict debugging; consider confidential VMs |
| R2 | Decryption timing and cache side channel | Constant step count, but memory access depends on the plaintext | Do not co-locate with untrusted workloads |
| R3 | D2 is a tractable relaxation (P4 Remark 10): it may under-refuse low-weight combinations not visible in the reduced basis | The exact problem is NP-hard | Larger *k*, band mode for sensitive columns |
| R4 | Temporal differencing across data refreshes | Answers about two data versions can be compared | Refresh in batches; see [deployment.md](deployment.md#changes-over-time) |
| R5 | Cutting entries from the end of the audit trail is not detectable by the chain alone | A hash chain cannot prove its own length | Ship the trail off-host; record the head digest (`audit verify`) externally |
| R6 | A database account can delete the newest admission records while **every** replica is stopped (a keyed chain cannot prove its own length), and so reset budgets | It cannot forge or edit records without the audit key, and running replicas detect any rollback | Grant write only to the gateway role; enable database audit logging; keep backups immutable |
| R7 | The admin token is a static shared secret | Simplicity | Put `/admin` behind your SSO proxy; rotate the token |
| R8 | `[data] query` runs as written | SQL is not parsed | Use a read-only database role (documented) |
| R12 | A call already waiting on a frozen database waits until the database answers or TCP gives up (about 15 s) | A frozen server process still acknowledges TCP | Readiness takes the replica out of rotation within seconds; further calls fail fast |
| R9 | Embeddings for `similarity_search` are held in the clear | Nearest-neighbour search on ciphertexts is not implemented | Omit `embedding_column` where embeddings are sensitive |
| R10 | Throughput per tenant is serialised | Required by invariant 2 | Separate tenants; size the latency quantum |
| R11 | No independent audit yet | — | This document and [audit-guide.md](audit-guide.md) prepare for one |
