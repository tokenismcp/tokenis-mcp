# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Email **director@j1729labs.online** with a description and its impact,
steps to reproduce (a minimal example against this repository is ideal), and
the file(s) or function(s) you believe are affected. We aim to acknowledge
reports within 5 business days. This is a small project without a dedicated
security team or a paid bug bounty; thank you for reporting privately first.

## Threat model in one paragraph

The **gateway process** (`tokenis-mcp serve`, or an application embedding
`TokenisGatewayService`) is the trusted boundary: it reads the plaintext
data at load time, holds the decryption key, and decrypts aggregates it has
admitted. Everything on the other side is untrusted: the **LLM** (which
chooses queries and may be steered by content it reads), the **MCP client**
and network, and anyone reading tool results. The gateway's job is that
nothing crosses to that side except schema metadata, admitted aggregates
over groups of at least *k* records (or coarser forms of them), keyed
pseudonyms, and purpose-gated Reveals — each recorded in a signed audit
trail under an authenticated identity.

For the full picture: [docs/threat-model.md](docs/threat-model.md) (assets,
boundaries, adversaries, every mitigation with its code and test),
[docs/audit-guide.md](docs/audit-guide.md) (for reviewers) and
[docs/verifying-releases.md](docs/verifying-releases.md) (signatures,
provenance, SBOMs).

## Deploying safely

- **Run the gateway on a host you control**, with the data file, the state
  directory and the two secrets readable only by its service account.
- **Keep secrets in a KMS-wrapped keystore** (`[keys]`, `tokenis-mcp secrets
  init`) with AWS KMS, Google Cloud KMS, Azure Key Vault or Vault Transit,
  and let only the gateway's identity unwrap. Environment variables
  (`TOKENIS_TOKENIZER_KEY`, `TOKENIS_AUDIT_KEY`) remain supported for small
  deployments. Keep the tokenizer key stable (bump `[tenant] epoch` to
  rotate every token deliberately) and the audit key away from anyone who
  can write the trail.
- **Serve from an encrypted ledger** (`tokenis-mcp ingest`, `[ledger]`) so
  serving hosts never read the source data.
- **Persist the admission state**: `[state] dir` for one process, or
  `[state] backend = "postgres"` for several replicas. Without either, a
  restart forgets the admission history (so the second half of a
  differencing pair can be asked after a restart). Give the state database
  to the gateway's role alone, and never restore it to an earlier point
  while replicas run ([docs/deployment.md](docs/deployment.md#backups)).
- **Changing the data is a security event.** A gateway restarted on
  different data refuses to start until `--reset-admission-state` is given,
  because answers computed on the old data can be differenced against
  answers on the new. Reset only when that trade-off is acceptable (e.g. a
  new reporting period with a fresh budget), and prefer coarser columns or
  a larger *k* when data changes often.
- **HTTP needs TLS in front** (a reverse proxy or load balancer). The server
  refuses to run HTTP without authentication; set `public_url` and
  `allowed_hosts` so Host-header validation matches your domain. Several
  replicas **must** use the postgres state backend: with the file backend,
  each process would keep its own history and allow its own full budget.
- **Identity.** Use `[auth] mode = "jwt"` with your IdP where you can, so the
  principal is the real end user; API keys identify whoever holds the key.
  Never let an agent framework pass a user identity through a tool argument.
- **Taint.** If your agent host knows when untrusted content (web pages,
  e-mails, retrieved documents) entered the conversation, pass it
  (`taint=1` in `tokenis.llm`, or the configured HTTP header) so the reduced
  D4 surface applies.
- **Ship the trace off-host** (`<state>/trace.jsonl`) to append-only storage,
  and check it with `tokenis-mcp audit verify`. The HMAC chain detects edits
  and reordering; only off-host retention detects entries cut from the end.
- Choose `min_query_set_size`, the budgets, which columns are `open` and
  whether sealed columns use `result_mode = "band"` from your own
  re-identification analysis. P3 in `papers/` explains why open attributes,
  not tokens, drive most re-identification.

## Known limitations (not vulnerabilities)

- Plaintext exists inside the gateway process at load time and during
  decryption; embeddings for `similarity_search` are held in the clear in
  that process.
- Decryption performs a constant number of steps but is not constant-time
  in the strict sense: its memory-access pattern depends on the plaintext,
  so a co-located attacker with cache-timing access to the gateway host
  could learn about decrypted aggregates.
- The ElGamal private key is held in process memory: generated per process,
  or unwrapped at start-up from the KMS-protected keystore. It never lives
  inside an HSM, and decryption happens in the gateway process.
- Cutting entries from the end of the audit trail is not detectable from the
  trail alone; record the head digest (`tokenis-mcp audit verify`)
  off-host.
- D2 is P4's tractable relaxation of an NP-hard question (Remark 10): it
  can over-refuse, and in principle under-refuse low-weight combinations
  that do not appear as a row of the reduced basis.
- `credential_id` equals the principal in this gateway, so credential
  rotation cannot reset a budget (the safe direction; P4 Theorem 13).
- No independent audit of this code has been performed. The "EC-FHE" source
  papers' own problems are documented in `tokenis/crypto/ec_fhe.py`.

## In scope

- Any way for an MCP or `tokenis.llm` caller to obtain a value that the
  admission policy should have refused: bypassing D1-D5 (including through
  concurrency, restarts, filter constructions, group_by, exists,
  compare_periods or the Reveal tools), or learning a denial's reason or a
  refused group's size.
- Choosing or forging the principal, bypassing API-key or JWT verification,
  or reaching tools over HTTP without credentials.
- A disclosure that is not recorded in the trace, or a trace edit that
  `verify_chain()` / `tokenis-mcp audit verify` does not detect (other than
  cutting its tail).
- Two replicas sharing a database admitting what one process would refuse,
  or a replica answering on an admission history that changed under it.
- Reading values or acting through the admin console, `/metrics` or the
  probes.
- Bugs in `crates/tokenis-core` or its bindings that break
  `Dec(Enc(x) + Enc(y)) = x + y`, leak key material or one-time secrets,
  accept an invalid point, let a mask or triple be used twice, or let input
  from Python or JavaScript crash the process (not bugs in `k256` itself:
  report those upstream).

## Out of scope

- The limitations listed above, and findings against `research/` code that
  only affect its synthetic corpora.
- Denial of service by an authenticated principal within its own budget.
