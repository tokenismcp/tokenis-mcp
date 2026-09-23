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

## Deploying safely

- **Run the gateway on a host you control**, with the data file, the state
  directory and the two secrets readable only by its service account.
- **Secrets come from the environment** (`TOKENIS_TOKENIZER_KEY`,
  `TOKENIS_AUDIT_KEY`, generated with `tokenis-mcp keygen-secret`), ideally
  injected from a secret manager. Keep the tokenizer key stable (rotating it
  changes every token; bump `[tenant] epoch` to rotate deliberately) and the
  audit key away from anyone who can write the trace file.
- **Set `[state] dir`.** Without it, a restart forgets the admission history
  (so the second half of a differencing pair can be asked after a restart)
  and the audit trail. `tokenis-mcp check` warns when it is missing.
- **Changing the data is a security event.** A gateway restarted on
  different data refuses to start until `--reset-admission-state` is given,
  because answers computed on the old data can be differenced against
  answers on the new. Reset only when that trade-off is acceptable (e.g. a
  new reporting period with a fresh budget), and prefer coarser columns or
  a larger *k* when data changes often.
- **HTTP needs TLS in front** (a reverse proxy or load balancer). The server
  refuses to run HTTP without authentication; set `public_url` and
  `allowed_hosts` so Host-header validation matches your domain. Run **one
  process per dataset**: budgets and the differencing history live in that
  process's state directory, so several replicas would each allow a full
  budget.
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
- The ElGamal private key is generated per process and held in memory, not
  in an HSM/KMS. Sealed data is re-encrypted from the source file at each
  start.
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
  `verify_chain()` / `tokenis-mcp audit verify` does not detect.
- Bugs in `crates/tokenis-core` or its bindings that break
  `Dec(Enc(x) + Enc(y)) = x + y`, leak key material or one-time secrets,
  accept an invalid point, let a mask or triple be used twice, or let input
  from Python or JavaScript crash the process (not bugs in `k256` itself:
  report those upstream).

## Out of scope

- The limitations listed above, and findings against `research/` code that
  only affect its synthetic corpora.
- Denial of service by an authenticated principal within its own budget.
