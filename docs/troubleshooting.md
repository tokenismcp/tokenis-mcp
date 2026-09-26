# Troubleshooting

Command-line errors are printed to stderr as `tokenis-mcp: <message>`. Run
`tokenis-mcp check --config tokenis.toml` first: it validates the file, the
secrets and every data row without creating or touching any state. Some
problems (the admission history, the audit trail, the database state
backend) only appear at `serve`, because `check` does not open them.

If a model gets a refusal and you want to know why, see
[tools.md](tools.md#why-a-question-is-refused): callers only ever get one
generic message, and the rule is in the operator log and the audit trail.

## Configuration errors

Unknown keys are errors, so a typo fails loudly. The message names the
table, as in `[tenant]: unknown key(s) nme`, or `[top level]: unknown
key(s) ...` for a misspelled table name. Check the key against
[configuration.md](configuration.md).

| Message | Fix |
|---|---|
| `a [data] source or a [ledger] path is required` | Add `[data]` (a `path`, or `url`/`url_env` with `table` or `query`), or a `[ledger]` that has been ingested |
| `[data]: use either path (a file) or url/url_env with query/table` | A file source and a database source are mixed; keep one |
| `[data]: a database source needs exactly one of query or table` | Set `table` or `query`, not both, not neither |
| `[data] url contains a password; ...` | Move the whole URL into an environment variable and name it with `url_env` |
| `at least one [[columns]] entry is required` / `schema: the schema needs at least one sealed column` | Every deployment needs at least one `sealed` column |
| `the http transport requires authentication: ...` | Set `[auth] mode` to `api_keys` or `jwt` |
| `[auth] mode = api_keys needs api_keys_file (or the postgres state backend)` | Add `api_keys_file`, or use `[state] backend = "postgres"` |
| `with the postgres state backend API keys live in the database; remove [auth] api_keys_file` | Remove `api_keys_file`; `tokenis-mcp keys create` writes to the database |
| `[keys] needs keystore (or a [state] dir to keep it in)` | Set `[keys] keystore` or `[state] dir` |

A data row that fails validation stops the load with its location, for
example `customers.csv:12: record '1042': missing value for 'industry'`,
or `customers row 12: ...` for a database table.

## Secrets

```text
environment variable TOKENIS_TOKENIZER_KEY is not set (generate one with `tokenis-mcp keygen-secret`)
$TOKENIS_TOKENIZER_KEY must be at least 16 bytes, hex or base64 encoded
```

Without `[keys]`, the tokenizer key (and the audit key, if
`[state] audit_key_env` is set) come from environment variables. Each must
decode, as hex or base64, to at least 16 bytes. `tokenis-mcp keygen-secret`
prints a 32-byte hex value. Keep them stable: a new tokenizer key changes
every token, and a new audit key makes the existing trail fail
verification.

In the Claude Code plugin or the Desktop bundle, set the keys in the
extension's settings, not your shell.

## The gateway will not start

**`StateMismatchError: ... was written for different data or admission settings`**

The admission history (in `[state] dir`, or the postgres database) belongs
to a different dataset or policy: the records or their open or token
values changed, the columns changed, `min_query_set_size` or `cell_aware`
changed, or (with a token column) the tokenizer key, tenant or epoch
changed, which changes every token. Budget settings do not cause this.

`tokenis-mcp serve --reset-admission-state` archives the old history and
starts a new one (file backend: `admission.jsonl` is renamed to
`admission.jsonl.<time>.old`; postgres: the tenant's rows are moved to
`<tenant>#archived-<time>`). **Resetting is a disclosure risk.** The new
history does not know what was answered before, so a caller can ask a query
on the new data whose difference from an old answer isolates a record, for
example a total taken just before and just after one record was added.
Reset only when that is acceptable, such as a genuinely new dataset or
callers who never saw the old answers.

**`need at least 2*min_query_set_size = N records to answer any aggregate (have M)`**

With fewer than *2k* records no aggregate can satisfy D1. Load more data or
lower `min_query_set_size` (at least 2).

**`TraceIntegrityError: <file>:<line>: chain broken` (or `entry was modified`, `HMAC does not verify`)**

The persisted audit trail does not verify, so the gateway refuses to open
it. Either the file was edited, or the audit key is not the one that signed
it. See [Reading the audit trail](#reading-the-audit-trail).

## A replica stops answering (postgres backend)

With `[state] backend = "postgres"`, each replica checks the shared history
before every call. If it no longer matches, the replica fails closed:
callers get `the gateway is temporarily unavailable`, the log has
`refusing calls: <reason>`, and `/readyz` returns 503 with
`"state": "diverged: restart this replica"`.

| Reason in the log | What happened | Fix |
|---|---|---|
| `... was reset or replaced while this replica was running; restart it` | Another replica started with `--reset-admission-state` or different data | Restart this replica with the same data and config as the others |
| `... changed underneath this replica (record N is gone or different): the database was restored from an earlier backup or edited` | The admission log lost or changed entries this replica had already seen | Read "Backups" in [deployment.md](deployment.md) before restarting: a restored history has forgotten the queries answered after the backup |

Other messages: `[state] backend = postgres: set TOKENIS_STATE_URL to the
database URL, ...` (the variable named by `url_env` is unset), and
`cannot open the postgres state: ...` (the database is unreachable, or the
`postgres` extra is missing: `pip install 'tokenis-mcp[postgres]'`). While
the database is unreachable, `/readyz` reports `"database": "unreachable"`.
The probes and `/metrics` are described in [deployment.md](deployment.md).

## Keystore

| Message | Fix |
|---|---|
| `no keystore at <path>: run \`tokenis-mcp secrets init\`` | Create it, or point `[keys] keystore` at the existing one |
| `environment variable <name> (the keystore passphrase) is not set` | Set the variable named by `passphrase_env` |
| `the keystore passphrase must be at least 16 bytes` | Use a longer passphrase |
| `cannot unwrap: wrong passphrase or tampered keystore` | Wrong passphrase, or the file was edited. Restore it from backup |
| `<path> belongs to tenant 'a', not 'b'` | Wraps are bound to the tenant; use the keystore made for this `[tenant] name` |
| `<path> is wrapped with local, but aws-kms is configured` | Move it with `tokenis-mcp secrets rewrap --config NEW --from OLD` |
| `AWS KMS refused to decrypt: ...` / `Cloud KMS refused to decrypt: ...` / `Azure Key Vault refused to unwrap: ...` / `Vault decrypt failed ...` | The service identity lacks permission on the key, the key is disabled, or the region or address is wrong |
| `<provider> needs its client library: pip install 'tokenis-mcp[aws]'` (or `gcp`, `azure`) | Install the extra |

The keystore needs the KMS decrypt operation to start, and the encrypt
operation for `secrets init` and `secrets rewrap`. `tokenis-mcp secrets
status --config F` checks that it unwraps without starting the server.
Losing the keystore loses every token and every ledger, so back it up.

## Ledger

| Message | Fix |
|---|---|
| `a persisted ledger needs [keys]: its keys live in the keystore` | Add `[keys]` |
| `no ledger at <path> yet and no [data] source: ...` | Configure `[data]` and run `tokenis-mcp ingest --config F` |
| `<path> was written for a different schema; re-run ingest` | `[[columns]]` changed; run `ingest` again |
| `<path> was written for tenant 'a' epoch 1, not 'a' epoch 2` | The tenant or epoch changed; run `ingest` again |
| `<path>/payload.bin does not match its manifest` | The payload was modified or replaced; restore both files or re-ingest |
| `<path>: wrong ledger key, or the ledger was modified` | The keystore is not the one used at ingest, or the ledger was edited |

## Database sources

| Message | Fix |
|---|---|
| `database sources need SQLAlchemy and a driver: ...` | Install the matching extra: `postgres`, `mysql`, `oracle`, `mssql`, `snowflake` or `bigquery` |
| `environment variable <name> (the database URL) is not set` | Set the variable named by `url_env` |
| `cannot use the database URL: ...` | The URL is malformed or names a driver that is not installed |
| `database error reading <table or query>: <ErrorClass>: ...` | Check connectivity, credentials, the table name and the role's read permission |
| `[data] table must be a plain (optionally schema-qualified) name` | Use `table` for a name only; put anything else in `query` |

The `query` is run as given. Use a database role that can only read the
rows the gateway serves.

## HTTP clients are rejected

- **401 with `invalid_token`.** The bearer token is missing, unknown,
  revoked or expired, or (JWT) its issuer, audience or scopes do not match
  `[auth.jwt]`. Check with `tokenis-mcp keys list --config F`.
- **421 `Invalid Host header` or 403 `Invalid Origin header`.** When the
  server is not bound to `127.0.0.1`, `localhost` or `::1`, DNS-rebinding
  protection accepts only the host of `[server] public_url` and the entries
  in `allowed_hosts`. Set `public_url` to the URL clients actually use, and
  add any other `Host` values (including a non-default port, as
  `host:port`) to `allowed_hosts`.
- **`the http transport needs --config`.** HTTP always needs a config file
  with `[auth]`; `--demo` works over stdio only.
- **`[ops] admin_token_env: set <name> to a secret of at least 16 characters`.**
  The admin dashboard (`/admin`) or the metrics token is configured but its
  variable is unset or too short. See [deployment.md](deployment.md).

## Every call is slow

This is intentional. Every tool call, answered or refused, is padded to a
multiple of `[disclosure] latency_granularity_ms` (default 250 ms), so
timing does not reveal which path ran. An agent that makes eight calls in
sequence spends at least two seconds waiting. Padding happens outside the
gateway's lock, so parallel tool calls wait together rather than one after
another. Lowering the quantum makes timing more informative to an attacker;
keep it above the gateway's real worst-case call time.

## Large totals, or every `var`, are refused

Aggregates are decrypted only within a bounded range. A total whose
absolute value in stored units (after `scale`) exceeds
`[decryption] max_value` (default 2^36, about 6.9e10) is refused, logged as
`rule=decryption-range`. `var` works on a column of squares, which exceeds
the range far sooner. Raise `max_value` (at most 2^40), or reduce `scale`.
Larger ranges make decryption slower unless `table_size` grows too.

## `uvx` picks an old Python

Tokenis needs Python 3.10 or later. `uvx` normally fetches a suitable
Python, but an older one can be selected by `UV_PYTHON` or a
`.python-version` file, and resolution then fails. Ask for a version
explicitly:

```bash
uvx --python 3.12 --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp serve --demo
```

In an MCP client's JSON config, add `"--python", "3.12"` at the start of
`args`.

## Reading the audit trail

```bash
tokenis-mcp audit verify --config tokenis.toml
```

It walks the whole trail (the file in `[state] dir`, or the `tokenis_trace`
table with the postgres backend), checks the hash chain and, when an audit
key is configured, every HMAC. It prints the location, the number of
entries by kind (`aggregate`, `reveal`, `denial`), the head digest and
whether the trail is signed. A problem prints `INTEGRITY FAILURE: <where>:
<reason>` and exits with status 1.

With the file backend, `trace.jsonl` has one JSON object per line: `kind`,
`index`, `prev_hash`, `digest`, `mac`, `value_summary` (the value that was
released) and `audit`, which holds `principal`, `obj_ref` (the tool, the
operation and the filters), `purpose`, `policy_version`, `decision`,
`timestamp` and, for denials, `detail`: the rule that fired. The file
contains released values, so protect it like the results themselves.
