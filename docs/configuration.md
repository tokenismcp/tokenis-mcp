# Configuration reference

A Tokenis deployment is one TOML file. Unknown keys are errors, so a typo
fails loudly instead of silently falling back to a default. Relative paths
are resolved against the file's directory. Secrets never go in the file: it
names environment variables instead.

The annotated [`examples/tokenis.toml`](../examples/tokenis.toml) uses every
section. Validate a file with `tokenis-mcp check --config tokenis.toml`.

## `[tenant]`

| Key | Default | Meaning |
|---|---|---|
| `name` | `"default"` | Tenant name, mixed into every token's scope |
| `epoch` | `1` | Bump to rotate every token (old tokens stop matching) |
| `tokenizer_key_env` | `"TOKENIS_TOKENIZER_KEY"` | Environment variable holding the tokenizer key: hex or base64, at least 16 bytes (`tokenis-mcp keygen-secret` makes 32) |

## `[data]` (a file or a database; required unless a `[ledger]` exists)

From a file:

| Key | Default | Meaning |
|---|---|---|
| `path` | required | CSV (header row) or JSON-lines file |
| `format` | from the extension | `csv` or `jsonl` (`.jsonl`/`.ndjson` imply `jsonl`) |
| `delimiter` | `","` | CSV delimiter |
| `encoding` | `"utf-8"` | File encoding |

From a database, through SQLAlchemy (install the matching extra:
`postgres`, `mysql`, `oracle`, `mssql`, `snowflake` or `bigquery`):

| Key | Default | Meaning |
|---|---|---|
| `url_env` | none | Environment variable holding the SQLAlchemy URL, credentials included, e.g. `postgresql+psycopg://reader:...@db/crm` |
| `url` | none | The URL written in the file; allowed only **without** a password (e.g. Kerberos, IAM or a local socket) |
| `table` | none | A plain table name (`schema.table` allowed); read with `SELECT *` |
| `query` | none | A `SELECT` instead of `table` (exactly one of the two). It runs as written: give the gateway a database role that can only read |
| `fetch_size` | `10000` | Rows streamed per round trip; the source is never held in memory at once |

Use a database role that can only read the rows the gateway serves.

Either way:

| Key | Default | Meaning |
|---|---|---|
| `id_column` | none | A unique record id; never exposed. Without it, rows are identified by position |
| `embedding_column` | none | Vector per record for `similarity_search`: a JSON array or `;`-separated numbers. Requires an `entity` column |

Every row is validated at load time. The first invalid row aborts the load
with its location.

## `[[columns]]` (at least one sealed)

One table per attribute the gateway uses. File columns not listed are
ignored.

| Key | Default | Meaning |
|---|---|---|
| `name` | required | `[a-z][a-z0-9_]*`, at most 63 characters; must match the file's header |
| `protection` | required | `open`, `token` or `sealed` (see below) |
| `description` | `""` | Shown to the model; say what the column means and its unit |
| `unit` | `""` | Shown with aggregates, e.g. `"KRW million"` |
| `scale` | `0` | Sealed only: decimal places kept exactly (`2` keeps cents) |
| `result_mode` | `"exact"` | Sealed only: `exact`, or `band` to report aggregates as 1-2-5 bands (`[2,000, 5,000)`) |
| `allow_variance` | `false` | Sealed only: enables `var` (stores a second encrypted column of squares) |
| `entity` | `false` | Token only: the column that identifies each record's subject; `similarity_search` returns these tokens. At most one |

- **`open`**: released verbatim. Filterable; a group key. Its distinct values
  (up to `max_enum_values`) are listed to the model.
- **`token`**: released only as a keyed 128-bit pseudonym; equal values get
  equal tokens. Filterable by token.
- **`sealed`**: encrypted when loaded; only aggregates over at least *k*
  records ever leave.

Values in open and token columns must be non-empty, and at most 256
characters. Sealed values must be numbers (decimal strings are parsed
exactly).

## `[admission]`: P4's D1-D5 controls

| Key | Default | Meaning |
|---|---|---|
| `min_query_set_size` | `5` | *k*: no aggregate over fewer than *k* records, or over all but fewer than *k* |
| `budget` | `200` | Admitted queries per principal per window. `group_by` uses one per group; `compare_periods` and `disclose_ratio` use two |
| `window` | `"day"` | Budget window: `day`, `hour` (UTC) or `total` |
| `taint_budget` | `20` | Budget while the caller's context is tainted |
| `taint_call_cap` | `50` | Calls (admitted or not) allowed while tainted |
| `cell_aware` | `true` | Also refuses query combinations that would pin down a small group, not only single records |

The differencing audit (D2) runs on every sum, average and variance. It
refuses a query if, combined with the queries already admitted -- from
**any** principal, since callers can pool their answers -- it would reveal an
individual record or a group smaller than *k*.

## `[decryption]`

| Key | Default | Meaning |
|---|---|---|
| `max_value` | `68719476736` (2^36) | Largest absolute aggregate, in stored units (after `scale`); larger ones are denied |
| `table_size` | `4194304` (2^22) | Cap on each decryptor's lookup table (8 bytes per entry) |

Each sealed column's decryptor is sized to that column's own bound (the sum
of its absolute values), so these are caps, not costs. Raise `max_value`
(up to 2^40) only if a column's totals can exceed about 6.9e10 in stored
units.

## `[disclosure]`

| Key | Default | Meaning |
|---|---|---|
| `latency_granularity_ms` | `250` | Every tool call takes a multiple of this, so timing reveals nothing about which path ran |
| `max_top_k` | `5` | Largest `similarity_search` result |
| `max_buckets` | `8` | Most buckets `disclose_bucket` may use |
| `max_groups` | `50` | Most distinct values a `group_by` key may have (counted over the whole dataset, so filters do not help; group by a coarser column) |
| `max_enum_values` | `100` | Open columns with more distinct values are not listed to the model value by value |

## `[[reveal.purposes]]`

Purposes authorise the two disclosure tools (`disclose_ratio`,
`disclose_bucket`). The model picks a purpose from this list; it cannot
invent one. Without any purposes, those tools are not offered.

| Key | Default | Meaning |
|---|---|---|
| `name` | required | `[a-z][a-z0-9_]*`, e.g. `quarterly_board_report` |
| `description` | required | Shown to the model |
| `principals` | `["*"]` | Who may use it; `"*"` is any authenticated principal |

## `[state]`

| Key | Default | Meaning |
|---|---|---|
| `backend` | `"file"` | `file` (one process; uses `dir`) or `postgres` (several replicas share one database) |
| `dir` | none | File backend: directory for the admission history (`admission.jsonl`) and the audit trail (`trace.jsonl`). Also the default home of the keystore |
| `url_env` | `"TOKENIS_STATE_URL"` | Postgres backend: environment variable holding the connection URL |
| `audit_key_env` | none | Environment variable with the key that HMAC-signs every audit entry (with `[keys]`, the keystore's audit key is used instead) |

With neither `dir` nor the postgres backend, a restart forgets which queries
were answered, and the budget and differencing audit start over.

**Several replicas.** With `backend = "postgres"` every tool call runs in one
database transaction under a per-tenant advisory lock. The replica first
replays admission decisions the others logged, then decides, and logs its
own before answering. A differencing pair split across two replicas is
refused exactly as if one process had seen both, and all replicas extend one
hash-chained audit trail. API keys live in the same database
(`tokenis-mcp keys create ... --config F` writes there; do not set
`api_keys_file`). Tables are created on first use: `tokenis_state`,
`tokenis_admission_log`, `tokenis_trace`, `tokenis_api_keys`. The lock
serialises calls per tenant, so replicas add availability, not throughput.

## `[keys]`: the keystore

Without `[keys]`, secrets come from environment variables and the ElGamal
key is new at every start (so the data is re-encrypted at every start). With
`[keys]`, `tokenis-mcp secrets init` generates four secrets -- the ElGamal
private key, the tokenizer key, the audit key and the ledger key -- and
stores them wrapped by a key-management service. Each wrap is bound to the
tenant, so a keystore cannot be swapped between tenants.

| Key | Providers | Meaning |
|---|---|---|
| `provider` | all | `local`, `aws-kms`, `vault-transit`, `gcp-kms` or `azure-keyvault` |
| `keystore` | all | Keystore file (default `<[state] dir>/keystore.json`), mode 0600 |
| `passphrase_env` | `local` | Variable holding the passphrase (scrypt, then AES-256-GCM). For development and air-gapped sites |
| `key_id`, `region` | `aws-kms` | KMS key id or ARN; region (default from the AWS environment). Needs the `aws` extra |
| `address`, `key_name`, `mount`, `namespace`, `token_env` | `vault-transit` | Vault address (`https://`, or `http://` on localhost only), transit key, mount (default `transit`), namespace, token variable (default `VAULT_TOKEN`) |
| `key_name` | `gcp-kms` | `projects/.../cryptoKeys/...`. Needs the `gcp` extra |
| `vault_url`, `key_name` | `azure-keyvault` | Key Vault URL and an RSA key permitting wrapKey, unwrapKey, sign and verify (RSA-OAEP-256 plus an RS256 signature per secret). Needs the `azure` extra |

Cloud credentials come from each SDK's usual sources (instance role,
workload identity, environment); none go in the file.
`tokenis-mcp secrets status --config F` checks that the keystore unwraps;
`tokenis-mcp secrets rewrap --config NEW --from OLD` moves it to another
KMS without changing any secret.

## `[ledger]`: serve without the plaintext source

| Key | Default | Meaning |
|---|---|---|
| `path` | none | Directory for the encrypted ledger (requires `[keys]`) |

`tokenis-mcp ingest --config F` reads `[data]` once and writes the ledger:
`manifest.json` (public metadata) and `payload.bin` (AES-256-GCM under the
keystore's ledger key, with sealed columns already EC-ElGamal encrypted).
When the ledger exists, `serve` loads it and never touches `[data]`, so the
serving host needs no access to the source database. Editing either file,
using another tenant's keystore or changing `[[columns]]` makes loading
fail; re-run `ingest` after a schema change.

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `transport` | `"stdio"` | `stdio` (one local user) or `http` (Streamable HTTP, requires `[auth]`) |
| `host` | `"127.0.0.1"` | HTTP bind address |
| `port` | `8000` | HTTP port |
| `public_url` | `http://<host>:<port>` | The URL clients use; its host is accepted in `Host` headers |
| `allowed_hosts` | `[]` | Extra `Host` header values to accept (DNS-rebinding protection is on when not bound to localhost) |
| `stdio_principal` | `local:<os-user>` | Principal for stdio sessions |
| `taint_header` | none | HTTP header your agent host sets to `1` when the conversation holds untrusted content |
| `default_taint` | `0` | Taint when the header is absent (or on stdio) |
| `max_concurrency` | `16` | Tool calls processed in parallel |
| `stateless` | `false` | HTTP: keep no MCP session in the process, so any replica behind a load balancer can serve any request (use with the postgres state backend) |
| `log_format` | `"text"` | `text` or `json` (one object per line, including the HTTP server's own logs) |

Command-line flags `--transport`, `--host` and `--port` override these.

## `[ops]`: health, metrics and the admin console (HTTP only)

| Key | Default | Meaning |
|---|---|---|
| `admin_token_env` | none | Variable holding the admin console password (at least 16 characters). Without it, `/admin` does not exist |
| `stats_retention_days` | `90` | How long the per-call statistics behind the admin console are kept (1-3650) |
| `metrics_token_env` | none | Variable holding a bearer token required on `/metrics`. Without it, `/metrics` is open (scrape it from inside your network) and denials are not broken down by rule |

Always served next to `/mcp`: `GET /healthz` (liveness) and `GET /readyz`
(ready once the ledger is sealed and, with the postgres backend, the
database answers and the shared history is intact). See
[deployment.md](deployment.md#operating-it).

## `[auth]` (required for HTTP)

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"none"` | `none` (stdio only), `api_keys` or `jwt` |
| `api_keys_file` | none | Key store for `api_keys` mode (created by `tokenis-mcp keys create`); not used with the postgres state backend, which keeps keys in the database |

`[auth.jwt]`, for tokens from your identity provider (Okta, Entra ID, Auth0,
Keycloak, ...):

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | Expected `iss` |
| `audience` | required | Expected `aud` |
| `jwks_url` | required | `https://` URL of the provider's JWKS |
| `algorithms` | `["RS256", "ES256"]` | Asymmetric algorithms only; HMAC and `none` are refused |
| `principal_claim` | `"sub"` | Claim used as the principal |
| `required_scopes` | `[]` | Scopes the token must carry (`scope` or `scp` claim) |

## Command line

| Command | What it does |
|---|---|
| `tokenis-mcp serve --config F \| --demo \| --config-or-demo F` | Run the MCP server. `--config-or-demo ""` serves the demo, for launchers that always pass a path |
| `tokenis-mcp check --config F` | Validate the config, the secrets and every data row; writes nothing |
| `tokenis-mcp tools --demo --format anthropic\|openai\|mcp` | Print the tool schemas a model sees |
| `tokenis-mcp ask --demo "question" [--provider anthropic\|openai] [--model M]` | Answer a question with an LLM using the tools |
| `tokenis-mcp keys create PRINCIPAL --config F` | Create an API key (printed once) |
| `tokenis-mcp keys list \| revoke KEY_ID --config F` | List or revoke keys; revocation applies without a restart |
| `tokenis-mcp keygen-secret` | Print a random 32-byte hex secret |
| `tokenis-mcp audit verify --config F` | Verify the audit trail's hash chain and HMACs (file or postgres) |
| `tokenis-mcp secrets init \| status --config F` | Create the keystore, or check it unwraps |
| `tokenis-mcp secrets rewrap --config NEW --from OLD` | Move the keystore to another KMS |
| `tokenis-mcp ingest --config F` | Read `[data]` once and write the encrypted `[ledger]` |

`serve` also takes `--reset-admission-state` (see
[troubleshooting.md](troubleshooting.md)). Every command takes
`--log-level` (or `TOKENIS_LOG_LEVEL`) and `--log-format text|json` (or
`TOKENIS_LOG_FORMAT`; default: `[server] log_format`).
