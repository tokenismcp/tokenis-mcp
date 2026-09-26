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

## `[data]` (required)

| Key | Default | Meaning |
|---|---|---|
| `path` | required | CSV (header row) or JSON-lines file |
| `format` | from the extension | `csv` or `jsonl` (`.jsonl`/`.ndjson` imply `jsonl`) |
| `delimiter` | `","` | CSV delimiter |
| `encoding` | `"utf-8"` | File encoding |
| `id_column` | none | A unique record id in the file; never exposed. Without it, rows are identified by file and line |
| `embedding_column` | none | Vector per record for `similarity_search`: a JSON array or `;`-separated numbers. Requires an `entity` column |

Every row is validated at load time. The first invalid row aborts the load
with its file and line number.

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
| `budget` | `200` | Admitted value queries per principal per window |
| `window` | `"day"` | Budget window: `day`, `hour` (UTC) or `total` |
| `taint_budget` | `20` | Budget while the caller's context is tainted |
| `taint_call_cap` | `50` | Calls (admitted or not) allowed while tainted |
| `cell_aware` | `true` | Also refuses query combinations that would pin down a small group, not only single records |

The differencing audit (D2) runs on every sum, average and variance. It
refuses a query if, combined with that principal's earlier admitted queries,
it would reveal an individual record or a group smaller than *k*.

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
| `max_groups` | `50` | Most groups `group_by` may return (add filters or use a coarser column beyond this) |
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
| `dir` | none | Directory for the admission history (`admission.jsonl`) and the audit trail (`trace.jsonl`). Set it for anything beyond experiments |
| `audit_key_env` | none | Environment variable with the key that HMAC-signs every audit entry |

Without `dir`, a restart forgets which queries were answered, and the
budget and differencing audit start over.

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

Command-line flags `--transport`, `--host` and `--port` override these.

## `[auth]` (required for HTTP)

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"none"` | `none` (stdio only), `api_keys` or `jwt` |
| `api_keys_file` | none | Key store for `api_keys` mode (created by `tokenis-mcp keys create`) |

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
| `tokenis-mcp audit verify --config F` | Verify the audit trail's hash chain and HMACs |

`serve` also takes `--reset-admission-state` (see
[troubleshooting.md](troubleshooting.md)). Every command takes
`--log-level`.
