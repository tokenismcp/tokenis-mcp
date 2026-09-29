# Deployment

Tokenis runs in three shapes. Pick the smallest one that fits:

| Shape | For | State lives in |
|---|---|---|
| **Local (stdio)** | One person, one MCP client (Claude Desktop, Claude Code) | `[state] dir` on disk |
| **Single server (HTTP)** | A team sharing one gateway | `[state] dir` on disk |
| **Replicated (HTTP)** | Availability: several gateway processes behind a load balancer | PostgreSQL (`[state] backend = "postgres"`) |

Local use is covered in [getting-started.md](getting-started.md). This page
covers the two HTTP shapes: a ready-made Docker Compose stack, the Helm chart
for Kubernetes, and how to operate either.

## What a production deployment looks like

```
 MCP clients ──HTTPS──▶ load balancer ──▶ tokenis replica ─┐
 (API key or JWT)                        ──▶ tokenis replica ─┼──▶ PostgreSQL: admission log,
                                                              │    audit trail, API keys
                         Prometheus ◀── /metrics ─────────────┘
 KMS (AWS / GCP / Azure / Vault) ◀── unwraps the keystore at start-up
```

- **Secrets** live in a keystore wrapped by your KMS (`[keys]`), not in
  environment variables. See [configuration.md](configuration.md#keys-the-keystore).
- **Data** is either read from the source database at start-up by every
  replica (`[data] url_env`), or ingested once into an encrypted ledger
  (`tokenis-mcp ingest`, `[ledger]`) so the serving hosts never touch the
  source.
- **Shared state** in PostgreSQL makes the replicas act as one gateway. Each
  tool call runs in a single transaction under a per-tenant advisory lock:
  the replica replays what the others decided, decides, records, and
  answers. A differencing pair split across two replicas is refused exactly
  as if one process had seen both queries.
- **The lock serialises calls per tenant.** Replicas add availability and
  rolling upgrades, not throughput. A call holds the lock for the time it
  computes (milliseconds to tens of milliseconds), not for the latency
  padding.

## Docker Compose

`deploy/compose/` is a complete stack on one machine: PostgreSQL (shared
state plus a sample CRM database), a one-shot init job (creates the keystore
and ingests the ledger), two stateless gateway replicas, an nginx load
balancer, Prometheus with the alert rules, and Grafana with the Tokenis
dashboard.

```bash
cd deploy/compose
./init-env.sh
```

```bash
docker compose up -d --build
```

```bash
docker compose exec tokenis tokenis-mcp keys create analyst@example.com --config /config/tokenis.toml
```

`init-env.sh` writes random secrets to `.env` (mode 600; never commit it).
Then:

| URL | What |
|---|---|
| `http://localhost:8080/mcp` | The MCP endpoint (bearer: the key printed above) |
| `http://localhost:8080/admin` | Admin console (password: `TOKENIS_ADMIN_TOKEN` in `.env`) |
| `http://localhost:3000` | Grafana (`admin` / `GRAFANA_ADMIN_PASSWORD`) |
| `http://localhost:9090` | Prometheus |

All ports bind to `127.0.0.1`. The sample data is fictional. To use your own,
edit `tokenis.toml` (columns, `[data]`) and point `CRM_DATABASE_URL` at your
database with a read-only role. For production, replace `provider = "local"`
with your KMS.

## Kubernetes (Helm)

The chart is in `deploy/helm/tokenis`. It runs the replicas as a Deployment
with a hardened pod spec: non-root (uid 10001), read-only root filesystem,
all capabilities dropped, `RuntimeDefault` seccomp. It sets probes on
`/healthz` and `/readyz`, a PodDisruptionBudget, and spreads replicas across
nodes. Optional features: Ingress, HPA, NetworkPolicy, ServiceMonitor,
PrometheusRule and a Grafana dashboard ConfigMap.

1. **Create the keystore** once, from a workstation that can use the KMS
   key, with a config naming the same tenant:

   ```bash
   tokenis-mcp secrets init --config tokenis.toml
   ```

2. **Create the Secrets.** The keystore is useless without the KMS key, so a
   Kubernetes Secret is an acceptable home for it.

   ```bash
   kubectl create secret generic tokenis-keystore --from-file=keystore.json
   ```

   ```bash
   kubectl create secret generic tokenis-state --from-literal=url='postgresql://tokenis:...@db:5432/tokenis?sslmode=require'
   ```

   ```bash
   kubectl create secret generic crm-reader --from-literal=url='postgresql+psycopg://reader:...@crm:5432/crm'
   ```

   ```bash
   kubectl create secret generic tokenis-admin --from-literal=token="$(openssl rand -hex 24)"
   ```

3. **Write `values.yaml`.** Put the gateway config in `config`, minus
   `[server]`, `[state]` and `[ops]`: the chart renders those from values and
   refuses a config that contains them.

   ```yaml
   config: |
     [tenant]
     name = "acme"
     [data]
     url_env = "SOURCE_DATABASE_URL"
     table = "customers"
     id_column = "id"
     [keys]
     provider = "aws-kms"
     key_id = "alias/tokenis"
     keystore = "/keys/keystore.json"
     [auth]
     mode = "api_keys"
     # [[columns]] ... [admission] ...
   server:
     publicUrl: https://tokenis.example.com
   keystore: {existingSecret: tokenis-keystore}
   admin: {enabled: true}
   extraEnv:
     - name: SOURCE_DATABASE_URL
       valueFrom: {secretKeyRef: {name: crm-reader, key: url}}
   serviceAccount:
     annotations:
       eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/tokenis
   ```

4. **Install:**

   ```bash
   helm install tokenis deploy/helm/tokenis -n tokenis --create-namespace -f values.yaml
   ```

The notes printed by `helm install` show how to create the first API key.
Workload identity (the service-account annotation) gives the pods KMS access
without static cloud credentials. CI renders the chart with every option on
and validates the output against the Kubernetes schemas (`kubeconform`). The
release was also installed on a real cluster (k3s): the replicas became
ready under the hardened pod spec, and a differencing pair sent to two
different pods was refused.

## Operating it

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness: the process serves requests |
| `GET /readyz` | Readiness: ledger sealed; with postgres, database reachable and shared history intact. 503 otherwise, and the check that failed is named |
| `GET /metrics` | Prometheus metrics. Set `[ops] metrics_token_env` whenever callers can reach the port: only then are denials broken down by rule (an open breakdown would tell a caller why they were refused) |
| `GET /admin` | Read-only admin console (`[ops] admin_token_env`) |

**Admin console.** Sign in with HTTP Basic auth, using any user name and
the admin token as the password. Every number comes from the database, so
every replica shows the same cluster-wide figures, over the last hour, 24
hours, 7 days or 30 days, and nothing resets when a process restarts.

| Page | Shows |
|---|---|
| Overview | Health, calls and denial rate compared with the previous period, latency percentiles, traffic, denials by rule, per-tool outcomes, recent audit entries, top users, and each replica with when it last served a call |
| Users | Per principal: calls, answers, refusals, the most frequent refusal rule, and the budget left in the current window. Exports every call as CSV |
| Audit trail | The shared, signed trail: searchable and filterable, exportable as CSV. Disclosed values are never shown or exported |
| Access | API keys: issue one (shown once), revoke one (effective on every replica with the next request). An admin activity log records every issue, revocation and export, with its source |
| Policy & schema | The admission settings and column protection in force |

Every call is recorded (tool, principal, outcome, rule, time, replica; never
an argument or a value) in `tokenis_calls`, in the shared database, or in
`calls.sqlite` in the state directory for a single server. Records are
written in the background every two seconds, so the console can lag by that
much, and recording never slows or fails a call. They are kept for
`[ops] stats_retention_days` (90). This is operational data: the security
record is the signed audit trail, written before any answer is released.

The console's write actions accept only requests the console itself makes
(a JSON body, a custom header and a same-origin `Origin`), so another site
cannot use a signed-in administrator's browser to issue or revoke keys. The
page makes no external requests and is served under a strict, nonce-based
Content Security Policy.

**Metrics** (all labels are low-cardinality; none carries a value):

| Metric | Type | Meaning |
|---|---|---|
| `tokenis_tool_calls_total{tool,outcome}` | counter | `ok`, `denied`, `invalid`, `unauthenticated`, `error` |
| `tokenis_denials_total{rule}` | counter | Refusals by admission rule (D1-D5, D4-*); only with a metrics token |
| `tokenis_tool_call_duration_seconds` | histogram | Per tool, after latency padding |
| `tokenis_records`, `tokenis_trace_entries` | gauge | Ledger size, audit trail length (-1: unreadable) |
| `tokenis_database_up`, `tokenis_state_diverged` | gauge | Postgres backend health |
| `tokenis_info{version,tenant,state_backend}` | gauge | Build information |

**Alerts.** `deploy/monitoring/alerts.yml` defines eight alerts: replica down,
database unreachable, state diverged, trace unreadable, a burst of D2
(differencing) denials, repeated refusals in tainted contexts, an error rate
above 5%, and slow calls. The chart ships the same rules as a
PrometheusRule.

**Logs.** Set `[server] log_format = "json"` (or `--log-format json`) for one
JSON object per line, including the HTTP server's own logs. Refusals are
logged with their rule (`denied tool=aggregate rule=D2`); the caller only
ever sees the generic message.

**Audit.** `tokenis-mcp audit verify --config F` walks the whole trail and
checks every hash link and HMAC. The trail can live in a file or in
PostgreSQL.

## Sizing

Memory grows with the data. With two sealed columns, a replica holds about
1 GB per million records once serving, and peaks at about 1.5 times that
while loading. Set the container limit accordingly (the chart's default of
2 GiB fits about 1.3 million records). Admission control's own cost depends
on the number of distinct combinations of open-column values (a few
thousand in typical data), not on the record count.

**Shared-state cost.** Each call makes about eight round trips to
PostgreSQL inside its transaction. Measured with the database on the same
host: 2.8 ms per call at the median (1.4 ms with the file backend), so one
tenant sustains about 400 calls per second across all replicas. Over a
network, add the round-trip time eight times. With the default 250 ms latency
quantum, that is headroom for well over a hundred concurrently active
clients per tenant.

## When the database is unavailable

With the postgres backend the gateway fails closed. It never answers
without recording the decision:

- Calls get "temporarily unavailable". Over HTTP, requests that cannot be
  authenticated because the key store is unreachable get `503` with
  `Retry-After: 2`.
- `/readyz` answers `503` within 2.5 s, so the load balancer stops routing
  to the replica. `/healthz` stays `200`, so it is not restarted.
- Connections carry connect, statement and lock timeouts. The server ends a
  session left idle inside a transaction after 30 s, so a replica that froze
  mid-call cannot hold the tenant lock for the others.
- When the database returns, the next call reconnects and service resumes.

Measured with two replicas under load: a database restart caused about one
second of `503`s; during a 25-second freeze, readiness answered `503` for the
duration and calls failed rather than queueing; no answer was ever given
without being recorded, and service resumed within a second of recovery.

## Backups

Back up PostgreSQL as you would any system of record. **Do not restore it to
an earlier point in time while replicas are running.** The admission log is
the gateway's memory of what it has already answered. If you roll it back, a
query that was refused because of an earlier answer can be admitted again,
and the answers can then be combined.

Replicas detect this. The admission log is hash-chained, and each replica
checks, inside every call's transaction, that the last record it saw is
still there, unchanged. If the log was rolled back or edited, the replica:

- stops answering (callers get a generic "temporarily unavailable");
- reports `/readyz` 503 with `"state": "diverged"`, so Kubernetes stops
  routing traffic to it;
- sets `tokenis_state_diverged 1`, which raises the `TokenisStateDiverged`
  alert.

It stays in this state until it is restarted. A replica that restarts replays
whatever history the database now holds. So before restarting, decide
whether that history is acceptable. If you are unsure, bump `[tenant] epoch`
(this rotates every token) and reset the history deliberately with
`--reset-admission-state`.

Also back up the keystore file. Without it (or without the KMS key that
wraps it), tokens cannot be reproduced and the ledger cannot be decrypted.

## Changes over time

- **New data, same columns.** Re-run `tokenis-mcp ingest` (or restart the
  replicas that read the source). If the open or token values change, the
  replicas refuse to start until you pass `--reset-admission-state`.
  Resetting forgets which answers were given, so answers about the old data
  can then be combined with answers about the new data. Budget for that, or
  bump the epoch.
- **Temporal differencing.** Asking the same question before and after a
  data update reveals the group's change between the two versions. With few
  records changing, that change can point at an individual. Refresh data in
  batches, not record by record.
- **Rotating keys.** `tokenis-mcp secrets rewrap --config NEW --from OLD`
  moves the keystore to another KMS key without changing any secret. Bumping
  `[tenant] epoch` rotates every token.
- **Upgrades.** Replicas are stateless apart from the shared database, so a
  rolling update (the chart's default, `maxUnavailable: 0`) needs no
  downtime.
