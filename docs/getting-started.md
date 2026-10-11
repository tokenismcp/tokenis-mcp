# Getting started

This guide takes you from nothing to an AI app (Claude, ChatGPT, Codex,
Gemini, Cursor, ...) answering questions over a confidential dataset, first on
built-in fictional data, then on your own.

## 1. Try it with the demo data

You need [uv](https://docs.astral.sh/uv/getting-started/installation/)
(it fetches a suitable Python for you). Pick your client:

**Claude Code: plugin (recommended).** Adds the server plus a skill that
teaches Claude to use it economically.

```text
/plugin marketplace add tokenismcp/tokenis-mcp
/plugin install tokenis@tokenis-mcp
```

Leave the config field empty when asked, and the plugin serves the demo data.

**Claude Code: server only.**

```bash
claude mcp add tokenis -- uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp serve --demo
```

**Claude Desktop.** Download `tokenis.mcpb` from the
[latest release](https://github.com/tokenismcp/tokenis-mcp/releases/latest)
and open it. Leave the config empty for the demo.

**Codex.** Add a stdio server to `~/.codex/config.toml`:

```toml
[mcp_servers.tokenis]
command = "uvx"
args = ["--index", "https://tokenismcp.github.io/tokenis-mcp/simple/",
        "tokenis-mcp", "serve", "--demo"]
```

**Any other MCP client** (Gemini CLI, Cursor, VS Code, Windsurf, Zed, ...): add
a stdio server. Remote settings for each app, and ChatGPT's OAuth sign-in, are
in [clients.md](clients.md).

```json
{
  "mcpServers": {
    "tokenis": {
      "command": "uvx",
      "args": ["--index", "https://tokenismcp.github.io/tokenis-mcp/simple/",
               "tokenis-mcp", "serve", "--demo"]
    }
  }
}
```

**Docker.**

```bash
docker run -i --rm ghcr.io/tokenismcp/tokenis-mcp
```

Now ask, for example:

> Which industry grew fastest from 2024 to 2025? And what is retail's total
> 2025 revenue?

The model calls `describe_dataset`, compares the two revenue columns per
industry, and reports that retail can't be answered. Retail has only two
companies, fewer than the minimum group size, and the gateway refuses to
aggregate them. That refusal is Tokenis doing its job.

The demo dataset is eight fictional companies; `describe_dataset` says so in
its `notice` field.

## 2. Use your own data

### The fast way: `tokenis-mcp init`

Point it at your CSV (or JSON-lines) file. It reads the data, guesses how
each column should be protected, writes `tokenis.toml` and a `.env` with
freshly generated keys (mode 600, added to `.gitignore` in a repository),
loads the result with every row to prove it works, and tells you what it
decided and why:

```bash
tokenis-mcp init customers.csv
#   id      id             unique identifier (never shown to the model)
#   token   customer_name  looks personal: shown only as a pseudonym
#   open    industry       5 distinct values: a category
#   sealed  revenue_2025   numbers: encrypted, only aggregates leave
#   vector  embedding      a vector per record, for similarity_search (never shown)
set -a; source .env; set +a
tokenis-mcp tools --config tokenis.toml     # exactly what a model will see
tokenis-mcp serve --config tokenis.toml
```

The guesses err toward protecting more: text that looks personal (e-mail,
phone, name, address, ...) or has many distinct values becomes a pseudonym,
numbers are sealed, and a column with empty cells is left out (the gateway
needs every cell filled) and listed at the end of the file. A year, a code or a
grade stays `open`. Review the result: write a real `description` for each
column, add units, and decide whether each `open` column may really be shown
verbatim. `--dry-run` only prints the decisions, `--k` sets the minimum
group size (default 5), `--force` overwrites an existing config and keys
(new keys make existing tokens and audit entries unverifiable). Headers that
are not valid column names (`Annual Revenue (KRW)`) are mapped by a
`[data.rename]` table, so your file stays as it is.

### Or describe your data by hand

Start from the annotated example and edit it:

```bash
curl -O https://raw.githubusercontent.com/tokenismcp/tokenis-mcp/main/examples/tokenis.toml
```

The key decision is each column's protection class:

| Class | What leaves the gateway | Typical columns |
|---|---|---|
| `open` | The value itself; usable in filters and groupings | industry, region, size band, year |
| `token` | A keyed pseudonym (same value, same token) | customer name, account manager |
| `sealed` | Only aggregates over at least *k* records | revenue, salary, balance, headcount |

Everything else in the file (admission budget, minimum group size, reveal
purposes, state directory, transport) has sensible defaults and is
documented in [configuration.md](configuration.md).

Data is a CSV file with a header row, or JSON lines. Columns in the file
that the config doesn't list are ignored.

### Create the two secrets (skip this if you used `init`)

```bash
export TOKENIS_TOKENIZER_KEY=$(uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp keygen-secret)
export TOKENIS_AUDIT_KEY=$(uvx --index https://tokenismcp.github.io/tokenis-mcp/simple/ tokenis-mcp keygen-secret)
```

Store them in your secret manager. Keep the tokenizer key stable, because
changing it changes every token. Keep the audit key away from anyone who
can edit the audit trail.

### Check, then serve

```bash
tokenis-mcp check --config tokenis.toml     # validates every row and setting; changes nothing
tokenis-mcp serve --config tokenis.toml     # stdio, for a local client
```

In the plugin or the Desktop bundle, set the config file and the two keys in
the extension's settings instead.

### Look at it with the MCP Inspector

To see the tools, call them by hand and read the raw answers (and refusals)
before connecting an AI app, use the official
[MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npx @modelcontextprotocol/inspector tokenis-mcp serve --config tokenis.toml
```

`tokenis-mcp ask --demo "question"` runs one question through a model and
prints every tool call to stderr; see [llm-integration.md](llm-integration.md).

## 3. Where to go next

- [tools.md](tools.md): what each tool answers, and why some questions are
  refused.
- [clients.md](clients.md): connect Claude, ChatGPT, Codex, Gemini CLI,
  Cursor, VS Code, Windsurf and the OpenAI and Gemini APIs.
- [ask.md](ask.md): a question screen for everyone, with single sign-on.
- [llm-integration.md](llm-integration.md): call the tools from the
  Anthropic, OpenAI or Gemini APIs, or local models, without an MCP client.
- [deployment.md](deployment.md): run it as a shared, authenticated HTTP
  service.
- [troubleshooting.md](troubleshooting.md): common errors and fixes.
- [SECURITY.md](../SECURITY.md): the threat model and its limits.
