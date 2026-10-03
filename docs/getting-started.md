# Getting started

This guide takes you from nothing to Claude answering questions over a
confidential dataset, first on built-in fictional data, then on your own.

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

**Any other MCP client** (Cursor, Windsurf, Zed, ...): add a stdio server.

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

Claude calls `describe_dataset`, compares the two revenue columns per
industry, and reports that retail can't be answered. Retail has only two
companies, fewer than the minimum group size, and the gateway refuses to
aggregate them. That refusal is Tokenis doing its job.

The demo dataset is eight fictional companies; `describe_dataset` says so in
its `notice` field.

## 2. Use your own data

### Describe your data

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

### Create the two secrets

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

## 3. Where to go next

- [tools.md](tools.md): what each tool answers, and why some questions are
  refused.
- [ask.md](ask.md): a question screen for everyone, with single sign-on.
- [llm-integration.md](llm-integration.md): call the tools from the
  Anthropic API, OpenAI-compatible APIs or local models, without an MCP client.
- [deployment.md](deployment.md): run it as a shared, authenticated HTTP
  service.
- [troubleshooting.md](troubleshooting.md): common errors and fixes.
- [SECURITY.md](../SECURITY.md): the threat model and its limits.
