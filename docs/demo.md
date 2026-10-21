# Try Tokenis without an LLM or API key

Run the existing quickstart against eight fictional companies. It shows an
allowed aggregate, a refused small-group query, and the audit trail without
sending a prompt to a model provider. You need Git and
[uv](https://docs.astral.sh/uv/getting-started/installation/); the first run
needs internet access to download the package and its dependencies.

## Run the tour

```bash
git clone https://github.com/tokenismcp/tokenis-mcp.git
cd tokenis-mcp
uv run --no-project --index https://tokenismcp.github.io/tokenis-mcp/simple/ --with tokenis-mcp==0.1.0 python examples/quickstart.py
```

If you already have the repository, run the last command from its root.
It uses the published v0.1.0 package in uv's environment, not an editable
build of the source tree. No Rust build or model API key is required.

The following excerpts were verified with v0.1.0 on macOS arm64, Python
3.10.20 and uv 0.11.19. The script was from repository commit
`408f863cbd8e717b832d426147c3db40a0f74596`.

## What to look for

The first response labels the data as fictional and reports eight records
with a minimum group size of three. The finance query returns:

```json
{
  "function": "sum",
  "column": "revenue_2025",
  "filters": {"industry": "finance"},
  "value": 4250000,
  "matched_records": 3,
  "unit": "KRW"
}
```

The retail query returns a generic denial beginning with:

```text
DENIED: Denied by the disclosure policy.
```

Retail has two records in this fixture. That explanation is available to us
as demo operators; the caller-facing response lists possible reasons and
does not identify the rule that fired.

The remaining calls show grouped results (with retail suppressed), a
period comparison, an existence check and an authorised ratio disclosure.
At the end, the tour prints:

```text
Disclosure trace: 8 entries, chain valid = True
```

The trace printed by this in-process tour is operator-side information,
including rule details. It is not the response sent to an LLM. Chain
verification here checks the demo trace, not production persistence,
external anchoring or independent security assurance.

## What this demonstrates — and its limits

This is a reproducible example of permitted and refused calls through the
in-process toolkit. It does not test an MCP transport or a hosted model,
and it does not prove resistance to every inference or differencing attack.
The gateway is trusted: plaintext and private keys can exist in its process.
Query-history checks use a relaxation with known limits, and dataset
refreshes introduce additional risks. There has been no independent audit.
See the [threat model](threat-model.md#8-residual-risks).

Next, [connect an AI app](clients.md) or read the
[getting-started guide](getting-started.md) before using your own data.
If the tour fails, report your OS, Python/uv versions, command and redacted
error in a [bug report](https://github.com/tokenismcp/tokenis-mcp/issues/new?template=bug_report.md).
