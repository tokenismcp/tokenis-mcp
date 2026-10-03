# Using the tools from an LLM API

For people who should simply ask questions in a browser, without an MCP client or code, use [Tokenis Ask](ask.md).

You do not need an MCP client to use Tokenis. The `tokenis.llm` module turns
the gateway's tools into tool definitions for the Anthropic Messages API or
any OpenAI-compatible Chat Completions API, and runs the calls the model
makes. Use it when the gateway lives inside your own application, or when
you want a local model to answer questions.

This path is not a separate implementation. `TokenisToolkit` wraps the same
server object that `tokenis-mcp serve` exposes, so tool schemas, argument
validation, admission control, the generic denial message and latency
padding are the same as over MCP.

## Install

From a checkout of the repository:

```bash
pip install -e ".[llm]"
```

Or from the Tokenis package index:

```bash
uv pip install --index https://tokenismcp.github.io/tokenis-mcp/simple/ "tokenis-mcp[llm]"
```

The `llm` extra adds the `anthropic` and `openai` client libraries. API keys
come from the environment only: `ANTHROPIC_API_KEY` for Anthropic,
`OPENAI_API_KEY` (and optionally `OPENAI_BASE_URL`) for OpenAI-compatible
endpoints. Never write a key into code or a config file.

## A gateway to talk to

The toolkit needs a `TokenisGatewayService`. Use the demo data, or build one
from your config file exactly as `serve` does:

```python
from tokenis.gateway.demo import demo_service
service = demo_service()

# or, from a config (reads the same environment variables as `serve`):
from tokenis.config import build_service, load_config
service = build_service(load_config("tokenis.toml"))
```

With a `[state]` section, calls made through the toolkit are recorded in the
admission history and the audit trail like any other. The file backend is
for one process; if a script and a running server must share a history, use
the postgres backend (see [configuration.md](configuration.md)).

## Anthropic

`ask_anthropic` runs the whole tool loop and returns the final text:

```python
import anthropic
from tokenis.llm import TokenisToolkit, ask_anthropic

toolkit = TokenisToolkit(service, principal=user_id)    # your authenticated user
client = anthropic.Anthropic()                           # reads ANTHROPIC_API_KEY
print(ask_anthropic(toolkit, "Which industry grew fastest from 2024 to 2025?",
                    client=client))
```

Its keyword arguments are `client` (default `anthropic.Anthropic()`),
`model` (default `claude-opus-5-5`), `max_tokens` (default 4096),
`max_turns` (default 12) and `on_tool`, a callback
`on_tool(name, arguments, outcome)` called for every tool call. If the model
has not produced a final answer after `max_turns` turns, it raises
`RuntimeError`.

To plug the tools into a loop you already have, use the pieces directly:

```python
messages = [{"role": "user", "content": question}]
while True:
    reply = client.messages.create(
        model=model, max_tokens=2048, system=toolkit.system_prompt,
        tools=toolkit.anthropic_tools(), messages=messages,
    )
    messages.append({"role": "assistant", "content": reply.content})
    if reply.stop_reason != "tool_use":
        break
    messages.append({"role": "user", "content": toolkit.anthropic_tool_results(reply.content)})
```

`anthropic_tool_results` answers every `tool_use` block in the reply, runs
them concurrently, and marks denials and invalid calls with
`"is_error": true`.

## OpenAI and OpenAI-compatible servers

`ask_openai` does the same for any Chat Completions endpoint with tool
calling. `model` is required; name the model you choose.

```python
from tokenis.llm import TokenisToolkit, ask_openai

toolkit = TokenisToolkit(service, principal=user_id)
print(ask_openai(toolkit, "Which region is largest?", model=model))
```

The default client is `openai.OpenAI()`, which reads `OPENAI_API_KEY` and
`OPENAI_BASE_URL`. To reach another provider or a local server, either set
`OPENAI_BASE_URL` or pass your own client:

```python
import os
import openai

client = openai.OpenAI(base_url="http://localhost:11434/v1",           # e.g. Ollama
                       api_key=os.environ.get("OPENAI_API_KEY", "unused"))
print(ask_openai(toolkit, question, client=client, model=model))
```

This works with vLLM, Ollama, LM Studio, LiteLLM and Azure OpenAI, among
others. Local servers usually ignore the key, but the client still needs a
value. With a local model the question, the tool results and the answer
never leave your machine. Tool-calling quality varies a lot between models:
Tokenis enforces its policy either way, but a weaker model may need more
turns or give up.

For your own loop, `toolkit.openai_tools()` gives the `tools=` list and
`toolkit.openai_tool_messages(message.tool_calls or [])` gives the
`role: tool` messages to append. Arguments that are not a JSON object come
back as `invalid arguments: not a JSON object`.

## Lower-level calls

| Member | What it does |
|---|---|
| `toolkit.definitions()` | `ToolDefinition(name, description, input_schema)` for each tool, with `$ref`s inlined (some APIs reject them) |
| `toolkit.call(name, arguments)` | Runs one tool; returns `ToolOutcome(content, is_error)` |
| `outcome.json()` | The parsed result, or `None` for an error |
| `toolkit.system_prompt` | Guidance for the model on using the tools economically. Not a security control |
| `adefinitions`, `acall`, `aanthropic_tool_results`, `aopenai_tool_messages` | Async versions, for code already running an event loop |

The synchronous methods also work when called from inside a running event
loop (they run in a helper thread), but in async code the `a...` versions
are the better choice.

## From the command line

Print the tool definitions a model would see:

```bash
tokenis-mcp tools --demo --format anthropic      # or openai, or mcp
tokenis-mcp tools --config tokenis.toml --format openai
```

Ask a question end to end:

```bash
export ANTHROPIC_API_KEY=...                       # from your secret manager
tokenis-mcp ask --demo "Which industry grew fastest from 2024 to 2025?"
```

`ask` takes `--provider anthropic|openai` (default: `anthropic` when
`ANTHROPIC_API_KEY` is set, otherwise `openai`), `--model` (required for
OpenAI-compatible providers; the Anthropic default is `claude-opus-5-5`) and
`--principal` (default `local:<os-user>`). Each tool call is printed to
stderr as `ok` or `DENIED`; the answer goes to stdout. For a local model:

```bash
export OPENAI_BASE_URL=http://localhost:11434/v1 OPENAI_API_KEY=unused
tokenis-mcp ask --demo --provider openai --model "$MODEL" "Which region is largest?"
```

## Examples

Two runnable scripts use the demo data by default and take `--config` for
your own:

- [`examples/anthropic_agent.py`](../examples/anthropic_agent.py): Claude
  with `ask_anthropic`; `--model` (default `claude-opus-5-5`) and
  `--principal`. It prints each tool call and, at the end, the number of
  audit-trail entries and whether the hash chain verifies.
- [`examples/openai_compatible_agent.py`](../examples/openai_compatible_agent.py):
  any OpenAI-compatible model with `ask_openai`; `--model` is required.

```bash
python examples/anthropic_agent.py "Which industry grew fastest from 2024 to 2025?"
python examples/openai_compatible_agent.py --model "$MODEL" "Compare total 2025 revenue across industries."
```

## Principal and taint

Over HTTP the principal comes from a verified API key or JWT. In this mode
there is no authentication layer: **the toolkit trusts the `principal` you
pass**. It must be the end user your application has already authenticated,
never a value the model or the user typed. It is the subject of the query
budget and is named in every audit entry. It must be 1-128 characters from
`[A-Za-z0-9._@:+-]`. Create one toolkit per user; they can share one
service, and budgets stay per principal. (The shared differencing history
covers everyone, as described in [tools.md](tools.md).)

Taint is also yours to set. Pass `taint=1` when the conversation holds
untrusted content such as retrieved documents, web pages or e-mail. You can
also set `toolkit.taint = 1` mid-conversation; it applies from the next
call. While tainted, D4 narrows the tools to counts and lookups and applies
the smaller tainted budget and call cap (see [tools.md](tools.md)). The
`[server] taint_header` and `default_taint` settings apply only to
`tokenis-mcp serve`; `tokenis-mcp ask` always runs untainted.

To use a remote gateway from the Anthropic API instead, run it over HTTP
with authentication ([deployment.md](deployment.md)) and connect it as a
remote MCP server; the principal then comes from the key.
