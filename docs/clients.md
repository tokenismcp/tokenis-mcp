# Connect any AI app

Tokenis is an MCP server. Any AI app that is an MCP client can use it, and
the gateway treats them all the same: the caller is identified by the
credential (an API key or your identity provider's token), never by anything
the model says, and every call passes the same admission control and lands in
the same signed audit trail. Which model sits behind the app does not change
what it can learn: aggregates over at least k records, pseudonyms, and
refusals that do not say why.

There are three ways in:

1. **Remote MCP over HTTP** (teams): run `tokenis-mcp serve --transport http`
   once, give each person an API key (or sign people in through your identity
   provider) and let their AI app connect to `https://<gateway>/mcp`.
2. **Local MCP over stdio** (one person): the app launches `tokenis-mcp serve`
   itself.
3. **No MCP at all**: [Tokenis Ask](ask.md) (a browser chat screen) or the
   Python toolkit `tokenis.llm` for your own code.

The console's **Connect AI apps** page produces the settings below for your
gateway, with its address filled in.

## What has been tested

The gateway is tested with real MCP clients (the MCP Python SDK, over stdio
and HTTP) in CI, and the install paths are launched the way their hosts
launch them (`packaging/check_packaging.py`). The OAuth discovery that
OAuth-only apps need is tested too (`tests/test_oauth_discovery.py`). The
settings for each app below follow that vendor's documentation. We have not
run every app against a gateway ourselves, so if one does not connect, check
the app's own version and its MCP documentation, and tell us.

| App | Connects through | Signs in with | Notes |
|---|---|---|---|
| Claude Code | HTTP or stdio | API key | Plugin available (server + analysis skill) |
| Claude Desktop | stdio | none (local) | `tokenis.mcpb` bundle |
| ChatGPT (developer-mode custom connector) | HTTP | **OAuth** | No API-key option: see below |
| Codex (CLI and app) | HTTP or stdio | API key from an environment variable | `~/.codex/config.toml` |
| Gemini CLI | HTTP or stdio | API key header | `gemini mcp add` |
| Cursor | HTTP or stdio | API key header | `mcp.json` |
| VS Code | HTTP or stdio | API key header | `.vscode/mcp.json` |
| Windsurf | HTTP or stdio | API key header | `mcp_config.json` |
| OpenAI API (Responses API) | `mcp` tool or function tools | API key as `authorization` | OpenAI's servers call your gateway: it must be reachable over https |
| Gemini API, Ollama, vLLM, SARA, other OpenAI-compatible | `tokenis.llm`, `tokenis-mcp ask`, Ask | provider key | Function calling required (SARA adds it for models without) |
| Anthropic API | `tokenis.llm`, or the Messages API's MCP connector | API key | |

## Settings, app by app

Replace `https://tokenis.example.com/mcp` with your gateway and `KEY` with the
person's API key (`tokenis-mcp keys create alice@example.com`). Never put a
key in a shared file that is committed.

**Claude Code**

```bash
claude mcp add --transport http tokenis https://tokenis.example.com/mcp \
  --header "Authorization: Bearer KEY"
```

**Codex** (`~/.codex/config.toml`, shared by the CLI and the app)

```toml
[mcp_servers.tokenis]
url = "https://tokenis.example.com/mcp"
bearer_token_env_var = "TOKENIS_API_KEY"
```

```bash
export TOKENIS_API_KEY=KEY      # before starting Codex
```

**Gemini CLI**

```bash
gemini mcp add --transport http --header "Authorization: Bearer KEY" \
  tokenis https://tokenis.example.com/mcp
```

**Cursor** (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{ "mcpServers": { "tokenis": {
    "url": "https://tokenis.example.com/mcp",
    "headers": { "Authorization": "Bearer KEY" } } } }
```

**VS Code** (`.vscode/mcp.json`)

```json
{ "servers": { "tokenis": {
    "type": "http", "url": "https://tokenis.example.com/mcp",
    "headers": { "Authorization": "Bearer KEY" } } } }
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`; press Refresh in Manage MCPs)

```json
{ "mcpServers": { "tokenis": {
    "serverUrl": "https://tokenis.example.com/mcp",
    "headers": { "Authorization": "Bearer KEY" } } } }
```

**Any other MCP client** over stdio:

```json
{ "mcpServers": { "tokenis": {
    "command": "uvx",
    "args": ["--index", "https://tokenismcp.github.io/tokenis-mcp/simple/",
             "tokenis-mcp", "serve", "--demo"] } } }
```

### ChatGPT: OAuth, not an API key

ChatGPT's custom connectors (developer mode) sign in with OAuth or not at all;
there is no field for an API key. So a gateway used from ChatGPT must accept
your identity provider's tokens instead of Tokenis API keys:

```toml
[server]
transport = "http"
public_url = "https://tokenis.example.com"

[auth]
mode = "jwt"

[auth.jwt]
issuer = "https://login.example.com/"
audience = "https://tokenis.example.com/mcp"
jwks_url = "https://login.example.com/.well-known/jwks.json"
algorithms = ["RS256"]
principal_claim = "email"
```

The gateway then answers an unauthenticated call with `401` and a
`WWW-Authenticate` header that points at its protected-resource metadata
(`/.well-known/oauth-protected-resource/mcp`), which names your identity
provider as the authorization server. ChatGPT finds the sign-in page from
there. The identity provider has to support dynamic client registration (or
you pre-register ChatGPT's redirect address with it); Auth0, Keycloak and
others do. In ChatGPT, add a custom MCP connector with the gateway address and
choose OAuth. Every person who signs in is charged their own budget under the
identity the provider returns.

We test the discovery step, not ChatGPT itself. ChatGPT's connector menus
change; follow OpenAI's current documentation for where to add one, and for
which plans may use developer mode.

### OpenAI API (Responses API)

Two ways. OpenAI's servers can call the gateway themselves with the `mcp` tool
(the gateway must be reachable from the internet over https):

```python
import os
from openai import OpenAI

client = OpenAI()
response = client.responses.create(
    model="MODEL",   # any model that supports tools
    tools=[{"type": "mcp", "server_label": "tokenis",
            "server_url": "https://tokenis.example.com/mcp",
            "authorization": os.environ["TOKENIS_API_KEY"],
            "require_approval": "never"}],   # "always" lets you review each call
    input="Which industry had the largest 2025 revenue?",
)
print(response.output_text)
```

Or keep the gateway private and run the tool loop in your own process, with
function tools:

```python
from tokenis.llm import TokenisToolkit

toolkit = TokenisToolkit(service, principal=current_user_id)   # your authenticated user
items = [{"role": "user", "content": question}]
while True:
    response = client.responses.create(model="MODEL", instructions=toolkit.system_prompt,
                                       tools=toolkit.responses_tools(), input=items)
    items += response.output
    outputs = toolkit.responses_tool_outputs(response.output)
    if not outputs:
        break
    items += outputs
print(response.output_text)
```

`tokenis-mcp tools --format responses` prints the tool definitions.

### Gemini, Ollama and other OpenAI-compatible models

Google's Gemini API, Ollama, vLLM, LiteLLM, Azure OpenAI and SARA speak the
OpenAI Chat Completions protocol, so the same code works for all of them:

```bash
export GEMINI_API_KEY=...
tokenis-mcp ask --demo --provider gemini --model MODEL "Which region is largest?"
tokenis-mcp ask --demo --provider ollama --model llama3.1 "Which region is largest?"
tokenis-mcp ask --demo --provider openai --base-url http://vllm:8000/v1 --model MODEL "..."
```

In Python, `ask_openai(toolkit, question, model=..., base_url=..., api_key=...)`,
with the addresses in `tokenis.llm.PROVIDER_PRESETS`. For the browser chat
screen use `[ask] provider = "gemini" | "ollama" | "openai" | "anthropic"`
([ask.md](ask.md)).

## Choosing a model

The gateway's guarantees do not depend on the model; the quality of the
answers does. Pick one with reliable tool calling. Large hosted models are the
most dependable. Small local models can work but are slow on a laptop and make
more mistakes (wrong filters, invented figures); Ask withholds an answer that
states figures no lookup returned, and SARA remembers tool calls that worked.

## Where the data goes

Whatever the gateway releases (aggregates, pseudonyms, the question) reaches
the model provider you connect. With a hosted model that is that provider's
data processing, under your agreement with them; with a model on your own
servers (vLLM, Ollama, SARA) nothing leaves your network. Individual records
never leave the gateway in either case.
