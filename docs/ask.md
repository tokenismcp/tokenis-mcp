# Tokenis Ask

Ask is a chat screen at `/ask` for people who will never configure an MCP
client. They sign in with the organisation's single sign-on and type a
question in plain language ("업종별 2025년 매출 합계를 보여줘", "Which region
grew most?"). An LLM answers it by calling the gateway's tools **as that
person**: their identity is the admission-control subject, so Ask spends the
same per-person budget as their API keys, every call is refused or answered
by the same rules, and every call is in the audit trail and the console.

The screen is in English by default; the EN / 한 switch at the top changes
the language at any time. It suggests questions to start with, lists what the data
can answer, shows each lookup the model made in plain words ("업종별 합계 ·
2025년 매출 — 완료"), explains refusals without naming the rule that fired,
and shows how much of the day's allowance is left.

## Turn it on

```toml
[ops.oidc]                       # people sign in with single sign-on
issuer = "https://login.example.com"
client_id = "tokenis"
admins = ["it-admin@example.com"]
users = ["@example.com"]          # Ask only: everyone with a verified address here

[ask]
provider = "anthropic"            # or "openai" for any OpenAI-compatible API
model = "claude-opus-5-5"
api_key_env = "ANTHROPIC_API_KEY"
suggestions = ["업종별 2025년 매출 합계를 보여줘", "지역별 평균 매출은?"]

[ask.labels]                      # display names, used on screen and by the model
industry = "업종"
revenue_2025 = "2025년 매출"
```

`[ask]` needs the HTTP transport and a sign-in method. Open
`https://<gateway>/ask`; `/` redirects there. The console's sidebar links to
it, and its **Connect AI apps** page links to it for people without an AI app.

Roles (`[ops.oidc]`): `users` may only ask; `viewers`, `auditors` and
`admins` may also open the console (each role has the rights of the ones
before it). Members are identities, `group:NAME` (from `roles_claim`) or
`@domain` (any **verified** e-mail address in that domain).

### Which model

| Setup | `[ask]` | Notes |
|---|---|---|
| Claude (Anthropic API) | `provider = "anthropic"`, `model = "claude-opus-5-5"`, `api_key_env = "ANTHROPIC_API_KEY"` | Best answers. Aggregates go to Anthropic's API under your agreement with Anthropic. |
| OpenAI-compatible service (OpenAI, Azure OpenAI, LiteLLM) | `provider = "openai"`, `base_url`, `model`, `api_key_env` | |
| Your own GPU server (vLLM, TGI) | `provider = "openai"`, `base_url = "http://vllm.models:8000/v1"`, `model` | Nothing leaves your network. 14B+ instruction models recommended. |
| SARA on-premises agent | `provider = "openai"`, `base_url = "http://127.0.0.1:8765/v1"`, `model = "sara"`, `api_key_env` | Function calling for any local model, plus a memory of tool calls that worked (below). |
| Ollama directly | `provider = "openai"`, `base_url = "http://127.0.0.1:11434/v1"`, `model`, `reasoning_effort = "none"` | Fine for a trial on a laptop; small models are slow and less reliable. |

`tool_protocol = "auto"` (the default) uses the API's function calling and
falls back to a JSON protocol when the server refuses tools, so models
without function calling work too. `reasoning_effort = "none"` turns off the
long hidden reasoning of local reasoning models (Qwen3: minutes → seconds).

An API key is never sent over plain `http://` to another host: use `https`,
or a model server on the same machine.

### SARA

SARA (J1729 Labs' on-premises agent runtime) serves `POST /v1/chat/completions`
with `tools` for any model behind it (Ollama, llama.cpp, vLLM):

- native function calling when the model has it; otherwise SARA describes
  the tools in the prompt, checks each call against the tool's schema
  (one repair round), and returns ordinary `tool_calls`;
- a **tool memory**: calls that were followed by a useful result are
  remembered (question, tool and arguments only, never results) and the
  closest ones are shown to the model for similar questions. Teach it the
  questions your screen suggests:

  ```bash
  curl -X POST http://127.0.0.1:8765/v1/tool-memory -H "Authorization: Bearer $SARA_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"question": "업종별 2025년 매출 합계를 보여줘", "tool": "group_by",
         "arguments": {"key": "industry", "function": "sum", "column": "revenue_2025"}}'
  ```

  `GET /v1/tool-memory` lists it, `DELETE /v1/tool-memory` clears it.

Run SARA with `SARA_LLM_BACKEND=ollama SARA_LLM_MODEL=<model>
SARA_API_KEY=<secret>`; it listens on 127.0.0.1 unless `SARA_BIND` says
otherwise. With Ollama it uses the native chat API with SARA's context
window (`SARA_LLM_CTX`, default 8192), so long tool conversations are not
cut at Ollama's 4K default.

## What the model sees, and what it cannot do

- The model gets the dataset description (`describe_dataset`: columns, the
  values you can filter on, k, the remaining budget) and the results of the
  calls it makes: aggregates over at least k records, pseudonyms, suppressed
  groups. Nothing else of the data.
- It acts with the asker's identity and budget. A prompt-injected or
  confused model can at worst ask questions the asker could have asked
  themselves; admission control (D1-D5) applies to every call.
- **Answers are checked for made-up figures.** If the model states numbers
  but no lookup succeeded, it gets one more turn to fetch them; if it still
  has none, the answer is replaced with a plain "no answer backed by the
  data" message. A Korean question answered in another language gets one
  turn to answer again in Korean.
- The question and the conversation's earlier answers (text only, at most
  12 turns, 16,000 characters) are sent with each question; nothing is
  stored on the server. The browser keeps the conversation for the tab
  (sessionStorage) until "New chat" or sign-out.

## Limits and operations

- `questions_per_hour` (default 60) per person, and one question at a time,
  per replica.
- `max_turns` (default 8) model turns per question; `timeout_seconds` per
  model call.
- Ask's tool calls are counted in `/metrics` and the call log like any
  other; the console shows them under the person's identity.
- The page is served under the same CSP as the console (no external
  requests); chat requests need the session cookie, a JSON body and the
  `X-Tokenis-Console` header, and must come from the gateway's own origin.

All keys: [configuration.md](configuration.md#ask).
