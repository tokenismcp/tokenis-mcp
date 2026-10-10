# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tokenis Ask: questions in plain language, answered by an LLM that uses
the gateway's tools on the asker's behalf -- for people who will never
configure an MCP client.

The asker signs in with the organisation's single sign-on (the same as the
admin console); their identity is the admission-control principal, so Ask
spends the same per-person budget as their MCP clients and every tool call
lands in the call log and the disclosure trace. The model only ever sees
what the tools release: aggregates over groups of at least k records.

Models (``[ask] provider``):

- ``anthropic`` -- the Claude Messages API (``api_key_env``, normally
  ``ANTHROPIC_API_KEY``).
- ``openai`` -- any OpenAI-compatible Chat Completions endpoint: OpenAI,
  Azure OpenAI, vLLM, LiteLLM, Ollama (``http://127.0.0.1:11434/v1``) or
  SARA (``http://127.0.0.1:8765/v1``).

Tool use (``tool_protocol``): ``native`` uses the API's function calling;
``json`` describes the tools in the prompt and reads one JSON object per
turn, so models without function calling (small local models) work too;
``auto`` tries native and falls back to json when the server refuses tools.

Results are sent to the model provider you configure. With a hosted
provider that is the provider's data processing; with a local model
(Ollama, vLLM, SARA) nothing leaves your network.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Deque, Dict, List, Mapping, Optional, Tuple

import anyio

from tokenis.llm import TokenisToolkit, ToolOutcome

log = logging.getLogger("tokenis.ask")

PROVIDERS = ("anthropic", "openai")
PROTOCOLS = ("auto", "native", "json")
MAX_QUESTION_CHARS = 2000
MAX_HISTORY_ITEMS = 12
MAX_HISTORY_CHARS = 16000
MAX_RESULT_CHARS = 6000

_THINK = re.compile(r"<think>.*?(</think>|$)", re.DOTALL)
_DEFAULT_BASE = {"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com/v1"}


@dataclass(frozen=True)
class AskSettings:
    """``[ask]`` in the configuration."""

    provider: str = "openai"
    model: str = ""
    base_url: str = ""
    #: Environment variable holding the provider's API key (none for a
    #: local model server).
    api_key_env: Optional[str] = None
    tool_protocol: str = "auto"
    max_turns: int = 8
    timeout_seconds: float = 120.0
    #: Per person, per replica.
    questions_per_hour: int = 60
    temperature: float = 0.2
    max_tokens: int = 1500
    #: Example questions shown on the empty screen (any language).
    suggestions: Tuple[str, ...] = ()
    #: Display names for columns, e.g. {"industry": "업종"}: used in the
    #: suggestions, the step list and by the model in its answers.
    labels: Mapping[str, str] = field(default_factory=dict)
    #: The screen's language until the person picks one: "en" or "ko".
    language: str = "en"
    #: Shown under the answer box, e.g. "SARA · on-premises".
    display_name: str = ""
    #: OpenAI-compatible only: "none" turns off the long hidden reasoning of
    #: local reasoning models (Qwen3 on Ollama: minutes -> seconds).
    reasoning_effort: str = ""

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise ValueError(f"[ask] provider must be one of {', '.join(PROVIDERS)}")
        if self.tool_protocol not in PROTOCOLS:
            raise ValueError(f"[ask] tool_protocol must be one of {', '.join(PROTOCOLS)}")
        if not self.model:
            raise ValueError("[ask] model is required")
        if not 1 <= self.max_turns <= 20:
            raise ValueError("[ask] max_turns must be 1 to 20")
        if not 5 <= self.timeout_seconds <= 600:
            raise ValueError("[ask] timeout_seconds must be 5 to 600")
        if not 1 <= self.questions_per_hour <= 10000:
            raise ValueError("[ask] questions_per_hour must be 1 to 10000")
        if self.reasoning_effort not in ("", "none", "low", "medium", "high"):
            raise ValueError("[ask] reasoning_effort must be none, low, medium or high")
        if self.language not in ("en", "ko"):
            raise ValueError("[ask] language must be en or ko")
        if len(self.suggestions) > 12 or any(not isinstance(s, str) or not 0 < len(s) <= 200
                                             for s in self.suggestions):
            raise ValueError("[ask] suggestions: at most 12 strings of 1-200 characters")
        if any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 60 for k, v in self.labels.items()):
            raise ValueError("[ask] labels: column name = display name (at most 60 characters)")
        url = self.endpoint
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("[ask] base_url must be an http(s) URL")

    @property
    def endpoint(self) -> str:
        return (self.base_url or _DEFAULT_BASE[self.provider]).rstrip("/")


class AskError(Exception):
    """Shown to the asker as-is: no provider internals."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _ToolsRefused(Exception):
    """The model server rejected function calling (auto -> json)."""


def _loopback(url: str) -> bool:
    return urllib.parse.urlsplit(url).hostname in ("localhost", "127.0.0.1", "::1")


def outcome_status(outcome: ToolOutcome) -> str:
    """ok | denied | invalid | unavailable, from a tool outcome."""
    if not outcome.is_error:
        return "ok"
    text = outcome.content
    if text.startswith("Denied by the disclosure policy"):
        return "denied"
    if text.startswith(("invalid arguments", "Unknown tool")):
        return "invalid"
    if "temporarily unavailable" in text:
        return "unavailable"
    return "invalid"


def strip_thinking(text: str) -> str:
    """Drop reasoning blocks some local models (Qwen3, DeepSeek-R1) emit."""
    return _THINK.sub("", text or "").strip()


def parse_json_reply(text: str) -> Optional[Dict[str, Any]]:
    """The first JSON object in a model reply (code fences and chatter
    around it are tolerated), or None."""
    text = strip_thinking(text)
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        value = json.loads(text[start:i + 1])
                    except ValueError:
                        break
                    return value if isinstance(value, dict) else None
        start = text.find("{", start + 1)
    return None


class RateLimiter:
    """At most ``per_hour`` questions per person in any 60 minutes, and one
    at a time (per replica)."""

    def __init__(self, per_hour: int) -> None:
        self.per_hour = per_hour
        self._lock = threading.Lock()
        self._seen: Dict[str, Deque[float]] = {}
        self._running: set = set()

    def acquire(self, who: str) -> Optional[str]:
        """None if ``who`` may ask now (call :meth:`release` after), else why not."""
        now = time.time()
        with self._lock:
            if who in self._running:
                return "busy"
            seen = self._seen.setdefault(who, deque())
            while seen and seen[0] < now - 3600:
                seen.popleft()
            if len(seen) >= self.per_hour:
                return "rate"
            seen.append(now)
            self._running.add(who)
            if len(self._seen) > 10000:  # forget idle people
                for key in [k for k, v in self._seen.items() if not v or v[-1] < now - 3600][:5000]:
                    self._seen.pop(key, None)
            return None

    def release(self, who: str) -> None:
        with self._lock:
            self._running.discard(who)


class AskEngine:
    """Runs one question: model turns and tool calls, as a stream of events
    (dicts) for the browser."""

    def __init__(self, service: Any, settings: AskSettings, api_key: Optional[str] = None, *,
                 metrics: Any = None, call_log: Any = None, opener: Any = None) -> None:
        if api_key and settings.endpoint.startswith("http://") and not _loopback(settings.endpoint):
            raise ValueError("[ask] refusing to send an API key over plain http to another host: use https")
        self.service = service
        self.settings = settings
        self._api_key = api_key
        self._metrics = metrics
        self._call_log = call_log
        self._open = opener or urllib.request.urlopen
        self._toolkits: "OrderedDict[str, TokenisToolkit]" = OrderedDict()
        self._lock = threading.Lock()
        self._protocol = "native" if settings.tool_protocol == "auto" else settings.tool_protocol
        self.limiter = RateLimiter(settings.questions_per_hour)

    # -- tools -----------------------------------------------------------------

    def toolkit(self, principal: str) -> TokenisToolkit:
        with self._lock:
            kit = self._toolkits.get(principal)
            if kit is None:
                kit = TokenisToolkit(self.service, principal=principal, max_concurrency=4,
                                     metrics=self._metrics, call_log=self._call_log)
                self._toolkits[principal] = kit
                while len(self._toolkits) > 256:
                    self._toolkits.popitem(last=False)
            else:
                self._toolkits.move_to_end(principal)
            return kit

    def catalog(self) -> Dict[str, Any]:
        """What the screen shows about the data: plain names, no internals."""
        labels = self.settings.labels
        schema = self.service.schema
        cols = []
        for c in schema.columns:
            entry = {"name": c.name, "label": labels.get(c.name) or c.description or c.name,
                     "description": c.description, "unit": c.unit,
                     "kind": {"open": "group", "token": "pseudonym", "sealed": "measure"}[c.protection],
                     "band": c.result_mode == "band"}
            if c.protection == "open":
                entry["values"] = len(self.service.domain(c.name))
            cols.append(entry)
        return {"columns": cols, "k": self.service.k, "records": self.service.record_count,
                # Configured questions are shown as written; otherwise both
                # languages are generated and the screen picks one.
                "suggestions": list(self.settings.suggestions) or None,
                "auto_suggestions": {"en": self._auto_suggestions("en"), "ko": self._auto_suggestions("ko")},
                "purposes": [p.name for p in self.service.settings.purposes]}

    def _auto_suggestions(self, lang: str) -> List[str]:
        labels = self.settings.labels
        schema = self.service.schema

        def name(c: Any) -> str:
            return labels.get(c.name) or c.description or c.name

        groups = list(schema.open)
        measures = [c for c in schema.sealed if c.result_mode != "band"] or list(schema.sealed)
        out: List[str] = []
        if lang == "ko":
            if groups and measures:
                out.append(f"{name(groups[0])}별 {name(measures[-1])} 합계를 보여줘")
            if len(groups) > 1 and measures:
                out.append(f"{name(groups[1])}별 평균 {name(measures[0])}은?")
            if groups:
                out.append(f"{name(groups[0])}별로 몇 건씩 있어?")
            if len(measures) > 1:
                out.append(f"{name(measures[0])}과 {name(measures[1])}을 비교해줘")
        else:
            if groups and measures:
                out.append(f"Total {name(measures[-1])} by {name(groups[0])}")
            if len(groups) > 1 and measures:
                out.append(f"Average {name(measures[0])} by {name(groups[1])}")
            if groups:
                out.append(f"How many records per {name(groups[0])}?")
            if len(measures) > 1:
                out.append(f"Compare {name(measures[0])} with {name(measures[1])}")
        return out

    # -- prompts -----------------------------------------------------------------

    def _system(self, kit: TokenisToolkit, dataset: str, lang: str) -> str:
        labels = self.settings.labels
        names = "\n".join(f"- {k}: {v}" for k, v in labels.items()) or "- (use the column descriptions)"
        language = "Korean" if lang == "ko" else "English"
        return f"""{kit.system_prompt}

You are Tokenis Ask. The person asking is a business user, not an engineer.
- Reply in the language of the person's question (if unsure: {language}).
- Lead with the answer in one or two sentences. Then, only if it helps, a short list or a small Markdown table.
- Call columns by these display names, never by their internal ids, and give units:
{names}
- Use only numbers that tool results returned; never estimate, invent or fill in suppressed values.
- Keep units exactly as the dataset gives them (e.g. "KRW million" is 백만 원); do not convert unless asked.
- Mention how many records a figure covers when the result says so.
- Add filters only for conditions the person actually stated; to compare groups, prefer one group_by call.
- 32-character hexadecimal values are pseudonyms: never show or invent them; say "one customer" etc.
- Individual records (one named company or person) cannot be looked up: say so, and offer a group-level answer.
- If a call is refused, do not retry near-identical narrow queries. Explain in plain words that the question was \
too narrow (it could point to individual records) or that the person's query allowance is running low, and \
suggest a broader question they could ask instead.
- If the dataset cannot answer the question, say so and suggest something it can answer.
- Do not mention internal rule names (D1-D5), admission control, encryption schemes or tool names unless asked.
- describe_dataset has already been called; its result follows. Do not call it again.

describe_dataset result:
{dataset}

Remember: answer in the language of the person's question ({language} if unsure)."""

    def _json_protocol(self, defs: List[Any]) -> str:
        tools = "\n".join(f"- {d.name}({signature(d.input_schema)})\n  {d.description}"
                          for d in defs if d.name != "describe_dataset")
        return f"""

You can call tools. Reply with exactly ONE JSON object and nothing else:
{{"tool": "<tool name>", "arguments": {{...}}}}  -- to call a tool; its result comes back in the next message, or
{{"answer": "<your final answer for the person, in their language; Markdown allowed>"}}  -- when you are done.
Get every number from a tool result first. Arguments marked ? are optional; leave them out unless needed.
Tools:
{tools}"""

    # -- model calls ---------------------------------------------------------------

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        s = self.settings
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "tokenis-ask"}
        if s.provider == "anthropic":
            headers["anthropic-version"] = "2023-06-01"
            if self._api_key:
                headers["x-api-key"] = self._api_key
        elif self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if s.provider == "openai" and s.reasoning_effort:
            body = {**body, "reasoning_effort": s.reasoning_effort}
        req = urllib.request.Request(s.endpoint + path, data=json.dumps(body).encode(), headers=headers)  # noqa: S310
        try:
            with self._open(req, timeout=s.timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read(2000).decode("utf-8", "replace")
            finally:
                exc.close()
            if exc.code == 400 and "tool" in detail.lower() and body.get("tools"):
                raise _ToolsRefused(detail) from None
            log.warning("ask: model server answered HTTP %s: %s", exc.code, detail[:500])
            if exc.code in (401, 403):
                raise AskError("model_auth", "The AI model refused the gateway's credentials.") from None
            if exc.code == 429:
                raise AskError("model_busy", "The AI model is busy. Try again in a minute.") from None
            raise AskError("model_error", "The AI model could not answer.") from None
        except (TimeoutError, OSError) as exc:  # URLError is an OSError
            log.warning("ask: model server unreachable: %s", exc)
            timeout = isinstance(exc, TimeoutError) or "timed out" in str(exc)
            raise AskError("model_timeout" if timeout else "model_unreachable",
                           "The AI model took too long to answer." if timeout
                           else "The AI model could not be reached.") from None
        except ValueError:
            raise AskError("model_error", "The AI model sent an unreadable reply.") from None
        if not isinstance(data, dict):
            raise AskError("model_error", "The AI model sent an unreadable reply.")
        return data

    async def _call(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = await anyio.to_thread.run_sync(self._post, path, body, abandon_on_cancel=True)
        return result

    # -- the loop ------------------------------------------------------------------

    async def run(self, principal: str, question: str, history: List[Dict[str, str]],
                  lang: str = "ko") -> AsyncIterator[Dict[str, Any]]:
        """Events: ``status`` (phase), ``tool`` (running, then its outcome),
        ``answer``, ``error``, and finally ``done`` with the budget left."""
        kit = self.toolkit(principal)
        yield {"type": "status", "phase": "reading"}
        described = await kit.acall("describe_dataset", {})
        if described.is_error:
            yield {"type": "error", "code": "gateway", "message": "The gateway is temporarily unavailable."}
            return
        defs = await kit.adefinitions()
        try:  # compact: small local models have small context windows
            dataset = json.dumps(json.loads(described.content), ensure_ascii=False, separators=(",", ":"))
        except ValueError:
            dataset = described.content
        system = self._system(kit, dataset, lang)
        run = _Run(kit, question, question + "\n" + "\n".join(m["content"] for m in history))
        try:
            if self.settings.provider == "anthropic":
                stream = self._run_anthropic(run, system, defs, question, history)
            else:
                stream = self._run_openai(run, system, defs, question, history)
            async for event in stream:
                yield event
        except AskError as exc:
            yield {"type": "error", "code": exc.code, "message": str(exc)}
        yield {"type": "done", "steps": run.n, "budget": await self.budget(principal)}

    async def budget(self, principal: str) -> Optional[Dict[str, Any]]:
        try:
            budgets = await anyio.to_thread.run_sync(self.service.budgets, [principal])
        except Exception:  # noqa: BLE001 -- the answer matters more than the meter
            return None
        value: Optional[Dict[str, Any]] = budgets.get(principal)
        return value

    async def _tool(self, run: "_Run", name: Any, args: Any) -> Tuple[Dict[str, Any], ToolOutcome]:
        run.n += 1
        if not isinstance(args, dict):
            outcome = ToolOutcome("invalid arguments: not a JSON object", True)
        elif name == "describe_dataset":
            outcome = await run.kit.acall("describe_dataset", {})
        else:
            outcome = await run.kit.acall(str(name), args)
        status = outcome_status(outcome)
        event: Dict[str, Any] = {"type": "tool", "id": run.n, "name": str(name), "status": status}
        if status == "ok":
            event["result"] = outcome.content[:1500]
            run.ok.append(outcome.content)
        return event, outcome

    @staticmethod
    def _for_model(outcome: ToolOutcome) -> str:
        text = outcome.content
        try:  # compact JSON: a quarter of the tokens of the indented form
            text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))
        except ValueError:
            pass
        return text if len(text) <= MAX_RESULT_CHARS else text[:MAX_RESULT_CHARS] + " ...(truncated)"

    def _final(self, run: "_Run", text: str, turn: int) -> Optional[Dict[str, Any]]:
        """The answer event, or None when the model gets one more turn
        (``run.nudge`` says why): it stated figures without any data behind
        them, or answered a Korean question in another language."""
        text = strip_thinking(text)
        made_up = ungrounded(text, run.context, run.ok)
        more = turn < self.settings.max_turns
        if made_up and not run.corrected and more:
            run.corrected, run.nudge = True, GROUNDING_NUDGE
            return None
        if made_up:
            # Never show unverified figures as an answer.
            log.info("ask: withheld an answer with figures no tool call returned")
            return {"type": "answer", "grounded": False,
                    "text": WITHHELD_KO if _HANGUL.search(run.context) else WITHHELD_EN}
        if (text and more and not run.relanguaged and _HANGUL.search(run.question)
                and not _HANGUL.search(text)):
            run.relanguaged, run.nudge = True, LANGUAGE_NUDGE_KO
            return None
        return {"type": "answer", "text": text, "grounded": True}

    async def _run_anthropic(self, run: "_Run", system: str, defs: List[Any], question: str,
                             history: List[Dict[str, str]]) -> AsyncIterator[Dict[str, Any]]:
        s = self.settings
        tools = [{"name": d.name, "description": d.description, "input_schema": d.input_schema}
                 for d in defs if d.name != "describe_dataset"]
        messages: List[Dict[str, Any]] = [*history, {"role": "user", "content": question}]
        for turn in range(s.max_turns + 1):
            last = turn == s.max_turns
            yield {"type": "status", "phase": "thinking" if not run.n else "writing"}
            body: Dict[str, Any] = {"model": s.model, "max_tokens": s.max_tokens, "system": system,
                                    "messages": messages, "temperature": s.temperature}
            if not last:
                body["tools"] = tools
            reply = await self._call("/v1/messages", body)
            content = [b for b in reply.get("content") or [] if isinstance(b, dict)]
            uses = [b for b in content if b.get("type") == "tool_use"]
            if not uses or last:
                text = "".join(str(b.get("text", "")) for b in content if b.get("type") == "text")
                final = self._final(run, text, turn)
                if final is not None:
                    yield final
                    return
                messages += [{"role": "assistant", "content": text or "-"},
                             {"role": "user", "content": run.nudge}]
                continue
            messages.append({"role": "assistant", "content": content})
            results: List[Dict[str, Any]] = []
            for use in uses:
                yield {"type": "tool", "id": run.n + 1, "name": use.get("name"), "args": use.get("input"),
                       "status": "running"}
                event, outcome = await self._tool(run, use.get("name", ""), use.get("input"))
                yield event
                results.append({"type": "tool_result", "tool_use_id": use.get("id"),
                                "content": self._for_model(outcome), **({"is_error": True} if outcome.is_error else {})})
            if turn == s.max_turns - 1:
                results.append({"type": "text", "text": LAST_TURN})
            messages.append({"role": "user", "content": results})

    async def _run_openai(self, run: "_Run", system: str, defs: List[Any], question: str,
                          history: List[Dict[str, str]]) -> AsyncIterator[Dict[str, Any]]:
        if self._protocol == "native":
            try:
                async for event in self._openai_native(run, system, defs, question, history):
                    yield event
                return
            except _ToolsRefused:
                if self.settings.tool_protocol != "auto" or run.n:
                    raise AskError("model_error", "The AI model does not support tool use.") from None
                log.info("ask: %s does not take tools natively; using the JSON protocol", self.settings.model)
                self._protocol = "json"
        async for event in self._openai_json(run, system, defs, question, history):
            yield event

    async def _openai_native(self, run: "_Run", system: str, defs: List[Any], question: str,
                             history: List[Dict[str, str]]) -> AsyncIterator[Dict[str, Any]]:
        s = self.settings
        tools = [{"type": "function", "function": {"name": d.name, "description": d.description,
                                                   "parameters": d.input_schema}}
                 for d in defs if d.name != "describe_dataset"]
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system}, *history,
                                          {"role": "user", "content": question}]
        for turn in range(s.max_turns + 1):
            last = turn == s.max_turns
            yield {"type": "status", "phase": "thinking" if not run.n else "writing"}
            body: Dict[str, Any] = {"model": s.model, "messages": messages, "temperature": s.temperature,
                                    "max_tokens": s.max_tokens}
            if not last:
                body["tools"] = tools
            reply = await self._call("/chat/completions", body)
            try:
                message = reply["choices"][0]["message"]
                calls = list(message.get("tool_calls") or [])
            except (KeyError, IndexError, TypeError, AttributeError):
                raise AskError("model_error", "The AI model sent an unreadable reply.") from None
            if not calls or last:
                text = str(message.get("content") or "")
                final = self._final(run, text, turn)
                if final is not None:
                    yield final
                    return
                messages += [{"role": "assistant", "content": text or "-"},
                             {"role": "user", "content": run.nudge}]
                continue
            messages.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})
            for i, call in enumerate(calls):
                fn = call.get("function") or {} if isinstance(call, dict) else {}
                raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except ValueError:
                    args = None
                yield {"type": "tool", "id": run.n + 1, "name": fn.get("name"), "args": args, "status": "running"}
                event, outcome = await self._tool(run, fn.get("name", ""), args)
                yield event
                call_id = call.get("id") if isinstance(call, dict) else None
                messages.append({"role": "tool", "tool_call_id": call_id or f"call_{turn}_{i}",
                                 "content": self._for_model(outcome)})
            if turn == s.max_turns - 1:
                messages.append({"role": "user", "content": LAST_TURN})

    async def _openai_json(self, run: "_Run", system: str, defs: List[Any], question: str,
                           history: List[Dict[str, str]]) -> AsyncIterator[Dict[str, Any]]:
        s = self.settings
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system + self._json_protocol(defs)},
                                          *history, {"role": "user", "content": question}]
        retried = False
        for turn in range(s.max_turns + 1):
            yield {"type": "status", "phase": "thinking" if not run.n else "writing"}
            body = {"model": s.model, "messages": messages, "temperature": s.temperature,
                    "max_tokens": s.max_tokens, "response_format": {"type": "json_object"}}
            reply = await self._call("/chat/completions", body)
            try:
                text = str(reply["choices"][0]["message"].get("content") or "")
            except (KeyError, IndexError, TypeError, AttributeError):
                raise AskError("model_error", "The AI model sent an unreadable reply.") from None
            parsed = parse_json_reply(text)
            if parsed is None:
                plain = strip_thinking(text)
                if plain and not plain.startswith("{"):
                    final = self._final(run, plain, turn)
                    if final is not None:
                        yield final
                        return
                    messages += [{"role": "assistant", "content": text}, {"role": "user", "content": run.nudge}]
                    continue
                if retried:
                    raise AskError("model_error", "The AI model did not follow the answer format.")
                retried = True
                messages += [{"role": "assistant", "content": text},
                             {"role": "user", "content": "Reply with ONE JSON object: a tool call or an answer."}]
                continue
            if "tool" not in parsed or turn == s.max_turns:
                answer = parsed.get("answer")
                if not isinstance(answer, str) or not answer.strip():
                    if turn < s.max_turns:
                        messages += [{"role": "assistant", "content": text},
                                     {"role": "user", "content": 'Now reply {"answer": "..."} for the person.'}]
                        continue
                    answer = ""
                final = self._final(run, answer, turn)
                if final is not None:
                    yield final
                    return
                messages += [{"role": "assistant", "content": text}, {"role": "user", "content": run.nudge}]
                continue
            name, args = str(parsed.get("tool")), parsed.get("arguments", {})
            yield {"type": "tool", "id": run.n + 1, "name": name, "args": args, "status": "running"}
            event, outcome = await self._tool(run, name, args)
            yield event
            note = (" " + LAST_TURN) if turn == s.max_turns - 1 else ""
            messages += [{"role": "assistant", "content": json.dumps({"tool": name, "arguments": args},
                                                                    ensure_ascii=False)},
                         {"role": "user", "content": f"TOOL RESULT ({name}, "
                                                     f"{'error' if outcome.is_error else 'ok'}): "
                                                     f"{self._for_model(outcome)}{note}"}]


@dataclass
class _Run:
    """One question's progress."""

    kit: TokenisToolkit
    question: str
    #: The question plus earlier turns: figures from there need no tool call.
    context: str
    n: int = 0
    ok: List[str] = field(default_factory=list)
    corrected: bool = False
    relanguaged: bool = False
    nudge: str = ""


GROUNDING_NUDGE = ("You stated figures without getting them from a tool. Call a tool to get them first, "
                   "or say that the data cannot answer.")
WITHHELD_KO = ("이 질문에는 데이터에서 확인된 숫자로 답하지 못했어요. 개별 회사나 사람 단위의 값은 볼 수 없으니, "
               "업종·지역·규모 같은 그룹 단위로 바꿔서 물어봐 주세요.")
WITHHELD_EN = ("I couldn't answer this with figures backed by the data. Values for a single company or person "
               "aren't available; try asking about a group instead (an industry, a region, a size band).")
LANGUAGE_NUDGE_KO = ("The person asked in Korean. Write the same answer again in Korean (한국어로 다시 답해 주세요); "
                     "keep every figure and unit exactly.")
_HANGUL = re.compile(r"[\uac00-\ud7a3]")
LAST_TURN = "Answer now from the results above; no more tool calls."


def signature(schema: Mapping[str, Any]) -> str:
    """A compact, model-readable rendering of a tool's JSON schema, e.g.
    ``function: sum|avg, column?: a|b, filters?: {region?: ...}`` -- a few
    hundred characters instead of several thousand, which matters for local
    models with 4K-token context windows."""

    def kind(node: Any) -> str:
        if not isinstance(node, Mapping):
            return "any"
        options = [o for o in node.get("anyOf", []) if isinstance(o, Mapping) and o.get("type") != "null"]
        if options:
            return " | ".join(kind(o) for o in options)
        if "enum" in node:
            values = [str(v) for v in node["enum"]]
            return "|".join(values) if len(values) <= 12 else "one of the listed values"
        if node.get("pattern") == "^[0-9a-f]{32}$":
            return "token"
        t = node.get("type")
        if t == "object" and isinstance(node.get("properties"), Mapping):
            return "{" + fields(node) + "}"
        if t == "array":
            return f"[{kind(node.get('items'))}]"
        return {"integer": "int", "number": "number", "boolean": "true|false"}.get(str(t), "text")

    def fields(node: Mapping[str, Any]) -> str:
        required = set(node.get("required", []))
        parts = []
        for name, prop in (node.get("properties") or {}).items():
            optional = name not in required or (isinstance(prop, Mapping) and "default" in prop)
            parts.append(f"{name}{'?' if optional else ''}: {kind(prop)}")
        return ", ".join(parts)

    return fields(schema)


_NUMBER = re.compile(r"\d[\d,.]*\d|\d")


def ungrounded(answer: str, question: str, results: List[str]) -> bool:
    """True when ``answer`` states figures but no tool call succeeded: the
    model (typically a small local one) made the numbers up."""
    if results:
        return False
    asked = set(_NUMBER.findall(question))
    figures = [n for n in _NUMBER.findall(answer) if n not in asked and len(n.replace(",", "").replace(".", "")) >= 2]
    return bool(figures)


def clean_history(raw: Any) -> List[Dict[str, str]]:
    """The earlier turns the browser sends back: text only, bounded."""
    if not isinstance(raw, list):
        return []
    items = [{"role": m["role"], "content": m["content"][:4000]}
             for m in raw[-MAX_HISTORY_ITEMS:]
             if isinstance(m, dict) and m.get("role") in ("user", "assistant")
             and isinstance(m.get("content"), str) and m["content"].strip()]
    while items and sum(len(m["content"]) for m in items) > MAX_HISTORY_CHARS:
        items.pop(0)
    while items and items[0]["role"] != "user":  # providers want user first, alternating
        items.pop(0)
    out: List[Dict[str, str]] = []
    for m in items:
        if out and out[-1]["role"] == m["role"]:
            out[-1] = m
        else:
            out.append(m)
    if out and out[-1]["role"] == "user":
        out.pop()
    return out


def ask_page_html() -> str:
    from importlib import resources

    return resources.files("tokenis").joinpath("assets/ask.html").read_text(encoding="utf-8")
