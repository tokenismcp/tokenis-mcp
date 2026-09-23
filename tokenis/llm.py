# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Use Tokenis tools from an LLM API directly, without running an MCP
server: the Anthropic Messages API, the OpenAI Chat Completions API, or any
OpenAI-compatible endpoint (vLLM, Ollama, LiteLLM, Azure OpenAI, ...).

The toolkit wraps the same :func:`~tokenis.mcp_server.server.create_server`
object an MCP client would talk to, so tool schemas, validation, admission
control, generic denials and latency padding are identical on both paths.

Anthropic::

    import anthropic
    from tokenis.llm import TokenisToolkit

    toolkit = TokenisToolkit(service, principal=user_id)   # your authenticated user
    client = anthropic.Anthropic()                          # reads ANTHROPIC_API_KEY
    messages = [{"role": "user", "content": question}]
    while True:
        reply = client.messages.create(
            model="claude-opus-5-5", max_tokens=2048, system=toolkit.system_prompt,
            tools=toolkit.anthropic_tools(), messages=messages,
        )
        messages.append({"role": "assistant", "content": reply.content})
        if reply.stop_reason != "tool_use":
            break
        messages.append({"role": "user", "content": toolkit.anthropic_tool_results(reply.content)})

OpenAI-compatible::

    reply = client.chat.completions.create(model=..., messages=messages,
                                           tools=toolkit.openai_tools())
    message = reply.choices[0].message
    messages.append(message)
    messages += toolkit.openai_tool_messages(message.tool_calls or [])

``principal`` must be the end user your application has already
authenticated -- the toolkit trusts it as the admission-control subject.
Pass ``taint=1`` when the conversation contains untrusted content
(retrieved documents, web pages, e-mails): D4 then narrows the tool surface
and applies the tainted budgets.
"""
from __future__ import annotations

import asyncio
import copy
import json
import threading
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, TypeVar

from mcp.server.mcpserver.exceptions import ToolError

from tokenis.gateway.service import TokenisGatewayService
from tokenis.mcp_server.server import INSTRUCTIONS, create_server, fixed_principal

_T = TypeVar("_T")


def _run(factory: Callable[[], Awaitable[_T]]) -> _T:
    """Run a coroutine from sync code, even when the calling thread already
    has a running event loop (e.g. inside a web framework handler)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())  # type: ignore[arg-type]
    box: Dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = asyncio.run(factory())  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 -- re-raised in the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=worker, name="tokenis-toolkit")
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]  # type: ignore[no-any-return]


def inline_refs(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve local ``$ref``s against ``$defs`` and drop ``$defs``: some
    LLM APIs reject or ignore JSON-Schema references in tool parameters."""
    defs = schema.get("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/$defs/"):
                target = copy.deepcopy(defs[ref.split("/")[-1]])
                extra = {k: v for k, v in node.items() if k != "$ref"}
                return resolve({**target, **extra})
            return {k: resolve(v) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    result: Dict[str, Any] = resolve(schema)
    return result


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]


@dataclass(frozen=True)
class ToolOutcome:
    """A tool call's result as text for the model. ``is_error`` marks a
    denial or invalid call (the text says which, generically)."""

    content: str
    is_error: bool = False

    def json(self) -> Any:
        return json.loads(self.content) if not self.is_error else None


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)


class TokenisToolkit:
    """Tokenis tools for one authenticated principal (see module docs)."""

    def __init__(
        self,
        service: TokenisGatewayService,
        *,
        principal: str,
        taint: int = 0,
        max_concurrency: int = 16,
    ) -> None:
        self.principal = principal
        self.taint = 1 if taint else 0
        self.server = create_server(
            service,
            principal_resolver=fixed_principal(principal),
            taint_resolver=lambda _ctx: self.taint,
            max_concurrency=max_concurrency,
        )
        self._definitions: Optional[List[ToolDefinition]] = None

    @property
    def system_prompt(self) -> str:
        """Guidance for the model on using the tools well (not a security
        control: enforcement happens in the gateway)."""
        return INSTRUCTIONS

    # -- tool definitions ------------------------------------------------------

    async def adefinitions(self) -> List[ToolDefinition]:
        if self._definitions is None:
            tools = await self.server.list_tools()
            self._definitions = [
                ToolDefinition(t.name, t.description or "", inline_refs(dict(t.input_schema)))
                for t in tools
            ]
        return list(self._definitions)

    def definitions(self) -> List[ToolDefinition]:
        return _run(self.adefinitions)

    def anthropic_tools(self) -> List[Dict[str, Any]]:
        """``tools=`` for ``anthropic.Anthropic().messages.create``."""
        return [
            {"name": d.name, "description": d.description, "input_schema": d.input_schema}
            for d in self.definitions()
        ]

    def openai_tools(self) -> List[Dict[str, Any]]:
        """``tools=`` for OpenAI-compatible ``chat.completions.create``."""
        return [
            {"type": "function",
             "function": {"name": d.name, "description": d.description, "parameters": d.input_schema}}
            for d in self.definitions()
        ]

    # -- calling ------------------------------------------------------------

    async def acall(self, name: str, arguments: Optional[Mapping[str, Any]] = None) -> ToolOutcome:
        try:
            result = await self.server.call_tool(name, dict(arguments or {}))
        except ToolError as exc:
            message = str(exc)
            prefix = f"Error executing tool {name}: "
            return ToolOutcome(message.removeprefix(prefix), True)
        text = "".join(getattr(block, "text", "") for block in getattr(result, "content", []))
        return ToolOutcome(text, bool(getattr(result, "is_error", False)))

    def call(self, name: str, arguments: Optional[Mapping[str, Any]] = None) -> ToolOutcome:
        return _run(lambda: self.acall(name, arguments))

    async def _gather(self, calls: List[Any]) -> List[ToolOutcome]:
        return list(await asyncio.gather(*calls))

    # -- Anthropic ------------------------------------------------------------

    async def aanthropic_tool_results(self, content: Iterable[Any]) -> List[Dict[str, Any]]:
        """``tool_result`` blocks for every ``tool_use`` block in an assistant
        message's ``content`` (SDK objects or dicts), run concurrently."""
        uses = [b for b in content if _field(b, "type") == "tool_use"]
        outcomes = await self._gather(
            [self.acall(_field(b, "name"), _field(b, "input") or {}) for b in uses]
        )
        return [
            {"type": "tool_result", "tool_use_id": _field(b, "id"), "content": o.content,
             **({"is_error": True} if o.is_error else {})}
            for b, o in zip(uses, outcomes)
        ]

    def anthropic_tool_results(self, content: Iterable[Any]) -> List[Dict[str, Any]]:
        blocks = list(content)
        return _run(lambda: self.aanthropic_tool_results(blocks))

    # -- OpenAI-compatible ----------------------------------------------------

    async def aopenai_tool_messages(self, tool_calls: Iterable[Any]) -> List[Dict[str, Any]]:
        """``role: tool`` messages answering an assistant message's
        ``tool_calls`` (SDK objects or dicts), run concurrently."""
        calls = list(tool_calls)
        parsed = []
        for call in calls:
            function = _field(call, "function")
            raw = _field(function, "arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except ValueError:
                args = None
            parsed.append((_field(function, "name"), args))
        outcomes = await self._gather([
            self.acall(name, args) if isinstance(args, dict)
            else _invalid_json()
            for name, args in parsed
        ])
        return [
            {"role": "tool", "tool_call_id": _field(call, "id"), "content": o.content}
            for call, o in zip(calls, outcomes)
        ]

    def openai_tool_messages(self, tool_calls: Iterable[Any]) -> List[Dict[str, Any]]:
        calls = list(tool_calls)
        return _run(lambda: self.aopenai_tool_messages(calls))


async def _invalid_json() -> ToolOutcome:
    return ToolOutcome("invalid arguments: not a JSON object", True)


# -- ready-made agent loops -----------------------------------------------------


def ask_anthropic(
    toolkit: TokenisToolkit,
    question: str,
    *,
    client: Any = None,
    model: str = "claude-opus-5-5",
    max_tokens: int = 4096,
    max_turns: int = 12,
    on_tool: Optional[Callable[[str, Mapping[str, Any], ToolOutcome], None]] = None,
) -> str:
    """Answer ``question`` with Claude using the Tokenis tools; returns the
    final text. ``client`` defaults to ``anthropic.Anthropic()`` (which
    reads ``ANTHROPIC_API_KEY`` from the environment)."""
    if client is None:
        import anthropic

        client = anthropic.Anthropic()
    tools = toolkit.anthropic_tools()
    messages: List[Dict[str, Any]] = [{"role": "user", "content": question}]
    for _ in range(max_turns):
        reply = client.messages.create(
            model=model, max_tokens=max_tokens, system=toolkit.system_prompt,
            tools=tools, messages=messages,
        )
        messages.append({"role": "assistant", "content": reply.content})
        if reply.stop_reason != "tool_use":
            return "".join(getattr(b, "text", "") for b in reply.content if _field(b, "type") == "text")
        results = toolkit.anthropic_tool_results(reply.content)
        if on_tool is not None:
            uses = [b for b in reply.content if _field(b, "type") == "tool_use"]
            for use, result in zip(uses, results):
                on_tool(_field(use, "name"), _field(use, "input") or {},
                        ToolOutcome(result["content"], bool(result.get("is_error"))))
        messages.append({"role": "user", "content": results})
    raise RuntimeError(f"no final answer after {max_turns} turns")


def ask_openai(
    toolkit: TokenisToolkit,
    question: str,
    *,
    client: Any = None,
    model: str,
    max_turns: int = 12,
    on_tool: Optional[Callable[[str, Mapping[str, Any], ToolOutcome], None]] = None,
) -> str:
    """Answer ``question`` with any OpenAI-compatible chat model. ``client``
    defaults to ``openai.OpenAI()`` (``OPENAI_API_KEY``, and
    ``OPENAI_BASE_URL`` for other providers or local servers)."""
    if client is None:
        import openai

        client = openai.OpenAI()
    tools = toolkit.openai_tools()
    messages: List[Any] = [
        {"role": "system", "content": toolkit.system_prompt},
        {"role": "user", "content": question},
    ]
    for _ in range(max_turns):
        reply = client.chat.completions.create(model=model, messages=messages, tools=tools)
        message = reply.choices[0].message
        calls = list(_field(message, "tool_calls") or [])
        messages.append(message)
        if not calls:
            return str(_field(message, "content") or "")
        answers = toolkit.openai_tool_messages(calls)
        if on_tool is not None:
            for call, answer in zip(calls, answers):
                fn = _field(call, "function")
                try:
                    args = json.loads(_field(fn, "arguments") or "{}")
                except ValueError:
                    args = {}
                on_tool(_field(fn, "name"), args, ToolOutcome(answer["content"]))
        messages.extend(answers)
    raise RuntimeError(f"no final answer after {max_turns} turns")
