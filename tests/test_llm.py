# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The LLM toolkit, against scripted stand-ins for the Anthropic and OpenAI
clients (no network, no API key)."""
import json
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("mcp", reason="needs the `server` extra (Python >= 3.10)")

from tokenis.gateway.demo import demo_service
from tokenis.gateway.service import DENIED_MESSAGE
from tokenis.llm import TokenisToolkit, ask_anthropic, ask_openai, inline_refs


@pytest.fixture
def toolkit():
    return TokenisToolkit(demo_service(latency_granularity_ms=1.0), principal="alice")


def test_schemas_are_self_contained(toolkit):
    for tools in (toolkit.anthropic_tools(), toolkit.openai_tools()):
        text = json.dumps(tools)
        assert "$ref" not in text and "$defs" not in text
    aggregate = next(t for t in toolkit.anthropic_tools() if t["name"] == "aggregate")
    filters = aggregate["input_schema"]["properties"]["filters"]["anyOf"][0]
    assert filters["properties"]["industry"]["anyOf"][0]["enum"] == ["finance", "retail", "tech"]
    assert inline_refs({"$defs": {"A": {"type": "string"}}, "items": {"$ref": "#/$defs/A"}}) == {
        "items": {"type": "string"}}


def test_calls_report_denials_as_errors(toolkit):
    ok = toolkit.call("aggregate", {"function": "sum", "column": "revenue_2025",
                                    "filters": {"industry": "tech"}})
    assert not ok.is_error and ok.json()["value"] == 7_000_000
    denied = toolkit.call("aggregate", {"function": "sum", "column": "revenue_2025",
                                        "filters": {"industry": "retail"}})
    assert denied.is_error and denied.content == DENIED_MESSAGE


class FakeAnthropic:
    """Replays a scripted conversation, recording what it was sent."""

    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs, default=lambda o: o.__dict__)))
        return self.turns.pop(0)


def test_ask_anthropic_runs_the_tool_loop(toolkit):
    tool_use = NS(type="tool_use", id="tu1", name="aggregate",
                  input={"function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}})
    client = FakeAnthropic([
        NS(stop_reason="tool_use", content=[NS(type="text", text="checking"), tool_use]),
        NS(stop_reason="end_turn", content=[NS(type="text", text="Retail is too small to report.")]),
    ])
    seen = []
    answer = ask_anthropic(toolkit, "Retail revenue?", client=client,
                           on_tool=lambda name, args, outcome: seen.append((name, outcome.is_error)))
    assert answer == "Retail is too small to report."
    assert seen == [("aggregate", True)]
    first, second = client.requests
    assert first["model"] == "claude-opus-5-5" and first["system"] == toolkit.system_prompt
    assert {t["name"] for t in first["tools"]} >= {"describe_dataset", "aggregate"}
    result = second["messages"][-1]["content"][0]
    assert result == {"type": "tool_result", "tool_use_id": "tu1", "content": DENIED_MESSAGE,
                      "is_error": True}


class FakeOpenAI:
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.chat = NS(completions=self)

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return NS(choices=[NS(message=self.turns.pop(0))])


def test_ask_openai_runs_the_tool_loop(toolkit):
    call = NS(id="c1", type="function",
              function=NS(name="group_by", arguments=json.dumps({"key": "industry",
                                                                  "column": "revenue_2024"})))
    client = FakeOpenAI([
        NS(role="assistant", content=None, tool_calls=[call]),
        NS(role="assistant", content="Tech leads.", tool_calls=None),
    ])
    assert ask_openai(toolkit, "Which industry is largest?", client=client, model="m") == "Tech leads."
    # The loop passes one growing list; pick out the tool reply.
    [tool_message] = [m for m in client.requests[1]["messages"]
                      if isinstance(m, dict) and m.get("role") == "tool"]
    assert tool_message["role"] == "tool" and tool_message["tool_call_id"] == "c1"
    groups = {g["group"]: g for g in json.loads(tool_message["content"])["groups"]}
    assert groups["retail"]["suppressed"] is True
    assert client.requests[0]["tools"][0]["type"] == "function"


def test_malformed_tool_arguments_are_errors_not_crashes(toolkit):
    messages = toolkit.openai_tool_messages([{"id": "x", "function": {"name": "aggregate",
                                                                      "arguments": "{nope"}}])
    assert messages[0]["content"].startswith("invalid arguments")
    out = toolkit.call("no_such_tool", {})
    assert out.is_error
