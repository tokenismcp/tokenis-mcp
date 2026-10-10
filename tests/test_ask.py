# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Tokenis Ask: helpers that keep small local models honest."""
import pytest

from tokenis.ask import (
    AskSettings,
    clean_history,
    parse_json_reply,
    signature,
    strip_thinking,
    ungrounded,
)


def test_parse_json_reply_tolerates_fences_and_thinking():
    text = '<think>hmm {"no": 1}</think>```json\n{"tool": "group_by", "arguments": {"key": "a}"}}\n```'
    assert parse_json_reply(text) == {"tool": "group_by", "arguments": {"key": "a}"}}
    assert parse_json_reply("no json here") is None
    assert strip_thinking("<think>x</think> hi") == "hi"


def test_signature_is_compact():
    schema = {"properties": {"function": {"enum": ["sum", "avg"]},
                             "column": {"anyOf": [{"enum": ["a", "b"]}, {"type": "null"}], "default": None},
                             "filters": {"anyOf": [{"type": "object", "properties": {
                                 "t": {"anyOf": [{"pattern": "^[0-9a-f]{32}$", "type": "string"}, {"type": "null"}],
                                       "default": None}}}, {"type": "null"}], "default": None}},
              "required": ["function"]}
    assert signature(schema) == "function: sum|avg, column?: a|b, filters?: {t?: token}"


def test_ungrounded_figures_are_detected():
    assert ungrounded("매출은 4,876억입니다", "Bitjae 2025년 매출?", [])
    assert not ungrounded("매출은 4,876억입니다", "q", ['{"value": 1}'])
    assert not ungrounded("2025년 자료는 없습니다", "2025년 매출?", [])


def test_clean_history_alternates_and_drops_trailing_user():
    raw = [{"role": "assistant", "content": "hi"}, {"role": "user", "content": "a"},
           {"role": "user", "content": "b"}, {"role": "assistant", "content": "c"},
           {"role": "system", "content": "x"}, {"role": "user", "content": "d"}]
    assert clean_history(raw) == [{"role": "user", "content": "b"}, {"role": "assistant", "content": "c"}]


def test_settings_validation():
    with pytest.raises(ValueError):
        AskSettings(model="")
    with pytest.raises(ValueError):
        AskSettings(model="m", provider="other")
    assert AskSettings(model="m", provider="anthropic").endpoint == "https://api.anthropic.com"


# -- the /ask screen and its API, end to end ------------------------------------------------------

import http.server
import json
import threading

pytest.importorskip("mcp")
pytest.importorskip("jwt")
from test_console_sso import WRITE, FakeIdP

from tokenis.ask import WITHHELD_EN, WITHHELD_KO, AskEngine


class FakeModel:
    """An OpenAI-compatible (or Anthropic) chat endpoint that plays back
    scripted replies and records what it was sent."""

    def __init__(self, replies, refuse_tools=False):
        self.replies = list(replies)
        self.requests = []
        self.refuse_tools = refuse_tools
        model = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                model.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if model.refuse_tools and body.get("tools"):
                    out, status = {"error": {"message": "model does not support tools"}}, 400
                else:
                    out, status = model.replies.pop(0), 200
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def tool_call(name, args, n=1):
    return {"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [
        {"id": f"c{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}]}


def text(content):
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


@pytest.fixture
def idp():
    server = FakeIdP()
    yield server
    server.server.shutdown()
    server.server.server_close()


def ask_app(tmp_path, idp, model, **settings):
    from starlette.testclient import TestClient

    from tokenis.calllog import SqliteCallLog
    from tokenis.console_auth import OidcClient, OidcSettings
    from tokenis.gateway.demo import demo_service
    from tokenis.mcp_server.server import create_server, fixed_principal
    from tokenis.ops import Metrics, install_routes

    oidc = OidcSettings(issuer=idp.issuer, client_id="tokenis-console", client_secret="s3cret",
                        redirect_url="http://testserver/admin/auth/callback",
                        admins=("alice@acme.example",), users=("@acme.example",))
    service = demo_service(latency_granularity_ms=1.0)
    calls = SqliteCallLog(":memory:", service.settings.tenant)
    metrics = Metrics()
    base = model.url + ("" if settings.get("provider") == "anthropic" else "/v1")
    engine = AskEngine(service, AskSettings(**{"model": "m", "base_url": base, **settings}),
                       metrics=metrics, call_log=calls)
    server = create_server(service, principal_resolver=fixed_principal("x"), metrics=metrics, call_log=calls)
    install_routes(server, service, metrics, oidc=OidcClient(oidc), session_key=b"k" * 32, call_log=calls,
                   ask=engine)

    return TestClient(server.streamable_http_app(), follow_redirects=False), calls


def sign_in_user(client, idp, email="bob@acme.example"):
    idp.user = {"sub": email, "email": email, "email_verified": True}
    start = client.get("/admin/auth/start?next=/ask")
    code, state = idp.authorize(start.headers["location"])
    return client.get(f"/admin/auth/callback?code={code}&state={state}")


def events(response):
    return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]


def chat(client, question, **extra):
    return client.post("/ask/api/chat", headers=WRITE, json={"question": question, **extra})


@pytest.fixture
def model():
    servers = []

    def make(replies, **kw):
        server = FakeModel(replies, **kw)
        servers.append(server)
        return server

    yield make
    for s in servers:
        s.close()


def test_a_user_signs_in_to_ask_and_never_sees_the_console(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    assert client.get("/ask").headers["location"] == "/admin/auth/login?next=/ask"
    login = client.get("/admin/auth/login?next=/ask")
    assert 'href="/admin/auth/start?next=/ask"' in login.text
    done = sign_in_user(client, idp)
    assert done.status_code == 302 and done.headers["location"] == "/ask"
    page = client.get("/ask")
    assert page.status_code == 200 and "script-src 'nonce-" in page.headers["content-security-policy"]
    assert "{{" not in page.text
    assert client.get("/admin").headers["location"] == "/ask"
    assert client.get("/admin/api/summary").status_code == 403
    ctx = client.get("/ask/api/context").json()
    assert ctx["me"]["role"] == "user" and ctx["me"]["console"] is False
    assert ctx["catalog"]["suggestions"] is None
    assert ctx["catalog"]["auto_suggestions"]["en"] and ctx["catalog"]["auto_suggestions"]["ko"]
    assert ctx["budget"]["remaining"] == 1000


def test_unverified_or_foreign_addresses_get_no_role(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    idp.user = {"sub": "m", "email": "mallory@acme.example", "email_verified": False}
    start = client.get("/admin/auth/start?next=/ask")
    code, state = idp.authorize(start.headers["location"])
    assert client.get(f"/admin/auth/callback?code={code}&state={state}").status_code == 403
    assert sign_in_user(client, idp, "eve@evil.example").status_code == 403


def test_the_sign_in_page_is_english_until_the_person_switches(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    page = client.get("/admin/auth/login?next=/ask", headers={"Accept-Language": "ko-KR,ko;q=0.9"})
    assert '<html lang="en">' in page.text and "Sign in to Tokenis Ask" in page.text
    assert 'href="/lang/ko?next=/admin/auth/login' in page.text
    page = client.get("/admin/auth/login?next=/ask", headers={"Cookie": "tokenis_lang=ko"})
    assert '<html lang="ko">' in page.text and "Tokenis Ask 로그인" in page.text
    switched = client.get("/lang/ko?next=/admin/auth/login%3Fnext%3D/ask")
    assert switched.status_code == 302 and switched.headers["location"] == "/admin/auth/login?next=/ask"
    assert "tokenis_lang=ko" in switched.headers["set-cookie"] and "Path=/" in switched.headers["set-cookie"]


def test_the_language_switch_only_returns_to_this_site(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    assert client.get("/lang/ko?next=https://evil.example/").headers["location"] == "/"
    assert client.get("/lang/ko?next=//evil.example/").headers["location"] == "/"
    assert client.get("/lang/fr").status_code == 404


def test_a_question_is_answered_with_tool_calls_under_the_users_own_budget(tmp_path, idp, model):
    m = model([tool_call("group_by", {"key": "industry", "function": "sum", "column": "revenue_2025"}),
               text("**tech** leads with 1,234 KRW.")])
    client, calls = ask_app(tmp_path, idp, m)
    sign_in_user(client, idp)
    out = events(chat(client, "Which industry earned most in 2025?"))
    kinds = [e["type"] for e in out]
    assert kinds[-1] == "done" and "answer" in kinds
    tools = [e for e in out if e["type"] == "tool"]
    assert [t["status"] for t in tools] == ["running", "ok"] and tools[0]["args"]["key"] == "industry"
    answer = next(e for e in out if e["type"] == "answer")
    assert answer["grounded"] and "tech" in answer["text"]
    assert out[-1]["budget"]["used"] > 0
    # The model was told about the data and sent the tool's real result.
    first, second = m.requests
    assert "describe_dataset result" in first["body"]["messages"][0]["content"]
    assert second["body"]["messages"][-1]["role"] == "tool" and "groups" in second["body"]["messages"][-1]["content"]
    calls.flush()
    assert any(p["principal"] == "bob@acme.example" for p in calls.principals("24h"))


def test_figures_without_a_lookup_are_withheld(tmp_path, idp, model):
    m = model([text("Bitjae earned 4,876 million."), text("It earned 4,876 million, trust me.")])
    client, _ = ask_app(tmp_path, idp, m)
    sign_in_user(client, idp)
    answer = next(e for e in events(chat(client, "Bitjae Corp revenue?")) if e["type"] == "answer")
    assert answer["grounded"] is False and answer["text"] == WITHHELD_EN
    assert "without getting them from a tool" in m.requests[1]["body"]["messages"][-1]["content"]
    m.replies += [text("모름 1,000원"), text("2,000원")]
    answer = next(e for e in events(chat(client, "비트재 매출은?")) if e["type"] == "answer")
    assert answer["text"] == WITHHELD_KO


def test_models_without_function_calling_use_the_json_protocol(tmp_path, idp, model):
    m = model([text('{"tool": "aggregate", "arguments": {"function": "count", "filters": {"industry": "tech"}}}'),
               text('```json\n{"answer": "There are 3 records."}\n```')], refuse_tools=True)
    client, _ = ask_app(tmp_path, idp, m)
    sign_in_user(client, idp)
    out = events(chat(client, "How many records?"))
    assert [e["status"] for e in out if e["type"] == "tool"] == ["running", "ok"]
    assert next(e for e in out if e["type"] == "answer")["text"] == "There are 3 records."
    prompt = m.requests[1]["body"]["messages"][0]["content"]
    assert "Reply with exactly ONE JSON object" in prompt and "aggregate(function:" in prompt


def test_refusals_are_reported_without_the_rule(tmp_path, idp, model):
    m = model([tool_call("aggregate", {"function": "sum", "column": "revenue_2025",
                                       "filters": {"region": "Seoul-Gangnam", "industry": "tech"}}),
               text("That group is too small to report.")])
    client, _ = ask_app(tmp_path, idp, m)
    sign_in_user(client, idp)
    out = events(chat(client, "Gangnam tech revenue?"))
    done = [e for e in out if e["type"] == "tool" and e["status"] != "running"]
    assert done and done[0]["status"] in ("denied", "ok")
    if done[0]["status"] == "denied":
        assert "result" not in done[0]
        assert "D1" not in json.dumps(out) and "D2" not in json.dumps(out)


def test_anthropic_messages_api(tmp_path, idp, model):
    m = model([{"content": [{"type": "tool_use", "id": "t1", "name": "aggregate",
                             "input": {"function": "count", "filters": {"industry": "tech"}}}], "stop_reason": "tool_use"},
               {"content": [{"type": "text", "text": "3 records."}], "stop_reason": "end_turn"}])
    client, _ = ask_app(tmp_path, idp, m, provider="anthropic")
    sign_in_user(client, idp)
    out = events(chat(client, "How many?"))
    assert next(e for e in out if e["type"] == "answer")["text"] == "3 records."
    assert m.requests[0]["path"] == "/v1/messages" and {k.lower(): v for k, v in m.requests[0]["headers"].items()}["anthropic-version"] == "2023-06-01"
    assert m.requests[1]["body"]["messages"][-1]["content"][0]["type"] == "tool_result"


def test_chat_needs_the_console_header_and_a_session(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    assert chat(client, "hi").status_code == 401
    sign_in_user(client, idp)
    assert client.post("/ask/api/chat", json={"question": "hi"}).status_code == 403
    assert chat(client, "").status_code == 400
    assert chat(client, "x" * 2001).status_code == 400


def test_questions_per_hour_are_limited(tmp_path, idp, model):
    m = model([text("Hello."), text("Hello again.")])
    client, _ = ask_app(tmp_path, idp, m, questions_per_hour=1)
    sign_in_user(client, idp)
    assert next(e for e in events(chat(client, "hi")) if e["type"] == "answer")
    assert events(chat(client, "hi again"))[0] == {"type": "error", "code": "rate", "message": "rate"}


def test_model_outages_become_plain_errors(tmp_path, idp, model):
    m = model([])
    client, _ = ask_app(tmp_path, idp, m, timeout_seconds=5)
    m.close()
    sign_in_user(client, idp)
    out = events(chat(client, "hi"))
    assert out[-2]["type"] == "error" and out[-2]["code"] in ("model_unreachable", "model_timeout")
    assert out[-1]["type"] == "done"


def test_an_api_key_is_never_sent_over_plain_http_to_another_host():
    with pytest.raises(ValueError, match="plain http"):
        AskEngine(None, AskSettings(model="m", base_url="http://llm.internal/v1"), "secret")


def test_a_korean_question_gets_a_korean_answer(tmp_path, idp, model):
    m = model([text("Ask about a group instead."), text("그룹 단위로 물어봐 주세요.")])
    client, _ = ask_app(tmp_path, idp, m)
    sign_in_user(client, idp)
    answer = next(e for e in events(chat(client, "비트재의 매출은?")) if e["type"] == "answer")
    assert answer["text"] == "그룹 단위로 물어봐 주세요."
    assert "Korean" in m.requests[1]["body"]["messages"][-1]["content"]


def test_the_console_is_english_by_default_and_follows_the_switch(tmp_path, idp, model):
    client, _ = ask_app(tmp_path, idp, model([]))
    sign_in_user(client, idp, "alice@acme.example")  # listed as admin in ask_app
    page = client.get("/admin")
    assert page.status_code == 200 and '<html lang="en">' in page.text
    client.cookies.set("tokenis_lang", "ko")
    page = client.get("/admin")
    assert '<html lang="ko">' in page.text
    assert 'data-l="en"' in page.text and 'data-l="ko"' in page.text
