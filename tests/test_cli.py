# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The `tokenis-mcp` CLI, including real stdio and HTTP transports."""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="needs the `server` extra (Python >= 3.10)")

from tokenis.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
ENV = {"TOKENIS_TOKENIZER_KEY": "11" * 32, "TOKENIS_AUDIT_KEY": "22" * 32}


@pytest.fixture
def example(tmp_path, monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    shutil.copy(EXAMPLES / "tokenis.toml", tmp_path / "tokenis.toml")
    shutil.copytree(EXAMPLES / "data", tmp_path / "data")
    return tmp_path / "tokenis.toml"


def test_tools_and_check(example, capsys):
    main(["tools", "--demo", "--format", "openai"])
    tools = json.loads(capsys.readouterr().out)
    assert tools[0]["function"]["name"] == "describe_dataset"
    main(["check", "--config", str(example)])
    summary = json.loads(capsys.readouterr().out)
    assert summary["records"] == 60
    assert not (example.parent / "state").exists()  # check changes nothing


def test_keys_and_audit(example, capsys):
    main(["keys", "create", "alice@example.com", "--config", str(example)])
    token = capsys.readouterr().out.strip()
    assert token.startswith("tkn_")
    main(["keys", "list", "--config", str(example)])
    [record] = json.loads(capsys.readouterr().out)
    assert record["principal"] == "alice@example.com" and not record["revoked"]
    main(["keys", "revoke", record["key_id"], "--config", str(example)])
    with pytest.raises(SystemExit):
        main(["keys", "revoke", record["key_id"], "--config", str(example)])

    from tokenis.config import build_service, load_config

    svc = build_service(load_config(example))
    svc.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "tech"}})
    main(["audit", "verify", "--config", str(example)])
    report = json.loads(capsys.readouterr().out)
    assert report["entries"] == 1 and report["signed"] is True
    (example.parent / "state" / "trace.jsonl").write_text("{}\n")
    with pytest.raises(SystemExit) as exc:
        main(["audit", "verify", "--config", str(example)])
    assert exc.value.code == 1


def test_stdio_end_to_end():
    from mcp.client.client import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(
        command=sys.executable, args=["-m", "tokenis", "--log-level", "WARNING", "serve", "--demo"],
    )

    async def session():
        async with Client(params) as client:
            tools = await client.list_tools()
            result = await client.call_tool("aggregate", {
                "function": "sum", "column": "revenue_2025", "filters": {"industry": "finance"}})
            denied = await client.call_tool("aggregate", {
                "function": "sum", "column": "revenue_2025", "filters": {"industry": "retail"}})
            return tools, result, denied

    tools, result, denied = asyncio.run(session())
    assert "describe_dataset" in {t.name for t in tools.tools}
    assert json.loads(result.content[0].text)["value"] == 4_250_000
    assert denied.is_error and "Denied by the disclosure policy" in denied.content[0].text


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_http_end_to_end_requires_a_valid_key(example, capsys):
    port = _free_port()
    text = example.read_text().replace('transport = "stdio"', 'transport = "http"')
    example.write_text(text.replace("port = 8000", f"port = {port}"))
    main(["keys", "create", "alice@example.com", "--config", str(example)])
    token = capsys.readouterr().out.strip()

    proc = subprocess.Popen(
        [sys.executable, "-m", "tokenis", "--log-level", "WARNING", "serve", "--config",
         str(example)],
        env={**os.environ, **ENV}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                if proc.poll() is not None:
                    pytest.fail(proc.stderr.read().decode())
                time.sleep(0.2)
        url = f"http://127.0.0.1:{port}/mcp"

        import httpx2
        from mcp.client.client import Client
        from mcp.client.streamable_http import streamable_http_client

        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        headers = {"Accept": "application/json, text/event-stream"}
        assert httpx2.post(url, json=init, headers=headers).status_code == 401
        bad = {**headers, "Authorization": "Bearer tkn_forged"}
        assert httpx2.post(url, json=init, headers=bad).status_code == 401

        async def session():
            http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"},
                                      timeout=httpx2.Timeout(30.0))
            async with http, Client(streamable_http_client(url, http_client=http)) as client:
                return await client.call_tool("describe_dataset", {})

        result = asyncio.run(session())
        described = json.loads(result.content[0].text)
        assert described["records"] == 60
        assert described["budget"]["remaining"] == 200
    finally:
        proc.terminate()
        proc.wait(timeout=20)
