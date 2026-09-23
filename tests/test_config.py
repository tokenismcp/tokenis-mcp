# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import json
import shutil
from pathlib import Path

import pytest

config = pytest.importorskip("tokenis.config", reason="needs the `server` extra (tomli on 3.10)")

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
ENV = {"TOKENIS_TOKENIZER_KEY": "11" * 32, "TOKENIS_AUDIT_KEY": "22" * 32}


@pytest.fixture
def example(tmp_path):
    shutil.copy(EXAMPLES / "tokenis.toml", tmp_path / "tokenis.toml")
    shutil.copytree(EXAMPLES / "data", tmp_path / "data")
    return tmp_path / "tokenis.toml"


def test_example_config_loads_and_serves(example):
    cfg = config.load_config(example)
    assert cfg.settings.admission.min_query_set_size == 5
    assert cfg.schema.entity.name == "customer_name"
    assert cfg.state_dir == example.parent / "state"
    svc = config.build_service(cfg, environ=ENV)
    assert svc.record_count == 60
    out = svc.invoke("aggregate", "a", {"function": "sum", "column": "revenue_2025",
                                        "filters": {"industry": "tech"}})
    assert isinstance(out["value"], float) and out["unit"] == "KRW million"
    employees = svc.invoke("aggregate", "a", {"function": "avg", "column": "employees",
                                              "filters": {"size_band": "small"}})
    assert employees["value"].startswith("[")  # result_mode = "band"


def _write(tmp_path, text):
    (tmp_path / "d.csv").write_text("id,amount,team\n1,5,x\n")
    path = tmp_path / "c.toml"
    path.write_text(text)
    return path


BASE = """
[data]
path = "d.csv"
id_column = "id"
[[columns]]
name = "amount"
protection = "sealed"
[[columns]]
name = "team"
protection = "open"
"""


@pytest.mark.parametrize("extra, message", [
    ("[admission]\nbudgett = 5\n", "unknown key"),
    ("[server]\ntransport = \"http\"\n", "requires authentication"),
    ("[auth]\nmode = \"api_keys\"\n", "api_keys_file"),
    ("[auth]\nmode = \"magic\"\n", "mode must be"),
    ("[admission]\nwindow = \"week\"\n", "window"),
    ("[decryption]\nmax_value = 0\n", "max_value"),
])
def test_invalid_configs_are_rejected(tmp_path, extra, message):
    with pytest.raises(config.ConfigError, match=message):
        config.load_config(_write(tmp_path, BASE + extra))


def test_secrets(tmp_path):
    assert config.decode_secret("ab" * 16, "X") == bytes.fromhex("ab" * 16)
    assert len(config.decode_secret("MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", "X")) == 20
    for bad in ("abcd", "not base64 !!", ""):
        with pytest.raises(config.ConfigError):
            config.decode_secret(bad, "X")
    cfg = config.load_config(_write(tmp_path, BASE))
    with pytest.raises(config.ConfigError, match="TOKENIS_TOKENIZER_KEY is not set"):
        config.build_service(cfg, environ={})


def test_row_errors_name_the_file_and_line(tmp_path):
    path = _write(tmp_path, BASE)
    (tmp_path / "d.csv").write_text("id,amount,team\n1,5,x\n2,oops,y\n")
    with pytest.raises(config.ConfigError, match=r"d\.csv:3.*expected a number"):
        config.build_service(config.load_config(path), environ=ENV)


def test_jsonl_and_embeddings(tmp_path):
    rows = [{"id": i, "amount": i, "team": "xy"[i % 2], "who": f"n{i}", "vec": [i, 1.0]}
            for i in range(6)]
    (tmp_path / "d.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    path = tmp_path / "c.toml"
    path.write_text(BASE.replace('path = "d.csv"', 'path = "d.jsonl"\nembedding_column = "vec"')
                    + '[[columns]]\nname = "who"\nprotection = "token"\nentity = true\n'
                    + "[admission]\nmin_query_set_size = 2\n")
    svc = config.build_service(config.load_config(path), environ=ENV)
    assert svc.record_count == 6
    assert "similarity_search" in svc.tool_names
