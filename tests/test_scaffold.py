# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""`tokenis-mcp init`: a starting configuration from a data file. The guesses must
protect more, never less, and what it writes must load and answer questions."""
import stat
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="needs the `server` extra (Python >= 3.10)")

from tokenis.cli import main
from tokenis.config import build_service, load_config
from tokenis.scaffold import analyse, decryption_max, normalise

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
HEADER = "id,Customer Name,E-mail,Industry,Annual Revenue (KRW),Score,Year,Notes\n"


def write_csv(tmp_path, rows, header=HEADER, name="clients.csv"):
    path = tmp_path / name
    path.write_text(header + "".join(rows), encoding="utf-8")
    return path


def sample(n=30, **overrides):
    rows = []
    for i in range(n):
        values = {"id": f"R{i:03d}", "name": f"Firm {i}", "mail": f"p{i}@x.example", "industry": ["tech", "retail", "bio"][i % 3],
                  "revenue": f"{1000 + i * 7}.5", "score": str(i % 9), "year": "2024", "notes": ""}
        values.update(overrides)
        rows.append(",".join(values[k] for k in ("id", "name", "mail", "industry", "revenue", "score", "year", "notes")) + "\n")
    return rows


def kinds(plan):
    return {c.source: c.protection for c in plan.columns}


def test_columns_are_classified_conservatively(tmp_path):
    plan = analyse(write_csv(tmp_path, sample()))
    assert kinds(plan) == {
        "id": "id", "Customer Name": "token", "E-mail": "token",   # personal names: pseudonyms
        "Industry": "open",                                         # 3 values: a category
        "Annual Revenue (KRW)": "sealed", "Score": "sealed",
        "Year": "open",                                             # a year is a category, not a quantity
        "Notes": "skip",                                            # empty cells
    }
    revenue = next(c for c in plan.columns if c.source.startswith("Annual"))
    assert revenue.name == "annual_revenue_krw" and revenue.scale == 1
    assert "empty cells" in next(c for c in plan.columns if c.name == "notes").reason


def test_many_distinct_text_values_become_pseudonyms_not_open(tmp_path):
    rows = [f"R{i},{i},x,city{i},1.0,1,2024,n\n" for i in range(80)]
    plan = analyse(write_csv(tmp_path, rows))
    assert kinds(plan)["Industry"] == "token"   # 80 distinct values: an identifier, not a category


def test_a_non_unique_id_like_column_is_not_the_id(tmp_path):
    rows = [f"A,{i},x,tech,1.0,1,2024,n\n" for i in range(10)]
    assert kinds(analyse(write_csv(tmp_path, rows)))["id"] != "id"


def test_names_are_normalised():
    assert normalise("Annual Revenue (KRW)") == "annual_revenue_krw"
    assert normalise("2024 sales") == "c_2024_sales" and normalise("###") == ""


def test_the_decryption_bound_grows_with_the_data(tmp_path):
    small = decryption_max(analyse(write_csv(tmp_path, sample())))
    assert small == (2 ** 36, None)
    big = analyse(write_csv(tmp_path, sample(5, revenue="9" * 12 + ".5"), name="big.csv"))
    value, warning = decryption_max(big)
    assert value > 2 ** 36 and warning is None or value == 2 ** 40


def test_init_writes_a_config_that_loads_and_answers(tmp_path, monkeypatch, capsys):
    data = write_csv(tmp_path, sample())
    out = tmp_path / "gateway"
    main(["init", str(data), "--out-dir", str(out), "--k", "3"])
    assert "checked 30 records" in capsys.readouterr().out
    env = out / ".env"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    keys = dict(line.split("=", 1) for line in env.read_text().splitlines() if "=" in line and not line.startswith("#"))
    assert set(keys) == {"TOKENIS_TOKENIZER_KEY", "TOKENIS_AUDIT_KEY"} and all(len(v) == 64 for v in keys.values())
    for name, value in keys.items():
        monkeypatch.setenv(name, value.strip())
    service = build_service(load_config(out / "tokenis.toml"))
    answer = service.invoke("group_by", "tester", {"key": "industry", "function": "sum", "column": "annual_revenue_krw"})
    assert {g["group"] for g in answer["groups"]} == {"tech", "retail", "bio"}
    assert answer["groups"][0]["value"] > 0
    # Nothing personal is released verbatim.
    config = (out / "tokenis.toml").read_text()
    assert 'name = "e_mail"\nprotection = "token"' in config and 'name = "customer_name"\nprotection = "token"' in config


def test_init_does_not_overwrite_without_force(tmp_path, capsys):
    data = write_csv(tmp_path, sample())
    main(["init", str(data), "--out-dir", str(tmp_path)])
    first = (tmp_path / ".env").read_text()
    with pytest.raises(SystemExit):
        main(["init", str(data), "--out-dir", str(tmp_path)])
    assert (tmp_path / ".env").read_text() == first
    main(["init", str(data), "--out-dir", str(tmp_path), "--force"])
    assert (tmp_path / ".env").read_text() != first


def test_dry_run_writes_nothing(tmp_path, capsys):
    main(["init", str(write_csv(tmp_path, sample())), "--out-dir", str(tmp_path / "x"), "--dry-run"])
    assert "sealed" in capsys.readouterr().out and not (tmp_path / "x").exists()


def test_the_env_file_is_added_to_gitignore_in_a_repository(tmp_path):
    (tmp_path / ".git").mkdir()
    main(["init", str(write_csv(tmp_path, sample())), "--out-dir", str(tmp_path)])
    assert {".env", "state/"} <= set((tmp_path / ".gitignore").read_text().splitlines())


def test_a_file_without_numbers_is_refused(tmp_path):
    path = tmp_path / "t.csv"
    path.write_text("id,industry\n" + "".join(f"R{i},{'ab'[i % 2]}\n" for i in range(10)))
    with pytest.raises(SystemExit):
        main(["init", str(path), "--out-dir", str(tmp_path / "o")])


def test_init_on_the_example_data_detects_the_embedding_and_id(tmp_path, capsys):
    main(["init", str(EXAMPLES / "data" / "customers.csv"), "--out-dir", str(tmp_path)])
    config = (tmp_path / ".." / tmp_path.name / "tokenis.toml").read_text()
    assert 'id_column = "id"' in config and 'embedding_column = "embedding"' in config
    assert 'entity = true' in config


def test_rename_maps_file_headers_to_column_names(tmp_path, monkeypatch):
    from tokenis.config import ConfigError, load_config

    for name in ("TOKENIS_TOKENIZER_KEY", "TOKENIS_AUDIT_KEY"):
        monkeypatch.setenv(name, "ab" * 32)
    base = ('[tenant]\nname = "t"\n[data]\npath = "d.csv"\n[data.rename]\n"Annual Revenue" = "revenue"\n'
            '[[columns]]\nname = "revenue"\nprotection = "sealed"\n[[columns]]\nname = "industry"\nprotection = "open"\n')
    (tmp_path / "d.csv").write_text("industry,Annual Revenue\n" + "".join(f"{'ab'[i % 2]},{i}\n" for i in range(12)))
    (tmp_path / "c.toml").write_text(base)
    assert build_service(load_config(tmp_path / "c.toml"), seal=False).record_count == 12
    for bad, message in (('"Annual Revenue" = "Revenue"', "not a valid column name"),
                         ('"A" = "x"\n"B" = "x"', "same column name")):
        (tmp_path / "bad.toml").write_text(base.replace('"Annual Revenue" = "revenue"', bad))
        with pytest.raises(ConfigError, match=message):
            load_config(tmp_path / "bad.toml")
