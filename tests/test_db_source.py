# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Loading data straight from a database through SQLAlchemy.

SQLite runs everywhere; PostgreSQL and MySQL run when TOKENIS_TEST_POSTGRES_URL
/ TOKENIS_TEST_MYSQL_URL point at a server (CI starts both as services)."""
import os
import sqlite3
from decimal import Decimal

import pytest

sqlalchemy = pytest.importorskip("sqlalchemy")
config = pytest.importorskip("tokenis.config")

ENV = {"TOKENIS_TOKENIZER_KEY": "11" * 32}

COLUMNS = """
[[columns]]
name = "customer"
protection = "token"
[[columns]]
name = "industry"
protection = "open"
[[columns]]
name = "revenue"
protection = "sealed"
scale = 2
[admission]
min_query_set_size = 3
window = "total"
"""

ROWS = [(i, f"c{i}", "tech" if i % 2 else "retail", Decimal(f"{1000 + i}.25")) for i in range(1, 13)]


def write_config(tmp_path, data):
    path = tmp_path / "tokenis.toml"
    path.write_text(data + COLUMNS)
    return config.load_config(path)


def check_answers(svc):
    total = svc.invoke("aggregate", "a", {"function": "sum", "column": "revenue",
                                          "filters": {"industry": "tech"}})
    expected = sum(r[3] for r in ROWS if r[2] == "tech")
    assert total["value"] == pytest.approx(float(expected))
    assert total["matched_records"] == 6


def seed(url):
    engine = sqlalchemy.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sqlalchemy.text("DROP TABLE IF EXISTS customers"))
        conn.execute(sqlalchemy.text(
            "CREATE TABLE customers (id INTEGER PRIMARY KEY, customer VARCHAR(40), "
            "industry VARCHAR(40), revenue NUMERIC(12, 2))"))
        conn.execute(sqlalchemy.text(
            "INSERT INTO customers VALUES (:id, :customer, :industry, :revenue)"),
            [{"id": i, "customer": c, "industry": ind, "revenue": str(rev)} for i, c, ind, rev in ROWS])
    engine.dispose()


def test_sqlite_table_and_query(tmp_path):
    db = tmp_path / "crm.sqlite"
    seed(f"sqlite:///{db}")
    for source in ('table = "customers"',
                   'query = "SELECT id, customer, industry, revenue FROM customers WHERE revenue > 0"'):
        cfg = write_config(tmp_path, f'[data]\nurl = "sqlite:///{db}"\nid_column = "id"\n{source}\n')
        check_answers(config.build_service(cfg, environ=ENV))


def test_credentials_stay_out_of_the_config(tmp_path):
    with pytest.raises(config.ConfigError, match="password"):
        write_config(tmp_path, '[data]\nurl = "postgresql://tokenis:hunter2@db/crm"\ntable = "t"\n')
    cfg = write_config(tmp_path, '[data]\nurl_env = "CRM_DB_URL"\ntable = "customers"\n')
    with pytest.raises(config.ConfigError, match="CRM_DB_URL"):
        config.build_service(cfg, environ=ENV)
    with pytest.raises(config.ConfigError, match="plain"):
        write_config(tmp_path, '[data]\nurl_env = "X"\ntable = "t; DROP TABLE t"\n')
    with pytest.raises(config.ConfigError, match="exactly one"):
        write_config(tmp_path, '[data]\nurl_env = "X"\ntable = "t"\nquery = "SELECT 1"\n')


def test_database_errors_are_reported_cleanly(tmp_path):
    db = tmp_path / "empty.sqlite"
    sqlite3.connect(db).close()
    cfg = write_config(tmp_path, f'[data]\nurl = "sqlite:///{db}"\ntable = "missing"\n')
    with pytest.raises(config.ConfigError, match="database error reading missing"):
        config.build_service(cfg, environ=ENV)


@pytest.mark.parametrize("env_name", ["TOKENIS_TEST_POSTGRES_URL", "TOKENIS_TEST_MYSQL_URL"])
def test_server_databases(tmp_path, env_name):
    url = os.environ.get(env_name)
    if not url:
        pytest.skip(f"{env_name} not set")
    seed(url)
    cfg = write_config(tmp_path, '[data]\nurl_env = "DB_URL"\nid_column = "id"\ntable = "customers"\n')
    check_answers(config.build_service(cfg, environ={**ENV, "DB_URL": url}))
