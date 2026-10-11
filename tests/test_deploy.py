# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deployment assets stay consistent with the code: the Compose config
loads, the Helm chart's copies of the monitoring files match the originals,
and alerts and dashboards only use metrics the gateway exports."""
import json
import re
from pathlib import Path

import pytest

from tokenis.config import load_config

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
CHART = DEPLOY / "helm" / "tokenis"


def exported_metrics():
    source = (ROOT / "tokenis" / "ops.py").read_text()
    names = set(re.findall(r"# TYPE (tokenis_\w+) (\w+)", source))
    out = set()
    for name, kind in names:
        out.add(name)
        if kind == "histogram":
            out |= {f"{name}_bucket", f"{name}_sum", f"{name}_count"}
    return out


def test_compose_config_loads():
    cfg = load_config(DEPLOY / "compose" / "tokenis.toml")
    assert cfg.state_backend == "postgres" and cfg.server.stateless
    assert cfg.keys is not None and cfg.ledger is not None and cfg.auth.mode == "api_keys"


def test_chart_copies_match_the_originals():
    assert (CHART / "files" / "alerts.yml").read_text() == (DEPLOY / "monitoring" / "alerts.yml").read_text()
    assert (CHART / "files" / "grafana-dashboard.json").read_text() == (
        DEPLOY / "monitoring" / "grafana" / "dashboards" / "tokenis.json").read_text()


def test_alerts_and_dashboard_use_exported_metrics():
    known = exported_metrics() | {"up"}
    rules = yaml.safe_load((DEPLOY / "monitoring" / "alerts.yml").read_text())
    exprs = [r["expr"] for g in rules["groups"] for r in g["rules"]]
    for r in (r for g in rules["groups"] for r in g["rules"]):
        assert r["labels"]["severity"] in ("critical", "warning") and r["annotations"]["summary"]
    dashboard = json.loads((DEPLOY / "monitoring" / "grafana" / "dashboards" / "tokenis.json").read_text())
    exprs += [t["expr"] for p in dashboard["panels"] for t in p["targets"]]
    used = {m for e in exprs for m in re.findall(r"\b(tokenis_\w+|up)\b", e)}
    assert used and used <= known, used - known


def test_the_registry_description_fits_the_registry_schema():
    """The MCP Registry schema caps `description` at 100 characters; packaging CI
    validates against it over the network, this catches it offline."""
    import json

    server = json.loads((Path(__file__).resolve().parent.parent / "server.json").read_text(encoding="utf-8"))
    assert 0 < len(server["description"]) <= 100
