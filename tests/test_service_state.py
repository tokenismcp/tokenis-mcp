# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Durable state: a restart must not forget the admission history (audit
finding: the second half of a differencing pair could simply be asked after
a restart), and the persisted disclosure trace must detect tampering."""
import json
import os
import stat

import pytest

from tokenis.audit.trace import DisclosureTrace, TraceIntegrityError
from tokenis.gateway.schema import (
    AdmissionSettings,
    ColumnSpec,
    DecryptionSettings,
    DisclosureSettings,
    GatewaySettings,
    Schema,
)
from tokenis.gateway.service import AdmissionDenied, TokenisGatewayService
from tokenis.gateway.state import StateMismatchError

KEY = b"t" * 32
AUDIT_KEY = b"a" * 32
SCHEMA = Schema(columns=(ColumnSpec("revenue", "sealed"), ColumnSpec("industry", "open"),
                         ColumnSpec("region", "open")))
ROWS = [("tech", "gangnam", 100), ("tech", "gangnam", 200), ("tech", "gangnam", 300),
        ("tech", "jongno", 4242)] + [("finance", "busan", 10 * i) for i in range(6)]
SUM = {"function": "sum", "column": "revenue"}


def gateway(state_dir, rows=ROWS, budget=100, audit_key=AUDIT_KEY, reset=False):
    settings = GatewaySettings(
        admission=AdmissionSettings(min_query_set_size=3, budget=budget, window="total"),
        decryption=DecryptionSettings(max_value=1 << 24, table_size=None),
        disclosure=DisclosureSettings(latency_granularity_ms=1.0),
    )
    svc = TokenisGatewayService(SCHEMA, KEY, settings, state_dir=state_dir, audit_key=audit_key,
                                reset_admission_state=reset)
    for i, (industry, region, revenue) in enumerate(rows):
        svc.ingest(str(i), {"industry": industry, "region": region, "revenue": revenue})
    return svc


def test_differencing_across_a_restart_is_refused(tmp_path):
    first = gateway(tmp_path)
    first.invoke("aggregate", "mallory", {**SUM, "filters": {"industry": "tech"}})
    restarted = gateway(tmp_path)
    with pytest.raises(AdmissionDenied) as exc:
        restarted.invoke("aggregate", "mallory",
                         {**SUM, "filters": {"industry": "tech", "region": "gangnam"}})
    assert exc.value.rule == "D2"


def test_row_order_does_not_change_the_history_fingerprint(tmp_path):
    """Regression (stability review): the fingerprint hashed rows in load
    order, so a replica whose database returned the same rows in another
    order refused to start."""
    first = gateway(tmp_path)
    first.invoke("aggregate", "mallory", {**SUM, "filters": {"industry": "tech"}})
    reordered = gateway(tmp_path, rows=list(reversed(ROWS)))
    with pytest.raises(AdmissionDenied):  # and the history still applies
        reordered.invoke("aggregate", "mallory",
                         {**SUM, "filters": {"industry": "tech", "region": "gangnam"}})
    with pytest.raises(StateMismatchError):  # different rows are still detected
        gateway(tmp_path, rows=ROWS + [("tech", "gangnam", 1)]).seal()


def test_budget_survives_a_restart(tmp_path):
    first = gateway(tmp_path, budget=2)
    for _ in range(2):
        first.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "finance"}})
    restarted = gateway(tmp_path, budget=2)
    with pytest.raises(AdmissionDenied) as exc:
        restarted.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "finance"}})
    assert exc.value.rule == "D3"
    # Raising the budget is a safe configuration change: history replays.
    raised = gateway(tmp_path, budget=3)
    raised.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "finance"}})


def test_trace_is_persisted_signed_and_private(tmp_path):
    first = gateway(tmp_path)
    first.invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    with pytest.raises(AdmissionDenied):
        first.invoke("aggregate", "a", {**SUM, "filters": {"industry": "nope"}})
    path = tmp_path / "trace.jsonl"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert [line["kind"] for line in lines] == ["aggregate", "denial"]
    assert all("mac" in line for line in lines)
    restarted = gateway(tmp_path)
    assert len(restarted.trace) == 2 and restarted.trace.verify_chain()
    restarted.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "tech"}})
    assert len(DisclosureTrace(path, hmac_key=AUDIT_KEY)) == 3


def test_tampered_or_rekeyed_trace_refuses_to_load(tmp_path):
    gateway(tmp_path).invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    path = tmp_path / "trace.jsonl"
    with pytest.raises(TraceIntegrityError, match="HMAC"):
        DisclosureTrace(path, hmac_key=b"x" * 32)
    entry = json.loads(path.read_text())
    entry["value_summary"] = "0"
    path.write_text(json.dumps(entry) + "\n")
    with pytest.raises(TraceIntegrityError, match="modified"):
        gateway(tmp_path)
    # Recomputing the digest does not help without the HMAC key.
    from tokenis.audit.trace import AuditRecord, TraceEntry

    forged = TraceEntry(entry["kind"], AuditRecord.from_dict(entry["audit"]), "0",
                        entry["prev_hash"], entry["index"])
    entry["digest"] = forged.digest
    path.write_text(json.dumps(entry) + "\n")
    with pytest.raises(TraceIntegrityError, match="HMAC"):
        DisclosureTrace(path, hmac_key=AUDIT_KEY)


def test_changed_data_needs_an_explicit_reset(tmp_path):
    gateway(tmp_path).invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    changed = ROWS + [("tech", "busan", 7)]
    with pytest.raises(StateMismatchError, match="reset"):
        gateway(tmp_path, rows=changed).invoke(
            "aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    fresh = gateway(tmp_path, rows=changed, reset=True)
    fresh.invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    assert list(tmp_path.glob("admission.jsonl.*.old"))


def test_torn_final_lines_from_a_crash_are_repaired(tmp_path):
    gateway(tmp_path).invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech"}})
    for name in ("admission.jsonl", "trace.jsonl"):
        with (tmp_path / name).open("a") as fh:
            fh.write('{"op": "decide", "subj')
    restarted = gateway(tmp_path)
    with pytest.raises(AdmissionDenied):
        restarted.invoke("aggregate", "a", {**SUM, "filters": {"industry": "tech", "region": "gangnam"}})
    restarted.invoke("aggregate", "a", {"function": "count", "filters": {"industry": "finance"}})
    # ...and the files stay loadable afterwards (appends did not land after garbage).
    again = gateway(tmp_path)
    assert again.trace.verify_chain() and len(again.trace) == 3


def test_a_failed_trail_write_leaves_a_valid_trail(tmp_path, monkeypatch):
    """Regression (stability review): a partial write (disk full) stayed in
    the file, the next entry was glued onto it, and the trail no longer
    verified -- nor would the gateway restart."""
    import tokenis.audit.trace as trace_module

    svc = gateway(tmp_path)
    svc.invoke("aggregate", "a", {**SUM, "filters": {"industry": "finance"}})
    real_fsync = trace_module.os.fsync
    calls = {"n": 0}

    def failing_fsync(fd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(28, "No space left on device")
        return real_fsync(fd)

    monkeypatch.setattr(trace_module.os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        svc.invoke("aggregate", "a", {**SUM, "filters": {"region": "busan"}})
    monkeypatch.setattr(trace_module.os, "fsync", real_fsync)
    svc.invoke("aggregate", "a", {**SUM, "filters": {"region": "busan"}})
    assert svc.trace.verify_chain()
    assert gateway(tmp_path).trace.verify_chain()  # and it restarts
