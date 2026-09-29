# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Several gateway replicas sharing one PostgreSQL: admission history, the
disclosure trace and API keys. Runs when TOKENIS_TEST_POSTGRES_URL points at
a server (CI starts one as a service)."""
import os
import threading
import uuid

import pytest

URL = os.environ.get("TOKENIS_TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="TOKENIS_TEST_POSTGRES_URL not set")

if URL:
    psycopg = pytest.importorskip("psycopg")
    from tokenis.audit.trace import DisclosureTrace, TraceIntegrityError
    from tokenis.config import api_key_store, build_service, load_config
    from tokenis.gateway.pgstate import PostgresApiKeyStore, PostgresState
    from tokenis.gateway.service import AdmissionDenied
    from tokenis.gateway.state import StateMismatchError

DSN = URL.replace("postgresql+psycopg://", "postgresql://")
KEY = "11" * 32
AUDIT = "22" * 32


# sum(tech) - sum(tech, gangnam) isolates the single tech/jongno record.
ROWS = [("tech", "gangnam", 100), ("tech", "gangnam", 200), ("tech", "gangnam", 300),
        ("tech", "jongno", 4242)] + [("finance", "busan", 10 * i) for i in range(6)]


def write_config(tmp_path, tenant, rows=ROWS, extra=""):
    data = tmp_path / "data.csv"
    lines = ["id,customer,industry,region,revenue"]
    lines += [f"r{i},c{i},{ind},{reg},{rev}" for i, (ind, reg, rev) in enumerate(rows)]
    data.write_text("\n".join(lines) + "\n")
    path = tmp_path / "tokenis.toml"
    path.write_text(f"""
[tenant]
name = "{tenant}"
[data]
path = "data.csv"
id_column = "id"
[[columns]]
name = "customer"
protection = "token"
[[columns]]
name = "region"
protection = "open"
[[columns]]
name = "industry"
protection = "open"
[[columns]]
name = "revenue"
protection = "sealed"
[admission]
min_query_set_size = 3
window = "total"
[state]
backend = "postgres"
audit_key_env = "AUDIT_KEY"
{extra}""")
    return load_config(path)


def env():
    return {"TOKENIS_TOKENIZER_KEY": KEY, "AUDIT_KEY": AUDIT, "TOKENIS_STATE_URL": URL}


@pytest.fixture
def tenant():
    return f"t-{uuid.uuid4().hex[:10]}"


def replicas(tmp_path, tenant, count=2):
    cfg = write_config(tmp_path, tenant)
    return [build_service(cfg, environ=env()) for _ in range(count)]


def total(svc, filters):
    return svc.invoke("aggregate", "analyst", {"function": "sum", "column": "revenue",
                                               "filters": filters})


PAIR = ({"industry": "tech"}, {"industry": "tech", "region": "gangnam"})


def test_a_differencing_pair_split_across_replicas_is_refused(tmp_path, tenant):
    a, b = replicas(tmp_path, tenant)
    total(a, PAIR[0])
    with pytest.raises(AdmissionDenied) as exc:
        total(b, PAIR[1])
    assert exc.value.rule == "D2"
    with pytest.raises(AdmissionDenied):
        total(a, PAIR[1])


def test_restart_restores_the_shared_history(tmp_path, tenant):
    a, _ = replicas(tmp_path, tenant)
    total(a, PAIR[0])
    (fresh,) = replicas(tmp_path, tenant, count=1)
    with pytest.raises(AdmissionDenied):
        total(fresh, PAIR[1])


def test_one_trace_chain_across_replicas(tmp_path, tenant):
    a, b = replicas(tmp_path, tenant)
    total(a, {"region": "busan"})
    total(b, {"region": "gangnam"})
    total(a, {"industry": "finance"})
    state = PostgresState(DSN, tenant)
    trace = DisclosureTrace(hmac_key=bytes.fromhex(AUDIT), storage=state.trace_storage())
    assert len(trace) == 3 and trace.verify_chain()
    assert [e.index for e in trace] == [0, 1, 2]
    # Editing a stored entry is detected.
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("UPDATE tokenis_trace SET entry = jsonb_set(entry, '{value_summary}', "
                     "'\"forged\"') WHERE tenant = %s AND idx = 1", (tenant,))
    with pytest.raises(TraceIntegrityError, match="modified"):
        DisclosureTrace(hmac_key=bytes.fromhex(AUDIT), storage=state.trace_storage())


def test_concurrent_replicas_serialise(tmp_path, tenant):
    services = replicas(tmp_path, tenant, count=3)
    errors = []

    def work(svc, i):
        try:
            for j in range(4):
                svc.invoke("aggregate", f"p{i}", {"function": "count", "filters":
                                                   {"region": ["busan", "gangnam"][j % 2]}})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(s, i)) for i, s in enumerate(services)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    with psycopg.connect(DSN) as conn:
        seqs = [r[0] for r in conn.execute(
            "SELECT seq FROM tokenis_admission_log WHERE tenant = %s ORDER BY seq", (tenant,))]
        idx = [r[0] for r in conn.execute(
            "SELECT idx FROM tokenis_trace WHERE tenant = %s ORDER BY idx", (tenant,))]
    assert seqs == list(range(1, 13)) and idx == list(range(12))


def test_changed_data_needs_an_explicit_reset(tmp_path, tenant):
    (a,) = replicas(tmp_path, tenant, count=1)
    total(a, {"region": "busan"})
    other = tmp_path / "other"
    other.mkdir()
    cfg = write_config(other, tenant, rows=ROWS + [("finance", "busan", 7)])
    with pytest.raises(StateMismatchError):
        build_service(cfg, environ=env())
    svc = build_service(cfg, environ=env(), reset_admission_state=True)
    assert len(svc.trace) == 0
    total(svc, {"region": "busan"})


def test_a_dropped_connection_reconnects_and_keeps_the_invariant(tmp_path, tenant):
    a, b = replicas(tmp_path, tenant)
    total(a, {"region": "busan"})
    # Kill a's connection from the server side (a database restart does this).
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                     "WHERE pid = %s", (a.shared_state._conn.info.backend_pid,))
    total(a, {"industry": "finance"})        # reconnects transparently
    total(b, PAIR[0])
    with pytest.raises(AdmissionDenied):
        total(a, PAIR[1])


def test_a_failover_that_loses_committed_records_is_detected_after_an_error(tmp_path, tenant):
    """Regression (security review): after a failed call the replica rebuilt
    from whatever the database held, so a failover to a lagging standby --
    which always drops connections -- slipped past the rollback check."""
    a, _ = replicas(tmp_path, tenant)
    total(a, PAIR[0])                        # committed: seq 1
    real_append = a.shared_state.append

    def failing_append(record):
        raise psycopg.OperationalError("simulated connection loss")
    a.shared_state.append = failing_append
    with pytest.raises(psycopg.OperationalError):
        total(a, {"region": "busan"})        # the call fails; state is marked stale
    a.shared_state.append = real_append
    with psycopg.connect(DSN, autocommit=True) as conn:  # the standby never had seq 1
        conn.execute("DELETE FROM tokenis_admission_log WHERE tenant = %s", (tenant,))
    with pytest.raises(StateMismatchError):
        total(a, PAIR[1])
    assert a.state_failure is not None


def test_an_edited_record_is_detected_by_every_replica(tmp_path, tenant):
    """Regression (security review): the chain was stored but not verified,
    so a replica syncing later replayed an edited record."""
    a, b = replicas(tmp_path, tenant)
    total(a, PAIR[0])
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("UPDATE tokenis_admission_log SET record = jsonb_set(record, '{admitted}', 'false') "
                     "WHERE tenant = %s AND seq = 1", (tenant,))
    with pytest.raises(StateMismatchError, match="fails verification"):
        total(b, PAIR[1])                    # b had not synced record 1 yet
    with pytest.raises(StateMismatchError):
        replicas(tmp_path, tenant, count=1)  # nor can a new replica start on it


def test_the_chain_is_keyed_by_the_audit_key(tmp_path, tenant):
    a, _ = replicas(tmp_path, tenant)
    total(a, PAIR[0])
    with psycopg.connect(DSN, autocommit=True) as conn:
        record, digest = conn.execute("SELECT record, digest FROM tokenis_admission_log "
                                      "WHERE tenant = %s AND seq = 1", (tenant,)).fetchone()
    import hashlib
    import json as _json
    body = _json.dumps(record, sort_keys=True, separators=(",", ":"))
    assert digest != hashlib.sha256(f"{'0' * 64}\n{body}".encode()).hexdigest()  # not an unkeyed hash


def test_tool_calls_and_readers_never_deadlock(tmp_path, tenant):
    """Regression (stability review): a tool call held the connection lock and
    then took the trace lock; /metrics and the dashboard took them in the
    other order, and one scrape during a call wedged the replica for good."""
    from tokenis.ops import Metrics, summary

    (a,) = replicas(tmp_path, tenant, count=1)
    metrics, stop, errors = Metrics(), threading.Event(), []

    def calls():
        for _ in range(80):
            try:
                total(a, {"region": "busan"})
            except AdmissionDenied:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def readers():
        while not stop.is_set():
            try:
                len(a.trace)
                metrics.render(a)
                summary(a, metrics)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    workers = [threading.Thread(target=calls)] + [threading.Thread(target=readers) for _ in range(3)]
    for t in workers:
        t.start()
    workers[0].join(timeout=60)
    stop.set()
    for t in workers[1:]:
        t.join(timeout=10)
    assert not any(t.is_alive() for t in workers), "deadlock"
    assert not errors


def test_api_keys_are_shared(tmp_path, tenant):
    cfg = write_config(tmp_path, tenant, extra='[auth]\nmode = "api_keys"\n')
    one = api_key_store(cfg, env())
    assert isinstance(one, PostgresApiKeyStore)
    token, record = one.create("alice@example.com")
    two = api_key_store(cfg, env())
    assert two.verify(token) == "alice@example.com"
    assert two.verify(token + "x") is None
    assert [r.principal for r in two.list()] == ["alice@example.com"]
    assert one.revoke(record.key_id)
    assert two.verify(token) is None


def test_a_history_restored_from_an_older_backup_fails_closed(tmp_path, tenant):
    a, b = replicas(tmp_path, tenant)
    total(a, PAIR[0])
    total(b, {"region": "busan"})
    # Simulate restoring the database from a backup taken before those calls.
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DELETE FROM tokenis_admission_log WHERE tenant = %s AND seq > 1", (tenant,))
    with pytest.raises(StateMismatchError, match="changed underneath"):
        total(b, {"region": "gangnam"})
    assert b.state_failure is not None
    with pytest.raises(StateMismatchError):  # stays closed until restarted
        total(b, {"region": "gangnam"})


def test_a_rewritten_record_is_detected_by_replicas_that_saw_the_original(tmp_path, tenant):
    """The case a sequence-number check misses: after a restore, a replica
    that never saw record 2 writes a new record 2. The replica that saw the
    original must notice rather than skip the new one."""
    a, b = replicas(tmp_path, tenant)
    total(a, {"region": "busan"})
    total(b, {"region": "gangnam"})          # b has seen seq 2
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DELETE FROM tokenis_admission_log WHERE tenant = %s AND seq = 2", (tenant,))
    a._last_seq, a._last_digest = 1, a.shared_state.records_after(0)[0][2]  # a never saw seq 2
    total(a, PAIR[0])                        # a writes a different seq 2
    with pytest.raises(StateMismatchError):
        total(b, PAIR[1])


def test_a_reset_elsewhere_stops_old_replicas(tmp_path, tenant):
    (old,) = replicas(tmp_path, tenant, count=1)
    total(old, {"region": "busan"})
    other = tmp_path / "other"
    other.mkdir()
    cfg = write_config(other, tenant, rows=ROWS + [("finance", "busan", 7)])
    build_service(cfg, environ=env(), reset_admission_state=True)
    with pytest.raises(StateMismatchError, match="reset or replaced"):
        total(old, {"region": "busan"})


def test_console_statistics_are_shared_by_replicas(tenant):
    """The admin console's numbers come from one table every replica writes."""
    from tokenis.calllog import PostgresCallLog

    a = PostgresCallLog(URL, tenant, replica="replica-a")
    b = PostgresCallLog(URL, tenant, replica="replica-b")
    for i in range(12):
        a.record("aggregate", f"user{i % 3}", "denied" if i % 4 == 0 else "ok", "D2" if i % 4 == 0 else None, 0.26)
    for _ in range(5):
        b.record("group_by", "user9", "ok", None, 0.51)
    b.flush()
    for view in (a.overview("1h"), b.overview("1h")):  # the same from either replica
        assert view["totals"] == {"ok": 14, "denied": 3} and view["denials_by_rule"] == {"D2": 3}
        assert {r["replica"] for r in view["replicas"]} == {"replica-a", "replica-b"}
        assert view["latency"]["p50"] == 260.0 and view["latency"]["p99"] == 510.0
    assert {r["principal"] for r in a.principals("24h")} == {"user0", "user1", "user2", "user9"}
    assert len(list(b.export("1h"))) == 17
    a.admin_event("admin console", "revoke key", "abc123", "", "10.0.0.1")
    assert b.admin_events()[0]["target"] == "abc123"
