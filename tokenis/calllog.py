# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Cluster-wide call statistics and the admin activity log, in SQL.

Every tool call is recorded -- tool, principal, outcome, denial rule, time
taken and the replica that served it; never an argument or a value -- so the
admin console shows the same numbers on every replica, over any time range,
and nothing resets when a process restarts. With the postgres state backend
the table lives in the shared database; a single server uses SQLite in its
state directory.

Recording must not slow calls down or fail them: records are queued in
memory and written in batches every couple of seconds by a background
thread. This is operational telemetry. The security record of what was
disclosed is the hash-chained, signed audit trail (tokenis.audit.trace),
which is written synchronously before any answer is released.
"""
from __future__ import annotations

import atexit
import logging
import math
import os
import socket
import sqlite3
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Iterator, List, Optional, Sequence, Tuple

log = logging.getLogger("tokenis.calllog")

#: Selectable ranges: (length in seconds, bucket width in seconds).
RANGES: Dict[str, Tuple[int, int]] = {
    "1h": (3600, 60),
    "24h": (86400, 1800),
    "7d": (7 * 86400, 3 * 3600),
    "30d": (30 * 86400, 12 * 3600),
}
#: Latency percentiles are exact over the most recent calls in the range, up
#: to this many (so a 30-day view stays cheap to compute).
LATENCY_SAMPLE = 200_000
MAX_QUEUE = 100_000

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS tokenis_calls (
        tenant      TEXT    NOT NULL,
        ts_ms       BIGINT  NOT NULL,
        replica     TEXT    NOT NULL,
        tool        TEXT    NOT NULL,
        principal   TEXT    NOT NULL,
        outcome     TEXT    NOT NULL,
        rule        TEXT    NOT NULL,
        duration_ms REAL    NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS tokenis_calls_time ON tokenis_calls (tenant, ts_ms)",
    """CREATE TABLE IF NOT EXISTS tokenis_admin_log (
        tenant  TEXT   NOT NULL,
        ts_ms   BIGINT NOT NULL,
        actor   TEXT   NOT NULL,
        action  TEXT   NOT NULL,
        target  TEXT   NOT NULL,
        detail  TEXT   NOT NULL,
        source  TEXT   NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS tokenis_admin_log_time ON tokenis_admin_log (tenant, ts_ms)",
)


def range_spec(key: str) -> Tuple[str, int, int]:
    """A known range key (defaulting to 24h), its length and bucket width."""
    key = key if key in RANGES else "24h"
    length, step = RANGES[key]
    return key, length, step


def _percentile(values: Sequence[float], q: float) -> Optional[float]:
    """Nearest-rank percentile of already sorted ``values``."""
    if not values:
        return None
    index = min(len(values) - 1, max(0, math.ceil(q * len(values)) - 1))
    return round(float(values[index]), 1)


class CallLog:
    """Queue, batch writer and queries; subclasses supply the connection."""

    placeholder = "%s"

    def __init__(self, tenant: str, *, replica: Optional[str] = None, retention_days: int = 90) -> None:
        self.tenant = tenant
        self.replica = replica or f"{socket.gethostname()}:{os.getpid()}"
        self.retention_days = retention_days
        self.dropped = 0
        self._queue: Deque[Tuple[Any, ...]] = deque()
        self._queue_lock = threading.Lock()
        self._db_lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_purge = 0.0

    # -- connection (subclasses) -------------------------------------------------

    def _run_sql(self, sql: str, params: Sequence[Any] = (), many: bool = False) -> List[Tuple[Any, ...]]:
        raise NotImplementedError

    def _sql(self, sql: str) -> str:
        return sql if self.placeholder == "%s" else sql.replace("%s", "?")

    def _query(self, sql: str, params: Sequence[Any] = ()) -> List[Tuple[Any, ...]]:
        with self._db_lock:
            return self._run_sql(self._sql(sql), params)

    def create_schema(self) -> None:
        with self._db_lock:
            for statement in SCHEMA:
                self._run_sql(statement)

    # -- writing ---------------------------------------------------------------------

    def start(self) -> "CallLog":
        self._thread = threading.Thread(target=self._loop, name="tokenis-calllog", daemon=True)
        self._thread.start()
        atexit.register(self.close)
        return self

    def record(self, tool: str, principal: str, outcome: str, rule: Optional[str], seconds: float) -> None:
        """Queue one call (never blocks on the database, never raises)."""
        row = (self.tenant, int(time.time() * 1000), self.replica, tool, principal or "",
               outcome, rule or "", round(seconds * 1000, 3))
        with self._queue_lock:
            if len(self._queue) >= MAX_QUEUE:
                self.dropped += 1
                return
            self._queue.append(row)

    def flush(self) -> int:
        with self._queue_lock:
            rows = list(self._queue)
            self._queue.clear()
        if not rows:
            return 0
        try:
            with self._db_lock:
                self._run_sql(self._sql(
                    "INSERT INTO tokenis_calls (tenant, ts_ms, replica, tool, principal, outcome, rule, "
                    "duration_ms) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"), rows, many=True)
        except Exception as exc:  # noqa: BLE001 -- telemetry must never break serving
            with self._queue_lock:  # keep them for the next attempt, within the cap
                room = MAX_QUEUE - len(self._queue)
                self._queue.extendleft(reversed(rows[-room:] if room > 0 else []))
                self.dropped += max(0, len(rows) - max(room, 0))
            log.warning("call statistics not written yet (%s); will retry", type(exc).__name__)
            return 0
        return len(rows)

    def _loop(self) -> None:
        while not self._stop.wait(2.0):
            self.flush()
            if time.time() - self._last_purge > 3600:
                self._last_purge = time.time()
                try:
                    self.purge()
                except Exception as exc:  # noqa: BLE001
                    log.warning("call statistics purge failed: %s", type(exc).__name__)

    def close(self) -> None:
        self._stop.set()
        self.flush()

    def purge(self) -> None:
        cutoff = int((time.time() - self.retention_days * 86400) * 1000)
        self._query("DELETE FROM tokenis_calls WHERE tenant = %s AND ts_ms < %s", (self.tenant, cutoff))

    # -- queries -----------------------------------------------------------------------

    def overview(self, range_key: str) -> Dict[str, Any]:
        """Totals, comparison with the previous period, timeline, per tool,
        per rule, latency percentiles and replicas -- for the whole cluster."""
        self.flush()  # include this replica's latest calls
        key, length, step = range_spec(range_key)
        now_ms = int(time.time() * 1000)
        start = now_ms - length * 1000
        t, s = self.tenant, step * 1000

        outcomes: Dict[str, int] = {}
        for outcome, n in self._query(
                "SELECT outcome, COUNT(*) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
                "GROUP BY outcome", (t, start)):
            outcomes[str(outcome)] = int(n)
        previous: Dict[str, int] = {}
        for outcome, n in self._query(
                "SELECT outcome, COUNT(*) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
                "AND ts_ms < %s GROUP BY outcome", (t, start - length * 1000, start)):
            previous[str(outcome)] = int(n)

        first_bucket = (start // s) * s
        buckets = {first_bucket + i * s: {"ok": 0, "denied": 0, "other": 0}
                   for i in range((now_ms - first_bucket) // s + 1)}
        for bucket, outcome, n in self._query(
                "SELECT (ts_ms / %s) * %s AS b, outcome, COUNT(*) FROM tokenis_calls "
                "WHERE tenant = %s AND ts_ms >= %s GROUP BY b, outcome", (s, s, t, start)):
            slot = buckets.setdefault(int(bucket), {"ok": 0, "denied": 0, "other": 0})
            name = outcome if outcome in ("ok", "denied") else "other"
            slot[name] += int(n)
        timeline = [{"t": b / 1000, **v} for b, v in sorted(buckets.items())]

        tools: Dict[str, Dict[str, int]] = {}
        for tool, outcome, n in self._query(
                "SELECT tool, outcome, COUNT(*) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
                "GROUP BY tool, outcome", (t, start)):
            tools.setdefault(str(tool), {})[str(outcome)] = int(n)
        rules = {str(r): int(n) for r, n in self._query(
            "SELECT rule, COUNT(*) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
            "AND outcome = 'denied' GROUP BY rule", (t, start))}

        durations = [float(d) for (d,) in self._query(
            "SELECT d FROM (SELECT duration_ms AS d FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
            "ORDER BY ts_ms DESC LIMIT %s) AS recent ORDER BY d", (t, start, LATENCY_SAMPLE))]

        replicas = [
            {"replica": str(r), "calls": int(n), "last_seen": int(last) / 1000}
            for r, n, last in self._query(
                "SELECT replica, COUNT(*), MAX(ts_ms) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
                "GROUP BY replica ORDER BY MAX(ts_ms) DESC", (t, start))
        ]
        return {
            "range": key, "step_seconds": step, "since": start / 1000,
            "totals": outcomes, "previous": previous, "timeline": timeline,
            "tools": tools, "denials_by_rule": rules, "replicas": replicas,
            "latency": {"p50": _percentile(durations, 0.5), "p95": _percentile(durations, 0.95),
                        "p99": _percentile(durations, 0.99), "samples": len(durations)},
            "dropped": self.dropped,
        }

    def principals(self, range_key: str) -> List[Dict[str, Any]]:
        self.flush()
        _, length, _ = range_spec(range_key)
        start = int((time.time() - length) * 1000)
        rows: Dict[str, Dict[str, Any]] = {}
        for principal, total, ok, denied, last in self._query(
                "SELECT principal, COUNT(*), SUM(CASE WHEN outcome = 'ok' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN outcome = 'denied' THEN 1 ELSE 0 END), MAX(ts_ms) FROM tokenis_calls "
                "WHERE tenant = %s AND ts_ms >= %s AND principal <> '' GROUP BY principal",
                (self.tenant, start)):
            rows[str(principal)] = {"principal": str(principal), "calls": int(total), "answered": int(ok or 0),
                                    "denied": int(denied or 0), "last_seen": int(last) / 1000, "rules": {}}
        for principal, rule, n in self._query(
                "SELECT principal, rule, COUNT(*) FROM tokenis_calls WHERE tenant = %s AND ts_ms >= %s "
                "AND outcome = 'denied' AND principal <> '' GROUP BY principal, rule", (self.tenant, start)):
            if str(principal) in rows:
                rows[str(principal)]["rules"][str(rule)] = int(n)
        return sorted(rows.values(), key=lambda r: -r["calls"])

    def export(self, range_key: str) -> Iterator[Tuple[Any, ...]]:
        """(time, replica, tool, principal, outcome, rule, duration_ms), oldest
        first, in pages."""
        self.flush()
        _, length, _ = range_spec(range_key)
        last = int((time.time() - length) * 1000) - 1
        while True:
            rows = self._query(
                "SELECT ts_ms, replica, tool, principal, outcome, rule, duration_ms FROM tokenis_calls "
                "WHERE tenant = %s AND ts_ms > %s ORDER BY ts_ms LIMIT 5000", (self.tenant, last))
            if not rows:
                return
            yield from rows
            last = int(rows[-1][0])
            if len(rows) < 5000:
                return

    # -- admin activity ------------------------------------------------------------------

    def admin_event(self, actor: str, action: str, target: str, detail: str, source: str) -> None:
        """Record an administrative action synchronously (it must not be lost)."""
        self._query("INSERT INTO tokenis_admin_log (tenant, ts_ms, actor, action, target, detail, source) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (self.tenant, int(time.time() * 1000), actor, action, target, detail, source))

    def admin_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [
            {"time": int(ts) / 1000, "actor": a, "action": act, "target": tg, "detail": d, "source": src}
            for ts, a, act, tg, d, src in self._query(
                "SELECT ts_ms, actor, action, target, detail, source FROM tokenis_admin_log "
                "WHERE tenant = %s ORDER BY ts_ms DESC LIMIT %s", (self.tenant, limit))
        ]


class SqliteCallLog(CallLog):
    """One server: a SQLite file in the state directory (or in memory)."""

    placeholder = "?"

    def __init__(self, path: str, tenant: str, **kwargs: Any) -> None:
        super().__init__(tenant, **kwargs)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10)
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            os.chmod(path, 0o600)
        self.create_schema()

    def _run_sql(self, sql: str, params: Sequence[Any] = (), many: bool = False) -> List[Tuple[Any, ...]]:
        if many:
            self._conn.executemany(sql, params)
            return []
        return self._conn.execute(sql, params).fetchall()


class PostgresCallLog(CallLog):
    """Several replicas: the shared PostgreSQL database, on a connection of
    its own (statistics never wait for, or hold up, a tool call's lock)."""

    def __init__(self, url: str, tenant: str, **kwargs: Any) -> None:
        import psycopg

        from tokenis.gateway.pgstate import CONNECT_OPTIONS

        super().__init__(tenant, **kwargs)
        self._psycopg = psycopg
        self._url = url
        self._options = CONNECT_OPTIONS
        self._conn: Any = None
        self.create_schema()

    def _run_sql(self, sql: str, params: Sequence[Any] = (), many: bool = False) -> List[Tuple[Any, ...]]:
        for attempt in (1, 2):
            if self._conn is None or self._conn.closed:
                self._conn = self._psycopg.connect(self._url, autocommit=True, **self._options)
            try:
                with self._conn.cursor() as cur:
                    if many:
                        cur.executemany(sql, params)
                        return []
                    cur.execute(sql, params)
                    return cur.fetchall() if cur.description else []
            except self._psycopg.OperationalError:
                self._conn.close()
                self._conn = None
                if attempt == 2:
                    raise
        return []
