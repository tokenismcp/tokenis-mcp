# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared state in PostgreSQL, so several gateway processes (replicas behind
a load balancer) act as one: the same admission history, budgets, disclosure
trace and API keys, whichever replica serves a call.

Every tool call runs inside one database transaction that first takes a
transaction-scoped advisory lock for the tenant. Under that lock the replica
replays any admission records other replicas appended since it last looked,
decides, computes, appends its own records and trace entries, and commits.
Admission decisions are therefore serialised across the whole deployment
exactly as they are within one process -- the property that stops two
halves of a differencing pair being admitted by two different replicas.

The cost is one short transaction per call; throughput is bounded by that
serialisation (see docs/deployment.md). Replicas give availability, not
parallel speed-up.

Tables (created on first use): ``tokenis_state``, ``tokenis_admission_log``,
``tokenis_trace`` and ``tokenis_api_keys``, all keyed by tenant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple, Type

from tokenis.audit.trace import TraceEntry, entry_from_dict, entry_to_dict
from tokenis.gateway.state import StateMismatchError
from tokenis.safe import equal

_GENESIS = "0" * 64

#: Connection settings. Server-side timeouts bound how long a call can wait
#: for the tenant lock or a statement; idle_in_transaction_session_timeout
#: makes the server end the session of a replica that froze or died inside a
#: transaction, which releases the tenant lock for the others. Keepalives and
#: tcp_user_timeout notice a vanished database host.
CONNECT_OPTIONS: Dict[str, Any] = {
    "connect_timeout": 5,
    "keepalives": 1,
    "keepalives_idle": 10,
    "keepalives_interval": 3,
    "keepalives_count": 3,
    "tcp_user_timeout": 15000,
    "options": ("-c statement_timeout=15000 -c lock_timeout=15000 "
                "-c idle_in_transaction_session_timeout=30000"),
    "application_name": "tokenis-gateway",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tokenis_state (
    tenant      TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    created     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tokenis_admission_log (
    tenant TEXT   NOT NULL,
    seq    BIGINT NOT NULL,
    record JSONB  NOT NULL,
    digest TEXT   NOT NULL,   -- HMAC(audit key, previous digest || record): a keyed chain
    PRIMARY KEY (tenant, seq)
);
CREATE TABLE IF NOT EXISTS tokenis_trace (
    tenant TEXT   NOT NULL,
    idx    BIGINT NOT NULL,
    entry  JSONB  NOT NULL,
    PRIMARY KEY (tenant, idx)
);
CREATE TABLE IF NOT EXISTS tokenis_api_keys (
    tenant     TEXT    NOT NULL,
    key_id     TEXT    NOT NULL,
    principal  TEXT    NOT NULL,
    key_hash   TEXT    NOT NULL,
    created_at BIGINT  NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (tenant, key_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS tokenis_api_keys_hash ON tokenis_api_keys (key_hash);
"""


class PostgresState:
    """One replica's connection to the shared state (thread-safe: calls are
    serialised by the gateway's own lock, and by ``_conn_lock`` here)."""

    def __init__(self, url: str, tenant: str) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise RuntimeError(
                "the postgres state backend needs: pip install 'tokenis-mcp[postgres]'"
            ) from exc
        self._psycopg = psycopg
        #: Exceptions meaning "the database call failed" (the gateway then
        #: rebuilds its in-memory admission state before trusting it again).
        self.database_errors: Tuple[Type[BaseException], ...] = (psycopg.Error,)
        self.url = url
        self.tenant = tenant
        self._conn_lock = threading.RLock()
        self._conn: Any = None
        #: Key for the admission log's chain (the audit HMAC key, set by the
        #: gateway). With it, a database account that lacks the keystore
        #: cannot write a history that verifies.
        self.chain_key: Optional[bytes] = None
        self._in_tx = False
        self._lock_key = int.from_bytes(
            hashlib.sha256(f"tokenis:{tenant}".encode()).digest()[:8], "big", signed=True)
        with self._connection() as conn, conn.transaction():
            # Serialise schema creation across replicas starting together.
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._lock_key,))
            conn.execute(SCHEMA_SQL)

    # -- connection ---------------------------------------------------------

    def _connect(self) -> Any:
        return self._psycopg.connect(self.url, autocommit=True, **CONNECT_OPTIONS)

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        with self._conn_lock:
            if self._conn is None or self._conn.closed:
                self._conn = self._connect()
            try:
                yield self._conn
            except self._psycopg.OperationalError:
                # Drop a broken connection; the next call reconnects. (An
                # inner context may already have dropped it.)
                if self._conn is not None:
                    self._conn.close()
                self._conn = None
                raise

    def _retry_once(self, fn: Any) -> Any:
        """Run ``fn(conn)``; if the connection turns out to be dead (database
        restart, failover, idle timeout), reconnect and run it once more.
        Only for statements that are safe to repeat."""
        try:
            with self._connection() as conn:
                return fn(conn)
        except self._psycopg.OperationalError:
            with self._connection() as conn:
                return fn(conn)

    def ping(self) -> bool:
        """Readiness: a short-lived connection of its own, so the probe
        answers promptly even while a call holds the main connection."""
        try:
            with self._psycopg.connect(self.url, autocommit=True, **{
                    **CONNECT_OPTIONS, "connect_timeout": 2,
                    "options": "-c statement_timeout=3000"}) as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001 -- readiness probe: any failure means not ready
            return False

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run the body under the tenant-wide advisory lock, committing at the
        end whether the body returned or raised: everything written records
        something that happened (a decision taken, a disclosure made)."""
        with self._conn_lock:
            if self._in_tx:
                yield
                return
            # BEGIN writes nothing, so a connection found dead here is
            # replaced and BEGIN retried: the first call after a database
            # restart succeeds instead of failing.
            self._retry_once(lambda c: c.execute("BEGIN"))
            conn = self._conn
            self._in_tx = True
            try:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._lock_key,))
                yield
            except self._psycopg.OperationalError:
                self._in_tx = False
                conn.close()
                self._conn = None
                raise
            finally:
                self._in_tx = False
                if not conn.closed:
                    # On an aborted transaction (a failed statement) COMMIT
                    # rolls back instead; the gateway then resynchronises.
                    try:
                        conn.execute("COMMIT")
                    except self._psycopg.OperationalError:
                        conn.close()
                        self._conn = None
                        raise

    # -- admission log ------------------------------------------------------

    def open(self, fingerprint: str, reset: bool) -> None:
        """Bind this tenant's history to ``fingerprint`` (see state.py)."""
        with self.transaction(), self._connection() as conn:
            row = conn.execute("SELECT fingerprint FROM tokenis_state WHERE tenant = %s",
                               (self.tenant,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO tokenis_state (tenant, fingerprint) VALUES (%s, %s)",
                             (self.tenant, fingerprint))
            elif row[0] != fingerprint:
                if not reset:
                    raise StateMismatchError(
                        f"the shared admission history for tenant {self.tenant!r} was written "
                        "for different data or admission settings; restart with "
                        "reset_admission_state (CLI: --reset-admission-state) if that is intended"
                    )
                archived = f"{self.tenant}#archived-{int(time.time())}"
                for table in ("tokenis_admission_log", "tokenis_trace"):
                    conn.execute(f"UPDATE {table} SET tenant = %s WHERE tenant = %s",  # noqa: S608 -- fixed table names
                                 (archived, self.tenant))
                conn.execute("UPDATE tokenis_state SET fingerprint = %s WHERE tenant = %s",
                             (fingerprint, self.tenant))

    def check(self, fingerprint: str, seen_seq: int, seen_digest: str) -> None:
        """Fail closed if the shared history is no longer the one this
        replica has replayed: the tenant was reset elsewhere (new data or
        policy), or the log was restored to an earlier point or rewritten.
        The log is hash-chained, so the record this replica saw last still
        carrying the digest it saw means everything before it is unchanged
        too."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT fingerprint, (SELECT digest FROM tokenis_admission_log "
                "WHERE tenant = %s AND seq = %s) FROM tokenis_state WHERE tenant = %s",
                (self.tenant, seen_seq, self.tenant)).fetchone()
        if row is None or row[0] != fingerprint:
            raise StateMismatchError(
                f"the shared admission history for tenant {self.tenant!r} was reset or replaced "
                "while this replica was running; restart it")
        if seen_seq and row[1] != seen_digest:
            raise StateMismatchError(
                f"the shared admission history for tenant {self.tenant!r} changed underneath this "
                f"replica (record {seen_seq} is gone or different): the database was restored "
                "from an earlier backup or edited. Refusing to answer; see docs/deployment.md")

    def link(self, prev: str, record: Dict[str, Any]) -> str:
        """The chain link for ``record`` after ``prev``: HMAC-SHA256 under the
        chain key when there is one, SHA-256 otherwise."""
        body = json.dumps(record, sort_keys=True, separators=(",", ":"))
        data = f"{prev}\n{body}".encode()
        if self.chain_key:
            return hmac.new(self.chain_key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def records_after(self, seq: int, prev: str = _GENESIS) -> List[Tuple[int, Dict[str, Any], str]]:
        """(seq, record, digest) for every record after ``seq``, oldest first,
        each verified to follow ``prev`` (the digest of record ``seq``): no
        gap, no edited record, no forged link."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT seq, record, digest FROM tokenis_admission_log WHERE tenant = %s "
                "AND seq > %s ORDER BY seq", (self.tenant, seq)).fetchall()
        out = []
        expected = seq + 1
        for s, raw, digest in rows:
            record = dict(raw) if isinstance(raw, dict) else {}
            if int(s) != expected or not equal(self.link(prev, record), str(digest)):
                raise StateMismatchError(
                    f"the shared admission history for tenant {self.tenant!r} fails verification at "
                    f"record {s}: a record is missing, edited, or was written without the audit key. "
                    "Refusing to answer; see docs/deployment.md")
            out.append((int(s), record, str(digest)))
            prev, expected = str(digest), expected + 1
        return out

    def append(self, record: Dict[str, Any]) -> Tuple[int, str]:
        """Append under the transaction's lock; returns (seq, digest)."""
        body = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self._connection() as conn:
            last = conn.execute(
                "SELECT seq, digest FROM tokenis_admission_log WHERE tenant = %s "
                "ORDER BY seq DESC LIMIT 1", (self.tenant,)).fetchone()
            seq, prev = (int(last[0]) + 1, str(last[1])) if last else (1, _GENESIS)
            digest = self.link(prev, json.loads(body))
            conn.execute("INSERT INTO tokenis_admission_log (tenant, seq, record, digest) "
                         "VALUES (%s, %s, %s, %s)", (self.tenant, seq, body, digest))
        return seq, digest

    # -- trace ------------------------------------------------------------------

    def trace_storage(self) -> "PostgresTraceStorage":
        return PostgresTraceStorage(self)


class PostgresTraceStorage:
    """``tokenis.audit.trace.TraceStorage`` over ``tokenis_trace``. The head
    is read from the table, under the gateway's transaction, so replicas
    extend one chain."""

    def __init__(self, state: PostgresState) -> None:
        self._state = state

    @property
    def lock(self) -> Any:
        """The trace must use this lock, not one of its own: a tool call
        holds it for its whole transaction, and a second lock taken in the
        other order by a reader (metrics, dashboard) would deadlock."""
        return self._state._conn_lock

    def head(self) -> Tuple[int, str]:
        with self._state._connection() as conn:
            row = conn.execute(
                "SELECT idx, entry->>'digest' FROM tokenis_trace WHERE tenant = %s "
                "ORDER BY idx DESC LIMIT 1", (self._state.tenant,)).fetchone()
        return (0, _GENESIS) if row is None else (int(row[0]) + 1, str(row[1]))

    def append(self, entry: TraceEntry, mac: Optional[str]) -> None:
        with self._state.transaction(), self._state._connection() as conn:
            conn.execute("INSERT INTO tokenis_trace (tenant, idx, entry) VALUES (%s, %s, %s)",
                         (self._state.tenant, entry.index, json.dumps(entry_to_dict(entry, mac))))

    def tail(self, n: int) -> List[TraceEntry]:
        with self._state._connection() as conn:
            rows = conn.execute("SELECT entry FROM tokenis_trace WHERE tenant = %s "
                                "ORDER BY idx DESC LIMIT %s", (self._state.tenant, n)).fetchall()
        return [entry_from_dict(raw)[0] for (raw,) in rows]

    def count(self) -> int:
        return self.head()[0]

    def scan(self) -> Iterator[Tuple[TraceEntry, Optional[str], Optional[str], str]]:
        last = -1
        while True:
            with self._state._connection() as conn:
                rows = conn.execute(
                    "SELECT idx, entry FROM tokenis_trace WHERE tenant = %s AND idx > %s "
                    "ORDER BY idx LIMIT 5000", (self._state.tenant, last)).fetchall()
            if not rows:
                return
            for idx, raw in rows:
                entry, digest, mac = entry_from_dict(raw)
                yield entry, digest, mac, f"tokenis_trace[{self._state.tenant}, {idx}]"
                last = int(idx)


class PostgresApiKeyStore:
    """API keys shared by every replica (same interface as
    :class:`tokenis.server_auth.ApiKeyStore`). Uses its own connection, so
    authenticating a request never waits for a tool call's transaction."""

    def __init__(self, url: str, tenant: str) -> None:
        self._state = PostgresState(url, tenant)

    def create(self, principal: str) -> Tuple[str, Any]:
        from tokenis.server_auth import TOKEN_PREFIX, ApiKeyRecord, validate_principal

        validate_principal(principal)
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        record = ApiKeyRecord(key_id=key_hash[:12], principal=principal, key_hash=key_hash,
                              created_at=int(time.time()))
        with self._state._connection() as conn:
            conn.execute(
                "INSERT INTO tokenis_api_keys (tenant, key_id, principal, key_hash, created_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (self._state.tenant, record.key_id, principal, key_hash, record.created_at))
        return token, record

    def revoke(self, key_id: str) -> bool:
        with self._state._connection() as conn:
            cur = conn.execute("UPDATE tokenis_api_keys SET revoked = true WHERE tenant = %s "
                               "AND key_id = %s AND NOT revoked", (self._state.tenant, key_id))
            return bool(cur.rowcount)

    def list(self) -> List[Any]:
        from tokenis.server_auth import ApiKeyRecord

        with self._state._connection() as conn:
            rows = conn.execute("SELECT key_id, principal, key_hash, created_at, revoked FROM "
                                "tokenis_api_keys WHERE tenant = %s ORDER BY created_at",
                                (self._state.tenant,)).fetchall()
        return [ApiKeyRecord(*row) for row in rows]

    def verify(self, token: str) -> Optional[str]:
        from tokenis.server_auth import TOKEN_PREFIX

        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > 256:
            return None
        candidate = hashlib.sha256(token.encode()).hexdigest()
        row = self._state._retry_once(lambda conn: conn.execute(
            "SELECT principal, key_hash FROM tokenis_api_keys WHERE tenant = %s "
            "AND key_hash = %s AND NOT revoked", (self._state.tenant, candidate)).fetchone())
        if row is None or not equal(str(row[1]), candidate):
            return None
        return str(row[0])
