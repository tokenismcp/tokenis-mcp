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

_GENESIS = "0" * 64

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
        self._in_tx = False
        self._lock_key = int.from_bytes(
            hashlib.sha256(f"tokenis:{tenant}".encode()).digest()[:8], "big", signed=True)
        with self._connection() as conn, conn.transaction():
            # Serialise schema creation across replicas starting together.
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._lock_key,))
            conn.execute(SCHEMA_SQL)

    # -- connection ---------------------------------------------------------

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        with self._conn_lock:
            if self._conn is None or self._conn.closed:
                self._conn = self._psycopg.connect(self.url, autocommit=True)
            try:
                yield self._conn
            except self._psycopg.OperationalError:
                # Drop a broken connection; the next call reconnects.
                self._conn.close()
                self._conn = None
                raise

    def ping(self) -> bool:
        try:
            with self._connection() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001 -- readiness probe: any failure means not ready
            return False

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run the body under the tenant-wide advisory lock, committing at the
        end whether the body returned or raised: everything written records
        something that happened (a decision taken, a disclosure made)."""
        with self._connection() as conn:
            if self._in_tx:
                yield
                return
            conn.execute("BEGIN")
            self._in_tx = True
            try:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._lock_key,))
                yield
            finally:
                self._in_tx = False
                if not conn.closed:
                    # On an aborted transaction (a failed statement) COMMIT
                    # rolls back instead; the gateway then resynchronises.
                    conn.execute("COMMIT")

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

    def records_after(self, seq: int) -> List[Tuple[int, Dict[str, Any]]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT seq, record FROM tokenis_admission_log WHERE tenant = %s AND seq > %s "
                "ORDER BY seq", (self.tenant, seq)).fetchall()
        return [(int(s), dict(r)) for s, r in rows]

    def append(self, record: Dict[str, Any]) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "INSERT INTO tokenis_admission_log (tenant, seq, record) "
                "SELECT %s, COALESCE(MAX(seq), 0) + 1, %s FROM tokenis_admission_log "
                "WHERE tenant = %s RETURNING seq",
                (self.tenant, json.dumps(record), self.tenant)).fetchone()
        return int(row[0])

    # -- trace ------------------------------------------------------------------

    def trace_storage(self) -> "PostgresTraceStorage":
        return PostgresTraceStorage(self)


class PostgresTraceStorage:
    """``tokenis.audit.trace.TraceStorage`` over ``tokenis_trace``. The head
    is read from the table, under the gateway's transaction, so replicas
    extend one chain."""

    def __init__(self, state: PostgresState) -> None:
        self._state = state

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
        with self._state._connection() as conn:
            row = conn.execute("SELECT principal, key_hash FROM tokenis_api_keys WHERE tenant = %s "
                               "AND key_hash = %s AND NOT revoked",
                               (self._state.tenant, candidate)).fetchone()
        if row is None or not hmac.compare_digest(str(row[1]), candidate):
            return None
        return str(row[0])
