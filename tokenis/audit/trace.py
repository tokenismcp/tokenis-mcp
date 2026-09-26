# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The disclosure trace Δ(D, Q) (P2 Definition 16): "the sequence of all
boundary crossings in the clear: outputs of Reveal, and the plaintext
results of admitted aggregate calls, each paired with its audit record."

Two design consequences from P2 §5.2 are enforced here, not just
documented:

1. **No tool may disclose as a side effect.** Anything that places a
   plaintext SEALED value in the exposed region must go through
   :meth:`DisclosureTrace.record_reveal` or
   :meth:`DisclosureTrace.record_aggregate_result` -- there is no other way
   to get a value into the trace, and (by convention enforced at the
   integration layer, e.g. :mod:`tokenis.mcp_server`) no other way a value
   should reach the model.
2. **Admission denials are disclosure and must be accounted as such**
   (P2 Remark 18, citing Kenthapadi et al.'s simulatable-auditing result: a
   data-dependent denial is a one-bit answer to a predicate of the
   caller's choosing). :meth:`DisclosureTrace.record_denial` exists so a
   trace that only logs successful calls is structurally impossible to
   produce through this API.

The log is hash-chained (each entry commits to a digest of the previous
entry), so removing, reordering or editing an entry is detectable by
:meth:`DisclosureTrace.verify_chain`. On its own a hash chain only protects
against *accidental* damage: anyone who can rewrite the file can recompute
it. Pass ``hmac_key`` and every entry also carries an HMAC-SHA256 over its
digest, so rewriting the chain requires the key; keep the key away from
anyone who can write the file (e.g. inject it from a KMS). Neither mechanism
can detect entries cut off the *end* of the file: ship the file to an
append-only store (WORM bucket, SIEM) or record :attr:`DisclosureTrace.head`
externally for that.

With ``path`` set, every entry is appended to a JSON-lines file (mode 0600)
and flushed to disk before the call that produced it returns; an existing
file is loaded and verified on start-up, and a file that fails verification
refuses to load rather than being silently continued. (The one repair
made automatically is dropping an incomplete final line left by a crash
mid-write: entries are written before their value is released, so that
entry's value never left the gateway.)

All methods are thread-safe.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Protocol, Tuple


@dataclass(frozen=True)
class AuditRecord:
    """P2 Definition 15: ``a = (principal, obj, purpose, policy_version,
    decision, time)``."""

    principal: str
    obj_ref: str
    purpose: str
    policy_version: str
    decision: str  # "permit" | "deny"
    timestamp: float = field(default_factory=time.time)
    #: Why a call was denied (the admission rule), for auditors. Never shown
    #: to the caller: a precise denial reason is itself a disclosure.
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "principal": self.principal,
            "obj_ref": self.obj_ref,
            "purpose": self.purpose,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "timestamp": self.timestamp,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditRecord":
        return cls(
            principal=str(data["principal"]),
            obj_ref=str(data["obj_ref"]),
            purpose=str(data["purpose"]),
            policy_version=str(data["policy_version"]),
            decision=str(data["decision"]),
            timestamp=float(data["timestamp"]),
            detail=str(data.get("detail", "")),
        )


@dataclass(frozen=True)
class TraceEntry:
    """One boundary crossing (or denial), hash-chained to the previous
    entry."""

    kind: str  # "reveal" | "aggregate" | "denial"
    audit: AuditRecord
    value_summary: Optional[str]  # None for denials; a string repr otherwise
    prev_hash: str
    index: int

    @property
    def digest(self) -> str:
        payload = json.dumps(
            {
                "kind": self.kind,
                "audit": self.audit.to_dict(),
                "value_summary": self.value_summary,
                "prev_hash": self.prev_hash,
                "index": self.index,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


_GENESIS_HASH = "0" * 64


class TraceIntegrityError(RuntimeError):
    """A persisted trace failed verification (edited, truncated in the
    middle, reordered, or signed with a different key)."""


def entry_to_dict(entry: TraceEntry, mac: Optional[str]) -> Dict[str, Any]:
    line: Dict[str, Any] = {
        "kind": entry.kind,
        "audit": entry.audit.to_dict(),
        "value_summary": entry.value_summary,
        "prev_hash": entry.prev_hash,
        "index": entry.index,
        "digest": entry.digest,
    }
    if mac is not None:
        line["mac"] = mac
    return line


def entry_from_dict(raw: Mapping[str, Any]) -> Tuple[TraceEntry, Optional[str], Optional[str]]:
    """(entry, stored digest, mac) -- raises on malformed input."""
    entry = TraceEntry(
        kind=raw["kind"],
        audit=AuditRecord.from_dict(raw["audit"]),
        value_summary=raw["value_summary"],
        prev_hash=raw["prev_hash"],
        index=int(raw["index"]),
    )
    return entry, raw.get("digest"), raw.get("mac")


class TraceStorage(Protocol):
    """Where trace entries live. ``head`` and ``append`` are called under the
    trace's lock (and, for shared storage, inside the gateway's transaction)."""

    def head(self) -> Tuple[int, str]:
        """(number of entries, digest of the last entry or the genesis hash)."""
        ...

    def append(self, entry: TraceEntry, mac: Optional[str]) -> None: ...

    def scan(self) -> Iterator[Tuple[TraceEntry, Optional[str], Optional[str], str]]:
        """Every entry in order: (entry, stored digest, mac, location)."""
        ...


class MemoryTraceStorage:
    def __init__(self) -> None:
        self.entries: List[Tuple[TraceEntry, Optional[str]]] = []

    def head(self) -> Tuple[int, str]:
        return len(self.entries), (self.entries[-1][0].digest if self.entries else _GENESIS_HASH)

    def append(self, entry: TraceEntry, mac: Optional[str]) -> None:
        self.entries.append((entry, mac))

    def scan(self) -> Iterator[Tuple[TraceEntry, Optional[str], Optional[str], str]]:
        for i, (entry, mac) in enumerate(list(self.entries)):
            yield entry, entry.digest, mac, f"entry {i}"


class FileTraceStorage:
    """JSON lines, appended and fsync'd, mode 0600. Only the head is kept in
    memory; reading streams the file."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._count = 0
        self._head = _GENESIS_HASH
        if self.path.exists():
            from tokenis.gateway.state import truncate_torn_tail

            # A crash mid-append leaves a line without its newline; the call
            # it recorded never returned a value, so it is safe to drop.
            truncate_torn_tail(self.path)

    def set_head(self, count: int, digest: str) -> None:
        self._count, self._head = count, digest

    def head(self) -> Tuple[int, str]:
        return self._count, self._head

    def append(self, entry: TraceEntry, mac: Optional[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry_to_dict(entry, mac), sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._count, self._head = entry.index + 1, entry.digest

    def scan(self) -> Iterator[Tuple[TraceEntry, Optional[str], Optional[str], str]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                where = f"{self.path}:{lineno}"
                try:
                    entry, digest, mac = entry_from_dict(json.loads(line))
                except (ValueError, KeyError, TypeError) as exc:
                    raise TraceIntegrityError(f"{where}: unreadable entry") from exc
                yield entry, digest, mac, where


class DisclosureTrace:
    """An append-only, hash-chained disclosure trace, optionally persisted
    and HMAC-signed (see the module docstring).

    ``path`` persists to a file; ``storage`` plugs in shared storage (the
    PostgreSQL backend in :mod:`tokenis.gateway.pgstate`). A persisted trace
    is verified end to end when opened, and refuses to open if it does not
    verify."""

    def __init__(
        self,
        path: Optional[str | os.PathLike[str]] = None,
        hmac_key: Optional[bytes] = None,
        storage: Optional[TraceStorage] = None,
    ) -> None:
        if hmac_key is not None and len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        if path is not None and storage is not None:
            raise ValueError("pass path or storage, not both")
        self._lock = threading.Lock()
        self._hmac_key = hmac_key
        self._storage: TraceStorage
        if storage is not None:
            self._storage = storage
            self._verify(raise_on_error=True)
        elif path is not None:
            file_storage = FileTraceStorage(Path(path))
            self._storage = file_storage
            count, head = self._verify(raise_on_error=True)
            file_storage.set_head(count, head)
        else:
            self._storage = MemoryTraceStorage()

    def _mac(self, digest: str) -> Optional[str]:
        if self._hmac_key is None:
            return None
        return hmac.new(self._hmac_key, digest.encode("ascii"), hashlib.sha256).hexdigest()

    def _verify(self, raise_on_error: bool) -> Tuple[int, str]:
        """Walk the whole trace; returns (count, head digest). With
        ``raise_on_error`` a problem raises TraceIntegrityError naming the
        entry; otherwise it returns (-1, "")."""
        prev, count = _GENESIS_HASH, 0
        try:
            for entry, digest, mac, where in self._storage.scan():
                if entry.index != count or entry.prev_hash != prev:
                    raise TraceIntegrityError(f"{where}: chain broken")
                if entry.digest != digest:
                    raise TraceIntegrityError(f"{where}: entry was modified")
                expected = self._mac(entry.digest)
                if expected is not None and not hmac.compare_digest(expected, str(mac or "")):
                    raise TraceIntegrityError(f"{where}: HMAC does not verify")
                prev, count = entry.digest, count + 1
        except TraceIntegrityError:
            if raise_on_error:
                raise
            return -1, ""
        return count, prev

    # -- appending --------------------------------------------------------

    def _append(self, kind: str, audit: AuditRecord, value_summary: Optional[str]) -> TraceEntry:
        with self._lock:
            count, prev_hash = self._storage.head()
            entry = TraceEntry(
                kind=kind,
                audit=audit,
                value_summary=value_summary,
                prev_hash=prev_hash,
                index=count,
            )
            # Durable first: a disclosure that cannot be recorded does not
            # happen (the exception propagates before any value is returned).
            self._storage.append(entry, self._mac(entry.digest))
            return entry

    def record_reveal(self, audit: AuditRecord, value: Any) -> TraceEntry:
        if audit.decision != "permit":
            raise ValueError(
                "record_reveal called with a non-permit audit record; a denied "
                "Reveal must go through record_denial, not record_reveal"
            )
        return self._append("reveal", audit, repr(value))

    def record_aggregate_result(self, audit: AuditRecord, value: Any) -> TraceEntry:
        if audit.decision != "permit":
            raise ValueError(
                "record_aggregate_result called with a non-permit audit record; "
                "a rejected call must go through record_denial"
            )
        return self._append("aggregate", audit, repr(value))

    def record_denial(self, audit: AuditRecord) -> TraceEntry:
        if audit.decision != "deny":
            raise ValueError("record_denial requires an audit record with decision='deny'")
        return self._append("denial", audit, None)

    # -- reading ----------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return self._storage.head()[0]

    def __iter__(self) -> Iterator[TraceEntry]:
        with self._lock:
            entries = [entry for entry, _d, _m, _w in self._storage.scan()]
        return iter(entries)

    def verify_chain(self) -> bool:
        """Recompute every hash link (and HMAC, when keyed); ``False`` means
        the trace has been tampered with (an entry removed, reordered, or
        edited in place)."""
        with self._lock:
            return self._verify(raise_on_error=False)[0] >= 0

    @property
    def head(self) -> str:
        """Digest of the latest entry (the genesis hash when empty): anchor
        this externally to make tail truncation detectable."""
        with self._lock:
            return self._storage.head()[1]

    def entries_for(self, principal: str) -> List[TraceEntry]:
        return [e for e in self if e.audit.principal == principal]
