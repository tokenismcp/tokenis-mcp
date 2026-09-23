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
from typing import Any, Dict, Iterator, List, Optional


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


class DisclosureTrace:
    """An append-only, hash-chained disclosure trace, optionally persisted
    and HMAC-signed (see the module docstring)."""

    def __init__(
        self,
        path: Optional[str | os.PathLike[str]] = None,
        hmac_key: Optional[bytes] = None,
    ) -> None:
        if hmac_key is not None and len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        self._lock = threading.Lock()
        self._entries: List[TraceEntry] = []
        self._macs: List[Optional[str]] = []
        self._hmac_key = hmac_key
        self._path = Path(path) if path is not None else None
        if self._path is not None and self._path.exists():
            from tokenis.gateway.state import truncate_torn_tail

            # A crash mid-append leaves a line without its newline; the call
            # it recorded never returned a value, so it is safe to drop.
            truncate_torn_tail(self._path)
            self._load(self._path)

    # -- persistence ------------------------------------------------------

    def _mac(self, digest: str) -> Optional[str]:
        if self._hmac_key is None:
            return None
        return hmac.new(self._hmac_key, digest.encode("ascii"), hashlib.sha256).hexdigest()

    def _load(self, path: Path) -> None:
        prev = _GENESIS_HASH
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    entry = TraceEntry(
                        kind=raw["kind"],
                        audit=AuditRecord.from_dict(raw["audit"]),
                        value_summary=raw["value_summary"],
                        prev_hash=raw["prev_hash"],
                        index=int(raw["index"]),
                    )
                except (ValueError, KeyError, TypeError) as exc:
                    raise TraceIntegrityError(f"{path}:{lineno}: unreadable entry") from exc
                if entry.index != len(self._entries) or entry.prev_hash != prev:
                    raise TraceIntegrityError(f"{path}:{lineno}: chain broken")
                if entry.digest != raw.get("digest"):
                    raise TraceIntegrityError(f"{path}:{lineno}: entry was modified")
                expected_mac = self._mac(entry.digest)
                if expected_mac is not None and not hmac.compare_digest(
                    expected_mac, str(raw.get("mac", ""))
                ):
                    raise TraceIntegrityError(f"{path}:{lineno}: HMAC does not verify")
                self._entries.append(entry)
                self._macs.append(raw.get("mac"))
                prev = entry.digest

    def _persist(self, entry: TraceEntry, mac: Optional[str]) -> None:
        if self._path is None:
            return
        line = {
            "kind": entry.kind,
            "audit": entry.audit.to_dict(),
            "value_summary": entry.value_summary,
            "prev_hash": entry.prev_hash,
            "index": entry.index,
            "digest": entry.digest,
        }
        if mac is not None:
            line["mac"] = mac
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # -- appending --------------------------------------------------------

    def _append(self, kind: str, audit: AuditRecord, value_summary: Optional[str]) -> TraceEntry:
        with self._lock:
            prev_hash = self._entries[-1].digest if self._entries else _GENESIS_HASH
            entry = TraceEntry(
                kind=kind,
                audit=audit,
                value_summary=value_summary,
                prev_hash=prev_hash,
                index=len(self._entries),
            )
            mac = self._mac(entry.digest)
            # Durable first: a disclosure that cannot be recorded does not
            # happen (the exception propagates before any value is returned).
            self._persist(entry, mac)
            self._entries.append(entry)
            self._macs.append(mac)
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
            return len(self._entries)

    def __iter__(self) -> Iterator[TraceEntry]:
        with self._lock:
            return iter(list(self._entries))

    def verify_chain(self) -> bool:
        """Recompute every hash link (and HMAC, when keyed); ``False`` means
        the trace has been tampered with (an entry removed, reordered, or
        edited in place)."""
        with self._lock:
            prev = _GENESIS_HASH
            for entry, mac in zip(self._entries, self._macs):
                if entry.prev_hash != prev:
                    return False
                prev = entry.digest
                expected = self._mac(prev)
                if expected is not None and not hmac.compare_digest(expected, mac or ""):
                    return False
            return True

    @property
    def head(self) -> str:
        """Digest of the latest entry (the genesis hash when empty): anchor
        this externally to make tail truncation detectable."""
        with self._lock:
            return self._entries[-1].digest if self._entries else _GENESIS_HASH

    def entries_for(self, principal: str) -> List[TraceEntry]:
        with self._lock:
            return [e for e in self._entries if e.audit.principal == principal]
