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
entry) purely so that :mod:`tokenis.conformance` has something concrete to
check for "every entry is present and in order, nothing was excised" --
this is a reference implementation's stand-in for a real tamper-evident
audit store (e.g. an append-only WORM log or a transparency log), not a
cryptographic commitment scheme in its own right.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional


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

    def to_dict(self) -> dict:
        return {
            "principal": self.principal,
            "obj_ref": self.obj_ref,
            "purpose": self.purpose,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "timestamp": self.timestamp,
        }


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


class DisclosureTrace:
    """An append-only, hash-chained disclosure trace."""

    def __init__(self) -> None:
        self._entries: List[TraceEntry] = []

    def _append(self, kind: str, audit: AuditRecord, value_summary: Optional[str]) -> TraceEntry:
        prev_hash = self._entries[-1].digest if self._entries else _GENESIS_HASH
        entry = TraceEntry(
            kind=kind,
            audit=audit,
            value_summary=value_summary,
            prev_hash=prev_hash,
            index=len(self._entries),
        )
        self._entries.append(entry)
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

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def verify_chain(self) -> bool:
        """Recompute every hash link; ``False`` means the trace has been
        tampered with (an entry removed, reordered, or edited in place)."""
        prev = _GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False
            prev = entry.digest
        return True

    def entries_for(self, principal: str) -> List[TraceEntry]:
        return [e for e in self._entries if e.audit.principal == principal]
