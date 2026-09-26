# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Durable admission state.

The D2 differencing control and the D3/D4 budgets are only as good as their
memory: if a restart forgets which query sets were admitted, the second half
of a differencing pair is simply asked after the restart. Rather than
snapshotting the admission matrices (which grow with the ledger), the
gateway appends every admission call -- its public inputs only, never a
value -- to a JSON-lines log, and replays the log through a fresh
:class:`~tokenis.gateway.admission.AdmissionPolicy` at start-up. Decisions
are deterministic functions of those inputs, so replay reproduces the exact
state.

The log's header records a fingerprint of everything the decisions depend
on (the public attribute columns, k, the catalogue, ...). If the data or
policy changed, the old history no longer describes the new ledger and the
gateway refuses to start until an operator explicitly resets it -- and
resetting is itself a risk worth a moment's thought: queries answered
against the old data can be differenced against queries on the new data.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterator

LOG_VERSION = 1


def truncate_torn_tail(path: Path) -> bool:
    """Cut a final line left incomplete by a crash mid-write (it has no
    trailing newline: every complete record ends with one). The call it
    recorded never returned, so dropping it loses nothing that was used.
    Returns whether anything was cut."""
    with path.open("rb+") as fh:
        data = fh.read()
        if not data or data.endswith(b"\n"):
            return False
        fh.truncate(data.rfind(b"\n") + 1)
        fh.flush()
        os.fsync(fh.fileno())
        return True


class StateMismatchError(RuntimeError):
    """The admission log was written for different data or policy."""


class AdmissionLog:
    def __init__(
        self,
        path: str | os.PathLike[str],
        fingerprint: str,
        reset: bool = False,
    ) -> None:
        self.path = Path(path)
        self.fingerprint = fingerprint
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            truncate_torn_tail(self.path)
            header = self._header()
            if header.get("fingerprint") != fingerprint:
                if not reset:
                    raise StateMismatchError(
                        f"{self.path} was written for different data or admission "
                        "settings. Restarting with a fresh history lets queries on "
                        "the old data be differenced against the new; if that is "
                        "acceptable, restart with reset_admission_state "
                        "(CLI: --reset-admission-state)."
                    )
                archived = self.path.with_name(f"{self.path.name}.{int(time.time())}.old")
                self.path.rename(archived)
        if not self.path.exists():
            self._write({"type": "header", "version": LOG_VERSION, "fingerprint": fingerprint,
                         "created": time.time()})

    def _header(self) -> Dict[str, Any]:
        with self.path.open("rb") as fh:
            first = fh.readline()
        try:
            header = json.loads(first.decode("utf-8"))
        except ValueError as exc:  # includes UnicodeDecodeError
            raise StateMismatchError(f"{self.path}: unreadable header") from exc
        if not isinstance(header, dict) or header.get("type") != "header" or header.get("version") != LOG_VERSION:
            raise StateMismatchError(f"{self.path}: not a version-{LOG_VERSION} admission log")
        return dict(header)

    def _write(self, record: Dict[str, Any]) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def records(self) -> Iterator[Dict[str, Any]]:
        """Every logged admission call, oldest first."""
        with self.path.open("rb") as fh:
            lines = fh.readlines()
        for i, line in enumerate(lines[1:], start=2):
            try:
                record = json.loads(line.decode("utf-8"))
            except ValueError as exc:  # includes UnicodeDecodeError
                raise StateMismatchError(f"{self.path}:{i}: corrupt record") from exc
            if not isinstance(record, dict):
                raise StateMismatchError(f"{self.path}:{i}: corrupt record")
            yield record

    def append(self, record: Dict[str, Any]) -> None:
        """Durably record one admission call before its result is used."""
        self._write(record)
