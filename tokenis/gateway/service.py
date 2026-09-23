# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""``TokenisGatewayService``: the product gateway. It loads a dataset
described by a :class:`~tokenis.gateway.schema.Schema`, encrypts its sealed
columns, and answers the tool surface in ``tokenis/spec/tool-surface.md``
under the full D1-D5 admission policy, logging every boundary crossing to
the disclosure trace. :mod:`tokenis.mcp_server.server` exposes it over MCP,
and :mod:`tokenis.llm` to LLM APIs directly.

Security-relevant behaviour
---------------------------
- **Identity.** Every call carries a ``principal`` that the *caller of this
  class* must have authenticated (P4 Theorem 13 / Corollary 14). The MCP
  server takes it from verified credentials, never from a tool argument.
- **Atomicity.** One lock covers admission, computation and auditing of a
  call. Without it, two concurrent queries can each pass the D2 check the
  other would fail -- enough to recover a single record by differencing.
- **Generic denials.** A refused call raises :class:`AdmissionDenied` with
  one fixed message whatever the reason; the rule that fired goes to the
  disclosure trace for auditors only. (A denial that says "matched 2" is a
  count disclosure; one that names the rule is a one-bit oracle.)
- **Durability.** With ``state_dir``, the admission history (D2 matrices,
  budgets, tainted-call counts) survives restarts via a replayed log, and
  the disclosure trace is persisted and optionally HMAC-signed -- see
  :mod:`tokenis.gateway.state` and :mod:`tokenis.audit.trace`.
- **Decryption failures** (an aggregate outside the configured range) are
  denials like any other, recorded in the trace.
- **Timing.** Direct method calls are padded to the declared latency
  quantum (W6); the MCP server pads asynchronously around :meth:`invoke`.

The ledger is loaded once: after the first query it is sealed, and
:meth:`ingest` refuses further rows (changing the data under an admission
history would silently invalidate D2).

Similarity search keeps embeddings in plaintext inside this trusted process
(the same boundary that sees plaintext at ingest) and releases only entity
tokens with a banded similarity -- a vector-similarity-preserving encryption
scheme is out of scope for the additive EC-ElGamal used here.
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import json
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, TypeVar

import numpy as np

from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.crypto.ec_fhe import Ciphertext, Decryptor, TokenisCryptoError, encrypt, keygen
from tokenis.gateway.admission import (
    AdmissionPolicy,
    All,
    And,
    Decision,
    Eq,
    MissingSubjectIdError,
    Query,
    QueryContext,
    characteristic_indicator,
)
from tokenis.gateway.admission import Predicate as AdmissionPredicate
from tokenis.gateway.latency import quantize_latency
from tokenis.gateway.reveal import RevealDenied, RevealObject, reveal
from tokenis.gateway.schema import ColumnSpec, GatewaySettings, Schema
from tokenis.gateway.state import AdmissionLog
from tokenis.semantic.tokenizer import ScopedTokenizer

POLICY_VERSION = "tokenis-gateway/2"

DENIED_MESSAGE = (
    "Denied by the disclosure policy. The request may match too few records, "
    "combine with earlier queries to isolate individual records, exceed your "
    "query budget, or need a purpose you are not authorised for. Try broader "
    "filters or a different question; the gateway does not say which reason "
    "applied."
)

_I63 = 1 << 62  # headroom so sums of a few values cannot overflow i64
_F = TypeVar("_F", bound=Callable[..., Any])


class AdmissionDenied(Exception):
    """A call refused by policy. The message is always
    :data:`DENIED_MESSAGE`; ``rule`` (for logs and tests, never for the
    caller) says which control fired."""

    def __init__(self, rule: str = "") -> None:
        super().__init__(DENIED_MESSAGE)
        self.rule = rule


class ArgumentError(ValueError):
    """Invalid arguments. Safe to show the caller: these checks depend only
    on the public schema and settings, never on the data."""


@dataclass(frozen=True)
class Caller:
    """Who is calling (already authenticated) and whether their context is
    tainted by untrusted content (P4 D4; supplied by the host)."""

    principal: str
    taint: int = 0


def _locked(method: _F) -> _F:
    @functools.wraps(method)
    def wrapper(self: "TokenisGatewayService", *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            self._seal_locked()
            return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _to_stored(value: Any, scale: int, column: str) -> int:
    """A sealed value in stored units: ``round(value * 10**scale)``, half
    away from zero, computed in decimal (no binary-float surprises)."""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{column}: expected a number, got {value!r}")
    try:
        d = Decimal(value) if not isinstance(value, float) else Decimal(repr(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"{column}: expected a number, got {value!r}") from exc
    if not d.is_finite():
        raise ValueError(f"{column}: value must be finite")
    stored = int((d.scaleb(scale)).to_integral_value(rounding=ROUND_HALF_UP))
    if abs(stored) >= _I63:
        raise ValueError(f"{column}: value too large")
    return stored


def _window_key(window: str, now: Optional[datetime] = None) -> str:
    now = now or datetime.now(timezone.utc)
    if window == "day":
        return now.strftime("%Y-%m-%d")
    if window == "hour":
        return now.strftime("%Y-%m-%dT%H")
    return "all"


def _fmt(x: float) -> str:
    return f"{x:,.0f}" if abs(x) >= 1 else f"{x:g}"


def band(value: float) -> str:
    """A 1-2-5 band containing ``value``, e.g. ``[2,000,000, 5,000,000)``."""
    if value == 0:
        return "0"
    mag = abs(value)
    base = 10 ** math.floor(math.log10(mag))
    steps = [1, 2, 5, 10]
    lo = next(s for s in reversed(steps[:-1]) if s * base <= mag * (1 + 1e-12))
    hi = steps[steps.index(lo) + 1]
    lower, upper = lo * base, hi * base
    if value > 0:
        return f"[{_fmt(lower)}, {_fmt(upper)})"
    return f"(-{_fmt(upper)}, -{_fmt(lower)}]"


def ratio_band(ratio: float) -> str:
    edges = [0.5, 0.8, 0.95, 1.05, 1.2, 2.0]
    labels = ["<0.5x", "0.5-0.8x", "0.8-0.95x", "0.95-1.05x", "1.05-1.2x", "1.2-2x", ">=2x"]
    for edge, label in zip(edges, labels):
        if ratio < edge:
            return label
    return labels[-1]


class TokenisGatewayService:
    """See the module docstring. Build it, :meth:`ingest` every row (or use
    :func:`tokenis.config.load_dataset`), then query."""

    def __init__(
        self,
        schema: Schema,
        tokenizer_key: bytes,
        settings: Optional[GatewaySettings] = None,
        *,
        state_dir: Optional[str | Path] = None,
        audit_key: Optional[bytes] = None,
        reset_admission_state: bool = False,
    ) -> None:
        self.schema = schema
        self.settings = settings or GatewaySettings()
        self._lock = threading.RLock()
        self._sealed = False
        self._state_dir = Path(state_dir) if state_dir is not None else None
        self._reset_state = reset_admission_state

        keypair = keygen()
        self._public_key = keypair.public
        dec = self.settings.decryption
        self._decryptor = Decryptor(keypair.private, dec.max_value, table_size=dec.table_size)
        self._tokenizer = ScopedTokenizer(key=tokenizer_key)
        self._scope = ScopedTokenizer.make_scope(tenant=self.settings.tenant, epoch=self.settings.epoch)

        self._ids: Dict[str, int] = {}
        self._public: Dict[str, List[str]] = {c.name: [] for c in schema.filterable}
        self._sealed_cts: Dict[str, List[Ciphertext]] = {c.name: [] for c in schema.sealed}
        self._square_cts: Dict[str, List[Ciphertext]] = {
            c.name: [] for c in schema.sealed if c.allow_variance
        }
        self._embeddings: Dict[str, np.ndarray] = {}
        self._embedding_dim: Optional[int] = None

        self.trace = DisclosureTrace(
            path=self._state_dir / "trace.jsonl" if self._state_dir else None,
            hmac_key=audit_key,
        )
        self._attrs: Dict[str, np.ndarray] = {}
        self._admission: Optional[AdmissionPolicy] = None
        self._log: Optional[AdmissionLog] = None

    # -- properties -----------------------------------------------------------

    @property
    def latency_granularity_ms(self) -> float:
        return self.settings.disclosure.latency_granularity_ms

    @property
    def record_count(self) -> int:
        return len(self._ids)

    @property
    def k(self) -> int:
        return self.settings.admission.min_query_set_size

    @property
    def tool_names(self) -> Tuple[str, ...]:
        """The tools this dataset and configuration support."""
        names = ["describe_dataset", "aggregate", "group_by"]
        if len(self.schema.sealed) >= 2:
            names.append("compare_periods")
        if self._embeddings:
            names.append("similarity_search")
        names.append("exists")
        if self.settings.purposes:
            names += ["disclose_ratio", "disclose_bucket"]
        return tuple(names)

    # -- loading ----------------------------------------------------------------

    def ingest(
        self,
        record_id: str,
        row: Mapping[str, Any],
        embedding: Optional[Sequence[float]] = None,
    ) -> None:
        """Add one record. Plaintext enters here and nowhere else: sealed
        values are encrypted, token values replaced by their pseudonyms, and
        only those forms are kept."""
        with self._lock:
            if self._sealed:
                raise RuntimeError(
                    "the ledger is sealed (queries have run against it); load a new "
                    "gateway to change the data"
                )
            record_id = str(record_id)
            if record_id in self._ids:
                raise ValueError(f"duplicate record id {record_id!r}")
            public: Dict[str, str] = {}
            for col in self.schema.filterable:
                raw = row.get(col.name)
                if raw is None or str(raw).strip() == "":
                    raise ValueError(f"record {record_id!r}: missing value for {col.name!r}")
                text = str(raw).strip()
                if len(text) > 256:
                    raise ValueError(f"record {record_id!r}: {col.name!r} longer than 256 characters")
                public[col.name] = (
                    self._tokenizer.tokenize(col.name, self._scope, text)
                    if col.protection == "token"
                    else text
                )
            sealed: Dict[str, Ciphertext] = {}
            squares: Dict[str, Ciphertext] = {}
            for col in self.schema.sealed:
                stored = _to_stored(row.get(col.name), col.scale, f"record {record_id!r}: {col.name}")
                sealed[col.name] = encrypt(self._public_key, stored)
                if col.allow_variance:
                    if stored * stored >= (1 << 63):
                        raise ValueError(
                            f"record {record_id!r}: {col.name} too large for VAR (its square overflows)"
                        )
                    squares[col.name] = encrypt(self._public_key, stored * stored)
            vector = None
            if embedding is not None:
                if self.schema.embedding_column is None or self.schema.entity is None:
                    raise ValueError("this schema has no embedding field")
                vector = np.asarray([float(x) for x in embedding], dtype=np.float64)
                if vector.ndim != 1 or vector.size == 0 or not np.all(np.isfinite(vector)):
                    raise ValueError(f"record {record_id!r}: embedding must be a non-empty finite vector")
                if self._embedding_dim is not None and vector.size != self._embedding_dim:
                    raise ValueError(
                        f"record {record_id!r}: embedding has {vector.size} dimensions, "
                        f"expected {self._embedding_dim}"
                    )
            # All validation done: commit the row atomically.
            self._ids[record_id] = len(self._ids)
            for name, value in public.items():
                self._public[name].append(value)
            for name, ct in sealed.items():
                self._sealed_cts[name].append(ct)
            for name, ct in squares.items():
                self._square_cts[name].append(ct)
            if vector is not None and self.schema.entity is not None:
                self._embedding_dim = vector.size
                norm = float(np.linalg.norm(vector))
                self._embeddings[public[self.schema.entity.name]] = (
                    vector / norm if norm > 0 else vector
                )

    def seal(self) -> None:
        """Freeze the ledger and build (or restore) the admission state.
        Called automatically by the first query."""
        with self._lock:
            self._seal_locked()

    def _seal_locked(self) -> None:
        if self._sealed:
            return
        n, k = self.record_count, self.k
        if n < 2 * k:
            raise RuntimeError(
                f"need at least 2*min_query_set_size = {2 * k} records to answer any "
                f"aggregate (have {n})"
            )
        adm = self.settings.admission
        self._attrs = {
            name: np.array(values, dtype=object) for name, values in self._public.items()
        }
        self._admission = AdmissionPolicy(
            n=n,
            public_attributes=self._attrs,
            catalogue=[c.name for c in self.schema.sealed],
            k=k,
            budget=adm.budget,
            taint_budget=adm.taint_budget,
            taint_call_cap=adm.taint_call_cap,
            cell_aware=adm.cell_aware,
        )
        if self._state_dir is not None:
            self._log = AdmissionLog(
                self._state_dir / "admission.jsonl",
                fingerprint=self._fingerprint(),
                reset=self._reset_state,
            )
            for record in self._log.records():
                self._replay(record)
        self._sealed = True

    def _fingerprint(self) -> str:
        """Everything past admission decisions depend on, except budgets
        (replay restores logged outcomes, so budget changes are safe)."""
        h = hashlib.sha256()
        meta = {
            "policy": POLICY_VERSION,
            "n": self.record_count,
            "k": self.k,
            "cell_aware": self.settings.admission.cell_aware,
            "catalogue": sorted(c.name for c in self.schema.sealed),
            "attributes": sorted(self._attrs),
        }
        h.update(json.dumps(meta, sort_keys=True).encode())
        for name in sorted(self._attrs):
            h.update(b"\x1e" + name.encode())
            for value in self._attrs[name]:
                h.update(b"\x1f" + str(value).encode())
        return h.hexdigest()

    def _replay(self, record: Dict[str, Any]) -> None:
        assert self._admission is not None  # noqa: S101 -- set just before replay
        context = QueryContext(
            subject_id=record["subject"],
            credential_id=record["subject"],
            taint=int(record["taint"]),
            window=record["window"],
        )
        query = None
        if record["op"] == "decide":
            query = Query(
                predicate=self._predicate(record["filters"]),
                function=record["function"],
                column=record.get("column"),
            )
        self._admission.restore(query, context, bool(record["admitted"]))

    # -- admission ----------------------------------------------------------------

    def _context(self, caller: Caller) -> QueryContext:
        return QueryContext(
            subject_id=caller.principal,
            credential_id=caller.principal,
            taint=1 if caller.taint else 0,
            window=_window_key(self.settings.admission.window),
        )

    def _predicate(self, filters: Mapping[str, str]) -> AdmissionPredicate:
        parts = [Eq(name, value) for name, value in sorted(filters.items())]
        if not parts:
            return All()
        return parts[0] if len(parts) == 1 else And(*parts)

    def _deny(self, caller: Caller, obj_ref: str, purpose: str, rule: str) -> AdmissionDenied:
        self.trace.record_denial(
            AuditRecord(
                principal=caller.principal or "", obj_ref=obj_ref, purpose=purpose,
                policy_version=POLICY_VERSION, decision="deny", detail=rule,
            )
        )
        return AdmissionDenied(rule)

    def _log_call(
        self, op: str, context: QueryContext, admitted: bool,
        filters: Optional[Mapping[str, str]] = None, function: Optional[str] = None,
        column: Optional[str] = None,
    ) -> None:
        if self._log is None:
            return
        record: Dict[str, Any] = {
            "op": op, "subject": context.subject_id, "taint": context.taint,
            "window": context.window, "admitted": admitted,
        }
        if op == "decide":
            record.update(filters=dict(filters or {}), function=function, column=column)
        self._log.append(record)

    def _decide(
        self, caller: Caller, filters: Mapping[str, str], function: str,
        column: Optional[str], obj_ref: str, purpose: str,
    ) -> Decision:
        """Run D1-D5 and durably log the call. Raises (after recording the
        denial) unless admitted. Caller must hold the lock."""
        assert self._admission is not None  # noqa: S101 -- _locked sealed the ledger
        context = self._context(caller)
        query = Query(predicate=self._predicate(filters), function=function, column=column)
        try:
            decision = self._admission.decide(query, context)
        except MissingSubjectIdError:
            raise self._deny(caller, obj_ref, purpose, "no-subject") from None
        self._log_call("decide", context, decision.admitted, filters, function, column)
        if not decision.admitted:
            raise self._deny(caller, obj_ref, purpose, decision.rule or "denied")
        return decision

    def _indicator(self, filters: Mapping[str, str]) -> np.ndarray:
        return characteristic_indicator(self._predicate(filters), self._attrs, self.record_count)

    def _decrypt_sum(
        self, caller: Caller, cts: List[Ciphertext], mask: np.ndarray, obj_ref: str, purpose: str,
    ) -> int:
        selected = [cts[i] for i in np.flatnonzero(mask)]
        total = selected[0]
        for ct in selected[1:]:
            total = total + ct
        try:
            return self._decryptor.decrypt(total)
        except TokenisCryptoError:
            raise self._deny(caller, obj_ref, purpose, "decryption-range") from None

    def _admitted_sum(
        self, caller: Caller, column: str, filters: Mapping[str, str], obj_ref: str, purpose: str,
    ) -> Tuple[int, int]:
        """An admitted SUM in stored units, and its set size."""
        decision = self._decide(caller, filters, "SUM", column, obj_ref, purpose)
        total = self._decrypt_sum(caller, self._sealed_cts[column], self._indicator(filters), obj_ref, purpose)
        return total, int(decision.set_size or 0)

    def _record(self, caller: Caller, obj_ref: str, purpose: str, value: Any) -> None:
        self.trace.record_aggregate_result(
            AuditRecord(
                principal=caller.principal, obj_ref=obj_ref, purpose=purpose,
                policy_version=POLICY_VERSION, decision="permit",
            ),
            value,
        )

    # -- argument validation (schema-only, safe to report) -----------------------

    def _sealed_column(self, name: Any) -> ColumnSpec:
        try:
            col = self.schema.column(str(name))
        except KeyError:
            col = None
        if col is None or col.protection != "sealed":
            names = ", ".join(c.name for c in self.schema.sealed)
            raise ArgumentError(f"column must be a sealed column: one of {names}")
        return col

    def _filters(self, filters: Any) -> Dict[str, str]:
        if filters is None:
            return {}
        if not isinstance(filters, Mapping):
            raise ArgumentError("filters must be an object mapping column names to values")
        allowed = {c.name for c in self.schema.filterable}
        out: Dict[str, str] = {}
        for key, value in filters.items():
            if value is None:
                continue
            if key not in allowed:
                raise ArgumentError(
                    f"cannot filter on {key!r}; filterable columns: {', '.join(sorted(allowed))}"
                )
            if not isinstance(value, str) or not 0 < len(value) <= 256:
                raise ArgumentError(f"filter value for {key!r} must be a non-empty string")
            out[str(key)] = value
        return out

    def _present(self, col: ColumnSpec, stored: float, power: int = 1) -> Any:
        value = stored / (10 ** (col.scale * power)) if col.scale else stored
        if col.result_mode == "band":
            return band(value)
        if isinstance(value, float):
            return round(value, 6)
        return value

    @staticmethod
    def _ref(tool: str, detail: str, filters: Mapping[str, str]) -> str:
        where = ",".join(f"{k}={v}" for k, v in sorted(filters.items())) or "*"
        return f"{tool}:{detail}|{where}"

    # -- tools (unpadded; callers pad -- see invoke) --------------------------------

    @_locked
    def _describe_dataset(self, caller: Caller) -> Dict[str, Any]:
        assert self._admission is not None  # noqa: S101 -- _locked sealed the ledger
        limit = self.settings.disclosure.max_enum_values
        columns = []
        for col in self.schema.columns:
            info: Dict[str, Any] = {
                "name": col.name, "protection": col.protection, "description": col.description,
            }
            if col.unit:
                info["unit"] = col.unit
            if col.protection == "open":
                domain = sorted(set(self._public[col.name]))
                info["filterable"] = True
                if len(domain) <= limit:
                    info["values"] = domain
                else:
                    info["distinct_values"] = len(domain)
            elif col.protection == "token":
                info["filterable"] = True
                info["note"] = "values are pseudonymous tokens; filter by a token you were given"
            else:
                ops = ["sum", "avg", "count"] + (["var"] if col.allow_variance else [])
                info["operations"] = ops
                info["result"] = "exact" if col.result_mode == "exact" else "banded (1-2-5)"
            columns.append(info)
        context = self._context(caller)
        return {
            "records": self.record_count,
            "min_query_set_size": self.k,
            "columns": columns,
            "budget": {
                "remaining": self._admission.remaining_budget(context),
                "window": self.settings.admission.window,
                "window_key": context.window,
            },
            "reveal_purposes": self.settings.purposes_for(caller.principal),
            "tools": list(self.tool_names),
        }

    @_locked
    def _aggregate(
        self, caller: Caller, function: str, column: Optional[str] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        function = str(function).lower()
        if function not in ("sum", "count", "avg", "var"):
            raise ArgumentError("function must be one of sum, count, avg, var")
        where = self._filters(filters)
        if function == "count":
            obj_ref = self._ref("aggregate", "count", where)
            decision = self._decide(caller, where, "COUNT", None, obj_ref, "aggregate")
            size = int(decision.set_size or 0)
            self._record(caller, obj_ref, "aggregate", size)
            return {"function": "count", "filters": where, "value": size, "matched_records": size}
        col = self._sealed_column(column)
        if function == "var" and not col.allow_variance:
            raise ArgumentError(f"var is not enabled for column {col.name!r}")
        obj_ref = self._ref("aggregate", f"{function}({col.name})", where)
        decision = self._decide(caller, where, function.upper(), col.name, obj_ref, "aggregate")
        size = int(decision.set_size or 0)
        mask = self._indicator(where)
        total = self._decrypt_sum(caller, self._sealed_cts[col.name], mask, obj_ref, "aggregate")
        if function == "sum":
            value = self._present(col, total)
        elif function == "avg":
            value = self._present(col, total / size)
        else:
            squares = self._decrypt_sum(caller, self._square_cts[col.name], mask, obj_ref, "aggregate")
            mean = total / size
            value = self._present(col, max(squares / size - mean * mean, 0.0), power=2)
        self._record(caller, obj_ref, "aggregate", value)
        result = {
            "function": function, "column": col.name, "filters": where,
            "value": value, "matched_records": size,
        }
        if col.unit:
            result["unit"] = col.unit + ("^2" if function == "var" else "")
        return result

    @_locked
    def _group_by(
        self, caller: Caller, key: str, function: str = "sum", column: Optional[str] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        key = str(key)
        if key not in self._public:
            names = ", ".join(c.name for c in self.schema.filterable)
            raise ArgumentError(f"key must be a filterable column: one of {names}")
        function = str(function).lower()
        if function not in ("sum", "count", "avg"):
            raise ArgumentError("function must be one of sum, count, avg")
        where = self._filters(filters)
        if key in where:
            raise ArgumentError("cannot group by a column that is also filtered")
        col = None if function == "count" else self._sealed_column(column)
        domain = sorted(set(self._public[key]))
        if len(domain) > self.settings.disclosure.max_groups:
            raise ArgumentError(
                f"{key!r} has more than {self.settings.disclosure.max_groups} groups; add filters "
                "or group by a coarser column"
            )
        groups = []
        for value in domain:
            group_filters = {**where, key: value}
            label = f"{function}({col.name if col else '*'})"
            obj_ref = self._ref("group_by", label, group_filters)
            try:
                decision = self._decide(
                    caller, group_filters, function.upper(), col.name if col else None,
                    obj_ref, "group_by",
                )
            except AdmissionDenied:
                groups.append({"group": value, "suppressed": True})
                continue
            size = int(decision.set_size or 0)
            if col is None:
                out: Any = size
            else:
                try:
                    total = self._decrypt_sum(
                        caller, self._sealed_cts[col.name], self._indicator(group_filters),
                        obj_ref, "group_by",
                    )
                except AdmissionDenied:
                    groups.append({"group": value, "suppressed": True})
                    continue
                out = self._present(col, total if function == "sum" else total / size)
            self._record(caller, obj_ref, "group_by", out)
            groups.append({"group": value, "suppressed": False, "value": out, "matched_records": size})
        result: Dict[str, Any] = {"key": key, "function": function, "filters": where, "groups": groups}
        if col is not None:
            result["column"] = col.name
        return result

    @_locked
    def _compare_periods(
        self, caller: Caller, column_a: str, column_b: str,
        filters: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        a_col, b_col = self._sealed_column(column_a), self._sealed_column(column_b)
        if a_col.name == b_col.name:
            raise ArgumentError("column_a and column_b must differ")
        if a_col.scale != b_col.scale:
            raise ArgumentError("columns with different scales cannot be compared")
        where = self._filters(filters)
        obj_ref = self._ref("compare_periods", f"{a_col.name}->{b_col.name}", where)
        a, _ = self._admitted_sum(caller, a_col.name, where, obj_ref, "compare_periods")
        b, _ = self._admitted_sum(caller, b_col.name, where, obj_ref, "compare_periods")
        tolerance = 0.02 * abs(a)
        direction = "flat" if abs(b - a) <= tolerance else ("increase" if b > a else "decrease")
        result: Dict[str, Any] = {
            "from": a_col.name, "to": b_col.name, "filters": where, "direction": direction,
            "ratio_band": ratio_band(b / a) if a > 0 and b >= 0 else None,
        }
        self._record(caller, obj_ref, "compare_periods", result)
        return result

    @_locked
    def _similarity_search(self, caller: Caller, token: str, top_k: int = 3) -> Dict[str, Any]:
        assert self._admission is not None  # noqa: S101 -- _locked sealed the ledger
        if not self._embeddings:
            raise ArgumentError("this dataset has no embeddings")
        limit = self.settings.disclosure.max_top_k
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= limit:
            raise ArgumentError(f"top_k must be an integer in [1, {limit}]")
        obj_ref = f"similarity_search:{token}|top_k={top_k}"
        context = self._context(caller)
        try:
            decision = self._admission.charge(context)
        except MissingSubjectIdError:
            raise self._deny(caller, obj_ref, "similarity_search", "no-subject") from None
        self._log_call("charge", context, decision.admitted)
        if not decision.admitted:
            raise self._deny(caller, obj_ref, "similarity_search", decision.rule or "denied")
        query = self._embeddings.get(str(token))
        if query is None:
            raise self._deny(caller, obj_ref, "similarity_search", "unknown-token")
        scored = sorted(
            ((float(np.dot(query, vec)), tok) for tok, vec in self._embeddings.items() if tok != token),
            reverse=True,
        )[:top_k]
        results = [{"token": tok, "similarity": _similarity_band(score)} for score, tok in scored]
        self._record(caller, obj_ref, "similarity_search", results)
        return {"token": token, "results": results}

    @_locked
    def _exists(self, caller: Caller, filters: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
        """Whether at least k records match. Deliberately not "any record":
        distinguishing 0 from 1 matches for a filter that includes a token
        would reveal that entity's attributes."""
        assert self._admission is not None  # noqa: S101 -- _locked sealed the ledger
        where = self._filters(filters)
        if not where:
            raise ArgumentError("exists needs at least one filter")
        obj_ref = self._ref("exists", "count", where)
        context = self._context(caller)
        query = Query(predicate=self._predicate(where), function="COUNT")
        try:
            decision = self._admission.decide(query, context)
        except MissingSubjectIdError:
            raise self._deny(caller, obj_ref, "exists", "no-subject") from None
        self._log_call("decide", context, decision.admitted, where, "COUNT", None)
        if decision.admitted:
            answer = True
        elif decision.rule == "D1":
            # D1's bit (inside [k, n-k] or not) is simulatable from public
            # attributes; the refused sizes collapse to "fewer than k" or
            # "all but fewer than k".
            answer = int(decision.set_size or 0) >= self.k
        else:
            raise self._deny(caller, obj_ref, "exists", decision.rule or "denied")
        self._record(caller, obj_ref, "exists", answer)
        return {"filters": where, "at_least_k_records": answer, "k": self.k}

    def _purpose(self, purpose: Any) -> str:
        if self.settings.purpose(str(purpose)) is None:
            names = ", ".join(p.name for p in self.settings.purposes) or "(none configured)"
            raise ArgumentError(f"purpose must be one of: {names}")
        return str(purpose)

    def _reveal(
        self, caller: Caller, obj: RevealObject, purpose: str, compute: Callable[[], Any],
    ) -> Any:
        rule = self.settings.purpose(purpose)

        def policy(principal: str, _obj: RevealObject, _purpose: str) -> bool:
            return rule is not None and rule.allows(principal)

        try:
            return reveal(
                caller.principal, obj, purpose, POLICY_VERSION, policy,
                lambda _obj: compute(), self.trace,
            )
        except RevealDenied:
            raise AdmissionDenied("purpose-not-authorised") from None

    @_locked
    def _disclose_ratio(
        self, caller: Caller, column: str, numerator_filters: Mapping[str, str],
        denominator_filters: Mapping[str, str], purpose: str,
    ) -> Dict[str, Any]:
        col = self._sealed_column(column)
        num_where, den_where = self._filters(numerator_filters), self._filters(denominator_filters)
        purpose = self._purpose(purpose)
        obj = RevealObject(
            ref=f"ratio:{self._ref('sum', col.name, num_where)}/{self._ref('sum', col.name, den_where)}",
            kind="aggregate",
        )

        def compute() -> float:
            num, _ = self._admitted_sum(caller, col.name, num_where, obj.ref, purpose)
            den, _ = self._admitted_sum(caller, col.name, den_where, obj.ref, purpose)
            if den == 0:
                raise self._deny(caller, obj.ref, purpose, "zero-denominator")
            return round(num / den, 6)

        ratio = self._reveal(caller, obj, purpose, compute)
        return {"column": col.name, "numerator_filters": num_where,
                "denominator_filters": den_where, "ratio": ratio}

    @_locked
    def _disclose_bucket(
        self, caller: Caller, column: str, thresholds: Sequence[float], labels: Sequence[str],
        purpose: str, filters: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        col = self._sealed_column(column)
        where = self._filters(filters)
        purpose = self._purpose(purpose)
        limit = self.settings.disclosure.max_buckets
        cuts = [float(t) for t in thresholds]
        if not 1 <= len(cuts) < limit or not all(math.isfinite(t) for t in cuts):
            raise ArgumentError(f"thresholds: 1 to {limit - 1} finite numbers")
        if any(b <= a for a, b in zip(cuts, cuts[1:])):
            raise ArgumentError("thresholds must be strictly increasing")
        names = [str(label) for label in labels]
        if len(names) != len(cuts) + 1 or not all(0 < len(n) <= 64 for n in names):
            raise ArgumentError("labels: one more than thresholds, each 1-64 characters")
        obj = RevealObject(ref=f"bucket:{self._ref('sum', col.name, where)}", kind="aggregate")

        def compute() -> str:
            total, _ = self._admitted_sum(caller, col.name, where, obj.ref, purpose)
            value = total / (10 ** col.scale) if col.scale else total
            for cut, name in zip(cuts, names):
                if value < cut:
                    return name
            return names[-1]

        label = self._reveal(caller, obj, purpose, compute)
        return {"column": col.name, "filters": where, "bucket": label}

    # -- dispatch -------------------------------------------------------------------

    def invoke(
        self, tool: str, principal: str, arguments: Optional[Mapping[str, Any]] = None,
        taint: int = 0,
    ) -> Dict[str, Any]:
        """Run one tool call *without* latency padding (the caller pads:
        the MCP server does so asynchronously). Raises
        :class:`ArgumentError` or :class:`AdmissionDenied`."""
        handlers: Dict[str, Callable[..., Dict[str, Any]]] = {
            "describe_dataset": self._describe_dataset,
            "aggregate": self._aggregate,
            "group_by": self._group_by,
            "compare_periods": self._compare_periods,
            "similarity_search": self._similarity_search,
            "exists": self._exists,
            "disclose_ratio": self._disclose_ratio,
            "disclose_bucket": self._disclose_bucket,
        }
        if tool not in self.tool_names:
            raise ArgumentError(f"unknown tool {tool!r}")
        caller = Caller(principal=principal, taint=1 if taint else 0)
        handler = handlers[tool]
        kwargs = dict(arguments or {})
        try:
            inspect.signature(handler).bind(caller, **kwargs)
        except TypeError as exc:
            raise ArgumentError(f"invalid arguments for {tool}: {exc}") from None
        return handler(caller, **kwargs)

    # -- padded public API (direct Python use; W6) ------------------------------------

    @quantize_latency
    def describe_dataset(self, principal: str, *, taint: int = 0) -> Dict[str, Any]:
        return self.invoke("describe_dataset", principal, {}, taint)

    @quantize_latency
    def aggregate(
        self, principal: str, function: str, column: Optional[str] = None,
        filters: Optional[Mapping[str, str]] = None, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke(
            "aggregate", principal, {"function": function, "column": column, "filters": filters}, taint
        )

    @quantize_latency
    def group_by(
        self, principal: str, key: str, function: str = "sum", column: Optional[str] = None,
        filters: Optional[Mapping[str, str]] = None, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke(
            "group_by", principal,
            {"key": key, "function": function, "column": column, "filters": filters}, taint,
        )

    @quantize_latency
    def compare_periods(
        self, principal: str, column_a: str, column_b: str,
        filters: Optional[Mapping[str, str]] = None, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke(
            "compare_periods", principal,
            {"column_a": column_a, "column_b": column_b, "filters": filters}, taint,
        )

    @quantize_latency
    def similarity_search(
        self, principal: str, token: str, top_k: int = 3, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke("similarity_search", principal, {"token": token, "top_k": top_k}, taint)

    @quantize_latency
    def exists(
        self, principal: str, filters: Optional[Mapping[str, str]] = None, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke("exists", principal, {"filters": filters}, taint)

    @quantize_latency
    def disclose_ratio(
        self, principal: str, column: str, numerator_filters: Mapping[str, str],
        denominator_filters: Mapping[str, str], purpose: str, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke(
            "disclose_ratio", principal,
            {"column": column, "numerator_filters": numerator_filters,
             "denominator_filters": denominator_filters, "purpose": purpose},
            taint,
        )

    @quantize_latency
    def disclose_bucket(
        self, principal: str, column: str, thresholds: Sequence[float], labels: Sequence[str],
        purpose: str, filters: Optional[Mapping[str, str]] = None, *, taint: int = 0,
    ) -> Dict[str, Any]:
        return self.invoke(
            "disclose_bucket", principal,
            {"column": column, "thresholds": list(thresholds), "labels": list(labels),
             "purpose": purpose, "filters": filters},
            taint,
        )

    def domain(self, column: str) -> List[str]:
        """The distinct values of an OPEN column (public by definition)."""
        col = self.schema.column(column)
        if col.protection != "open":
            raise ArgumentError(f"{column!r} is not an open column")
        with self._lock:
            return sorted(set(self._public[column]))

    def catalogue_resource(self) -> Dict[str, Any]:
        """Schema metadata only: no values, no budgets."""
        return {
            "columns": [
                {"name": c.name, "protection": c.protection, "description": c.description,
                 **({"unit": c.unit} if c.unit else {})}
                for c in self.schema.columns
            ],
            "min_query_set_size": self.k,
            "reveal_purposes": {p.name: p.description for p in self.settings.purposes},
        }


def _similarity_band(score: float) -> str:
    for edge, label in ((0.5, "low"), (0.8, "medium"), (0.95, "high")):
        if score < edge:
            return label
    return "very high"
