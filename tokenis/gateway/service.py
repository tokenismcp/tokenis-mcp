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

import contextlib
import functools
import hashlib
import inspect
import itertools
import json
import math
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

import numpy as np

from tokenis._core import CiphertextVector
from tokenis.audit.trace import AuditRecord, DisclosureTrace
from tokenis.crypto.ec_fhe import (
    MAX_TABLE_SIZE,
    Decryptor,
    PrivateKey,
    TokenisCryptoError,
    keygen,
)
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
from tokenis.gateway.state import AdmissionLog, StateMismatchError
from tokenis.semantic.tokenizer import ScopedTokenizer

if TYPE_CHECKING:  # pragma: no cover
    from tokenis.gateway.pgstate import PostgresState

POLICY_VERSION = "tokenis-gateway/2"

DENIED_MESSAGE = (
    "Denied by the disclosure policy. The request may match too few records, "
    "combine with earlier queries to isolate individual records, exceed your "
    "query budget, or need a purpose you are not authorised for. Try broader "
    "filters or a different question; the gateway does not say which reason "
    "applied."
)

_I63 = 1 << 62  # headroom so sums of a few values cannot overflow i64


class _Rare:
    """Stands for every filterable value held by fewer than k records (see
    ``TokenisGatewayService._cells``); equal to no filter value."""

    def __repr__(self) -> str:
        return "<rare>"


_RARE = _Rare()
_F = TypeVar("_F", bound=Callable[..., Any])


class AdmissionDenied(Exception):
    """A call refused by policy. The message is always
    :data:`DENIED_MESSAGE`; ``rule`` (for logs and tests, never for the
    caller) says which control fired."""

    def __init__(self, rule: str = "") -> None:
        super().__init__(DENIED_MESSAGE)
        self.rule = rule


class IngestError(ValueError):
    """A record in an :meth:`TokenisGatewayService.ingest_many` batch is
    invalid; ``index`` is its position in the batch."""

    def __init__(self, index: int, reason: str) -> None:
        super().__init__(reason)
        self.index = index
        self.reason = reason


class ArgumentError(ValueError):
    """Invalid arguments. Safe to show the caller: these checks depend only
    on the public schema and settings, never on the data."""


@dataclass(frozen=True)
class Caller:
    """Who is calling (already authenticated) and whether their context is
    tainted by untrusted content (P4 D4; supplied by the host)."""

    principal: str
    taint: int = 0


#: How long a call waits for the gateway's lock before giving up with
#: GatewayUnavailable. Calls hold it for milliseconds; a long wait means one
#: call is stuck (e.g. on an unresponsive database) and queueing more
#: behind it would only exhaust the server's workers.
LOCK_TIMEOUT_S = 20.0


_GENESIS_DIGEST = "0" * 64


class GatewayUnavailable(RuntimeError):
    """The gateway cannot serve the call right now (busy or its state store
    is unreachable). Fails closed; callers see a generic message."""


def _locked(method: _F) -> _F:
    @functools.wraps(method)
    def wrapper(self: "TokenisGatewayService", *args: Any, **kwargs: Any) -> Any:
        with self._hold(), self._shared_transaction():
            self._seal_locked()
            self._sync_shared()
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
        private_key: Optional[bytes] = None,
        shared_state: Optional["PostgresState"] = None,
    ) -> None:
        if shared_state is not None and state_dir is not None:
            raise ValueError("pass state_dir or shared_state, not both")
        self.schema = schema
        self.settings = settings or GatewaySettings()
        self._lock = threading.RLock()
        self._hold_depth = 0
        self._held_since: Optional[float] = None
        self._sealed = False
        self._state_dir = Path(state_dir) if state_dir is not None else None
        self._reset_state = reset_admission_state

        # A persistent key (from the keystore) lets ciphertexts outlive the
        # process -- required for a persisted ledger; otherwise a fresh key
        # per process, and the data is re-encrypted at every start.
        if private_key is not None:
            self._private_key: PrivateKey = PrivateKey.from_bytes(private_key)
            self._public_key = self._private_key.public_key()
        else:
            keypair = keygen()
            self._private_key = keypair.private
            self._public_key = keypair.public
        #: Sum of |stored value| per sealed column (and of squares): a hard
        #: bound on any aggregate, so each column's decryptor is sized to it.
        self._bounds: Dict[str, int] = {}
        self._decryptors: Dict[str, Decryptor] = {}
        self._tokenizer = ScopedTokenizer(key=tokenizer_key)
        self._scope = ScopedTokenizer.make_scope(tenant=self.settings.tenant, epoch=self.settings.epoch)

        self._filterable = schema.filterable
        self._sealed_columns = schema.sealed
        self._ids: Dict[str, int] = {}
        self._public: Dict[str, List[str]] = {c.name: [] for c in schema.filterable}
        self._sealed_cts: Dict[str, CiphertextVector] = {
            c.name: CiphertextVector(self._public_key) for c in schema.sealed
        }
        self._square_cts: Dict[str, CiphertextVector] = {
            c.name: CiphertextVector(self._public_key) for c in schema.sealed if c.allow_variance
        }
        for c in schema.sealed:
            self._bounds[c.name] = 0
            if c.allow_variance:
                self._bounds[c.name + "\x00sq"] = 0
        self._embeddings: Dict[str, np.ndarray] = {}
        self._embedding_dim: Optional[int] = None

        #: Admission history, trace and API keys shared with other replicas
        #: through PostgreSQL (see tokenis.gateway.pgstate).
        self.shared_state = shared_state
        self._last_seq = 0
        self._last_digest = ""
        #: The last record known to be committed: after a failed call, the
        #: records this replica wrote may have been rolled back, but these
        #: must still be in the database.
        self._committed_seq = 0
        self._committed_digest = ""
        self._admission_stale = False
        self._state_fingerprint = ""
        #: Set when the shared history no longer matches this replica; every
        #: call (and readiness) fails until the process restarts.
        self.state_failure: Optional[str] = None
        self.trace = DisclosureTrace(
            path=self._state_dir / "trace.jsonl" if self._state_dir else None,
            hmac_key=audit_key,
            storage=shared_state.trace_storage() if shared_state is not None else None,
        )
        if shared_state is not None and audit_key is not None:
            shared_state.chain_key = audit_key
        self._attrs: Dict[str, np.ndarray] = {}
        # Filled at seal, when the per-record strings are released:
        self._record_count = 0
        self._domains: Dict[str, List[str]] = {}
        self._cell_of_record = np.zeros(0, dtype=np.int64)
        self._cell_attrs: Dict[str, np.ndarray] = {}
        self._cell_weights = np.zeros(0, dtype=np.int64)
        self._admission: Optional[AdmissionPolicy] = None
        self._log: Optional[AdmissionLog] = None

    # -- properties -----------------------------------------------------------

    @property
    def latency_granularity_ms(self) -> float:
        return self.settings.disclosure.latency_granularity_ms

    @property
    def record_count(self) -> int:
        return self._record_count if self._sealed else len(self._ids)

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
        """Add one record (see :meth:`ingest_many`, which is much faster for
        many records)."""
        try:
            self.ingest_many([(record_id, row, embedding)])
        except IngestError as exc:
            raise ValueError(exc.reason) from None

    def ingest_many(
        self, records: Iterable[Tuple[Any, Mapping[str, Any], Optional[Sequence[float]]]],
    ) -> int:
        """Add ``(record_id, row, embedding)`` records as one atomic batch:
        every record is validated before any is committed, then each sealed
        column is encrypted in parallel inside the Rust core. Plaintext
        enters here and nowhere else -- only ciphertexts and pseudonyms are
        kept. Raises :class:`IngestError` naming the offending record's
        position; nothing from the batch is kept in that case."""
        with self._lock:
            if self._sealed:
                raise RuntimeError(
                    "the ledger is sealed (queries have run against it); load a new "
                    "gateway to change the data"
                )
            if getattr(self, "_from_ledger", False):
                raise RuntimeError("this gateway was loaded from a persisted ledger; re-run ingest")
            batch = [self._prepare(i, rid, row, emb) for i, (rid, row, emb) in enumerate(records)]
            seen: Dict[str, int] = {}
            expected_dim = self._embedding_dim
            for i, (record_id, _public, _stored, vector) in enumerate(batch):
                if record_id in seen:
                    raise IngestError(i, f"duplicate record id {record_id!r}")
                seen[record_id] = i
                if vector is not None:
                    expected_dim = expected_dim or vector.size
                    if vector.size != expected_dim:
                        raise IngestError(
                            i, f"record {record_id!r}: embedding has {vector.size} dimensions, "
                            f"expected {expected_dim}",
                        )
            # Encrypt into fresh vectors first so a failure leaves the ledger
            # untouched, then move them in.
            fresh: Dict[str, CiphertextVector] = {}
            for col in self.schema.sealed:
                values = [b[2][col.name] for b in batch]
                fresh[col.name] = CiphertextVector(self._public_key)
                fresh[col.name].extend_encrypt(values)
                if col.allow_variance:
                    squares = CiphertextVector(self._public_key)
                    squares.extend_encrypt([v * v for v in values])
                    fresh[col.name + "\x00sq"] = squares
            for col in self.schema.sealed:
                self._sealed_cts[col.name].extend(fresh[col.name])
                values = [b[2][col.name] for b in batch]
                self._bounds[col.name] += sum(abs(v) for v in values)
                if col.allow_variance:
                    self._square_cts[col.name].extend(fresh[col.name + "\x00sq"])
                    self._bounds[col.name + "\x00sq"] += sum(v * v for v in values)
            for record_id, public, _stored, vector in batch:
                self._ids[record_id] = len(self._ids)
                for name, value in public.items():
                    self._public[name].append(value)
                if vector is not None and self.schema.entity is not None:
                    self._embedding_dim = vector.size
                    norm = float(np.linalg.norm(vector))
                    self._embeddings[public[self.schema.entity.name]] = (
                        vector / norm if norm > 0 else vector
                    )
            return len(batch)

    def _prepare(
        self, index: int, record_id: Any, row: Mapping[str, Any],
        embedding: Optional[Sequence[float]],
    ) -> Tuple[str, Dict[str, str], Dict[str, int], Optional[np.ndarray]]:
        record_id = str(record_id)
        where = f"record {record_id!r}"
        if record_id in self._ids:
            raise IngestError(index, f"duplicate record id {record_id!r}")
        public: Dict[str, str] = {}
        for col in self._filterable:
            raw = row.get(col.name)
            if raw is None or str(raw).strip() == "":
                raise IngestError(index, f"{where}: missing value for {col.name!r}")
            text = str(raw).strip()
            if len(text) > 256:
                raise IngestError(index, f"{where}: {col.name!r} longer than 256 characters")
            public[col.name] = (
                self._tokenizer.tokenize(col.name, self._scope, text)
                if col.protection == "token"
                else text
            )
        stored: Dict[str, int] = {}
        for col in self._sealed_columns:
            try:
                value = _to_stored(row.get(col.name), col.scale, f"{where}: {col.name}")
            except ValueError as exc:
                raise IngestError(index, str(exc)) from None
            if col.allow_variance and value * value >= (1 << 63):
                raise IngestError(index, f"{where}: {col.name} too large for VAR (its square overflows)")
            stored[col.name] = value
        vector = None
        if embedding is not None:
            if self.schema.embedding_column is None or self.schema.entity is None:
                raise IngestError(index, "this schema has no embedding field")
            try:
                vector = np.asarray([float(x) for x in embedding], dtype=np.float64)
            except (TypeError, ValueError):
                raise IngestError(index, f"{where}: embedding must contain only numbers") from None
            if vector.ndim != 1 or vector.size == 0 or not np.all(np.isfinite(vector)):
                raise IngestError(index, f"{where}: embedding must be a non-empty finite vector")
            if self._embedding_dim is not None and vector.size != self._embedding_dim:
                raise IngestError(
                    index,
                    f"{where}: embedding has {vector.size} dimensions, expected {self._embedding_dim}",
                )
        return record_id, public, stored, vector

    # -- persistence (see tokenis.ledger) ----------------------------------------

    def _export_state(self) -> Dict[str, Any]:
        with self._lock:
            if self._sealed:
                raise RuntimeError("export the ledger before the first query (it is sealed)")
            return {
                "records": self.record_count,
                "public_key": self._public_key.to_bytes().hex(),
                "public": {name: list(values) for name, values in self._public.items()},
                "sealed": {name: vec.to_bytes() for name, vec in self._sealed_cts.items()},
                "squares": {name: vec.to_bytes() for name, vec in self._square_cts.items()},
                "bounds": dict(self._bounds),
                "embeddings": dict(self._embeddings),
            }

    def _import_state(self, state: Mapping[str, Any]) -> None:
        with self._lock:
            if self.record_count or self._sealed:
                raise RuntimeError("import a ledger into an empty gateway only")
            if state["public_key"] != self._public_key.to_bytes().hex():
                raise ValueError("the ledger was encrypted under a different key than the keystore's")
            n = int(state["records"])
            expected = {c.name for c in self.schema.filterable}
            if set(state["public"]) != expected or any(len(v) != n for v in state["public"].values()):
                raise ValueError("ledger columns do not match the schema")
            for col in self.schema.sealed:
                vec = CiphertextVector.from_bytes(self._public_key, state["sealed"][col.name])
                if len(vec) != n:
                    raise ValueError(f"ledger column {col.name!r} has the wrong length")
                self._sealed_cts[col.name] = vec
                if col.allow_variance:
                    self._square_cts[col.name] = CiphertextVector.from_bytes(
                        self._public_key, state["squares"][col.name])
            self._public = {name: list(values) for name, values in state["public"].items()}
            self._bounds = {k: int(v) for k, v in state["bounds"].items()}
            for token, vector in state["embeddings"]:
                self._embeddings[token] = np.asarray(vector, dtype=np.float64)
                self._embedding_dim = self._embeddings[token].size
            # Record ids are not persisted (they are never needed after
            # loading and may themselves be sensitive); a loaded ledger is
            # complete, so ingesting into it is refused.
            self._ids = {f"#{i}": i for i in range(n)}
            self._from_ledger = True

    def seal(self) -> None:
        """Freeze the ledger and build (or restore) the admission state.
        Called automatically by the first query."""
        with self._lock, self._shared_transaction():
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
        self._attrs = {
            name: np.array(values, dtype=object) for name, values in self._public.items()
        }
        self._domains = {name: sorted(set(values)) for name, values in self._public.items()}
        cell_attrs, weights, cell_of_record = self._cells()
        self._cell_weights = weights
        self._admission = self._new_admission(cell_attrs)
        self._build_decryptors()
        if self.shared_state is not None:
            self._state_fingerprint = self._fingerprint()
            self.shared_state.open(self._state_fingerprint, reset=self._reset_state)
            self._last_seq, self._last_digest = 0, ""
            self._sync_shared()
        elif self._state_dir is not None:
            self._log = AdmissionLog(
                self._state_dir / "admission.jsonl",
                fingerprint=self._fingerprint(),
                reset=self._reset_state,
            )
            for record in self._log.records():
                self._replay(record)
        # Per-record strings are no longer needed: every predicate is
        # evaluated per cell and mapped back to records with one gather.
        self._record_count = n
        self._cell_attrs = cell_attrs
        self._cell_of_record = cell_of_record
        self._attrs = {}
        self._public = {name: [] for name in self._public}
        self._ids = {}
        self._sealed = True

    def _new_admission(self, cell_attrs: Dict[str, np.ndarray]) -> AdmissionPolicy:
        adm = self.settings.admission
        return AdmissionPolicy(
            n=len(self._cell_weights),
            public_attributes=cell_attrs,
            weights=self._cell_weights,
            catalogue=[c.name for c in self.schema.sealed],
            k=self.k,
            budget=adm.budget,
            taint_budget=adm.taint_budget,
            taint_call_cap=adm.taint_call_cap,
            cell_aware=adm.cell_aware,
        )

    # -- shared state (several replicas, one PostgreSQL) ---------------------------

    @contextlib.contextmanager
    def _hold(self) -> Iterator[None]:
        """The gateway lock, with a bounded wait, recording how long the
        current holder has had it (readiness reports a stuck call)."""
        if not self._lock.acquire(timeout=LOCK_TIMEOUT_S):
            raise GatewayUnavailable(f"gateway busy: a call has held the lock for over {LOCK_TIMEOUT_S:.0f} s")
        self._hold_depth += 1
        if self._hold_depth == 1:
            self._held_since = time.monotonic()
        try:
            yield
        finally:
            self._hold_depth -= 1
            if self._hold_depth == 0:
                self._held_since = None
            self._lock.release()

    def busy_seconds(self) -> float:
        """How long the current call has held the gateway lock (0 if none)."""
        since = self._held_since
        return 0.0 if since is None else time.monotonic() - since

    @contextlib.contextmanager
    def _shared_transaction(self) -> Iterator[None]:
        """With shared state, the whole call runs in one database transaction
        under the tenant's advisory lock; any database failure leaves the
        in-memory admission state suspect, so it is rebuilt from the log on
        the next call rather than trusted."""
        if self.shared_state is None:
            yield
            return
        try:
            with self.shared_state.transaction():
                yield
        except self.shared_state.database_errors:
            self._admission_stale = True
            raise
        except BaseException:
            # A refusal or argument error: the transaction still committed.
            self._committed_seq, self._committed_digest = self._last_seq, self._last_digest
            raise
        self._committed_seq, self._committed_digest = self._last_seq, self._last_digest

    def _sync_shared(self) -> None:
        """Replay admission calls other replicas logged since we last looked
        (caller holds the transaction, so nothing new can appear meanwhile)."""
        if self.shared_state is None:
            return
        if self.state_failure is not None:
            raise StateMismatchError(self.state_failure)
        try:
            if self._admission_stale and self._sealed:
                # A database call failed: what this replica last wrote may
                # have been rolled back, but what was committed must still be
                # there -- a failover to a lagging standby or a restore also
                # drops connections, and must not slip through here.
                self.shared_state.check(self._state_fingerprint, self._committed_seq,
                                        self._committed_digest)
                self._admission = self._new_admission(self._cell_attrs)
                self._last_seq, self._last_digest = 0, ""
            elif self._sealed:
                self.shared_state.check(self._state_fingerprint, self._last_seq, self._last_digest)
            self._admission_stale = False
            new = self.shared_state.records_after(self._last_seq, self._last_digest or _GENESIS_DIGEST)
        except StateMismatchError as exc:
            if self._sealed:
                self.state_failure = str(exc)
            raise
        for seq, record, digest in new:
            self._replay(record)
            self._last_seq, self._last_digest = seq, digest

    def _cells(self) -> Tuple[Dict[str, np.ndarray], np.ndarray, np.ndarray]:
        """Group records into cells no admissible query can tell apart, so
        admission control scales with the number of cells, not records.

        Admissible predicates are conjunctions of ``column == value`` over
        filterable columns. Two records with equal filterable values are
        therefore always in or out together. Further, a value held by fewer
        than k records can never appear in an *admitted* predicate: any
        conjunction naming it matches fewer than k records and D1 refuses
        it. So such rare values are merged into one sentinel that no filter
        value equals -- the per-cell result of every predicate then equals
        the per-record result for everything D1 admits, and the refused ones
        are refused either way. ``tests/test_admission_cells.py`` checks the
        decisions against the uncompressed policy (and caught an ordering
        bug the argument above glosses over -- see below)."""
        k = self.k
        names = sorted(self._attrs)
        codes, domains = [], []
        for name in names:
            # Factorise without materialising a fixed-width string copy.
            index: Dict[str, int] = {}
            values = self._attrs[name]
            code = np.fromiter(
                (index.setdefault(v, len(index)) for v in values), dtype=np.int64, count=len(values)
            )
            counts = np.bincount(code, minlength=len(index))
            code[counts[code] < k] = -1
            codes.append(code)
            domains.append(np.array(list(index), dtype=object))
        matrix = np.stack(codes, axis=1)
        cells, first, inverse, weights = np.unique(
            matrix, axis=0, return_index=True, return_inverse=True, return_counts=True
        )
        # Order cells by their first record. D2's cell-aware test inspects
        # the rows of a reduced row-echelon form, which depends on column
        # order; in first-occurrence order every pivot choice and
        # elimination step over cells mirrors the per-record computation.
        order = np.argsort(first, kind="stable")
        cells, weights = cells[order], weights[order]
        rank = np.empty_like(order)
        rank[order] = np.arange(len(order))
        cell_of_record = rank[inverse.reshape(-1)]
        attrs = {
            name: np.array(
                [str(domain[c]) if c >= 0 else _RARE for c in cells[:, j]], dtype=object
            )
            for j, (name, domain) in enumerate(zip(names, domains))
        }
        return attrs, weights.astype(np.int64), cell_of_record

    def _build_decryptors(self) -> None:
        """One decryptor per sealed column (and per squares column), sized to
        the column's own bound: every aggregate over a column is a subset
        sum, so |aggregate| <= sum(|v|). Each decryption then walks a fixed,
        small number of steps -- fixed per column, so timing reveals nothing
        about the query -- instead of the configured worst case."""
        cap = self.settings.decryption
        for key, bound in self._bounds.items():
            max_value = max(1, min(bound, cap.max_value))
            span = 2 * max_value + 1
            balanced = max(4096, math.isqrt(span) * 16)
            table = min(span, balanced, cap.table_size or MAX_TABLE_SIZE, MAX_TABLE_SIZE)
            self._decryptors[key] = Decryptor(self._private_key, max_value, table_size=table)

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
        meta["fingerprint"] = 2
        h.update(json.dumps(meta, sort_keys=True).encode())
        # The multiset of rows, independent of their order: replicas reading
        # the same rows in a different order (a database without ORDER BY,
        # a reshuffled heap) must agree. Each row hashes to a 256-bit number
        # and the numbers are added modulo 2^256 -- unlike XOR, duplicate
        # rows do not cancel.
        names = sorted(self._attrs)
        columns = [self._attrs[name] for name in names]
        total = 0
        for row in zip(*columns):
            # JSON: unambiguous whatever characters the values contain.
            digest = hashlib.sha256(json.dumps([str(v) for v in row]).encode()).digest()
            total = (total + int.from_bytes(digest, "big")) % (1 << 256)
        h.update(total.to_bytes(32, "big"))
        return h.hexdigest()

    def _replay(self, record: Dict[str, Any]) -> None:
        try:
            self._replay_record(record)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise StateMismatchError(
                f"the admission history holds a corrupt record ({type(exc).__name__}: {exc}); "
                "it was edited or damaged. Restore it, or reset it deliberately "
                "(--reset-admission-state)"
            ) from None

    def _replay_record(self, record: Dict[str, Any]) -> None:
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
        if self._log is None and self.shared_state is None:
            return
        record: Dict[str, Any] = {
            "op": op, "subject": context.subject_id, "taint": context.taint,
            "window": context.window, "admitted": admitted,
        }
        if op == "decide":
            record.update(filters=dict(filters or {}), function=function, column=column)
        if self.shared_state is not None:
            self._last_seq, self._last_digest = self.shared_state.append(record)
        else:
            assert self._log is not None  # noqa: S101 -- checked above
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
        """Records matching ``filters`` -- used only after admission, so every
        filter value is a common one and the per-cell result is exact."""
        assert self._admission is not None  # noqa: S101 -- only called after sealing
        cells = characteristic_indicator(self._predicate(filters), self._cell_attrs, self._admission.n)
        return cells[self._cell_of_record]

    def _decrypt_sum(
        self, caller: Caller, column: str, mask: np.ndarray, obj_ref: str, purpose: str,
        squares: bool = False,
    ) -> int:
        vector = (self._square_cts if squares else self._sealed_cts)[column]
        decryptor = self._decryptors[column + "\x00sq" if squares else column]
        try:
            total = vector.sum_where(mask.astype(np.uint8).tobytes())
            return decryptor.decrypt(total)
        except TokenisCryptoError:
            raise self._deny(caller, obj_ref, purpose, "decryption-range") from None

    def _admitted_sum(
        self, caller: Caller, column: str, filters: Mapping[str, str], obj_ref: str, purpose: str,
    ) -> Tuple[int, int]:
        """An admitted SUM in stored units, and its set size."""
        decision = self._decide(caller, filters, "SUM", column, obj_ref, purpose)
        total = self._decrypt_sum(caller, column, self._indicator(filters), obj_ref, purpose)
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

    def _exact_column(self, name: Any, tool: str) -> ColumnSpec:
        """A sealed column the Reveal tools may use. A column reported only
        in 1-2-5 bands is refused: caller-chosen thresholds (or ratios
        against it) would narrow a total below its band by bisection."""
        col = self._sealed_column(name)
        if col.result_mode == "band":
            raise ArgumentError(f"{col.name} is reported in bands only; {tool} cannot use it")
        return col

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
                domain = self._domains[col.name]
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
        notice = {"notice": self.settings.notice} if self.settings.notice else {}
        return {
            **notice,
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
        total = self._decrypt_sum(caller, col.name, mask, obj_ref, "aggregate")
        if function == "sum":
            value = self._present(col, total)
        elif function == "avg":
            value = self._present(col, total / size)
        else:
            squares = self._decrypt_sum(caller, col.name, mask, obj_ref, "aggregate", squares=True)
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
        if key not in self._domains:
            names = ", ".join(c.name for c in self.schema.filterable)
            raise ArgumentError(f"key must be a filterable column: one of {names}")
        function = str(function).lower()
        if function not in ("sum", "count", "avg"):
            raise ArgumentError("function must be one of sum, count, avg")
        where = self._filters(filters)
        if key in where:
            raise ArgumentError("cannot group by a column that is also filtered")
        col = None if function == "count" else self._sealed_column(column)
        domain = self._domains[key]
        if len(domain) > self.settings.disclosure.max_groups:
            raise ArgumentError(
                f"{key!r} has more than {self.settings.disclosure.max_groups} distinct values; "
                "group by a coarser column, or use aggregate with a filter on the values you need"
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
                        caller, col.name, self._indicator(group_filters),
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
        col = self._exact_column(column, "disclose_ratio")
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
        col = self._exact_column(column, "disclose_bucket")
        where = self._filters(filters)
        purpose = self._purpose(purpose)
        limit = self.settings.disclosure.max_buckets
        cuts = [float(t) for t in thresholds]
        if not 1 <= len(cuts) < limit or not all(math.isfinite(t) for t in cuts):
            raise ArgumentError(f"thresholds: 1 to {limit - 1} finite numbers")
        if any(b <= a for a, b in itertools.pairwise(cuts)):
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
            self._seal_locked()
            return list(self._domains[column])

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
