# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The dataset schema and gateway settings: which columns exist, what
protection class each has (P2 §3.2), and the admission, decryption,
disclosure and Reveal-purpose policy the gateway enforces over them.

Everything here is plain, validated, immutable data. :mod:`tokenis.config`
builds it from a TOML file; tests and embedding applications can build it
directly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from tokenis.crypto.ec_fhe import MAX_SUPPORTED_RANGE, MAX_TABLE_SIZE

PROTECTION_CLASSES = ("open", "token", "sealed")
RESULT_MODES = ("exact", "band")
BUDGET_WINDOWS = ("total", "day", "hour")
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _check_name(kind: str, name: str) -> None:
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(
            f"{kind} name {name!r} must match [a-z][a-z0-9_]* (at most 63 characters)"
        )


@dataclass(frozen=True)
class ColumnSpec:
    """One attribute of the dataset.

    - ``open``: released verbatim; usable in filters and as a group key.
    - ``token``: released only as a keyed pseudonym (equal values, equal
      tokens); usable in filters and as a group key *by token*.
    - ``sealed``: encrypted at load time; only aggregates over it leave the
      gateway, subject to admission control.

    ``scale`` (sealed only) keeps that many decimal places: values are
    stored as ``round(v * 10**scale)`` and reported divided back.
    ``result_mode="band"`` reports aggregates over the column as a coarse
    1-2-5 band instead of an exact value. ``allow_variance`` enables VAR,
    which needs a second encrypted column of squares (and a decryption range
    large enough for their sums). ``entity`` marks the one token column that
    identifies a record's subject (what ``similarity_search`` returns).
    """

    name: str
    protection: str
    description: str = ""
    unit: str = ""
    scale: int = 0
    result_mode: str = "exact"
    allow_variance: bool = False
    entity: bool = False

    def __post_init__(self) -> None:
        _check_name("column", self.name)
        if self.protection not in PROTECTION_CLASSES:
            raise ValueError(
                f"column {self.name!r}: protection must be one of {PROTECTION_CLASSES}"
            )
        if not 0 <= self.scale <= 6:
            raise ValueError(f"column {self.name!r}: scale must be in [0, 6]")
        if self.result_mode not in RESULT_MODES:
            raise ValueError(f"column {self.name!r}: result_mode must be one of {RESULT_MODES}")
        if self.protection != "sealed" and (
            self.scale or self.allow_variance or self.result_mode != "exact"
        ):
            raise ValueError(
                f"column {self.name!r}: scale/result_mode/allow_variance apply to sealed columns only"
            )
        if self.entity and self.protection != "token":
            raise ValueError(f"column {self.name!r}: only a token column can be the entity")
        if len(self.description) > 500 or len(self.unit) > 40:
            raise ValueError(f"column {self.name!r}: description or unit too long")


@dataclass(frozen=True)
class Schema:
    """The dataset's columns plus two optional non-attribute fields:
    ``id_column`` (a unique record identifier in the source data; never
    exposed) and ``embedding_column`` (a vector per record for
    ``similarity_search``; never exposed, requires an entity column)."""

    columns: Tuple[ColumnSpec, ...]
    id_column: Optional[str] = None
    embedding_column: Optional[str] = None

    def __post_init__(self) -> None:
        names = [c.name for c in self.columns]
        if len(set(names)) != len(names):
            raise ValueError("column names must be unique")
        if not self.sealed:
            raise ValueError("the schema needs at least one sealed column")
        if sum(c.entity for c in self.columns) > 1:
            raise ValueError("at most one column can be the entity")
        for extra in (self.id_column, self.embedding_column):
            if extra is not None:
                _check_name("field", extra)
                if extra in names:
                    raise ValueError(f"{extra!r} is a schema column; it cannot also be the id/embedding field")
        if self.embedding_column is not None and self.entity is None:
            raise ValueError("embedding_column requires an entity token column")

    def column(self, name: str) -> ColumnSpec:
        for c in self.columns:
            if c.name == name:
                return c
        raise KeyError(name)

    @property
    def open(self) -> Tuple[ColumnSpec, ...]:
        return tuple(c for c in self.columns if c.protection == "open")

    @property
    def tokens(self) -> Tuple[ColumnSpec, ...]:
        return tuple(c for c in self.columns if c.protection == "token")

    @property
    def sealed(self) -> Tuple[ColumnSpec, ...]:
        return tuple(c for c in self.columns if c.protection == "sealed")

    @property
    def filterable(self) -> Tuple[ColumnSpec, ...]:
        """Columns a predicate may name: OPEN literals and TOKEN pseudonyms
        (P2 §3.5 -- the exposed vocabulary only)."""
        return tuple(c for c in self.columns if c.protection != "sealed")

    @property
    def entity(self) -> Optional[ColumnSpec]:
        return next((c for c in self.columns if c.entity), None)


@dataclass(frozen=True)
class AdmissionSettings:
    """P4 D1-D5 parameters. ``budget`` admitted value-bearing queries per
    principal per ``window``; ``taint_*`` apply while the caller's context
    holds untrusted content."""

    min_query_set_size: int = 5
    budget: int = 200
    window: str = "day"
    taint_budget: int = 20
    taint_call_cap: int = 50
    cell_aware: bool = True

    def __post_init__(self) -> None:
        if self.min_query_set_size < 2:
            raise ValueError("min_query_set_size must be at least 2")
        if min(self.budget, self.taint_budget, self.taint_call_cap) < 1:
            raise ValueError("budgets and the tainted call cap must be positive")
        if self.window not in BUDGET_WINDOWS:
            raise ValueError(f"window must be one of {BUDGET_WINDOWS}")


@dataclass(frozen=True)
class DecryptionSettings:
    """Caps for decryption. Each sealed column gets its own decryptor sized
    to that column's hard bound -- the sum of its absolute stored values,
    which no aggregate can exceed -- so small data decrypts in well under a
    millisecond. ``max_value`` caps that range (aggregates beyond it are
    denied) and ``table_size`` caps each decryptor's table (8 bytes per
    entry; larger tables decrypt proportionally faster)."""

    max_value: int = 1 << 36
    table_size: Optional[int] = 1 << 22

    def __post_init__(self) -> None:
        if not 1 <= self.max_value <= MAX_SUPPORTED_RANGE:
            raise ValueError(f"max_value must be in [1, {MAX_SUPPORTED_RANGE}]")
        if self.table_size is not None and not 1 <= self.table_size <= MAX_TABLE_SIZE:
            raise ValueError(f"table_size must be in [1, {MAX_TABLE_SIZE}]")


@dataclass(frozen=True)
class DisclosureSettings:
    """Response shaping. ``latency_granularity_ms`` is W6's declared
    latency quantum (every tool call takes a multiple of it)."""

    latency_granularity_ms: float = 250.0
    max_top_k: int = 5
    max_buckets: int = 8
    max_groups: int = 50
    max_enum_values: int = 100

    def __post_init__(self) -> None:
        if self.latency_granularity_ms <= 0:
            raise ValueError("latency_granularity_ms must be positive")
        if min(self.max_top_k, self.max_buckets, self.max_groups, self.max_enum_values) < 1:
            raise ValueError("disclosure limits must be positive")


@dataclass(frozen=True)
class RevealPurpose:
    """A named, server-side purpose that authorises the Reveal tools
    (``disclose_ratio``/``disclose_bucket``) for the listed principals
    (``"*"``: any authenticated principal). The model chooses among the
    names; it cannot invent one."""

    name: str
    description: str
    principals: Tuple[str, ...] = ("*",)

    def __post_init__(self) -> None:
        _check_name("purpose", self.name)
        if not self.principals:
            raise ValueError(f"purpose {self.name!r} lists no principals")

    def allows(self, principal: str) -> bool:
        return "*" in self.principals or principal in self.principals


@dataclass(frozen=True)
class GatewaySettings:
    tenant: str = "default"
    epoch: int = 1
    admission: AdmissionSettings = field(default_factory=AdmissionSettings)
    decryption: DecryptionSettings = field(default_factory=DecryptionSettings)
    disclosure: DisclosureSettings = field(default_factory=DisclosureSettings)
    purposes: Tuple[RevealPurpose, ...] = ()
    #: Shown to the model by describe_dataset (e.g. "fictional demo data").
    notice: str = ""

    def __post_init__(self) -> None:
        names = [p.name for p in self.purposes]
        if len(set(names)) != len(names):
            raise ValueError("purpose names must be unique")

    def purpose(self, name: str) -> Optional[RevealPurpose]:
        return next((p for p in self.purposes if p.name == name), None)

    def purposes_for(self, principal: str) -> Dict[str, str]:
        return {p.name: p.description for p in self.purposes if p.allows(principal)}
