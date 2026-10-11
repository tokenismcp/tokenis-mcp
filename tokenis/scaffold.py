# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""``tokenis-mcp init``: a starting configuration from a CSV or JSON-lines file.

It reads the file, guesses how each column should be protected, writes a
``tokenis.toml`` and a ``.env`` with freshly generated keys, and says what it
decided and why. The result is a starting point to review, not a verdict:
the guesses err toward protecting more (an ambiguous column becomes a token
or is left out, never shown verbatim).

Rules, in order, per column:

- left out: empty cells (the gateway needs every open, token and sealed cell
  filled), cells over 256 characters, or a header that is not a valid name
  after normalising (``Annual Revenue`` becomes ``annual_revenue``);
- the record id: a column named ``id`` or ending in ``_id`` whose values are
  unique (never exposed to the model);
- an embedding: text that is a list of numbers (``0.1;0.2;...``), used by
  ``similarity_search`` and never shown;
- a token (shown only as a keyed pseudonym): a name that looks personal
  (e-mail, phone, name, address, ...) or text with many distinct values;
- sealed (encrypted, only aggregates leave): numbers;
- open (shown verbatim, usable to filter and group): text with few distinct
  values.
"""
from __future__ import annotations

import csv
import json
import math
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

MAX_CELL = 256
MAX_OPEN_VALUES = 50  # at most this many distinct values: a category, not an identifier
SCALE_CAP = 6
STORED_LIMIT = 2 ** 40  # the largest [decryption] max_value
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_CATEGORY_NUMBER = re.compile(r"(^|[-_ ])(code|zip|postal|year|month|quarter|grade|class|type|category|status|flag)($|[-_ ])|코드|우편|연도|등급",
                             re.IGNORECASE)
_VECTOR = re.compile(r"^\[?\s*[-+]?\d+(\.\d+)?([;,\s]+[-+]?\d+(\.\d+)?)+\s*\]?$")
_PERSONAL = re.compile(
    r"e[-_ ]?mail|phone|mobile|tel\b|fax|ssn|passport|national[-_ ]?id|resident|address|street|"
    r"first[-_ ]?name|last[-_ ]?name|full[-_ ]?name|(^|[-_ ])name($|[-_ ])|birth|dob|account[-_ ]?(no|number)|"
    r"card|iban|ip[-_ ]?addr|이름|성명|전화|주민|주소|이메일|계좌|카드|생년",
    re.IGNORECASE)


@dataclass
class ColumnPlan:
    source: str
    name: str
    protection: str  # open | token | sealed | id | skip
    reason: str
    scale: int = 0
    values: int = 0
    total: int = 0  # sealed: sum of |value| in stored units


@dataclass
class Plan:
    rows: int
    columns: List[ColumnPlan]
    warnings: List[str] = field(default_factory=list)

    def of(self, protection: str) -> List[ColumnPlan]:
        return [c for c in self.columns if c.protection == protection]


def normalise(header: str) -> str:
    """``Annual Revenue (KRW)`` -> ``annual_revenue_krw``; empty if nothing usable."""
    text = re.sub(r"[^a-z0-9]+", "_", header.strip().lower()).strip("_")
    if text and not text[0].isalpha():
        text = "c_" + text
    return text[:63]


def _read_rows(path: Path, delimiter: str = ",", encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        with path.open(encoding=encoding) as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError("every line of a JSON-lines file must be an object")
                    yield row
        return
    with path.open(newline="", encoding=encoding) as handle:
        yield from csv.DictReader(handle, delimiter=delimiter)


def _number(text: str) -> Optional[Tuple[int, int]]:
    """(digits after the decimal point, integer part sign-free value scaled) of a plain
    decimal number, or None. Exponents, thousands separators and NaN are not numbers here."""
    if not re.fullmatch(r"[+-]?\d+(\.\d+)?", text):
        return None
    whole, _, frac = text.lstrip("+-").partition(".")
    return len(frac), int(whole + frac)


def analyse(path: Path, *, delimiter: str = ",", encoding: str = "utf-8", max_rows: int = 5_000_000) -> Plan:
    columns: Dict[str, Dict[str, Any]] = {}
    rows = 0
    for row in _read_rows(path, delimiter, encoding):
        rows += 1
        if rows > max_rows:
            raise ValueError(f"more than {max_rows:,} rows: start from a sample and edit the file")
        for key, value in row.items():
            if key is None:
                continue
            c = columns.setdefault(key, {"seen": 0, "empty": 0, "long": 0, "numeric": True, "decimals": 0,
                                         "distinct": set(), "overflow": False, "by_decimals": {}, "vector": True})
            c["seen"] += 1
            text = "" if value is None else str(value).strip()
            if not text:
                c["empty"] += 1
                continue
            if len(text) > MAX_CELL:
                c["long"] += 1
            if c["vector"] and not _VECTOR.match(text):
                c["vector"] = False
            num = _number(text) if c["numeric"] else None
            if num is None:
                c["numeric"] = False
            else:
                c["decimals"] = max(c["decimals"], num[0])
                c["by_decimals"][num[0]] = c["by_decimals"].get(num[0], 0) + num[1]
            if not c["overflow"]:
                c["distinct"].add(text)
                if len(c["distinct"]) > 2000:
                    c["overflow"] = True
                    c["distinct"] = set(list(c["distinct"])[:2000])
    if rows == 0:
        raise ValueError("the file has no data rows")

    plan = Plan(rows=rows, columns=[])
    used: Dict[str, str] = {}
    for source, c in columns.items():
        name = normalise(source)
        if not name or not _NAME.match(name):
            plan.columns.append(ColumnPlan(source, name, "skip", "no usable column name"))
            continue
        if name in used:
            plan.columns.append(ColumnPlan(source, name, "skip", f"same name as {used[name]!r} after normalising"))
            continue
        used[name] = source
        if c["empty"] or c["seen"] < rows:
            plan.columns.append(ColumnPlan(source, name, "skip",
                                           f"{c['empty'] + rows - c['seen']} empty cells (the gateway needs every cell filled)"))
            continue
        if c["long"]:
            plan.columns.append(ColumnPlan(source, name, "skip", f"cells longer than {MAX_CELL} characters"))
            continue
        if c["vector"] and not c["numeric"]:
            plan.columns.append(ColumnPlan(source, name, "embedding",
                                           "a vector per record, for similarity_search (never shown)"))
            continue
        distinct = len(c["distinct"]) if not c["overflow"] else 10 ** 9
        unique = distinct == rows
        if (name == "id" or name.endswith("_id")) and unique:
            plan.columns.append(ColumnPlan(source, name, "id", "unique identifier (never shown to the model)"))
            continue
        if _PERSONAL.search(source) or _PERSONAL.search(name):
            plan.columns.append(ColumnPlan(source, name, "token", "looks personal: shown only as a pseudonym",
                                           values=distinct))
            continue
        if c["numeric"] and _CATEGORY_NUMBER.search(source) and c["decimals"] == 0:
            # A code, a year, a grade: numbers that name a category, not a quantity.
            if not c["overflow"] and distinct <= MAX_OPEN_VALUES and not unique:
                plan.columns.append(ColumnPlan(source, name, "open", f"{distinct} distinct codes: a category",
                                               values=distinct))
            else:
                plan.columns.append(ColumnPlan(source, name, "token", "numeric code with many values: pseudonym",
                                               values=distinct if not c["overflow"] else 2000))
            continue
        if c["numeric"]:
            scale = min(c["decimals"], SCALE_CAP)
            if c["decimals"] > SCALE_CAP:
                plan.warnings.append(f"{name}: more than {SCALE_CAP} decimal places; rounded to {SCALE_CAP}")
            total = sum(part * 10 ** (scale - d) if d <= scale else part // 10 ** (d - scale)
                        for d, part in c["by_decimals"].items())
            plan.columns.append(ColumnPlan(source, name, "sealed", "numbers: encrypted, only aggregates leave",
                                           scale=scale, total=total))
            continue
        if not c["overflow"] and distinct <= MAX_OPEN_VALUES and not unique:
            plan.columns.append(ColumnPlan(source, name, "open", f"{distinct} distinct values: a category",
                                           values=distinct))
        else:
            plan.columns.append(ColumnPlan(source, name, "token", "many distinct values: shown only as a pseudonym",
                                           values=distinct if not c["overflow"] else 2000))
    embeddings = plan.of("embedding")
    for extra in embeddings[1:]:
        extra.protection, extra.reason = "skip", "a second vector column (only one is supported)"
    if embeddings and not any(c.protection == "token" for c in plan.columns):
        embeddings[0].protection, embeddings[0].reason = "skip", "similarity_search needs a token column to name the neighbours"
    if not plan.of("sealed"):
        plan.warnings.append("no numeric column found: the gateway needs at least one sealed (numeric) column")
    ids = plan.of("id")
    if len(ids) > 1:
        for extra in ids[1:]:
            extra.protection, extra.reason = "token", "another unique column: shown only as a pseudonym"
    return plan


def decryption_max(plan: Plan) -> Tuple[int, Optional[str]]:
    """A ``[decryption] max_value``: the next power of two above twice the biggest
    column total (answers over subsets can only be smaller), at least 2^36."""
    biggest = max((c.total for c in plan.of("sealed")), default=0)
    need = max(2 ** 36, 2 ** math.ceil(math.log2(max(2, 2 * biggest))))
    if need > STORED_LIMIT:
        return STORED_LIMIT, (f"a column's total ({biggest:,} in stored units) may exceed the limit of 2^40: "
                              "lower the column's precision or express it in larger units, or aggregates "
                              "over large groups will be denied")
    return need, None


def render_config(plan: Plan, *, data_path: str, tenant: str, k: int, state_dir: str,
                  delimiter: str, units: Dict[str, str]) -> str:
    ids = plan.of("id")
    max_value, _ = decryption_max(plan)
    lines = [
        "# Generated by `tokenis-mcp init`. A starting point: review every column below.",
        "# Reference: https://github.com/tokenismcp/tokenis-mcp/blob/main/docs/configuration.md",
        "#",
        "# The keys are in .env (generated, not committed). Load them, then:",
        "#   set -a; source .env; set +a",
        "#   tokenis-mcp check --config tokenis.toml     # validate the config and every row",
        "#   tokenis-mcp serve --config tokenis.toml     # stdio: for a local AI app",
        "",
        "[tenant]",
        f'name = "{tenant}"',
        "epoch = 1                                   # bump to rotate every token",
        'tokenizer_key_env = "TOKENIS_TOKENIZER_KEY"',
        "",
        "[data]",
        f"path = {json.dumps(data_path)}",
    ]
    if delimiter != ",":
        lines.append(f"delimiter = {json.dumps(delimiter)}")
    if ids:
        lines.append(f'id_column = "{ids[0].name}"                    # unique record id; never exposed')
    vectors = plan.of("embedding")
    if vectors:
        lines.append(f'embedding_column = "{vectors[0].name}"             # never exposed')
    renamed = [c for c in plan.columns if c.protection not in ("skip",) and c.source != c.name]
    if renamed:
        lines += ["", "[data.rename]                               # headers that are not valid column names"]
        lines += [f"{json.dumps(c.source)} = {json.dumps(c.name)}" for c in renamed]
    lines += ["", "[state]", f"dir = {json.dumps(state_dir)}                       # admission history and audit trail",
              'audit_key_env = "TOKENIS_AUDIT_KEY"', "", "[admission]",
              f"min_query_set_size = {k}                      # k: no aggregate over fewer records", "",
              "[decryption]", f"max_value = {max_value}", ""]
    first_token = True
    for column in plan.columns:
        if column.protection in ("skip", "id", "embedding"):
            continue
        lines += ["[[columns]]", f'name = "{column.name}"', f'protection = "{column.protection}"',
                  f"description = {json.dumps(column.source.strip())}      # say what it means, for the model"]
        unit = units.get(column.name)
        if unit:
            lines.append(f"unit = {json.dumps(unit)}")
        if column.protection == "sealed" and column.scale:
            lines.append(f"scale = {column.scale}")
        if column.protection == "token" and first_token:
            lines.append("entity = true                               # what similarity_search returns")
            first_token = False
        lines += [f"# {column.reason}", ""]
    skipped = [c for c in plan.columns if c.protection == "skip"]
    if skipped:
        lines.append("# Left out (not in the file's columns list above):")
        lines += [f"#   {c.source!r}: {c.reason}" for c in skipped]
        lines.append("")
    lines += [
        "# To serve several people over HTTP, uncomment and see docs/deployment.md:",
        "# [server]",
        '# transport = "http"',
        "# [auth]",
        '# mode = "api_keys"',
        '# api_keys_file = "api_keys.json"             # tokenis-mcp keys create alice@example.com',
        "",
    ]
    return "\n".join(lines)


def new_keys() -> Dict[str, str]:
    return {"TOKENIS_TOKENIZER_KEY": secrets.token_hex(32), "TOKENIS_AUDIT_KEY": secrets.token_hex(32)}


def describe(plan: Plan) -> str:
    width = max((len(c.source) for c in plan.columns), default=10)
    out = [f"{plan.rows:,} rows, {len(plan.columns)} columns:"]
    labels = {"open": "open    ", "token": "token   ", "sealed": "sealed  ", "id": "id      ",
              "embedding": "vector  ", "skip": "left out"}
    for c in plan.columns:
        out.append(f"  {labels[c.protection]}  {c.source:<{width}}  {c.reason}")
    return "\n".join(out)
