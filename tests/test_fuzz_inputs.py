# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Property-based fuzzing of everything the gateway reads that an attacker
could have written or altered: ciphertext encodings, the encrypted ledger,
the keystore, the audit trail, the admission log and the configuration.

The property is the same throughout: altered input is either rejected with
the component's own error type, or (where the format tolerates it) read back
as exactly what was written. Never a crash with some other exception, never
a silently different value.

``TOKENIS_FUZZ_EXAMPLES`` scales the number of examples per test (default
60; the nightly fuzz workflow runs thousands). The Rust core has its own
coverage-guided targets in ``fuzz/``.
"""
import copy
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tokenis._core import CiphertextVector, PrivateKey
from tokenis.audit.trace import AuditRecord, DisclosureTrace, TraceIntegrityError
from tokenis.config import ConfigError, parse_config
from tokenis.gateway.demo import DEMO_SCHEMA, DEMO_SETTINGS, demo_rows, demo_service
from tokenis.gateway.state import StateMismatchError
from tokenis.keystore import (
    KeystoreError,
    LocalPassphraseWrapper,
    create_keystore,
    load_keystore,
)
from tokenis.ledger import LedgerError, load_ledger, write_ledger

EXAMPLES = int(os.environ.get("TOKENIS_FUZZ_EXAMPLES", "60"))
FUZZ = settings(max_examples=EXAMPLES, deadline=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
KEY = b"k" * 32


@st.composite
def mutated(draw, original: bytes):
    """``original`` with a few byte flips, insertions, deletions or a cut."""
    data = bytearray(original)
    for _ in range(draw(st.integers(1, 4))):
        op = draw(st.sampled_from(["flip", "set", "insert", "delete", "truncate"]))
        if not data and op != "insert":
            op = "insert"
        i = draw(st.integers(0, max(0, len(data) - 1)))
        if op == "flip":
            data[i] ^= 1 << draw(st.integers(0, 7))
        elif op == "set":
            data[i] = draw(st.integers(0, 255))
        elif op == "insert":
            data[i:i] = draw(st.binary(min_size=1, max_size=8))
        elif op == "delete":
            del data[i:i + draw(st.integers(1, 8))]
        else:
            del data[i:]
    return bytes(data)


# -- ciphertext vectors ---------------------------------------------------------------

PUBLIC = PrivateKey.generate().public_key()
VECTOR = CiphertextVector(PUBLIC)
VECTOR.extend_encrypt(list(range(-20, 20)))
VECTOR_BYTES = VECTOR.to_bytes()


@FUZZ
@given(st.one_of(st.binary(max_size=400), mutated(VECTOR_BYTES)))
def test_ciphertext_vectors_reject_garbage(data):
    try:
        parsed = CiphertextVector.from_bytes(PUBLIC, data)
    except ValueError:
        return
    # Whatever parses re-encodes to exactly the same bytes (canonical form).
    assert parsed.to_bytes() == data


# -- the encrypted ledger ---------------------------------------------------------------

def _demo_service():
    return demo_service(tokenizer_key=KEY, private_key=b"\x01" * 32)


LEDGER_KEY = os.urandom(32)
_LEDGER_DIR = Path(tempfile.mkdtemp(prefix="tokenis-fuzz-ledger-")) / "ledger"
write_ledger(_demo_service(), _LEDGER_DIR, LEDGER_KEY)
LEDGER_FILES = {name: (_LEDGER_DIR / name).read_bytes() for name in ("manifest.json", "payload.bin")}


@FUZZ
@given(st.sampled_from(sorted(LEDGER_FILES)), st.data())
def test_a_tampered_ledger_never_loads_different_data(name, data):
    changed = data.draw(mutated(LEDGER_FILES[name]))
    hypothesis.assume(changed != LEDGER_FILES[name])
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger"
        shutil.copytree(_LEDGER_DIR, path)
        (path / name).write_bytes(changed)
        try:
            svc = load_ledger(path, DEMO_SCHEMA, LEDGER_KEY, b"\x01" * 32, KEY, DEMO_SETTINGS)
        except LedgerError:
            return
    # Only a change that means the same thing may load: reformatted JSON.
    assert name == "manifest.json"
    assert json.loads(changed) == json.loads(LEDGER_FILES[name])
    assert svc.record_count == len(demo_rows())


# -- the keystore -----------------------------------------------------------------------

PASSPHRASE = b"fuzzing passphrase, long enough"
_KS_DIR = Path(tempfile.mkdtemp(prefix="tokenis-fuzz-ks-"))
_WRAPPER = LocalPassphraseWrapper(PASSPHRASE)
create_keystore(_KS_DIR / "keystore.json", _WRAPPER, "acme")
KEYSTORE = (_KS_DIR / "keystore.json").read_bytes()
SECRETS = load_keystore(_KS_DIR / "keystore.json", _WRAPPER, "acme")


@settings(max_examples=max(10, EXAMPLES // 3), deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(mutated(KEYSTORE))
def test_a_tampered_keystore_never_yields_other_secrets(changed):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "keystore.json"
        path.write_bytes(changed)
        try:
            header = json.loads(changed)
            salt = __import__("base64").b64decode(header["wrapper"]["salt"])
            wrapper = LocalPassphraseWrapper(PASSPHRASE, salt)
        except Exception:  # noqa: BLE001 -- unreadable header: load must still fail cleanly
            wrapper = _WRAPPER
        try:
            loaded = load_keystore(path, wrapper, "acme")
        except KeystoreError:
            return
    assert loaded.tokenizer_key == SECRETS.tokenizer_key
    assert loaded.elgamal_private_key == SECRETS.elgamal_private_key
    assert loaded.ledger_key == SECRETS.ledger_key and loaded.audit_key == SECRETS.audit_key


# -- the audit trail --------------------------------------------------------------------

AUDIT_KEY = b"a" * 32
_TRACE_DIR = Path(tempfile.mkdtemp(prefix="tokenis-fuzz-trace-"))
_trace = DisclosureTrace(path=_TRACE_DIR / "trace.jsonl", hmac_key=AUDIT_KEY)
for i in range(6):
    record = AuditRecord(principal=f"p{i % 2}", obj_ref=f"aggregate:sum(x)|k={i}", purpose="aggregate",
                         policy_version="v", decision="permit" if i % 3 else "deny", timestamp=1e9 + i)
    if i % 3:
        _trace.record_aggregate_result(record, 1000 + i)
    else:
        _trace.record_denial(record)
TRACE = (_TRACE_DIR / "trace.jsonl").read_bytes()
TRACE_ENTRIES = list(_trace)


@FUZZ
@given(mutated(TRACE))
def test_a_tampered_audit_trail_is_detected(changed):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        path.write_bytes(changed)
        try:
            entries = list(DisclosureTrace(path=path, hmac_key=AUDIT_KEY))
        except TraceIntegrityError:
            return
    # Accepted only if every surviving entry is original. A cut-off final
    # line is dropped by design (a call interrupted mid-append never
    # returned); removing trailing entries cannot be detected by a hash
    # chain alone, which is why operators should record the head digest
    # externally (see docs/threat-model.md).
    assert entries == TRACE_ENTRIES[:len(entries)]


# -- the admission log ------------------------------------------------------------------

_STATE_DIR = Path(tempfile.mkdtemp(prefix="tokenis-fuzz-state-"))


def _gateway(state_dir):
    return demo_service(latency_granularity_ms=1.0, tokenizer_key=KEY, state_dir=state_dir)


_first = _gateway(_STATE_DIR)
for filters in ({"industry": "finance"}, {"industry": "tech"}, {"region": "Seoul"}):
    try:
        _first.invoke("aggregate", "mallory", {"function": "sum", "column": "revenue_2025", "filters": filters})
    except Exception:  # noqa: BLE001 -- denials are fine; we only need log records
        pass
ADMISSION_LOG = (_STATE_DIR / "admission.jsonl").read_bytes()


@FUZZ
@given(mutated(ADMISSION_LOG))
def test_a_corrupted_admission_log_fails_to_start_cleanly(changed):
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "admission.jsonl").write_bytes(changed)
        try:
            _gateway(tmp).seal()
        except StateMismatchError:
            return


# -- configuration ----------------------------------------------------------------------

BASE_CONFIG = {
    "tenant": {"name": "acme"},
    "data": {"path": "data.csv", "id_column": "id"},
    "columns": [
        {"name": "customer", "protection": "token", "entity": True},
        {"name": "industry", "protection": "open"},
        {"name": "revenue", "protection": "sealed", "scale": 2},
    ],
    "admission": {"min_query_set_size": 5, "window": "day"},
    "server": {"transport": "http", "port": 8000},
    "auth": {"mode": "api_keys", "api_keys_file": "keys.json"},
    "state": {"dir": "state"},
}

toml_scalars = st.one_of(st.none(), st.booleans(), st.integers(-2**40, 2**40), st.floats(allow_nan=True),
                         st.text(max_size=20), st.binary(max_size=4).map(bytes.hex))
toml_values = st.recursive(toml_scalars, lambda inner: st.one_of(
    st.lists(inner, max_size=3), st.dictionaries(st.text(max_size=12), inner, max_size=3)), max_leaves=6)


def _paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _paths(v, prefix + (i,))


ALL_PATHS = [p for p in _paths(BASE_CONFIG) if p]


@FUZZ
@given(st.lists(st.tuples(st.sampled_from(ALL_PATHS), st.sampled_from(["set", "delete", "add"]), toml_values,
                          st.text(max_size=12)), min_size=1, max_size=3))
def test_any_malformed_config_is_a_config_error(edits):
    raw = copy.deepcopy(BASE_CONFIG)
    for path, op, value, new_key in edits:
        parent = raw
        try:
            for part in path[:-1]:
                parent = parent[part]
            if op == "set":
                parent[path[-1]] = value
            elif op == "delete":
                del parent[path[-1]]
            elif isinstance(parent, dict):
                parent[new_key] = value
        except (KeyError, IndexError, TypeError):
            continue
    try:
        parse_config(raw, Path("/tmp/tokenis-fuzz"))
    except ConfigError:
        pass
