# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.audit.trace import DisclosureTrace
from tokenis.crypto.ec_elgamal import Decryptor, keygen
from tokenis.gateway.compute import AggregateEngine, Predicate, average, variance
from tokenis.gateway.reveal import RevealDenied, RevealObject, reveal


@pytest.fixture
def engine_and_decryptor():
    kp = keygen()
    engine = AggregateEngine(public_key=kp.public)
    rows = [
        ("r1", {"industry": "finance", "region": "seoul"}, 100),
        ("r2", {"industry": "finance", "region": "busan"}, 200),
        ("r3", {"industry": "retail", "region": "seoul"}, 50),
    ]
    for rid, pf, val in rows:
        engine.ingest(rid, pf, val, with_square=True)
    return engine, Decryptor(kp.private, max_value=1_000_000)


def test_count_is_public_and_correct(engine_and_decryptor):
    engine, _ = engine_and_decryptor
    pred = Predicate("finance", lambda row: row["industry"] == "finance")
    assert engine.count(pred) == 2


def test_sum_via_homomorphic_add(engine_and_decryptor):
    engine, dec = engine_and_decryptor
    pred = Predicate("finance", lambda row: row["industry"] == "finance")
    assert dec.decrypt(engine.sum(pred)) == 300


def test_sum_empty_predicate_raises(engine_and_decryptor):
    engine, _ = engine_and_decryptor
    pred = Predicate("none", lambda row: False)
    with pytest.raises(ValueError):
        engine.sum(pred)


def test_average_and_variance(engine_and_decryptor):
    engine, dec = engine_and_decryptor
    pred = Predicate("finance", lambda row: row["industry"] == "finance")
    s = dec.decrypt(engine.sum(pred))
    ss = dec.decrypt(engine.sum_of_squares(pred))
    n = engine.count(pred)
    assert average(s, n) == 150.0
    assert variance(s, ss, n) == 2500.0


def test_variance_requires_squares_column():
    kp = keygen()
    engine = AggregateEngine(public_key=kp.public)
    engine.ingest("r1", {"industry": "finance"}, 100, with_square=False)
    pred = Predicate("finance", lambda row: row["industry"] == "finance")
    with pytest.raises(ValueError):
        engine.sum_of_squares(pred)


def test_reveal_permit_and_deny_are_both_logged():
    trace = DisclosureTrace()
    obj = RevealObject(ref="acct-1.balance", kind="ciphertext")

    def policy(principal, obj, purpose):
        return purpose == "authorized_case"

    def decrypt_fn(obj):
        return 12345

    value = reveal("analyst", obj, "authorized_case", "v1", policy, decrypt_fn, trace)
    assert value == 12345

    with pytest.raises(RevealDenied):
        reveal("analyst", obj, "curiosity", "v1", policy, decrypt_fn, trace)

    assert len(trace) == 2
    assert trace.verify_chain()
    kinds = [e.kind for e in trace]
    assert kinds == ["reveal", "denial"]


def test_disclosure_trace_detects_tampering():
    trace = DisclosureTrace()
    obj = RevealObject(ref="x", kind="ciphertext")
    reveal("a", obj, "p", "v1", lambda *_: True, lambda _o: 1, trace)
    reveal("a", obj, "p", "v1", lambda *_: True, lambda _o: 2, trace)
    assert trace.verify_chain()

    # Simulate tampering by directly mutating the internal entry list.
    entries = trace._entries  # type: ignore[attr-defined]
    tampered = entries[0]
    from dataclasses import replace

    entries[0] = replace(tampered, value_summary="tampered")
    assert not trace.verify_chain()
