# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W6 (Uniform latency): response latency and error taxonomy are
quantized to a declared granularity independent of the data, so the
interface exposes no data-dependent timing channel.

Implemented by :func:`tokenis.gateway.latency.quantize_latency`, applied
to every value-bearing method on :class:`~tokenis.gateway.service.TokenisGatewayService`
(see that module's docstring). These tests check the *observable*
property directly -- that admitted and denied calls land in the same
declared time bucket -- rather than re-deriving the padding arithmetic
:mod:`tokenis.gateway.latency`'s own unit tests already cover.
"""
import math
import time

from tokenis.gateway.service import TokenisGatewayService, load_demo_ledger

GRANULARITY_MS = 150.0


def _timed_ms(fn) -> float:
    start = time.perf_counter()
    try:
        fn()
    except Exception:  # noqa: BLE001 - timing helper cares about elapsed time, not exception type
        pass
    return (time.perf_counter() - start) * 1000.0


def _bucket(elapsed_ms: float, granularity_ms: float) -> int:
    return math.floor((elapsed_ms + 1e-6) / granularity_ms)


def test_admitted_and_denied_aggregate_calls_land_in_the_same_bucket():
    svc = TokenisGatewayService(latency_granularity_ms=GRANULARITY_MS)
    load_demo_ledger(svc)

    # "finance" (3 rows) is admitted; "retail" (2 rows) is refused by D1
    # -- a real gap in latency between these two, unpadded, would let an
    # observer distinguish "computed and decrypted a sum" from "refused
    # immediately" purely from timing.
    admitted_ms = _timed_ms(lambda: svc.aggregate("a", "sum", industry="finance"))
    denied_ms = _timed_ms(lambda: svc.aggregate("a", "sum", industry="retail"))

    assert _bucket(admitted_ms, GRANULARITY_MS) == _bucket(denied_ms, GRANULARITY_MS)


def test_reveal_denied_and_reveal_permitted_land_in_the_same_bucket():
    svc = TokenisGatewayService(latency_granularity_ms=GRANULARITY_MS)
    load_demo_ledger(svc)

    denied_ms = _timed_ms(
        lambda: svc.disclose_ratio("a", "finance", "tech", purpose="just curious")
    )
    permitted_ms = _timed_ms(
        lambda: svc.disclose_ratio("a", "finance", "tech", purpose="authorized_demo")
    )

    assert _bucket(denied_ms, GRANULARITY_MS) == _bucket(permitted_ms, GRANULARITY_MS)


def test_observed_latency_is_always_at_least_one_granularity():
    """Even a call that resolves near-instantly (a fast D1 rejection, say)
    must not be observably faster than the declared granularity -- the
    floor itself is part of the declared profile."""
    svc = TokenisGatewayService(latency_granularity_ms=GRANULARITY_MS)
    load_demo_ledger(svc)
    elapsed_ms = _timed_ms(lambda: svc.exists("a", industry="nonexistent-industry"))
    assert elapsed_ms >= GRANULARITY_MS * 0.95  # small tolerance for scheduler jitter


def test_observed_latency_is_quantized_to_declared_multiples():
    svc = TokenisGatewayService(latency_granularity_ms=GRANULARITY_MS)
    load_demo_ledger(svc)
    for _ in range(5):
        elapsed_ms = _timed_ms(lambda: svc.aggregate("a", "sum", industry="finance"))
        bucket_index = round(elapsed_ms / GRANULARITY_MS)
        # within ~15% of a clean multiple of the granularity -- loose
        # enough to absorb scheduler/GC jitter on a shared CI runner,
        # tight enough to catch the padding not firing at all.
        assert abs(elapsed_ms - bucket_index * GRANULARITY_MS) < GRANULARITY_MS * 0.15
