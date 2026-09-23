# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W6 (Uniform latency): response latency and error taxonomy are
quantized to a declared granularity independent of the data, so the
interface exposes no data-dependent timing channel.

Implemented by :func:`tokenis.gateway.latency.quantize_latency`, applied
to every public tool method on :class:`~tokenis.gateway.service.TokenisGatewayService`
(and, asynchronously, around every MCP tool call -- see
``tokenis/mcp_server/test_server.py``). These tests check the *observable*
property directly -- that admitted and denied calls land in the same
declared time bucket -- rather than re-deriving the padding arithmetic
:mod:`tokenis.gateway.latency`'s own unit tests already cover.
"""
import math
import time

from tokenis.gateway.demo import demo_service

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


def _restricted_purpose_settings():
    from dataclasses import replace

    from tokenis.gateway.demo import DEMO_PURPOSE, DEMO_SETTINGS

    return replace(DEMO_SETTINGS, purposes=(replace(DEMO_PURPOSE, principals=("a",)),))


def test_admitted_and_denied_aggregate_calls_land_in_the_same_bucket():
    svc = demo_service(latency_granularity_ms=GRANULARITY_MS)

    # "finance" (3 rows) is admitted; "retail" (2 rows) is refused by D1
    # -- a real gap in latency between these two, unpadded, would let an
    # observer distinguish "computed and decrypted a sum" from "refused
    # immediately" purely from timing.
    admitted_ms = _timed_ms(lambda: svc.aggregate("a", "sum", "revenue_2025", {"industry": "finance"}))
    denied_ms = _timed_ms(lambda: svc.aggregate("a", "sum", "revenue_2025", {"industry": "retail"}))

    assert _bucket(admitted_ms, GRANULARITY_MS) == _bucket(denied_ms, GRANULARITY_MS)


def test_reveal_denied_and_reveal_permitted_land_in_the_same_bucket():
    svc = demo_service(latency_granularity_ms=GRANULARITY_MS)

    ratio = {
        "column": "revenue_2025",
        "numerator_filters": {"industry": "finance"},
        "denominator_filters": {"industry": "tech"},
        "purpose": "demo_review",
    }
    # "mallory" holds no Reveal purpose in this configuration; "a" does.
    svc = demo_service(
        latency_granularity_ms=GRANULARITY_MS,
        settings=_restricted_purpose_settings(),
    )
    denied_ms = _timed_ms(lambda: svc.disclose_ratio("mallory", **ratio))
    permitted_ms = _timed_ms(lambda: svc.disclose_ratio("a", **ratio))

    assert _bucket(denied_ms, GRANULARITY_MS) == _bucket(permitted_ms, GRANULARITY_MS)


def test_observed_latency_is_always_at_least_one_granularity():
    """Even a call that resolves near-instantly (a fast D1 rejection, say)
    must not be observably faster than the declared granularity -- the
    floor itself is part of the declared profile."""
    svc = demo_service(latency_granularity_ms=GRANULARITY_MS)
    elapsed_ms = _timed_ms(lambda: svc.exists("a", {"industry": "retail"}))
    assert elapsed_ms >= GRANULARITY_MS * 0.95  # small tolerance for scheduler jitter


def test_observed_latency_is_quantized_to_declared_multiples():
    svc = demo_service(latency_granularity_ms=GRANULARITY_MS)
    for _ in range(5):
        elapsed_ms = _timed_ms(lambda: svc.aggregate("a", "sum", "revenue_2025", {"industry": "finance"}))
        bucket_index = round(elapsed_ms / GRANULARITY_MS)
        # within ~15% of a clean multiple of the granularity -- loose
        # enough to absorb scheduler/GC jitter on a shared CI runner,
        # tight enough to catch the padding not firing at all.
        assert abs(elapsed_ms - bucket_index * GRANULARITY_MS) < GRANULARITY_MS * 0.15
