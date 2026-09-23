# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import time

import pytest

from tokenis.gateway.latency import pad_to_granularity, quantize_latency


def test_pad_to_granularity_rounds_up_to_next_bucket():
    start = time.perf_counter()
    elapsed = pad_to_granularity(start, granularity_ms=50.0)
    assert elapsed >= 50.0
    assert elapsed < 100.0  # should land in the first bucket, not overshoot


def test_pad_to_granularity_rejects_non_positive_granularity():
    with pytest.raises(ValueError):
        pad_to_granularity(time.perf_counter(), granularity_ms=0)


class _Demo:
    def __init__(self, granularity_ms=50.0):
        self.latency_granularity_ms = granularity_ms

    @quantize_latency
    def fast(self):
        return "ok"

    @quantize_latency
    def slow(self):
        time.sleep(0.06)
        return "ok"

    @quantize_latency
    def fails(self):
        raise ValueError("boom")


def test_quantize_latency_pads_fast_calls():
    d = _Demo(granularity_ms=50.0)
    start = time.perf_counter()
    assert d.fast() == "ok"
    assert (time.perf_counter() - start) * 1000 >= 45.0  # small jitter tolerance


def test_quantize_latency_rounds_slow_calls_up_to_next_bucket():
    d = _Demo(granularity_ms=50.0)
    start = time.perf_counter()
    d.slow()  # true cost ~60ms -> should land in the 100ms bucket, not 50ms
    elapsed = (time.perf_counter() - start) * 1000
    assert elapsed >= 95.0


def test_quantize_latency_pads_the_exception_path_too():
    d = _Demo(granularity_ms=50.0)
    start = time.perf_counter()
    with pytest.raises(ValueError):
        d.fails()
    assert (time.perf_counter() - start) * 1000 >= 45.0


def test_success_and_failure_land_in_the_same_bucket():
    d = _Demo(granularity_ms=80.0)

    start = time.perf_counter()
    d.fast()
    fast_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    with pytest.raises(ValueError):
        d.fails()
    fail_ms = (time.perf_counter() - start) * 1000

    assert int(fast_ms // 80.0) == int(fail_ms // 80.0)
