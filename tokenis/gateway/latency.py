# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Latency quantization (P2 Definition 17, W6): "response latency and
error taxonomy are quantized to a declared granularity that does not
depend on the data, so that the interface exposes no timing channel
beyond the declared profile."

The mechanism is simple on purpose: measure how long the real operation
took, then sleep out the remainder until the *next* multiple of a declared
granularity. A call is never returned early (that's impossible -- the
answer isn't ready yet) and never quantized down, only up, so the
observable latency is always in ``{granularity, 2*granularity,
3*granularity, ...}`` regardless of which branch inside the wrapped call
ran or how fast it happened to be.

**This wraps success and failure identically.** An admission denial that
fails fast (D1's minimum-query-set-size check, say) and a permitted call
that goes on to decrypt a large aggregate are, before quantization, at two
very different points on the clock -- and that difference is itself a
timing side channel an adversary could use to learn which branch executed
without ever seeing the denial/permit decision directly. `@quantize_latency`
is applied via a ``try/finally`` so the padding happens whether the wrapped
call returns normally or raises.
"""
from __future__ import annotations

import functools
import math
import time
from typing import Callable, TypeVar

_F = TypeVar("_F", bound=Callable)


def remaining_in_bucket(start_perf_counter: float, granularity_ms: float) -> float:
    """Seconds left until the next multiple of ``granularity_ms`` (at least
    one full bucket) since ``start_perf_counter``."""
    if granularity_ms <= 0:
        raise ValueError("granularity_ms must be positive")
    elapsed_ms = (time.perf_counter() - start_perf_counter) * 1000.0
    buckets = max(1, math.ceil(elapsed_ms / granularity_ms))
    return max(0.0, (buckets * granularity_ms - elapsed_ms) / 1000.0)


async def pad_to_granularity_async(start_perf_counter: float, granularity_ms: float) -> None:
    """:func:`pad_to_granularity` for async code: sleeps without holding a
    worker thread, so padding costs no concurrency."""
    import anyio

    await anyio.sleep(remaining_in_bucket(start_perf_counter, granularity_ms))


def pad_to_granularity(start_perf_counter: float, granularity_ms: float) -> float:
    """Sleep out the remainder of the current time bucket. Returns the
    total elapsed time (including the pad) in milliseconds, for callers
    that want to log or test it.

    ``granularity_ms`` must be positive. The response is padded to at
    least one full bucket even for a call that completes in effectively
    zero time, so the observable floor is always >= ``granularity_ms``,
    not "however fast the fastest branch happens to run."
    """
    if granularity_ms <= 0:
        raise ValueError("granularity_ms must be positive")
    elapsed_ms = (time.perf_counter() - start_perf_counter) * 1000.0
    buckets = max(1, math.ceil(elapsed_ms / granularity_ms))
    target_ms = buckets * granularity_ms
    remaining_s = (target_ms - elapsed_ms) / 1000.0
    if remaining_s > 0:
        time.sleep(remaining_s)
    return max(elapsed_ms, target_ms)


def quantize_latency(func: _F) -> _F:
    """Method decorator: pads the wrapped instance method's wall-clock
    latency to ``self.latency_granularity_ms`` (a required attribute of
    the class this decorates), identically on the success and exception
    paths.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        start = time.perf_counter()
        try:
            return func(self, *args, **kwargs)
        finally:
            pad_to_granularity(start, self.latency_granularity_ms)

    return wrapper  # type: ignore[return-value]
