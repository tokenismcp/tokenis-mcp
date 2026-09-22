# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W6 (Uniform latency): response latency and error taxonomy should be
quantized to a declared granularity independent of the data, so the
interface exposes no data-dependent timing channel.

Marked ``xfail`` deliberately -- see ``tokenis/spec/well-formedness.md``,
"W6 and this reference implementation": this reference SDK does not
implement a latency-quantization layer, so this test documents a known,
named gap (checked deterministically, not via flaky wall-clock timing)
rather than silently passing or being omitted. A real deployment needs
this layer; R2's "optimised engine" is the place it is expected to live.
"""
import pytest

from tokenis.conformance.reference_gateway import ReferenceGateway


@pytest.mark.xfail(
    reason="reference implementation has no latency-quantization layer; "
    "see tokenis/spec/well-formedness.md",
    strict=True,
)
def test_gateway_declares_a_latency_quantization_granularity():
    gw = ReferenceGateway()
    assert hasattr(gw, "latency_granularity_ms"), (
        "a W6-conformant gateway must declare the granularity it quantizes "
        "response latency to; this reference implementation declares none"
    )
