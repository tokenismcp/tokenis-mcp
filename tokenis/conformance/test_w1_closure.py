# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W1 (Closure): every value appearing outside the protected domain is
open-class, a token, a ciphertext handle, or an output of Reveal."""
from tokenis.conformance.reference_gateway import ReferenceGateway


def test_public_lookup_returns_only_open_fields():
    gw = ReferenceGateway()
    result = gw.call_tool("lookup_public", {"record_id": "r1"}, principal="analyst")
    assert result.protection_class == "open"
    # The public fields for a demo row are industry (OPEN) and
    # customer_token (already TOKEN-class at rest -- never raw plaintext).
    assert result.value["industry"] in {"finance", "retail"}
    assert result.value["customer_token"] != "Acme Corp"
    assert len(result.value["customer_token"]) == 32  # 128-bit hex token


def test_aggregate_result_is_a_plain_number_not_a_ciphertext_handle():
    gw = ReferenceGateway()
    result = gw.call_tool("aggregate", {"industry": "finance"}, principal="analyst")
    assert isinstance(result.value, int)
    assert result.protection_class == "sealed_aggregate"
    assert result.crossed_boundary is True


def test_no_raw_customer_name_ever_appears_in_a_tool_result():
    """Nothing this harness can return should ever contain a raw plaintext
    customer name -- names only ever cross the boundary as tokens (in
    lookups) or are never present at all (in aggregates)."""
    gw = ReferenceGateway()
    raw_names = {"Acme Corp", "Beta LLC", "Gamma Inc", "Delta Co", "Epsilon Ltd"}
    for record_id in ["r1", "r2", "r3", "r4", "r5"]:
        result = gw.call_tool("lookup_public", {"record_id": record_id}, principal="analyst")
        assert str(result.value) not in raw_names
        for name in raw_names:
            assert name not in str(result.value)
