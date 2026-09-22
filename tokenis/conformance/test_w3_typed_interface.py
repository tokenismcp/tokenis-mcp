# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W3 (Typed interface): every tool argument and return is typed by
protection class; no free-form field carries an enclosed value without
egress screening."""
from tokenis.conformance.reference_gateway import ReferenceGateway

_VALID_CLASSES = {"open", "token", "sealed_aggregate", "revealed"}


def test_every_tool_result_declares_a_protection_class():
    gw = ReferenceGateway()
    results = [
        gw.call_tool("lookup_public", {"record_id": "r1"}, principal="a"),
        gw.call_tool("aggregate", {"industry": "finance"}, principal="a"),
        gw.call_tool(
            "disclose_ratio",
            {"numerator_industry": "finance", "denominator_industry": "retail"},
            principal="a",
        ),
    ]
    for r in results:
        assert r.protection_class in _VALID_CLASSES


def test_catalogue_declares_a_protection_class_per_attribute():
    gw = ReferenceGateway()
    for meta in gw.catalogue().values():
        assert "protection_class" in meta
        assert meta["protection_class"] in {"open", "token", "sealed"}


def test_lookup_result_carries_no_free_form_untyped_field():
    """Every key in a lookup_public result must be a catalogued attribute
    (or a structurally-token field like customer_token) -- there is no
    passthrough "extra" or "raw" bag a future change could smuggle an
    enclosed value through."""
    gw = ReferenceGateway()
    result = gw.call_tool("lookup_public", {"record_id": "r1"}, principal="a")
    catalogued = set(gw.catalogue().keys())
    for key in result.value:
        assert key in catalogued or key == "customer_token"
