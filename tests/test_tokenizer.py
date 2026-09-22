# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.semantic.tokenizer import GeneralizationHierarchy, ScopedTokenizer


@pytest.fixture
def tokenizer():
    return ScopedTokenizer(key=b"x" * 32)


def test_deterministic(tokenizer):
    scope = tokenizer.make_scope(tenant="acme", epoch=1)
    a = tokenizer.tokenize("customer_name", scope, "Acme Corp")
    b = tokenizer.tokenize("customer_name", scope, "Acme Corp")
    assert a == b


def test_different_values_differ(tokenizer):
    scope = tokenizer.make_scope(tenant="acme", epoch=1)
    a = tokenizer.tokenize("customer_name", scope, "Acme Corp")
    b = tokenizer.tokenize("customer_name", scope, "Other Corp")
    assert a != b


def test_scope_confines_attribute(tokenizer):
    """Definition 1: scope always includes the attribute name, so two
    different attributes never share a token space even for the same
    string value."""
    scope = tokenizer.make_scope(tenant="acme", epoch=1)
    a = tokenizer.tokenize("customer_name", scope, "Acme Corp")
    b = tokenizer.tokenize("supplier_name", scope, "Acme Corp")
    assert a != b


def test_epoch_rotation_changes_token(tokenizer):
    scope1 = tokenizer.make_scope(tenant="acme", epoch=1)
    scope2 = tokenizer.make_scope(tenant="acme", epoch=2)
    a = tokenizer.tokenize("customer_name", scope1, "Acme Corp")
    b = tokenizer.tokenize("customer_name", scope2, "Acme Corp")
    assert a != b


def test_framing_prevents_ambiguous_concatenation(tokenizer):
    """attribute='ab', scope_id='c' must not collide with attribute='a',
    scope_id='bc' even though naive concatenation would produce the same
    bytes."""
    t1 = tokenizer.tokenize("ab", "c", "value")
    t2 = tokenizer.tokenize("a", "bc", "value")
    assert t1 != t2


def test_short_key_rejected():
    with pytest.raises(ValueError):
        ScopedTokenizer(key=b"short")


def test_generalization_hierarchy():
    gh = GeneralizationHierarchy(
        {
            "locality": [
                lambda v: v.split("-")[0],
                lambda v: "capital_area" if v.startswith("Seoul") else "other",
            ]
        }
    )
    assert gh.generalize("locality", "Seoul-Gangnam", 0) == "Seoul-Gangnam"
    assert gh.generalize("locality", "Seoul-Gangnam", 1) == "Seoul"
    assert gh.generalize("locality", "Seoul-Gangnam", 2) == "capital_area"
    assert gh.max_level("locality") == 2


def test_generalization_out_of_range_rejected():
    gh = GeneralizationHierarchy({"locality": [lambda v: v]})
    with pytest.raises(ValueError):
        gh.generalize("locality", "x", 5)
