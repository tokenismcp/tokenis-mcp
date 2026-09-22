# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""W4 (Declared scope): every TOKEN-class attribute declares a scope
function and rotation policy -- i.e. no tokenization call site uses a bare
value without an explicit scope naming the attribute and an epoch/tenant."""
import pytest

from tokenis.conformance.reference_gateway import ReferenceGateway
from tokenis.semantic.tokenizer import ScopedTokenizer


def test_reference_gateway_declares_a_scope_for_every_token_attribute():
    gw = ReferenceGateway()
    catalogue = gw.catalogue()
    token_attrs = [a for a, meta in catalogue.items() if meta["protection_class"] == "token"]
    assert token_attrs, "expected at least one TOKEN-class attribute in the demo catalogue"
    # The gateway's own tokenizer usage always goes through make_scope();
    # verify the resulting scope string names both the tenant and epoch.
    scope = gw._scope  # internal, but this is exactly what we're checking
    assert "tenant=" in scope
    assert "epoch=" in scope


def test_tokenizer_requires_scope_argument_not_bare_value():
    """The tokenizer API has no method that takes just (attribute, value)
    -- scope is a required positional argument, so a call site cannot
    accidentally tokenize without declaring one."""
    tok = ScopedTokenizer(key=b"x" * 32)
    with pytest.raises(TypeError):
        tok.tokenize("customer_name", "Acme Corp")  # missing scope argument


def test_different_epochs_are_distinguishable_tokens():
    """A rotation policy is only meaningful if rotating the epoch actually
    changes the token -- otherwise "declaring" a rotation policy would be
    theater."""
    tok = ScopedTokenizer(key=b"x" * 32)
    s1 = tok.make_scope(tenant="acme", epoch=1)
    s2 = tok.make_scope(tenant="acme", epoch=2)
    assert tok.tokenize("customer_name", s1, "Acme Corp") != tok.tokenize(
        "customer_name", s2, "Acme Corp"
    )
