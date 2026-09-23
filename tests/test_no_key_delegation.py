# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import copy
import pickle

import pytest

from tokenis.crypto.no_key_delegation import (
    MODULUS,
    AffineFunctional,
    MaskedValue,
    MultiplicationOpening,
    Owner,
    TokenisCryptoError,
    blinded_bootstrap,
    combine_multiplication,
    delegate_affine,
    evaluate_affine_masked,
    open_multiplication,
    reconstruct_multiplication,
    unblind_affine_result,
)


@pytest.fixture
def owner():
    return Owner()


def _multiply(owner, s, t):
    triple = owner.prepare_triple()
    opening = open_multiplication(owner, s, t, triple)
    return reconstruct_multiplication(owner, triple, opening, combine_multiplication(opening))


def test_blind_unblind_roundtrip(owner):
    masked, mask = owner.blind(42)
    assert owner.unblind(masked, mask) == 42


def test_negative_values_are_mod_n(owner):
    masked, mask = owner.blind(-5)
    assert owner.unblind(masked, mask) == MODULUS - 5


def test_masked_values_hide_and_differ(owner):
    """[NOKEY] Lemma 6: the masked value is a fresh uniform element each
    time, so repeated maskings of one plaintext never repeat."""
    seen = {owner.blind(7)[0].to_bytes() for _ in range(300)}
    assert len(seen) == 300
    assert (7).to_bytes(32, "big") not in seen


def test_mask_is_one_time(owner):
    masked, mask = owner.blind(42)
    owner.unblind(masked, mask)
    assert mask.consumed
    with pytest.raises(TokenisCryptoError):
        owner.unblind(masked, mask)


def test_mask_bound_to_its_owner(owner):
    masked, mask = Owner().blind(5)
    with pytest.raises(TokenisCryptoError):
        owner.unblind(masked, mask)


@pytest.mark.parametrize("serialize", [pickle.dumps, copy.deepcopy])
def test_secret_handles_refuse_serialization(owner, serialize):
    _, mask = owner.blind(1)
    for obj in (owner, mask, owner.prepare_triple()):
        with pytest.raises(TypeError):
            serialize(obj)
    assert "redacted" in repr(mask)


class TestAffineDelegation:
    def test_correctness(self, owner):
        """[NOKEY] Theorem 23."""
        f = AffineFunctional(coefficients=[2, 3, -1], intercept=5)
        values = [10, 20, 7]
        masked, correction = delegate_affine(owner, f, values)
        result = unblind_affine_result(owner, evaluate_affine_masked(f, masked), correction)
        assert result == f.evaluate(values) == 2 * 10 + 3 * 20 - 7 + 5

    def test_server_view_contains_no_plaintext(self, owner):
        f = AffineFunctional(coefficients=[1, 1])
        masked, _ = delegate_affine(owner, f, [123, 456])
        view = [m.to_bytes() for m in masked]
        assert (123).to_bytes(32, "big") not in view
        assert (456).to_bytes(32, "big") not in view

    def test_correction_is_one_time(self, owner):
        f = AffineFunctional(coefficients=[1])
        masked, correction = delegate_affine(owner, f, [9])
        result = evaluate_affine_masked(f, masked)
        unblind_affine_result(owner, result, correction)
        with pytest.raises(TokenisCryptoError):
            unblind_affine_result(owner, result, correction)

    def test_length_mismatch(self, owner):
        with pytest.raises(TokenisCryptoError):
            delegate_affine(owner, AffineFunctional(coefficients=[1, 2]), [1])


class TestMaskedMultiplication:
    def test_correctness(self, owner):
        """[NOKEY] Theorem 24 / eq. (6)."""
        assert _multiply(owner, 123, 456) == 123 * 456
        assert _multiply(owner, -17, 9) == (-17 * 9) % MODULUS

    def test_server_view_contains_no_operands(self, owner):
        triple = owner.prepare_triple()
        opening = open_multiplication(owner, 123, 456, triple)
        view = opening.to_bytes()
        assert (123).to_bytes(32, "big") not in (view[:32], view[32:])
        assert MultiplicationOpening.from_bytes(view).to_bytes() == view

    def test_reopening_a_triple_raises(self, owner):
        """Reusing a triple would reveal s1-s2 and t1-t2 to the server."""
        triple = owner.prepare_triple()
        open_multiplication(owner, 5, 6, triple)
        with pytest.raises(TokenisCryptoError):
            open_multiplication(owner, 7, 8, triple)

    def test_triple_consumed_by_reconstruction(self, owner):
        triple = owner.prepare_triple()
        opening = open_multiplication(owner, 5, 6, triple)
        eg = combine_multiplication(opening)
        reconstruct_multiplication(owner, triple, opening, eg)
        assert triple.consumed
        with pytest.raises(TokenisCryptoError):
            reconstruct_multiplication(owner, triple, opening, eg)

    def test_foreign_triple_rejected(self, owner):
        triple = Owner().prepare_triple()
        with pytest.raises(TokenisCryptoError):
            open_multiplication(owner, 5, 6, triple)

    def test_foreign_secrets_are_rejected_without_being_destroyed(self, owner):
        """Offering a secret to the wrong owner must not burn the caller's
        only copy of it."""
        other = Owner()
        masked, mask = owner.blind(77)
        with pytest.raises(TokenisCryptoError, match="different Owner"):
            other.unblind(masked, mask)
        assert not mask.consumed
        assert owner.unblind(masked, mask) == 77

        triple = owner.prepare_triple()
        opening = open_multiplication(owner, 3, 4, triple)
        eg = combine_multiplication(opening)
        with pytest.raises(TokenisCryptoError):
            reconstruct_multiplication(other, triple, opening, eg)
        assert not triple.consumed
        assert reconstruct_multiplication(owner, triple, opening, eg) == 12


class TestBlindedBootstrap:
    def test_preserves_value_with_fresh_pad(self, owner):
        masked, mask = owner.blind(99)
        new_masked, new_mask = blinded_bootstrap(owner, masked, mask)
        assert new_masked != masked
        assert owner.unblind(new_masked, new_mask) == 99

    def test_custom_refresh_applied(self, owner):
        masked, mask = owner.blind(10)
        new_masked, new_mask = blinded_bootstrap(owner, masked, mask, refresh=lambda x: x + 1)
        assert owner.unblind(new_masked, new_mask) == 11


def test_masked_value_encoding_validated():
    with pytest.raises(TokenisCryptoError):
        MaskedValue.from_bytes(b"\xff" * 32)  # >= n
    with pytest.raises(TokenisCryptoError):
        MaskedValue.from_bytes(b"\x01" * 31)
