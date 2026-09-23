# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.crypto.no_key_delegation import (
    AffineFunctional,
    MaskedValue,
    Owner,
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
    # A small modulus keeps the exhaustive-uniformity tests below fast;
    # the protocol's correctness/secrecy proofs don't depend on size.
    return Owner(n=10007)


def test_blind_unblind_roundtrip(owner):
    masked, mask = owner.blind(42)
    assert owner.unblind(masked, mask) == 42


def test_unblind_rejects_mismatched_modulus(owner):
    other_owner = Owner(n=97)
    masked, mask = other_owner.blind(5)
    with pytest.raises(ValueError):
        owner.unblind(masked, mask)


def test_blind_hides_the_value(owner):
    """The masked value the untrusted party would see is not, in general,
    equal to the plaintext -- a minimal sanity check that masking actually
    does something (the real guarantee, uniformity/independence, is
    exercised statistically below)."""
    masked, _ = owner.blind(42)
    assert masked.masked != 42


def test_masking_is_uniform_over_many_trials(owner):
    """[NOKEY] Lemma 6: for a fixed plaintext, the masked value is uniform
    on Z/nZ. A chi-square-style spot check: with enough trials, the masked
    values should not cluster near the plaintext or show any other
    obvious structure."""
    import random

    rng = random.Random(20260920)
    owner_r = Owner(n=1009, rng=rng)
    seen = set()
    for _ in range(2000):
        masked, _ = owner_r.blind(7)
        seen.add(masked.masked)
    # Coupon-collector expectation for 2000 draws from Unif({0..1008}):
    # E[distinct] = 1009 * (1 - (1 - 1/1009)**2000) ~= 869. A small
    # cluster of masked values (what a broken/non-uniform mask would
    # produce) would fall far short of this; a healthy margin below the
    # true expectation still rules that out.
    assert len(seen) > 800


class TestAffineDelegation:
    def test_correctness_matches_plaintext_evaluation(self, owner):
        """[NOKEY] Theorem 23: Pi_lin outputs f(x_1, ..., x_t) exactly."""
        f = AffineFunctional(coefficients=[2, 3, -1], intercept=5)
        values = [10, 20, 7]

        masked_values, correction = delegate_affine(owner, f, values)
        masked_result = evaluate_affine_masked(f, masked_values)
        result = unblind_affine_result(owner, masked_result, correction)

        assert result == f.evaluate(values, owner.n) % owner.n

    def test_server_never_sees_plaintext_values(self, owner):
        f = AffineFunctional(coefficients=[1, 1], intercept=0)
        values = [123, 456]
        masked_values, _ = delegate_affine(owner, f, values)
        server_view = [mv.masked for mv in masked_values]
        assert 123 not in server_view
        assert 456 not in server_view

    def test_correctness_across_many_random_instances(self):
        import random

        rng = random.Random(1729)
        for _ in range(200):
            n = 10007
            owner_r = Owner(n=n, rng=rng)
            coeffs = [rng.randrange(-50, 50) for _ in range(4)]
            intercept = rng.randrange(-50, 50)
            f = AffineFunctional(coefficients=coeffs, intercept=intercept)
            values = [rng.randrange(0, n) for _ in range(4)]

            masked_values, correction = delegate_affine(owner_r, f, values)
            masked_result = evaluate_affine_masked(f, masked_values)
            result = unblind_affine_result(owner_r, masked_result, correction)

            assert result == f.evaluate(values, n) % n


class TestMaskedMultiplication:
    def test_correctness_matches_plaintext_product(self, owner):
        """[NOKEY] Theorem 24 / eq. (6)."""
        s, s_prime = 123, 456
        triple = owner.prepare_triple()

        opening = open_multiplication(owner, s, s_prime, triple)
        eg = combine_multiplication(opening)
        result = reconstruct_multiplication(triple, opening, eg)

        assert result == (s * s_prime) % owner.n

    def test_server_never_sees_the_operands(self, owner):
        s, s_prime = 123, 456
        triple = owner.prepare_triple()
        opening = open_multiplication(owner, s, s_prime, triple)
        # The server's entire view of this multiplication is (e, g); it
        # should not equal the raw secrets.
        assert opening.e != s
        assert opening.g != s_prime

    def test_correctness_across_many_random_instances(self):
        import random

        rng = random.Random(42)
        n = 10007
        owner_r = Owner(n=n, rng=rng)
        for _ in range(500):
            s = rng.randrange(0, n)
            s_prime = rng.randrange(0, n)
            triple = owner_r.prepare_triple()
            opening = open_multiplication(owner_r, s, s_prime, triple)
            eg = combine_multiplication(opening)
            result = reconstruct_multiplication(triple, opening, eg)
            assert result == (s * s_prime) % n

    def test_negative_operands(self, owner):
        s, s_prime = -17, 9
        triple = owner.prepare_triple()
        opening = open_multiplication(owner, s, s_prime, triple)
        eg = combine_multiplication(opening)
        result = reconstruct_multiplication(triple, opening, eg)
        assert result == (s * s_prime) % owner.n

    def test_reusing_a_triple_raises(self, owner):
        """[NOKEY] (P3), "fresh one-time randomness": reusing a Beaver
        triple across two products leaks (s1-s2) and (s1'-s2') to the
        Server, breaking the secrecy proof Theorem 28 depends on. This is
        enforced, not just documented -- see open_multiplication's
        docstring."""
        triple = owner.prepare_triple()
        open_multiplication(owner, 5, 6, triple)
        with pytest.raises(ValueError):
            open_multiplication(owner, 7, 8, triple)

    def test_triple_from_a_different_modulus_owner_rejected(self):
        owner_a = Owner(n=10007)
        triple = owner_a.prepare_triple()
        different_modulus_owner = Owner(n=97)
        with pytest.raises(ValueError):
            open_multiplication(different_modulus_owner, 5, 6, triple)


class TestBlindedBootstrap:
    def test_preserves_the_value(self, owner):
        masked, mask = owner.blind(99)
        new_masked, new_mask = blinded_bootstrap(owner, masked, mask)
        assert owner.unblind(new_masked, new_mask) == 99

    def test_refreshes_the_mask(self, owner):
        masked, mask = owner.blind(99)
        _new_masked, new_mask = blinded_bootstrap(owner, masked, mask)
        # Extremely unlikely to collide by chance with a 10007-modulus
        # uniform draw; a collision here would indicate `blind` isn't
        # drawing fresh randomness.
        assert new_mask != mask

    def test_custom_refresh_function_applied(self, owner):
        masked, mask = owner.blind(10)
        new_masked, new_mask = blinded_bootstrap(owner, masked, mask, refresh=lambda x: x + 1)
        assert owner.unblind(new_masked, new_mask) == 11


def test_masked_value_is_a_plain_dataclass():
    mv = MaskedValue(masked=5, n=97)
    assert mv.masked == 5
    assert mv.n == 97
