# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests: the algebraic identities the crypto modules
promise, checked against hypothesis-generated inputs rather than a handful
of hand-picked values."""
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tokenis.crypto.ec_fhe import (
    Ciphertext,
    Decryptor,
    EllipticRational,
    add,
    encrypt,
    keygen,
    negate,
    scalar_mul,
    subtract,
)
from tokenis.crypto.no_key_delegation import (
    AffineFunctional,
    Owner,
    combine_multiplication,
    delegate_affine,
    evaluate_affine_masked,
    open_multiplication,
    reconstruct_multiplication,
    unblind_affine_result,
)

MAX = 50_000
small_ints = st.integers(min_value=-MAX // 4, max_value=MAX // 4)
settings.register_profile(
    "tokenis",
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
settings.load_profile("tokenis")


@pytest.fixture(scope="module")
def keys():
    kp = keygen()
    return kp, Decryptor(kp.private, max_value=MAX)


@given(x=small_ints, y=small_ints)
def test_add_is_homomorphic(keys, x, y):
    kp, dec = keys
    assert dec.decrypt(add(encrypt(kp.public, x), encrypt(kp.public, y))) == x + y


@given(x=small_ints, y=small_ints)
def test_subtract_is_homomorphic(keys, x, y):
    kp, dec = keys
    assert dec.decrypt(subtract(encrypt(kp.public, x), encrypt(kp.public, y))) == x - y


@given(x=small_ints)
def test_negate_is_homomorphic(keys, x):
    kp, dec = keys
    assert dec.decrypt(negate(encrypt(kp.public, x))) == -x


@given(x=st.integers(min_value=-1000, max_value=1000), k=st.integers(min_value=-10, max_value=10))
def test_scalar_mul_is_homomorphic(keys, x, k):
    kp, dec = keys
    assert dec.decrypt(scalar_mul(encrypt(kp.public, x), k)) == x * k


@given(x=small_ints)
def test_serialization_roundtrip(keys, x):
    kp, dec = keys
    ct = encrypt(kp.public, x)
    assert dec.decrypt(Ciphertext.from_bytes(ct.to_bytes(), public=kp.public)) == x


@given(x=small_ints)
def test_encryption_is_randomized(keys, x):
    kp, _ = keys
    assert encrypt(kp.public, x).to_bytes() != encrypt(kp.public, x).to_bytes()


@given(
    a=st.integers(-10**6, 10**6),
    b=st.integers(1, 10**6),
    c=st.integers(-10**6, 10**6),
    d=st.integers(1, 10**6),
)
def test_elliptic_rational_addition_matches_fractions(a, b, c, d):
    from fractions import Fraction

    total = EllipticRational(a, b) + EllipticRational(c, d)
    assert Fraction(total.numerator, total.denominator) == Fraction(a, b) + Fraction(c, d)


N = 2**61 - 1  # a prime modulus keeps these fast; correctness is modulus-independent


@given(
    coeffs=st.lists(st.integers(-(10**9), 10**9), min_size=1, max_size=6),
    data=st.data(),
)
def test_affine_delegation_is_correct(coeffs, data):
    values = data.draw(st.lists(st.integers(0, N - 1), min_size=len(coeffs), max_size=len(coeffs)))
    intercept = data.draw(st.integers(0, N - 1))
    owner = Owner(n=N)
    f = AffineFunctional(coefficients=coeffs, intercept=intercept)
    masked, correction = delegate_affine(owner, f, values)
    result = unblind_affine_result(owner, evaluate_affine_masked(f, masked), correction)
    assert result == f.evaluate(values, N)


@given(s=st.integers(0, N - 1), t=st.integers(0, N - 1))
def test_masked_multiplication_is_correct(s, t):
    owner = Owner(n=N)
    triple = owner.prepare_triple()
    opening = open_multiplication(owner, s, t, triple)
    assert reconstruct_multiplication(triple, opening, combine_multiplication(opening)) == (s * t) % N
