# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.crypto.ec_fhe import (
    DEFAULT_MAX_VALUE,
    Decryptor,
    EllipticRational,
    add,
    bootstrap,
    decrypt,
    decrypt_rational,
    encrypt,
    encrypt_rational,
    keygen,
    multiply,
    negate,
    scalar_mul,
    subtract,
)


@pytest.fixture(scope="module")
def keypair():
    return keygen()


def test_encrypt_decrypt_roundtrip(keypair):
    ct = encrypt(keypair.public, 42)
    assert decrypt(keypair.private, ct) == 42


def test_negative_plaintext_roundtrip(keypair):
    ct = encrypt(keypair.public, -17)
    assert decrypt(keypair.private, ct) == -17


def test_homomorphic_add(keypair):
    a = encrypt(keypair.public, 5)
    b = encrypt(keypair.public, 7)
    assert decrypt(keypair.private, add(a, b)) == 12


def test_homomorphic_subtract(keypair):
    a = encrypt(keypair.public, 5)
    b = encrypt(keypair.public, 7)
    assert decrypt(keypair.private, subtract(a, b)) == -2


def test_homomorphic_negate(keypair):
    a = encrypt(keypair.public, 5)
    assert decrypt(keypair.private, negate(a)) == -5


def test_scalar_mul(keypair):
    a = encrypt(keypair.public, 5)
    assert decrypt(keypair.private, scalar_mul(a, 4)) == 20


def test_sum_over_many_values(keypair):
    total = encrypt(keypair.public, 0)
    for v in range(50):
        total = add(total, encrypt(keypair.public, v))
    assert decrypt(keypair.private, total) == sum(range(50))


def test_decrypt_outside_range_raises(keypair):
    """Unlike Paillier, this scheme encodes the message in the exponent and
    decrypts via a bounded baby-step-giant-step search (see the module
    docstring's DEFAULT_MAX_VALUE comment) -- a value outside that range is
    a real, expected failure mode, not a bug."""
    ct = encrypt(keypair.public, DEFAULT_MAX_VALUE + 10**6)
    with pytest.raises(ValueError):
        decrypt(keypair.private, ct, max_value=1000)


def test_operator_overloads(keypair):
    a = encrypt(keypair.public, 10)
    b = encrypt(keypair.public, 3)
    assert decrypt(keypair.private, a + b) == 13
    assert decrypt(keypair.private, a - b) == 7
    assert decrypt(keypair.private, a * 5) == 50


def test_decryptor_convenience_wrapper(keypair):
    dec = Decryptor(keypair.private)
    assert dec.decrypt(encrypt(keypair.public, 99)) == 99


def test_different_keys_cannot_be_combined(keypair):
    other = keygen()
    a = encrypt(keypair.public, 5)
    b = encrypt(other.public, 5)
    with pytest.raises(ValueError):
        add(a, b)


def test_different_keys_cannot_decrypt_each_other(keypair):
    other = keygen()
    ct = encrypt(keypair.public, 42)
    with pytest.raises(ValueError):
        decrypt(other.private, ct)


def test_multiply_is_not_implemented(keypair):
    """See tokenis.crypto.ec_fhe's module docstring, point 2: the source
    paper's ciphertext x ciphertext multiplication does not type-check, so
    this raises rather than silently doing something else."""
    a = encrypt(keypair.public, 3)
    b = encrypt(keypair.public, 4)
    with pytest.raises(NotImplementedError):
        multiply(a, b)


class TestEllipticRational:
    def test_equivalence(self):
        assert EllipticRational(1, 2) == EllipticRational(2, 4)
        assert EllipticRational(1, 2) == EllipticRational(3, 6)
        assert EllipticRational(1, 2) != EllipticRational(1, 3)

    def test_canonical_form(self):
        assert EllipticRational(6, 8).canonical() == EllipticRational(3, 4)
        assert EllipticRational(3, -4).canonical() == EllipticRational(-3, 4)

    def test_addition(self):
        # 1/2 + 1/3 = 5/6, per [RATIONAL] Definition 4.4.
        assert EllipticRational(1, 2) + EllipticRational(1, 3) == EllipticRational(5, 6)

    def test_negation_and_subtraction(self):
        a = EllipticRational(3, 4)
        assert -a == EllipticRational(-3, 4)
        assert a - a == EllipticRational(0, 1)

    def test_from_float_continued_fraction(self):
        r = EllipticRational.from_float(0.75)
        assert r == EllipticRational(3, 4)

    def test_from_float_fixed_point(self):
        r = EllipticRational.from_float_fixed_point(1.5, precision=2)
        assert r == EllipticRational(150, 100)
        assert r.to_float() == 1.5

    def test_to_points_matches_scalar_multiples(self):
        from tokenis.crypto.ec_fhe import PrivateKey

        def k_g(k: int) -> bytes:
            return PrivateKey.from_bytes(k.to_bytes(32, "big")).public_key().to_bytes()

        num_point, den_point = EllipticRational(3, 4).to_points()
        assert (num_point, den_point) == (k_g(3), k_g(4))
        assert EllipticRational(0, 1).to_points()[0] == b"\x00"

    def test_zero_denominator_rejected(self):
        with pytest.raises(ValueError):
            EllipticRational(1, 0)


def test_encrypt_decrypt_rational_roundtrip(keypair):
    ct = encrypt_rational(keypair.public, 3.14, precision=4)
    assert decrypt_rational(keypair.private, ct, precision=4) == pytest.approx(3.14)


def test_encrypt_decrypt_rational_negative(keypair):
    ct = encrypt_rational(keypair.public, -2.5, precision=2)
    assert decrypt_rational(keypair.private, ct, precision=2) == pytest.approx(-2.5)


def test_homomorphic_add_rational(keypair):
    """Addition under a shared fixed-point denominator -- see
    encrypt_rational's docstring for why the denominator must match."""
    a = encrypt_rational(keypair.public, 1.5, precision=3)
    b = encrypt_rational(keypair.public, 2.25, precision=3)
    total = decrypt_rational(keypair.private, add(a, b), precision=3)
    assert total == pytest.approx(3.75)


def test_bootstrap_preserves_plaintext(keypair):
    """[ECFHE] Algorithm 5, literal implementation: decrypt-then-re-encrypt
    under the private key -- see bootstrap()'s docstring for what this does
    and does not provide."""
    ct = encrypt(keypair.public, 123)
    fresh = bootstrap(keypair.private, keypair.public, ct)
    assert decrypt(keypair.private, fresh) == 123
    # Fresh ElGamal randomness means the ciphertext components differ even
    # though the plaintext is unchanged.
    assert fresh.c1 != ct.c1 or fresh.c2 != ct.c2
