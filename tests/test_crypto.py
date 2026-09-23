# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.crypto.paillier import (
    Decryptor,
    add,
    decrypt,
    encrypt,
    keygen,
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


def test_sum_over_large_values(keypair):
    """Unlike the discrete-log-based scheme this module replaced, Paillier
    decryption has no bounded search range -- confirm a large sum still
    decrypts exactly."""
    total = encrypt(keypair.public, 0)
    for v in (10**9, 10**12, -(10**11), 10**15):
        total = add(total, encrypt(keypair.public, v))
    assert decrypt(keypair.private, total) == 10**9 + 10**12 - 10**11 + 10**15


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
