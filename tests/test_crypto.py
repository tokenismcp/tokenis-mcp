# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
import pytest

from tokenis.crypto.ec_elgamal import (
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


def test_decryptor_reuse_and_out_of_range(keypair):
    dec = Decryptor(keypair.private, max_value=10_000)
    assert dec.decrypt(encrypt(keypair.public, 9_999)) == 9_999
    assert dec.decrypt(encrypt(keypair.public, -9_999)) == -9_999
    with pytest.raises(ValueError):
        dec.decrypt(encrypt(keypair.public, 50_000))


def test_different_keys_do_not_decrypt_each_other(keypair):
    other = keygen()
    ct = encrypt(keypair.public, 42)
    with pytest.raises(ValueError):
        decrypt(other.private, ct, max_value=1000)
