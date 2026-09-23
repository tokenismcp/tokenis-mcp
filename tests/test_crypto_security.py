# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Security properties of tokenis.crypto as seen from Python -- each test
pins down one claim from tokenis/crypto/ec_fhe.py's "IMPLEMENTATION AND
SECURITY PROPERTIES" section. (The decryption-work-independence property
is pinned in Rust: crates/tokenis-core/src/elgamal.rs,
`search_work_is_independent_of_plaintext`.)"""
import copy
import inspect
import pickle

import pytest

from tokenis.crypto import ec_fhe
from tokenis.crypto.ec_fhe import (
    CURVE_ORDER,
    Ciphertext,
    Decryptor,
    PrivateKey,
    PublicKey,
    TokenisCryptoError,
    decrypt,
    encrypt,
    keygen,
    scalar_mul,
)


@pytest.fixture(scope="module")
def keypair():
    return keygen()


# -- secret hygiene ---------------------------------------------------------


def test_private_key_has_no_scalar_attribute(keypair):
    assert not hasattr(keypair.private, "scalar")
    assert not hasattr(keypair.private, "__dict__")


def test_secrets_not_in_repr(keypair):
    secret_hex = keypair.private.export_secret_bytes().hex()
    for obj in (keypair.private, keypair, Decryptor(keypair.private, 16)):
        assert secret_hex not in repr(obj)
        assert "redacted" in repr(keypair.private)


@pytest.mark.parametrize("serialize", [pickle.dumps, copy.copy, copy.deepcopy])
def test_private_key_and_decryptor_refuse_serialization(keypair, serialize):
    with pytest.raises(TypeError):
        serialize(keypair.private)
    with pytest.raises(TypeError):
        serialize(Decryptor(keypair.private, 16))


def test_no_way_to_inject_randomness():
    """Randomness is drawn from the OS CSPRNG inside Rust; no public entry
    point accepts a caller-supplied RNG."""
    for fn in (ec_fhe.keygen, ec_fhe.encrypt, ec_fhe.encrypt_rational, ec_fhe.bootstrap):
        assert "rng" not in inspect.signature(fn).parameters


def test_private_key_import_export_roundtrip(keypair):
    restored = PrivateKey.from_bytes(keypair.private.export_secret_bytes())
    assert restored.public_key() == keypair.public


@pytest.mark.parametrize(
    "raw",
    [
        bytes(32),  # zero
        CURVE_ORDER.to_bytes(32, "big"),  # n
        b"\xff" * 32,  # > n
        b"\x01" * 31,  # wrong length
    ],
)
def test_private_key_rejects_invalid_scalars(raw):
    with pytest.raises(TokenisCryptoError):
        PrivateKey.from_bytes(raw)


def test_crypto_errors_are_value_errors():
    assert issubclass(TokenisCryptoError, ValueError)


# -- input validation -------------------------------------------------------


def test_encrypt_rejects_float(keypair):
    with pytest.raises(TypeError):
        encrypt(keypair.public, 1.5)


def test_encrypt_rejects_out_of_64_bit_range(keypair):
    with pytest.raises(OverflowError):
        encrypt(keypair.public, 2**63)


def test_public_key_roundtrip(keypair):
    assert PublicKey.from_bytes(keypair.public.to_bytes()) == keypair.public


def test_ciphertext_roundtrip(keypair):
    ct = encrypt(keypair.public, 1234)
    restored = Ciphertext.from_bytes(ct.to_bytes(), public=keypair.public)
    assert restored == ct
    assert decrypt(keypair.private, restored) == 1234


def test_ciphertext_with_identity_components_roundtrips(keypair):
    zero = scalar_mul(encrypt(keypair.public, 5), 0)
    assert zero.c1 == b"\x00" and zero.c2 == b"\x00"
    assert zero.to_bytes() == b"\x01\x00\x00"
    assert decrypt(keypair.private, Ciphertext.from_bytes(zero.to_bytes())) == 0


def _off_curve_x_encoding() -> bytes:
    """A syntactically valid compressed encoding with no point on the
    curve (about half of all x-coordinates have none)."""
    for x in range(1, 256):
        candidate = b"\x02" + x.to_bytes(32, "big")
        try:
            PublicKey.from_bytes(candidate)
        except TokenisCryptoError:
            return candidate
    raise AssertionError("no off-curve x found")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b"\x02" + b[1:],  # unknown version
        lambda b: b[:-1],  # truncated
        lambda b: b + b"\x00",  # trailing bytes
        lambda b: b[:1] + b"\x05" + b[2:],  # invalid SEC1 prefix
        lambda b: b"",  # empty
    ],
)
def test_ciphertext_from_bytes_rejects_malformed(keypair, mutate):
    data = encrypt(keypair.public, 7).to_bytes()
    with pytest.raises(TokenisCryptoError):
        Ciphertext.from_bytes(mutate(data))


def test_off_curve_points_rejected(keypair):
    bad = _off_curve_x_encoding()
    with pytest.raises(TokenisCryptoError):
        PublicKey.from_bytes(bad)
    good = encrypt(keypair.public, 7).to_bytes()
    with pytest.raises(TokenisCryptoError):
        Ciphertext.from_bytes(b"\x01" + bad + good[34:])


def test_public_key_rejects_identity():
    with pytest.raises(TokenisCryptoError):
        PublicKey.from_bytes(b"\x00")


def test_key_mismatch_detected(keypair):
    other = keygen()
    with pytest.raises(TokenisCryptoError):
        encrypt(keypair.public, 1) + encrypt(other.public, 1)
    with pytest.raises(TokenisCryptoError):
        decrypt(other.private, encrypt(keypair.public, 1))


def test_decryptor_range_validated(keypair):
    for bad in (0, ec_fhe.MAX_SUPPORTED_RANGE + 1):
        with pytest.raises(TokenisCryptoError):
            Decryptor(keypair.private, bad)
    for bad_table in (0, ec_fhe.MAX_TABLE_SIZE + 1):
        with pytest.raises(TokenisCryptoError):
            Decryptor(keypair.private, 1000, table_size=bad_table)
    # A tiny table over a huge range would be an unbounded walk: refused
    # up front rather than hanging the caller.
    with pytest.raises(TokenisCryptoError):
        Decryptor(keypair.private, ec_fhe.MAX_SUPPORTED_RANGE, table_size=1)


def test_decryptor_table_size_trades_memory_for_speed(keypair):
    big = Decryptor(keypair.private, 2**32, table_size=2**18)
    assert big.table_size == 2**18
    for m in (2**32, -(2**32), 123_456_789_012 // 100):
        assert big.decrypt(encrypt(keypair.public, m)) == m
    assert Decryptor(keypair.private, 3, table_size=1000).table_size == 7


def test_bootstrap_requires_matching_key(keypair):
    other = keygen()
    with pytest.raises(ValueError):
        ec_fhe.bootstrap(keypair.private, other.public, encrypt(keypair.public, 1))
