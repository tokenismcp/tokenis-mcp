# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Security properties of tokenis.crypto -- each test pins down one claim
from tokenis/crypto/ec_fhe.py's "IMPLEMENTATION AND SECURITY PROPERTIES"
docstring section, so the claim can't silently regress."""
import copy
import pickle
import random
import warnings

import pytest

from tokenis.crypto import ec_fhe
from tokenis.crypto.ec_fhe import (
    CURVE_ORDER,
    Ciphertext,
    Decryptor,
    PrivateKey,
    PublicKey,
    decrypt,
    encrypt,
    keygen,
    scalar_mul,
)
from tokenis.crypto.randomness import InsecureRandomnessWarning, random_below


@pytest.fixture(scope="module")
def keypair():
    return keygen()


# -- secret hygiene ---------------------------------------------------------


def test_private_key_scalar_not_in_repr(keypair):
    scalar = str(keypair.private.scalar)
    assert scalar not in repr(keypair.private)
    assert scalar not in repr(keypair)
    assert scalar not in repr(Decryptor(keypair.private, max_value=16))


@pytest.mark.parametrize("serialize", [pickle.dumps, copy.copy, copy.deepcopy])
def test_private_key_refuses_serialization(keypair, serialize):
    with pytest.raises(TypeError):
        serialize(keypair.private)


def test_decryptor_refuses_serialization(keypair):
    with pytest.raises(TypeError):
        pickle.dumps(Decryptor(keypair.private, max_value=16))


@pytest.mark.parametrize("scalar", [0, -1, CURVE_ORDER, CURVE_ORDER + 5])
def test_private_key_rejects_out_of_range_scalar(scalar):
    with pytest.raises(ValueError):
        PrivateKey(scalar)


# -- input validation -------------------------------------------------------


def test_encrypt_rejects_float(keypair):
    with pytest.raises(TypeError):
        encrypt(keypair.public, 1.5)


def test_public_key_roundtrip(keypair):
    assert PublicKey.from_bytes(keypair.public.to_bytes()) == keypair.public


def test_ciphertext_roundtrip(keypair):
    ct = encrypt(keypair.public, 1234)
    restored = Ciphertext.from_bytes(ct.to_bytes(), public=keypair.public)
    assert restored == ct
    assert decrypt(keypair.private, restored) == 1234


def test_ciphertext_with_infinity_components_roundtrips(keypair):
    zero = scalar_mul(encrypt(keypair.public, 5), 0)
    assert zero.c1 == b"\x00" and zero.c2 == b"\x00"
    restored = Ciphertext.from_bytes(zero.to_bytes(), public=keypair.public)
    assert decrypt(keypair.private, restored) == 0


def test_zero_plaintext(keypair):
    assert decrypt(keypair.private, encrypt(keypair.public, 0)) == 0


def _off_curve_x_encoding() -> bytes:
    """A syntactically valid compressed encoding whose x-coordinate has no
    matching y on secp256k1 (about half of all x values don't)."""
    from coincurve import PublicKey as CPoint

    for x in range(1, 1000):
        candidate = b"\x02" + x.to_bytes(32, "big")
        try:
            CPoint(candidate)
        except ValueError:
            return candidate
    raise AssertionError("no off-curve x found")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b"\x02" + b[1:],  # unknown version
        lambda b: b[:-1],  # truncated
        lambda b: b + b"\x00",  # trailing bytes
        lambda b: b[:1] + b"\x05" + b[2:],  # invalid SEC1 prefix
    ],
)
def test_ciphertext_from_bytes_rejects_malformed(keypair, mutate):
    data = encrypt(keypair.public, 7).to_bytes()
    with pytest.raises(ValueError):
        Ciphertext.from_bytes(mutate(data))


def test_ciphertext_rejects_off_curve_point(keypair):
    bad = _off_curve_x_encoding()
    good = encrypt(keypair.public, 7)
    with pytest.raises(ValueError):
        Ciphertext(c1=bad, c2=good.c2)
    with pytest.raises(ValueError):
        PublicKey.from_bytes(bad)


def test_public_key_rejects_infinity():
    with pytest.raises(ValueError):
        PublicKey(b"\x00")


# -- timing: no plaintext-dependent early exit ------------------------------


def test_decrypt_work_is_independent_of_plaintext(keypair, monkeypatch):
    """Decryption must do the same amount of group work whether the
    plaintext is found on the first giant step or the last one. Counts
    point additions rather than measuring wall time, so it's deterministic.
    """
    dec = Decryptor(keypair.private, max_value=10_000)
    small = encrypt(keypair.public, 1)
    large = encrypt(keypair.public, 9_999)
    negative = encrypt(keypair.public, -9_999)

    calls = {"n": 0}
    real_add = ec_fhe._add

    def counting_add(a, b):
        calls["n"] += 1
        return real_add(a, b)

    monkeypatch.setattr(ec_fhe, "_add", counting_add)

    counts = []
    for ct in (small, large, negative):
        calls["n"] = 0
        dec.decrypt(ct)
        counts.append(calls["n"])
    assert len(set(counts)) == 1, counts


# -- randomness -------------------------------------------------------------


def test_default_randomness_does_not_warn():
    with warnings.catch_warnings():
        warnings.simplefilter("error", InsecureRandomnessWarning)
        random_below(1000)
        random_below(1000, random.SystemRandom())
        keygen()


def test_seeded_rng_warns():
    with pytest.warns(InsecureRandomnessWarning):
        random_below(1000, random.Random(1))
    with pytest.warns(InsecureRandomnessWarning):
        keygen(rng=random.Random(1))


def test_random_below_is_in_range():
    for _ in range(200):
        assert 0 <= random_below(7) < 7
    with pytest.raises(ValueError):
        random_below(0)
