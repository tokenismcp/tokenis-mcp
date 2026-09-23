# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additively homomorphic encryption via the Paillier cryptosystem
(Paillier, 1999; security rests on the Decisional Composite Residuosity
assumption -- a well-studied, peer-reviewed construction, not a scheme
invented for this repository):

    Enc(m1) (+) Enc(m2) = Enc(m1 + m2)
    Enc(m) (*) k        = Enc(m * k)      for a *public* integer k

This satisfies the additively-homomorphic scheme abstraction the Tokenis
paper series assumes (P2 Definition 3: an IND-CPA-secure scheme with
``Dec(Enc(x) (+) Enc(y)) = x + y`` over the plaintext group).

Why Paillier here, and not a hand-rolled elliptic-curve construction
----------------------------------------------------------------------
An earlier version of this module implemented additive ElGamal directly
over raw elliptic-curve point arithmetic (using the pure-Python `ecdsa`
package's point operations), which meant this repository's own code was
the only thing standing between "point addition" and "a cryptographic
primitive" -- and decryption needed a baby-step-giant-step discrete-log
search bounded to a fixed plaintext range. Neither property is
appropriate for anything beyond a demo.

This module instead delegates the actual arithmetic to `phe`
(python-paillier), a library purpose-built for additively homomorphic
encryption rather than a general EC toolkit repurposed for it, and gets
two concrete improvements for free: decryption is direct (no
baby-step-giant-step, no bounded plaintext range -- see the removed
`Decryptor`/`max_value` machinery in this module's git history), and the
scheme itself (Paillier) is one of the most widely analysed
partially-homomorphic constructions in the literature, independent of
this repository.

--------------------------------------------------------------------------
STILL A REFERENCE INTEGRATION -- READ BEFORE USING FOR REAL SECRETS
--------------------------------------------------------------------------
Building on a well-established scheme and a maintained library is a real
improvement over hand-rolled point arithmetic, but it is not the same
claim as "this specific integration has been independently security
audited" -- it has not. In particular: key generation, storage and
rotation policy are this repository's own responsibility and are not
addressed here at all (see :mod:`tokenis.gateway.service` for where keys
are currently generated in-process and held only in memory, which is
adequate for the examples and tests in this repository and not a key
management story for a real deployment); `phe`'s pure-Python modular
exponentiation is not hardened against timing side-channels. Treat this
module as appropriate for demonstrating the disclosure-boundary
architecture end to end, not as a drop-in replacement for a reviewed KMS
+ HSM-backed production deployment (see ``reports/SUMMARY.md`` on the
open/closed boundary between this SDK and the product's real engine).
"""
from __future__ import annotations

from dataclasses import dataclass

from phe import paillier

#: Paillier modulus bit length. 2048 matches the commonly recommended
#: floor for RSA-family moduli (Paillier's security reduces to the same
#: factoring-adjacent hardness family via the Decisional Composite
#: Residuosity assumption); raise it (e.g. 3072) for a larger security
#: margin at the cost of slower key generation and larger ciphertexts.
DEFAULT_KEY_LENGTH = 2048


@dataclass(frozen=True)
class PublicKey:
    """Wraps a ``phe.paillier.PaillierPublicKey``. Safe to distribute."""

    _key: paillier.PaillierPublicKey


@dataclass(frozen=True)
class PrivateKey:
    """Wraps a ``phe.paillier.PaillierPrivateKey``. Never serialize or log
    this."""

    _key: paillier.PaillierPrivateKey
    public: PublicKey


@dataclass(frozen=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


@dataclass(frozen=True)
class Ciphertext:
    """A Paillier ciphertext, tagged with the public key it was encrypted
    under (mixing ciphertexts from different keys is a caller error we can
    catch structurally rather than silently producing garbage)."""

    _enc: paillier.EncryptedNumber
    public: PublicKey

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        return add(self, other)

    def __sub__(self, other: "Ciphertext") -> "Ciphertext":
        return subtract(self, other)

    def __mul__(self, k: int) -> "Ciphertext":
        return scalar_mul(self, k)


def keygen(key_length: int = DEFAULT_KEY_LENGTH) -> KeyPair:
    """Generate a fresh Paillier keypair."""
    pub, priv = paillier.generate_paillier_keypair(n_length=key_length)
    public = PublicKey(_key=pub)
    private = PrivateKey(_key=priv, public=public)
    return KeyPair(private=private, public=public)


def encrypt(pk: PublicKey, m: int) -> Ciphertext:
    """Encrypt integer ``m`` (may be negative) under ``pk``."""
    return Ciphertext(_enc=pk._key.encrypt(int(m)), public=pk)


def decrypt(sk: PrivateKey, ct: Ciphertext) -> int:
    """Decrypt ``ct`` with ``sk``. Unlike the discrete-log-based scheme
    this module replaced, this is direct and exact for any plaintext in
    the scheme's (enormous, ~617-decimal-digit at 2048 bits) representable
    range -- no bounded search, no precomputed table."""
    if ct.public._key != sk.public._key:
        raise ValueError("ciphertext was not encrypted under this key's matching public key")
    value = sk._key.decrypt(ct._enc)
    return int(value)


def add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: ``Dec(add(Enc(x), Enc(y))) == x + y``."""
    _check_same_key(a, b)
    return Ciphertext(_enc=a._enc + b._enc, public=a.public)


def negate(a: Ciphertext) -> Ciphertext:
    """Homomorphic negation: ``Dec(negate(Enc(x))) == -x``."""
    return scalar_mul(a, -1)


def subtract(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic subtraction: ``Dec(subtract(Enc(x), Enc(y))) == x - y``."""
    _check_same_key(a, b)
    return Ciphertext(_enc=a._enc - b._enc, public=a.public)


def scalar_mul(a: Ciphertext, k: float) -> Ciphertext:
    """Multiply a ciphertext by a *known public* integer ``k``.

    Used for e.g. scaling a SUM ciphertext by a publicly-known set size
    when computing AVG, or for negation (``k = -1``). ``k`` must be
    public: this operation is not private with respect to ``k``, only
    with respect to the plaintext ``a`` encrypts.
    """
    return Ciphertext(_enc=a._enc * k, public=a.public)


def _check_same_key(a: Ciphertext, b: Ciphertext) -> None:
    if a.public._key != b.public._key:
        raise ValueError("cannot combine ciphertexts encrypted under different public keys")


class Decryptor:
    """Kept for interface continuity with earlier revisions of this
    module and with :mod:`tokenis.gateway.compute`'s usage. Paillier
    decryption needs no amortised table (see :func:`decrypt`'s
    docstring), so this class is now a thin, stateless-except-for-the-key
    wrapper rather than the expensive baby-step-giant-step cache it used
    to be.
    """

    def __init__(self, sk: PrivateKey, max_value: int = 0):
        # max_value is accepted and ignored: retained only so callers
        # written against the previous (range-bounded) API don't need to
        # change their call sites. Paillier decryption is exact and
        # unbounded within the scheme's representable range regardless.
        del max_value
        self.sk = sk

    def decrypt(self, ct: Ciphertext) -> int:
        return decrypt(self.sk, ct)
