# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additively homomorphic ElGamal encryption over an elliptic curve group,
in "exponential" (exponent-encoded) form.

    Enc(m)               = (r*G, r*Pub + m*G)      for random scalar r
    Enc(m1) (+) Enc(m2)   = componentwise point addition = Enc(m1 + m2)
    Dec(sk, (C1, C2))     = discrete_log_G(C2 - sk*C1) = m

This satisfies the additively-homomorphic scheme abstraction used by the
Tokenis paper series (P2 Definition 3: IND-CPA under DDH, with
``Dec(Enc(x) (+) Enc(y)) = x + y`` over the plaintext group). Because the
message is encoded in the exponent, decryption requires solving a discrete
logarithm; this module uses baby-step-giant-step, which is only tractable
for a bounded plaintext range (``max_value``, default 2**40) -- exactly the
regime a gateway needs, since released values are aggregates over a finite
ledger, not arbitrary field elements.

--------------------------------------------------------------------------
REFERENCE IMPLEMENTATION -- NOT AUDITED -- DO NOT USE FOR REAL SECRETS
--------------------------------------------------------------------------
This module exists to make the disclosure-boundary architecture in the
Tokenis papers (P2/P3/P4) runnable end to end, and to give the
:mod:`tokenis.conformance` suite something concrete to test against. It is
a plain-Python, non-constant-time implementation with no side-channel
hardening, no key-management story, and no independent security review. The
product's real, "optimised" cryptographic engine is closed source (see
``reports/SUMMARY.md`` in this repository, and the R2 technical report it is
drawn from) -- this module is *not* that engine. Do not point it at real
production data or real secret values.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, PointJacobi

#: Default curve. secp256k1 was chosen for wide availability in the `ecdsa`
#: package used here; nothing about the construction depends on this
#: particular curve.
DEFAULT_CURVE = SECP256k1

#: Default bound on plaintexts (and on sums of plaintexts) that decryption
#: will search for via baby-step-giant-step. This is a real cost/range
#: tradeoff, not a formality: this module does plain, unbatched Jacobian
#: point arithmetic, at roughly 15-20 microseconds per point add on a
#: laptop, and BSGS needs O(sqrt(max_value)) of them to build the table
#: plus O(sqrt(max_value)) more to search it. 2**24 (~16.8M) keeps a
#: one-shot :func:`decrypt` call (which builds a fresh table every time)
#: at a fraction of a second, which comfortably covers aggregate sums over
#: every corpus in this repository. Callers who need a wider range should
#: construct one :class:`Decryptor` (amortising the table build across many
#: decryptions) and pass an explicit, larger ``max_value`` -- and should
#: expect the table build itself to take seconds to tens of seconds well
#: before this range: this is a reference implementation, not the
#: production engine (see the module docstring).
DEFAULT_MAX_VALUE = 2**24


def _order(curve) -> int:
    return curve.generator.order()


@dataclass(frozen=True)
class PrivateKey:
    """A scalar secret key. Never serialize or log this."""

    scalar: int
    curve: Any = field(default_factory=lambda: DEFAULT_CURVE, compare=False)

    def public_key(self) -> "PublicKey":
        return PublicKey(point=self.scalar * self.curve.generator, curve=self.curve)


@dataclass(frozen=True)
class PublicKey:
    """An elliptic-curve point ``sk * G``. Safe to distribute."""

    point: PointJacobi
    curve: Any = field(default_factory=lambda: DEFAULT_CURVE, compare=False)


@dataclass(frozen=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


@dataclass(frozen=True)
class Ciphertext:
    """An ElGamal ciphertext ``(c1, c2) = (r*G, r*Pub + m*G)``."""

    c1: PointJacobi
    c2: PointJacobi
    curve: Any = field(default_factory=lambda: DEFAULT_CURVE, compare=False)

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        return add(self, other)

    def __sub__(self, other: "Ciphertext") -> "Ciphertext":
        return subtract(self, other)


def keygen(curve=DEFAULT_CURVE, rng: Optional[object] = None) -> KeyPair:
    """Generate a fresh keypair.

    ``rng`` may be a :class:`random.Random`/``numpy.random.Generator``-like
    object exposing ``randrange(n)`` / ``integers(1, n)``; if omitted, the
    stdlib :mod:`secrets` module is used (cryptographically-strong OS
    randomness -- appropriate for *this* reference module's own use, but
    again: this module as a whole is not audited).
    """
    n = _order(curve)
    if rng is None:
        import secrets

        sk = 1 + secrets.randbelow(n - 1)
    elif hasattr(rng, "integers"):  # numpy.random.Generator
        sk = int(rng.integers(1, n))
    else:  # random.Random-like
        sk = rng.randrange(1, n)
    priv = PrivateKey(scalar=sk, curve=curve)
    return KeyPair(private=priv, public=priv.public_key())


def _random_scalar(curve, rng: Optional[object]) -> int:
    n = _order(curve)
    if rng is None:
        import secrets

        return 1 + secrets.randbelow(n - 1)
    if hasattr(rng, "integers"):
        return int(rng.integers(1, n))
    return rng.randrange(1, n)


def encrypt(pk: PublicKey, m: int, rng: Optional[object] = None) -> Ciphertext:
    """Encrypt integer ``m`` (may be negative) under ``pk``."""
    curve = pk.curve
    r = _random_scalar(curve, rng)
    c1 = r * curve.generator
    c2 = r * pk.point + m * curve.generator
    return Ciphertext(c1=c1, c2=c2, curve=curve)


def add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: ``Dec(add(Enc(x), Enc(y))) == x + y``."""
    return Ciphertext(c1=a.c1 + b.c1, c2=a.c2 + b.c2, curve=a.curve)


def negate(a: Ciphertext) -> Ciphertext:
    """Homomorphic negation: ``Dec(negate(Enc(x))) == -x``."""
    return Ciphertext(c1=-a.c1, c2=-a.c2, curve=a.curve)


def subtract(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic subtraction: ``Dec(subtract(Enc(x), Enc(y))) == x - y``."""
    return add(a, negate(b))


def scalar_mul(a: Ciphertext, k: int) -> Ciphertext:
    """Multiply a ciphertext by a *known public* integer ``k``.

    Used for e.g. scaling a SUM ciphertext by a publicly-known set size when
    computing AVG, or for negation (``k = -1``). ``k`` must be public: this
    operation is not private with respect to ``k``, only with respect to
    the plaintext ``a`` encrypts.
    """
    if k == 0:
        return Ciphertext(c1=INFINITY, c2=INFINITY, curve=a.curve)
    return Ciphertext(c1=k * a.c1, c2=k * a.c2, curve=a.curve)


def encrypt_zero_like(pk: PublicKey, rng: Optional[object] = None) -> Ciphertext:
    """``Enc(0)`` -- used by the disclosure-boundary simulators (P2 Theorem 28)
    to replace a ciphertext crossing the boundary without revealing its
    contents.
    """
    return encrypt(pk, 0, rng=rng)


class Decryptor:
    """Wraps a private key with a cached baby-step table for repeated
    decryption in a bounded plaintext range ``[-max_value, max_value]``.

    Building the baby-step table is the expensive part of BSGS
    (``O(sqrt(max_value))`` point additions); this class builds it once and
    reuses it for every :meth:`decrypt` call, which is the pattern a
    gateway actually needs (many aggregate decryptions per key).
    """

    def __init__(self, sk: PrivateKey, max_value: int = DEFAULT_MAX_VALUE):
        if max_value <= 0:
            raise ValueError("max_value must be positive")
        self.sk = sk
        self.max_value = max_value
        self._m = 1 + math.isqrt(max_value)
        self._table: Dict[bytes, int] = self._build_table(sk.curve)

    def _build_table(self, curve) -> Dict[bytes, int]:
        table: Dict[bytes, int] = {}
        point = INFINITY
        g = curve.generator
        for j in range(self._m + 1):
            table[_point_key(point)] = j
            point = point + g
        return table

    def decrypt(self, ct: Ciphertext) -> int:
        """Recover the integer plaintext (or raise :class:`ValueError` if it
        lies outside ``[-max_value, max_value]``)."""
        # M = c2 - sk*c1 = m*G
        shared = self.sk.scalar * ct.c1
        m_point = ct.c2 + (-shared)

        positive = self._bsgs(m_point)
        if positive is not None:
            return positive
        # m may be negative: search for -m instead, on -M = (-m)*G.
        negative = self._bsgs(-m_point)
        if negative is not None:
            return -negative
        raise ValueError(
            f"plaintext not found in range [-{self.max_value}, {self.max_value}]; "
            "increase max_value or check that the ciphertext/key are correct"
        )

    def _bsgs(self, target) -> Optional[int]:
        """Find non-negative ``m <= max_value`` with ``m*G == target``, or
        ``None`` if none exists in range. Standard baby-step-giant-step:
        the baby-step table holds ``j*G`` for ``j in [0, m]``
        (``m = ceil(sqrt(max_value))``); each giant step subtracts ``m*G``
        from the target and checks the table, covering ``i*m + j`` up to
        ``~max_value`` in ``O(sqrt(max_value))`` table lookups.
        """
        g = self.sk.curve.generator
        giant_step = (-self._m) * g
        point = target
        for i in range(self._m + 1):
            key = _point_key(point)
            if key in self._table:
                candidate = i * self._m + self._table[key]
                if candidate <= self.max_value:
                    return candidate
            point = point + giant_step
        return None


def _point_key(p) -> bytes:
    if p == INFINITY:
        return b"inf"
    return int(p.x()).to_bytes(32, "big") + int(p.y()).to_bytes(32, "big")


def decrypt(sk: PrivateKey, ct: Ciphertext, max_value: int = DEFAULT_MAX_VALUE) -> int:
    """Convenience one-shot decrypt. Prefer :class:`Decryptor` when
    decrypting many ciphertexts under the same key -- it amortises the
    baby-step table build.
    """
    return Decryptor(sk, max_value=max_value).decrypt(ct)
