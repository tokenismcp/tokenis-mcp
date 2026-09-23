# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Elliptic-curve additively homomorphic encryption, plus a literal
implementation of the "elliptic rational number" and "EC-FHE" constructions
from three source papers the project maintainer supplied:

  [ECHC]    Y. Lee, M. Shim, J. Lee, "Homomorphic-based Encryption using
            Weil Pairing: A Foundation for Fully Homomorphic Encryption on
            Elliptic Curves" (2025) -- referred to elsewhere in this
            repository as "P1".
  [RATIONAL] Anonymous, "Rational Number Representation over Elliptic
            Curves via Equivalence Relations: Extending ECHC to Fractional
            Scalar Multiplication" (2025).
  [ECFHE]   Anonymous, "Extension to Real Number Representations over
            Elliptic Curves: ... a complete elliptic curve-based fully
            homomorphic encryption (EC-FHE) scheme" (2025).

This module is written to match those papers' constructions as literally as
possible, at the maintainer's explicit request, made after being shown --
and acknowledging -- three problems in the papers themselves. Documenting
those problems here is not optional commentary: it is the difference
between an honest reference module and a misleading one, and this
repository's own SECURITY.md and CONTRIBUTING.md commit to the former.

1. ECHC's "EI function" sigma: E(F_q) -> Z_n1 x Z_n2 is applied and then
   immediately inverted in every Encrypt/Decrypt formula the paper gives
   (C1 = sigma^-1(k*sigma(P)), etc.) -- since sigma^-1(sigma(x)) = x for any
   bijection, sigma contributes nothing to what is actually computed. What
   the paper's own algorithms compute is standard additive elliptic-curve
   ElGamal: C1 = k*P, C2 = M + k*Q, Dec = C2 - sk*C1. Separately, the
   paper's own "Remark on computability and security" states that
   *actually* computing sigma (finding a point's (a, b) coordinates in a
   chosen basis) is "computationally equivalent to two discrete
   logarithms" -- exactly the hardness the scheme's security rests on. So
   sigma is either a no-op (as used) or uncomputable (if taken seriously);
   either way there is nothing to implement beyond EC-ElGamal, which is
   what the functions below actually are.

2. [ECFHE]'s ciphertext-times-ciphertext multiplicative homomorphism
   (Theorem 8, "tensor product") defines U * V := sigma^-1(e_n(sigma(U),
   sigma(V))), where e_n is the Weil pairing. e_n's output lands in mu_n
   (a group of roots of unity -- elements of a field extension), while
   sigma^-1's stated domain is Z_n1 x Z_n2. Applying sigma^-1 to a mu_n
   element is outside its domain as defined: the construction the paper's
   entire multiplicative-homomorphism story rests on does not type-check.
   `multiply()` below raises `NotImplementedError` for this reason -- not
   because it wasn't attempted, but because there is nothing well-defined
   in the source paper to implement. What *is* implemented is
   `scalar_mul`: multiplying a ciphertext by a known plaintext integer,
   which is a standard capability of any additively homomorphic scheme and
   requires none of the above.

3. [ECFHE]'s Bootstrap (Algorithm 5) works by using a "bootstrap key" to
   partially decrypt the noisy ciphertext, then re-encrypting the result
   with fresh randomness. In genuine FHE (BGV/BFV/CKKS/TFHE), bootstrapping
   refreshes accumulated noise WITHOUT the party performing it ever seeing
   the plaintext or holding decryption capability -- that property is the
   entire reason FHE lets an untrusted server compute on encrypted data
   without the server ever learning what it computed on. `bootstrap()`
   below is implemented literally as the paper describes it: it takes the
   private key as an argument and decrypts internally. It MUST be run by
   the key holder, never by an untrusted evaluator, and it does not confer
   any "compute on data you can't see" property beyond what a normal
   decrypt-then-re-encrypt already gives a key holder.

If you are choosing a scheme for a new deployment based on what's here,
none of the above should read as "EC-FHE is a stronger alternative to
Paillier" (an earlier revision of this SDK used `phe`/python-paillier as
its crypto backend, replaced by this module at the maintainer's explicit
request -- see this repository's commit history and CHANGELOG.md): it is
EC-based additive homomorphism, same capability class as Paillier, with a
rational-number plaintext encoding layered on top and a bootstrap
operation that only the key holder can run.

--------------------------------------------------------------------------
IMPLEMENTATION AND SECURITY PROPERTIES -- READ BEFORE USING FOR REAL SECRETS
--------------------------------------------------------------------------
Group arithmetic is delegated to libsecp256k1 (via the `coincurve`
bindings) -- the C library Bitcoin Core uses, widely deployed and
extensively reviewed -- not implemented in Python. Concretely:

- Every scalar multiplication involving a secret scalar (the private key,
  per-encryption randomness, the plaintext itself) runs through
  libsecp256k1's constant-time routines.
- Every point parsed from untrusted bytes (`PublicKey.from_bytes`,
  `Ciphertext.from_bytes`, or constructing either directly) is validated
  to lie on secp256k1, rejecting invalid-curve inputs rather than doing
  arithmetic on them.
- Decryption's baby-step-giant-step search runs a fixed number of
  iterations for a given ``max_value`` regardless of the plaintext, rather
  than returning at the first match (which would leak the plaintext's
  magnitude through timing). Python-level operations (dict lookups, big-int
  arithmetic) still vary slightly, so this is "no plaintext-dependent early
  exit," not "constant-time"; the gateway's W6 latency quantization
  (:mod:`tokenis.gateway.latency`) pads whole tool calls on top of this.
- Secrets never appear in ``repr`` output, and `PrivateKey` refuses to be
  pickled or copied, so a key doesn't leak into logs, tracebacks or caches
  by accident.
- All secret randomness comes from the OS CSPRNG unless a caller
  explicitly passes ``rng``, which raises `InsecureRandomnessWarning` (see
  :mod:`tokenis.crypto.randomness`).

What this module cannot provide, and why: secret scalars live in Python
``int`` objects, which are immutable and may be copied by the interpreter,
so they cannot be reliably zeroised from memory after use; and keys are
generated and held in-process rather than in an HSM/KMS. Both need either
native key-handling code or dedicated hardware -- the key-management and
HSM integration R2 places in the closed product engine, not in this SDK.
No independent audit of this integration has been performed, and the
source papers remain unreviewed preprints with the problems listed above.
"""
from __future__ import annotations

import math
import operator
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Dict, Optional, Tuple

from coincurve import PublicKey as _CPoint

from tokenis.crypto.randomness import random_nonzero_below

#: The curve every key and ciphertext in this module lives on.
CURVE_NAME = "secp256k1"

#: Order of secp256k1's generator (the size of the scalar field Z/nZ).
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Default bound on plaintexts (and on sums of plaintexts) that decryption
#: will search for via baby-step-giant-step -- see [ECFHE] Theorem 10.6 and
#: [ECHC] §5.1, both of which note that recovering an integer from its point
#: representation costs O(sqrt(n)). 2**24 (~16.8M) keeps a decrypt in the
#: tens of milliseconds and comfortably covers aggregate sums over every
#: corpus in this repository. Callers needing a wider range should construct
#: one `Decryptor` with an explicit, larger ``max_value`` -- decryption cost
#: grows with sqrt(max_value) on every call, by design (see the module
#: docstring on fixed-iteration decryption).
DEFAULT_MAX_VALUE = 2**24

#: Default fixed-point scaling exponent for `encrypt_rational` /
#: `decrypt_rational`: real numbers are encoded as integer numerators over
#: an implicit, public denominator of 10**DEFAULT_PRECISION, matching
#: [ECFHE] Algorithm 2's "standard mode" (decimal rounding to `delta`
#: places) rather than its "optimized mode" (continued-fraction
#: convergents) -- standard mode is the one whose denominator is fixed and
#: shared across values, which is what addition under encryption requires
#: (see `encrypt_rational`'s docstring).
DEFAULT_PRECISION = 6

_CIPHERTEXT_VERSION = 1
_INFINITY = b"\x00"

# ---------------------------------------------------------------------------
# Point arithmetic. A point is a coincurve PublicKey, or None for the point
# at infinity (which libsecp256k1 cannot represent as a public key).
# ---------------------------------------------------------------------------

_Point = Optional[_CPoint]


def _scalar_bytes(k: int) -> bytes:
    return k.to_bytes(32, "big")


def _base_mul(k: int) -> _Point:
    k %= CURVE_ORDER
    return None if k == 0 else _CPoint.from_secret(_scalar_bytes(k))


def _mul(p: _Point, k: int) -> _Point:
    k %= CURVE_ORDER
    if p is None or k == 0:
        return None
    return p.multiply(_scalar_bytes(k))


def _add(a: _Point, b: _Point) -> _Point:
    if a is None:
        return b
    if b is None:
        return a
    try:
        return _CPoint.combine_keys([a, b])
    except ValueError:
        # libsecp256k1 rejects a sum equal to the point at infinity.
        return None


def _neg(p: _Point) -> _Point:
    return _mul(p, CURVE_ORDER - 1)


def _encode(p: _Point) -> bytes:
    return _INFINITY if p is None else p.format(compressed=True)


def _decode(data: bytes) -> _Point:
    """Parse a SEC1-compressed point (or ``b"\\x00"`` for infinity),
    rejecting anything that is not a valid secp256k1 point."""
    if data == _INFINITY:
        return None
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("invalid point encoding (expected 33-byte SEC1 compressed)")
    try:
        return _CPoint(data)
    except ValueError as exc:
        raise ValueError("point is not on secp256k1") from exc


def _split_point(buf: bytes) -> Tuple[bytes, bytes]:
    if not buf:
        raise ValueError("truncated ciphertext")
    if buf[0] == 0:
        return buf[:1], buf[1:]
    if len(buf) < 33:
        raise ValueError("truncated ciphertext")
    return buf[:33], buf[33:]


# ---------------------------------------------------------------------------
# Keys and ciphertexts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, eq=False)
class PrivateKey:
    """A secret scalar in ``[1, n)``. Redacted from ``repr`` and refuses to
    be pickled or copied -- see the module docstring."""

    scalar: int = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scalar, int) or not 1 <= self.scalar < CURVE_ORDER:
            raise ValueError("private scalar must be an integer in [1, curve order)")

    def public_key(self) -> "PublicKey":
        return PublicKey(_encode(_base_mul(self.scalar)))

    def __reduce__(self) -> Any:
        raise TypeError(
            "refusing to pickle or copy a PrivateKey: secret key material must "
            "not be serialized implicitly (caches, task queues, deep copies)"
        )


@dataclass(frozen=True)
class PublicKey:
    """A secp256k1 point ``sk * G``, held as its 33-byte SEC1 compressed
    encoding (validated on construction). Safe to distribute."""

    encoded: bytes
    _point: Any = field(default=None, init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        point = _decode(bytes(self.encoded))
        if point is None:
            raise ValueError("a public key cannot be the point at infinity")
        object.__setattr__(self, "encoded", bytes(self.encoded))
        object.__setattr__(self, "_point", point)

    def to_bytes(self) -> bytes:
        return self.encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicKey":
        return cls(bytes(data))


@dataclass(frozen=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


@dataclass(frozen=True)
class Ciphertext:
    """An elliptic-curve additive-ElGamal ciphertext ``(c1, c2) = (r*G,
    r*Pub + m*G)``, each component held as a SEC1 compressed point (or
    ``b"\\x00"`` for infinity) and validated on construction. In [ECHC]'s
    notation this is exactly what ``(sigma^-1(C1), sigma^-1(C2))`` reduces
    to (see module docstring).

    ``public`` records the key it was encrypted under so that combining
    ciphertexts from different keys fails loudly (`add`/`subtract`) instead
    of silently decrypting to garbage. It is not part of the wire format:
    pass it to `from_bytes` if you want that check on deserialized values.
    """

    c1: bytes
    c2: bytes
    public: Optional[PublicKey] = None
    _p1: Any = field(default=None, init=False, repr=False, compare=False, hash=False)
    _p2: Any = field(default=None, init=False, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "c1", bytes(self.c1))
        object.__setattr__(self, "c2", bytes(self.c2))
        object.__setattr__(self, "_p1", _decode(self.c1))
        object.__setattr__(self, "_p2", _decode(self.c2))

    @classmethod
    def _from_points(cls, p1: _Point, p2: _Point, public: Optional[PublicKey]) -> "Ciphertext":
        # Internal fast path: p1/p2 came out of libsecp256k1 arithmetic and
        # are already valid, so skip re-parsing them.
        ct = object.__new__(cls)
        for name, value in (
            ("c1", _encode(p1)),
            ("c2", _encode(p2)),
            ("public", public),
            ("_p1", p1),
            ("_p2", p2),
        ):
            object.__setattr__(ct, name, value)
        return ct

    def to_bytes(self) -> bytes:
        """Versioned wire format: ``0x01 || c1 || c2``."""
        return bytes([_CIPHERTEXT_VERSION]) + self.c1 + self.c2

    @classmethod
    def from_bytes(cls, data: bytes, public: Optional[PublicKey] = None) -> "Ciphertext":
        data = bytes(data)
        if not data or data[0] != _CIPHERTEXT_VERSION:
            raise ValueError("unsupported ciphertext encoding version")
        c1, rest = _split_point(data[1:])
        c2, rest = _split_point(rest)
        if rest:
            raise ValueError("trailing bytes after ciphertext")
        return cls(c1=c1, c2=c2, public=public)

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        return add(self, other)

    def __sub__(self, other: "Ciphertext") -> "Ciphertext":
        return subtract(self, other)

    def __mul__(self, k: int) -> "Ciphertext":
        return scalar_mul(self, k)


def keygen(rng: Optional[Any] = None) -> KeyPair:
    """Generate a fresh keypair ([ECHC] Algorithm 1 / [ECFHE] Algorithm 8's
    non-bootstrap-key portion -- see `bootstrap`'s docstring for why this
    module does not generate a separate "bootstrap key": the paper's own
    Algorithm 5 uses it only to decrypt, so it is the private key under
    another name). Leave ``rng`` unset outside tests."""
    priv = PrivateKey(random_nonzero_below(CURVE_ORDER, rng))
    return KeyPair(private=priv, public=priv.public_key())


def encrypt(pk: PublicKey, m: int, rng: Optional[Any] = None) -> Ciphertext:
    """Encrypt integer ``m`` (may be negative) under ``pk``. Leave ``rng``
    unset outside tests."""
    m = operator.index(m)  # rejects floats instead of silently truncating
    r = random_nonzero_below(CURVE_ORDER, rng)
    return Ciphertext._from_points(_base_mul(r), _add(_mul(pk._point, r), _base_mul(m)), pk)


def _check_same_key(a: Ciphertext, b: Ciphertext) -> None:
    if a.public is not None and b.public is not None and a.public != b.public:
        raise ValueError("cannot combine ciphertexts encrypted under different public keys")


def add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: ``Dec(add(Enc(x), Enc(y))) == x + y``."""
    _check_same_key(a, b)
    return Ciphertext._from_points(_add(a._p1, b._p1), _add(a._p2, b._p2), a.public or b.public)


def negate(a: Ciphertext) -> Ciphertext:
    """Homomorphic negation: ``Dec(negate(Enc(x))) == -x``."""
    return Ciphertext._from_points(_neg(a._p1), _neg(a._p2), a.public)


def subtract(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic subtraction: ``Dec(subtract(Enc(x), Enc(y))) == x - y``."""
    _check_same_key(a, b)
    return add(a, negate(b))


def scalar_mul(a: Ciphertext, k: int) -> Ciphertext:
    """Multiply a ciphertext by a *known public* integer ``k``.

    This is the only multiplicative capability this module provides -- see
    the module docstring's point 2 for why ciphertext-times-ciphertext
    multiplication (what [ECFHE]'s Theorem 8 attempts) is not implemented.
    ``k`` must be public: this operation is not private with respect to
    ``k``, only with respect to the plaintext ``a`` encrypts.
    """
    k = operator.index(k)
    return Ciphertext._from_points(_mul(a._p1, k), _mul(a._p2, k), a.public)


def multiply(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Ciphertext-times-ciphertext multiplication -- NOT implemented.

    [ECFHE]'s Theorem 8 defines this via ``sigma^-1(e_n(sigma(U),
    sigma(V)))``, where the Weil pairing ``e_n`` outputs an element of
    ``mu_n`` (a root of unity in a field extension) but ``sigma^-1`` is
    only defined on ``Z_n1 x Z_n2``. That is a domain mismatch in the
    source construction, not an implementation gap on this module's part --
    see the module docstring's point 2. For genuine multiplication of two
    secret values, use the interactive Beaver-triple protocol in
    :mod:`tokenis.crypto.no_key_delegation`. Raises unconditionally so a
    caller expecting this capability gets an explanation instead of
    silently wrong output.
    """
    raise NotImplementedError(
        "ciphertext x ciphertext multiplication is not implemented: the "
        "source construction ([ECFHE] Theorem 8) does not type-check -- "
        "see tokenis.crypto.ec_fhe's module docstring, point 2. Use "
        "scalar_mul() for multiplication by a known plaintext integer, or "
        "tokenis.crypto.no_key_delegation for interactive multiplication of "
        "two secret values."
    )


class Decryptor:
    """Wraps a private key with a cached baby-step table for repeated
    decryption in a bounded plaintext range ``[-max_value, max_value]``.

    The table (``O(sqrt(max_value))`` points) is built once. Each
    `decrypt` then performs a fixed number of giant steps -- see the module
    docstring for why it does not stop at the first match.
    """

    def __init__(self, sk: PrivateKey, max_value: int = DEFAULT_MAX_VALUE):
        if max_value <= 0:
            raise ValueError("max_value must be positive")
        self._sk = sk
        self._public = sk.public_key()
        self.max_value = max_value
        self._m = 1 + math.isqrt(max_value)
        self._giant = _neg(_base_mul(self._m))
        self._table: Dict[bytes, int] = {}
        generator = _base_mul(1)
        point: _Point = None
        for j in range(self._m + 1):
            self._table[_encode(point)] = j
            point = _add(point, generator)

    def __repr__(self) -> str:
        return f"Decryptor(max_value={self.max_value})"

    def __reduce__(self) -> Any:
        raise TypeError("refusing to pickle or copy a Decryptor (it holds a private key)")

    def decrypt(self, ct: Ciphertext) -> int:
        """Recover the integer plaintext, or raise :class:`ValueError` if it
        lies outside ``[-max_value, max_value]`` or ``ct`` was encrypted
        under a different key."""
        if ct.public is not None and ct.public != self._public:
            raise ValueError("ciphertext was not encrypted under this key's matching public key")
        m_point = _add(ct._p2, _neg(_mul(ct._p1, self._sk.scalar)))
        positive = self._search(m_point)
        negative = self._search(_neg(m_point))
        if positive is not None:
            return positive
        if negative is not None:
            return -negative
        raise ValueError(
            f"plaintext not found in range [-{self.max_value}, {self.max_value}]; "
            "increase max_value or check that the ciphertext/key are correct"
        )

    def _search(self, target: _Point) -> Optional[int]:
        """Find non-negative ``m <= max_value`` with ``m*G == target``.
        Always walks all ``m + 1`` giant steps (no early return)."""
        found: Optional[int] = None
        point = target
        for i in range(self._m + 1):
            j = self._table.get(_encode(point))
            if j is not None and found is None:
                candidate = i * self._m + j
                if candidate <= self.max_value:
                    found = candidate
            point = _add(point, self._giant)
        return found


def decrypt(sk: PrivateKey, ct: Ciphertext, max_value: int = DEFAULT_MAX_VALUE) -> int:
    """Convenience one-shot decrypt. Prefer :class:`Decryptor` when
    decrypting many ciphertexts under the same key -- it amortises the
    baby-step table build."""
    return Decryptor(sk, max_value=max_value).decrypt(ct)


# ---------------------------------------------------------------------------
# Elliptic rational numbers -- [RATIONAL] Definitions 4.1-4.4, Theorem 5.1
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EllipticRational:
    """A rational number ``a/b``, per [RATIONAL] Definition 4.1's elliptic
    rational pair ``(a, b)_P := (aP, bP)``.

    This class holds the integers ``a``/``b`` rather than the curve points
    themselves: [RATIONAL]'s own addition law (Definition 4.4,
    ``[a/b] + [c/d] = [(ad+bc)/(bd)]``) computes with ``a, b, c, d`` as
    integers, and there is no way to compute ``ad`` from the points ``aP``
    and ``dP`` alone without solving a discrete log (recovering ``a`` from
    ``aP``) -- exactly the hardness the surrounding scheme relies on. This
    is plaintext-side bookkeeping (an encoding, not itself encrypted); use
    `to_points` to render the ``(aP, bP)`` notation the papers use, and
    `encrypt_rational` to actually protect a value under a key.
    """

    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if self.denominator == 0:
            raise ValueError("denominator must be nonzero")

    def canonical(self) -> "EllipticRational":
        """Reduce to lowest terms with a positive denominator (Algorithm 1
        of [RATIONAL], "Canonical Form Computation")."""
        g = math.gcd(abs(self.numerator), abs(self.denominator))
        n, d = self.numerator // g, self.denominator // g
        if d < 0:
            n, d = -n, -d
        return EllipticRational(n, d)

    def to_points(self) -> Tuple[bytes, bytes]:
        """Render as the ``(aP, bP)`` pair [RATIONAL] Definition 4.1
        notates this value as, with ``P`` the secp256k1 generator and each
        point SEC1-compressed (``b"\\x00"`` for the point at infinity)."""
        return (_encode(_base_mul(self.numerator)), _encode(_base_mul(self.denominator)))

    def __eq__(self, other: object) -> bool:
        """Equivalence per [RATIONAL] Definition 4.2: ``(a,b) ~ (c,d)`` iff
        ``ad == bc`` (the elliptic-curve form is ``adP = bcP``, which is
        this same condition modulo the curve's group order -- see Lemma 4.1
        of that paper)."""
        if not isinstance(other, EllipticRational):
            return NotImplemented
        return self.numerator * other.denominator == self.denominator * other.numerator

    def __hash__(self) -> int:
        c = self.canonical()
        return hash((c.numerator, c.denominator))

    def __add__(self, other: "EllipticRational") -> "EllipticRational":
        """[RATIONAL] Definition 4.4 / Theorem 4.1."""
        return EllipticRational(
            self.numerator * other.denominator + other.numerator * self.denominator,
            self.denominator * other.denominator,
        ).canonical()

    def __neg__(self) -> "EllipticRational":
        return EllipticRational(-self.numerator, self.denominator)

    def __sub__(self, other: "EllipticRational") -> "EllipticRational":
        return self + (-other)

    def to_float(self) -> float:
        return self.numerator / self.denominator

    @classmethod
    def from_float(cls, x: float, max_denominator: int = 10**9) -> "EllipticRational":
        """[ECFHE] Algorithm 2, "optimized mode": a continued-fraction
        convergent approximation (Theorem 5.1(ii)'s bound on denominator
        size). ``fractions.Fraction.limit_denominator`` implements exactly
        this: the best rational approximation with denominator at most
        ``max_denominator``, found via the continued-fraction expansion."""
        frac = Fraction(x).limit_denominator(max_denominator)
        return cls(frac.numerator, frac.denominator)

    @classmethod
    def from_float_fixed_point(cls, x: float, precision: int = DEFAULT_PRECISION) -> "EllipticRational":
        """[ECFHE] Algorithm 2, "standard mode": decimal rounding to
        ``precision`` places (``a = round(x * 10**precision), b =
        10**precision``), per Theorem 5.1(i). Unlike `from_float`'s
        continued-fraction mode, every value produced this way shares the
        same denominator -- the property `encrypt_rational` depends on to
        make addition under encryption meaningful (see its docstring)."""
        scale = 10**precision
        return cls(round(x * scale), scale)


# ---------------------------------------------------------------------------
# Rational-valued encryption -- fixed-point encoding over the integer scheme
# above, plus a literal implementation of [ECFHE] Algorithm 5 (Bootstrap).
# ---------------------------------------------------------------------------


def encrypt_rational(
    pk: PublicKey, x: float, precision: int = DEFAULT_PRECISION, rng: Optional[Any] = None
) -> Ciphertext:
    """Encrypt a real number ``x`` by fixed-point scaling: the numerator of
    ``EllipticRational.from_float_fixed_point(x, precision)`` is encrypted
    with the integer scheme above; the denominator (``10**precision``) is
    *not* encrypted -- it is public and identical for every ciphertext
    produced with the same ``precision``.

    This shared-denominator requirement is what [RATIONAL]'s Theorem 4.1
    (well-definedness of addition, ``[a/b] + [c/d] = [(ad+bc)/(bd)]``)
    reduces to when ``b == d``: ``(ad+bc)/(bd) = (a+c)/b`` exactly, i.e.
    homomorphic addition of the encrypted numerators under a fixed
    denominator gives the encrypted sum. Encrypting numerator *and*
    denominator independently (so two arbitrary rationals could be added
    with mismatched denominators, ``ad+bc``) is not offered, because it
    would need ciphertext-times-plaintext-numerator cross products where
    both operands are encrypted -- exactly the multiplication `multiply()`
    explains is not implemented.
    """
    scaled = EllipticRational.from_float_fixed_point(x, precision)
    return encrypt(pk, scaled.numerator, rng=rng)


def decrypt_rational(
    sk: PrivateKey, ct: Ciphertext, precision: int = DEFAULT_PRECISION, max_value: int = DEFAULT_MAX_VALUE
) -> float:
    """Inverse of `encrypt_rational`: BSGS-recovers the integer numerator
    and divides by the (public, caller-supplied) ``10**precision``."""
    numerator = decrypt(sk, ct, max_value=max_value)
    return numerator / (10**precision)


def bootstrap(
    sk: PrivateKey,
    pk: PublicKey,
    ct: Ciphertext,
    max_value: int = DEFAULT_MAX_VALUE,
    rng: Optional[Any] = None,
) -> Ciphertext:
    """[ECFHE] Algorithm 5, "Precision-Preserving Bootstrap" -- implemented
    literally: Phase 1 ("Decrypt-and-Extract") recovers the plaintext with
    the private key; Phase 2 ("Re-encode with fresh randomness")
    re-encrypts it. Phase 3 (noise/precision *certification* bookkeeping)
    is omitted: this module does not track a running noise budget, so
    there is nothing to certify beyond "this ciphertext now carries fresh
    ElGamal randomness."

    Read this function's signature before using it: it takes the *private*
    key as an argument. That is not an oversight -- it is what the paper's
    own Algorithm 5 specifies ("Partial-Decrypt(ct_noisy, bsk)"). See the
    module docstring's point 3 for what this does and does not achieve: it
    is a decrypt-then-re-encrypt refresh that only the key holder can
    perform, not a noise-refresh an untrusted evaluator could run without
    learning the plaintext. If your use case needs the latter (an
    untrusted party reducing ciphertext noise without seeing the
    plaintext), this function does not provide it, and per the module
    docstring, nothing in the source papers does either.
    """
    plaintext = decrypt(sk, ct, max_value=max_value)
    return encrypt(pk, plaintext, rng=rng)
