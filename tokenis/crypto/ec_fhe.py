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
STILL A REFERENCE INTEGRATION -- READ BEFORE USING FOR REAL SECRETS
--------------------------------------------------------------------------
This is plain-Python, non-constant-time point arithmetic (via the `ecdsa`
package) with no side-channel hardening, no key-management story, and no
independent security review -- on top of source papers that are themselves
unpublished/unreviewed preprints with the specific, demonstrated problems
above. Do not point this at real production data or real secret values.
"""
from __future__ import annotations

import math
import secrets
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Dict, Optional, Tuple

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, PointJacobi

#: Default curve. secp256k1 was chosen for wide availability in the `ecdsa`
#: package used here; nothing about the construction depends on this
#: particular curve, and none of the source papers name a specific curve
#: either (the [ECFHE] paper's "pairing-friendly BN curve, k=12" requirement
#: is for the Weil-pairing tensor product this module does not implement --
#: see the module docstring's point 2).
DEFAULT_CURVE = SECP256k1

#: Default bound on plaintexts (and on sums of plaintexts) that decryption
#: will search for via baby-step-giant-step -- see [ECFHE] Theorem 10.6 and
#: [ECHC] §5.1's "Weil Pairing Computation" analysis, both of which note
#: that recovering an integer from its point representation costs
#: O(sqrt(n)) via baby-step-giant-step or Pollard's rho; this module uses
#: the former. 2**24 (~16.8M) keeps a one-shot decrypt at a fraction of a
#: second and comfortably covers aggregate sums over every corpus in this
#: repository. Callers needing a wider range should construct one
#: `Decryptor` (amortising the table build across many decryptions) with an
#: explicit, larger `max_value`.
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
    """An elliptic-curve additive-ElGamal ciphertext ``(c1, c2) = (r*G,
    r*Pub + m*G)``. In [ECHC]'s notation this is exactly what
    ``(sigma^-1(C1), sigma^-1(C2))`` reduces to (see module docstring).

    Carries the public key it was encrypted under (``public``, compared but
    not hashed) so that combining ciphertexts encrypted under different
    keys fails loudly (see `add`/`subtract`) instead of silently producing
    a ciphertext that decrypts to garbage under either key.
    """

    c1: PointJacobi
    c2: PointJacobi
    public: Optional[PublicKey] = None
    curve: Any = field(default_factory=lambda: DEFAULT_CURVE, compare=False)

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        return add(self, other)

    def __sub__(self, other: "Ciphertext") -> "Ciphertext":
        return subtract(self, other)

    def __mul__(self, k: int) -> "Ciphertext":
        return scalar_mul(self, k)


def keygen(curve=DEFAULT_CURVE, rng: Optional[Any] = None) -> KeyPair:
    """Generate a fresh keypair ([ECHC] Algorithm 1 / [ECFHE] Algorithm 8's
    non-bootstrap-key portion -- see `bootstrap`'s docstring for why this
    module does not generate a separate "bootstrap key": the paper's own
    Algorithm 5 uses it only to decrypt, so it is the private key under
    another name).

    ``rng`` may be a :class:`random.Random`/``numpy.random.Generator``-like
    object exposing ``randrange(n)`` / ``integers(1, n)``; if omitted, the
    stdlib :mod:`secrets` module is used.
    """
    n = _order(curve)
    if rng is None:
        sk = 1 + secrets.randbelow(n - 1)
    elif hasattr(rng, "integers"):  # numpy.random.Generator
        sk = int(rng.integers(1, n))
    else:  # random.Random-like
        sk = rng.randrange(1, n)
    priv = PrivateKey(scalar=sk, curve=curve)
    return KeyPair(private=priv, public=priv.public_key())


def _random_scalar(curve, rng: Optional[Any]) -> int:
    n = _order(curve)
    if rng is None:
        return 1 + secrets.randbelow(n - 1)
    if hasattr(rng, "integers"):
        return int(rng.integers(1, n))
    return rng.randrange(1, n)


def encrypt(pk: PublicKey, m: int, rng: Optional[Any] = None) -> Ciphertext:
    """Encrypt integer ``m`` (may be negative) under ``pk``."""
    curve = pk.curve
    r = _random_scalar(curve, rng)
    c1 = r * curve.generator
    c2 = r * pk.point + m * curve.generator
    return Ciphertext(c1=c1, c2=c2, public=pk, curve=curve)


def _check_same_key(a: Ciphertext, b: Ciphertext) -> None:
    if a.public is not None and b.public is not None and a.public != b.public:
        raise ValueError("cannot combine ciphertexts encrypted under different public keys")


def add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: ``Dec(add(Enc(x), Enc(y))) == x + y``."""
    _check_same_key(a, b)
    return Ciphertext(c1=a.c1 + b.c1, c2=a.c2 + b.c2, public=a.public or b.public, curve=a.curve)


def negate(a: Ciphertext) -> Ciphertext:
    """Homomorphic negation: ``Dec(negate(Enc(x))) == -x``."""
    return Ciphertext(c1=-a.c1, c2=-a.c2, public=a.public, curve=a.curve)


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
    if k == 0:
        return Ciphertext(c1=INFINITY, c2=INFINITY, public=a.public, curve=a.curve)
    return Ciphertext(c1=k * a.c1, c2=k * a.c2, public=a.public, curve=a.curve)


def multiply(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Ciphertext-times-ciphertext multiplication -- NOT implemented.

    [ECFHE]'s Theorem 8 defines this via ``sigma^-1(e_n(sigma(U),
    sigma(V)))``, where the Weil pairing ``e_n`` outputs an element of
    ``mu_n`` (a root of unity in a field extension) but ``sigma^-1`` is
    only defined on ``Z_n1 x Z_n2``. That is a domain mismatch in the
    source construction, not an implementation gap on this module's part --
    see the module docstring's point 2. Raises unconditionally so a caller
    expecting this capability gets an explanation instead of silently
    wrong output.
    """
    raise NotImplementedError(
        "ciphertext x ciphertext multiplication is not implemented: the "
        "source construction ([ECFHE] Theorem 8) does not type-check -- "
        "see tokenis.crypto.ec_fhe's module docstring, point 2. Use "
        "scalar_mul() for multiplication by a known plaintext integer, "
        "which is well-defined and implemented."
    )


class Decryptor:
    """Wraps a private key with a cached baby-step table for repeated
    decryption in a bounded plaintext range ``[-max_value, max_value]``.

    Building the baby-step table is the expensive part of BSGS
    (``O(sqrt(max_value))`` point additions); this class builds it once and
    reuses it for every :meth:`decrypt` call.
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
        if ct.public is not None and ct.public.point != self.sk.public_key().point:
            raise ValueError("ciphertext was not encrypted under this key's matching public key")
        shared = self.sk.scalar * ct.c1
        m_point = ct.c2 + (-shared)

        positive = self._bsgs(m_point)
        if positive is not None:
            return positive
        negative = self._bsgs(-m_point)
        if negative is not None:
            return -negative
        raise ValueError(
            f"plaintext not found in range [-{self.max_value}, {self.max_value}]; "
            "increase max_value or check that the ciphertext/key are correct"
        )

    def _bsgs(self, target) -> Optional[int]:
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

    def to_points(self, generator: Optional[PointJacobi] = None) -> Tuple[PointJacobi, PointJacobi]:
        """Render as the ``(aP, bP)`` pair [RATIONAL] Definition 4.1
        notates this value as."""
        g = generator if generator is not None else DEFAULT_CURVE.generator
        return (self.numerator * g, self.denominator * g)

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
