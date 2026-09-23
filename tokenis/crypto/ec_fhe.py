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
IMPLEMENTATION AND SECURITY PROPERTIES
--------------------------------------------------------------------------
Every operation in this module runs in Rust (``crates/tokenis-core``,
exposed here as the ``tokenis._core`` extension module); this file only
adapts it to Python. The same core backs the TypeScript SDK (compiled to
WebAssembly), so all three languages share one implementation and one wire
format. See that crate's documentation for the full list; in brief:

- Curve arithmetic is RustCrypto's ``k256`` (audited by NCC Group in 2023),
  whose secret-dependent operations are constant-time by design.
- Private keys live in Rust memory that is zeroed when the key is dropped.
  Python holds an opaque handle: there is no ``.scalar`` attribute, keys
  and decryptors refuse pickling and copying, and ``repr`` is redacted.
  ``PrivateKey.export_secret_bytes()`` exists for key backup/escrow, and is
  the one deliberate way a secret becomes Python memory.
- Randomness always comes from the operating system CSPRNG inside Rust;
  the Python API has no parameter through which a caller can inject a
  weaker source (the Rust crate's ``*_with(rng)`` variants, meant for
  deterministic tests, are not bound). A failing OS RNG raises
  ``TokenisCryptoError`` instead of aborting.
- Points parsed from bytes are validated on-curve and must be canonical
  (compressed) encodings.
- Decryption walks the same number of baby-step-giant-step steps
  whatever the plaintext, in bounded memory (``Decryptor(sk, max_value,
  table_size)``: 8 bytes per table entry), and releases the GIL while it
  does. Its memory access pattern still depends on the plaintext, so it is
  not constant-time against a co-located cache-timing attacker.
- Integer plaintexts must fit in a signed 64-bit integer.

Not provided: hardware-backed key storage (HSM/KMS), and an independent
audit of this integration. The source papers remain unreviewed preprints
with the problems listed above.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Tuple

from tokenis._core import (
    DEFAULT_MAX_VALUE,
    MAX_SUPPORTED_RANGE,
    MAX_TABLE_SIZE,
    Ciphertext,
    Decryptor,
    PrivateKey,
    PublicKey,
    TokenisCryptoError,
    base_point_multiple,
    fixed_point_encode,
)
from tokenis._core import encrypt as _encrypt

__all__ = [
    "CURVE_NAME",
    "CURVE_ORDER",
    "DEFAULT_MAX_VALUE",
    "DEFAULT_PRECISION",
    "MAX_SUPPORTED_RANGE",
    "MAX_TABLE_SIZE",
    "Ciphertext",
    "Decryptor",
    "EllipticRational",
    "KeyPair",
    "PrivateKey",
    "PublicKey",
    "TokenisCryptoError",
    "add",
    "bootstrap",
    "decrypt",
    "decrypt_rational",
    "encrypt",
    "encrypt_rational",
    "keygen",
    "multiply",
    "negate",
    "scalar_mul",
    "subtract",
]

#: The curve every key and ciphertext in this module lives on.
CURVE_NAME = "secp256k1"

#: Order of secp256k1's generator (the size of the scalar field Z/nZ).
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Default fixed-point scaling exponent for `encrypt_rational` /
#: `decrypt_rational`: real numbers are encoded as integer numerators over
#: an implicit, public denominator of 10**DEFAULT_PRECISION, matching
#: [ECFHE] Algorithm 2's "standard mode" -- the mode whose denominator is
#: fixed and shared across values, which is what addition under encryption
#: requires (see `encrypt_rational`'s docstring).
DEFAULT_PRECISION = 6


@dataclass(frozen=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


def keygen() -> KeyPair:
    """Generate a fresh keypair from the OS CSPRNG ([ECHC] Algorithm 1 /
    [ECFHE] Algorithm 8's non-bootstrap-key portion -- see `bootstrap` for
    why there is no separate "bootstrap key")."""
    private = PrivateKey.generate()
    return KeyPair(private=private, public=private.public_key())


def encrypt(pk: PublicKey, m: int) -> Ciphertext:
    """Encrypt integer ``m`` (may be negative; must fit in 64 bits)."""
    return _encrypt(pk, m)


def add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic addition: ``Dec(add(Enc(x), Enc(y))) == x + y``."""
    return a + b


def subtract(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic subtraction: ``Dec(subtract(Enc(x), Enc(y))) == x - y``."""
    return a - b


def negate(a: Ciphertext) -> Ciphertext:
    """Homomorphic negation: ``Dec(negate(Enc(x))) == -x``."""
    return -a


def scalar_mul(a: Ciphertext, k: int) -> Ciphertext:
    """Multiply a ciphertext by a *known public* integer ``k``.

    This is the only multiplicative capability of the encryption scheme --
    see the module docstring's point 2. ``k`` must be public: this is not
    private with respect to ``k``, only with respect to the plaintext.
    """
    return a * k


def multiply(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Ciphertext-times-ciphertext multiplication -- NOT implemented.

    [ECFHE]'s Theorem 8 defines this via ``sigma^-1(e_n(sigma(U),
    sigma(V)))``, where the Weil pairing ``e_n`` outputs an element of
    ``mu_n`` but ``sigma^-1`` is only defined on ``Z_n1 x Z_n2`` -- a
    domain mismatch in the source construction (module docstring, point 2).
    For multiplying two secret values, use the interactive Beaver-triple
    protocol in :mod:`tokenis.crypto.no_key_delegation`.
    """
    raise NotImplementedError(
        "ciphertext x ciphertext multiplication is not implemented: the "
        "source construction ([ECFHE] Theorem 8) does not type-check -- "
        "see tokenis.crypto.ec_fhe's module docstring, point 2. Use "
        "scalar_mul() for a known plaintext factor, or "
        "tokenis.crypto.no_key_delegation to multiply two secret values."
    )


def decrypt(sk: PrivateKey, ct: Ciphertext, max_value: int = DEFAULT_MAX_VALUE) -> int:
    """One-shot decrypt. Prefer a long-lived :class:`Decryptor` when
    decrypting many ciphertexts -- it builds its baby-step table once."""
    return Decryptor(sk, max_value).decrypt(ct)


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
        return (
            base_point_multiple((self.numerator % CURVE_ORDER).to_bytes(32, "big")),
            base_point_multiple((self.denominator % CURVE_ORDER).to_bytes(32, "big")),
        )

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
        make addition under encryption meaningful (see its docstring).

        Rounds half away from zero, identically in every Tokenis SDK
        (Python's built-in ``round`` would round half to even and disagree
        with the Rust and TypeScript encoders)."""
        return cls(fixed_point_encode(x, precision), 10**precision)


# ---------------------------------------------------------------------------
# Rational-valued encryption -- fixed-point encoding over the integer scheme
# above, plus a literal implementation of [ECFHE] Algorithm 5 (Bootstrap).
# ---------------------------------------------------------------------------


def encrypt_rational(pk: PublicKey, x: float, precision: int = DEFAULT_PRECISION) -> Ciphertext:
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
    return encrypt(pk, fixed_point_encode(x, precision))


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
    if pk != sk.public_key():
        raise ValueError("bootstrap: pk does not match sk")
    return Decryptor(sk, max_value).refresh(ct)
