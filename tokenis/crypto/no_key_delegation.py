# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""No-key delegation of EC-FHE-encoded values to an untrusted party.

Implements the protocol from:

  [NOKEY] C. Lee, "No-Key Delegation of Elliptic-Curve Fully Homomorphic
          Encryption: Unconditional Server-Side Confidentiality and
          Post-Quantum Data-Leakage Resistance" (J1729 Labs, 2026).

This is a genuinely different, and genuinely sound, piece of work from the
three source papers :mod:`tokenis.crypto.ec_fhe` documents specific problems
in. [NOKEY] does not touch the broken part of that construction: its
multiplication protocol (Beaver triples over Z/nZ, [NOKEY] Definitions
17-18) is built on the one well-defined multiplicative structure the source
papers provide -- the cyclic-subgroup transport ``rho_R`` -- and never goes
near the Weil-pairing "tensor product" that :func:`tokenis.crypto.ec_fhe.
multiply` refuses to implement. And it does not claim an untrusted party can
bootstrap without the key: its blinded-bootstrap step (`blinded_bootstrap`
below, [NOKEY] Construction 20) explicitly requires the *Owner* -- the key
holder -- to remove the mask, refresh, and re-mask; the untrusted `Server`
role never sees plaintext or holds key material at any point.

What this module actually gives you
------------------------------------
Delegation, not stronger encryption. An `Owner` holds all key material and
never transmits it. A `Server` holds only one-time-pad-*masked* scalars
(elements of Z/nZ, the ring the Owner's EC-FHE encoding lives in via
`tokenis.crypto.ec_fhe`'s EllipticRational / the curve's cyclic subgroup)
and evaluates public affine functions directly, or products interactively
via precomputed Beaver triples. [NOKEY]'s Theorems 27-29 and 31 show: every
individual message to the Server, and the whole transcript across a
circuit, is *exactly* uniform on its group and *statistically independent*
of the plaintext (this is a literal one-time pad, Lemma 6 in that paper --
not a computational hardness argument). Because independent distributions
stay independent under arbitrary post-processing -- including quantum
post-processing, via the trace-distance and Holevo-bound arguments
[NOKEY] Theorem 32 -- this means: an adversary who fully compromises the
`Server`, even one running Shor's algorithm on a working quantum computer,
learns *nothing* about the plaintext, because there is no functional
relationship between what the Server holds and the plaintext for any
algorithm, classical or quantum, to exploit. That is a real, provable
guarantee, and it is a different (much stronger, at the delegation
boundary) claim than "ECDLP is hard."

What this does NOT do:

- It does not make :mod:`tokenis.crypto.ec_fhe`'s underlying scheme
  post-quantum. If the *Owner* is compromised, its key material and
  plaintexts are exactly as exposed as before -- this module changes *who*
  is exposed (moving the ECDLP-dependent computation off the
  always-online, breach-prone Server and onto the offline, guarded Owner),
  not whether ECDLP itself resists a quantum attacker.
- It is not non-interactive. Unlike "encrypt once, hand it to the Server,
  never talk to it again," every multiplication (`MultiplicationTriple` /
  `open_multiplication` / `combine_multiplication` /
  `reconstruct_multiplication`) and every noise-refresh
  (`blinded_bootstrap`) needs a round trip through the Owner. This is not
  an implementation shortcut: [NOKEY] §IX(c) explains it is the accepted,
  provably-necessary cost of *unconditional* (rather than computational)
  security for two-party multiplication, citing Beaver 1991 and Ben-Or/
  Goldwasser/Wigderson 1988 -- both real, foundational secure-computation
  results.
- It is not wired into :mod:`tokenis.gateway.service` or the MCP tool
  surface. This module is a standalone, independently-testable primitive;
  integrating it into the gateway's trust model (i.e. actually running the
  aggregate-compute engine as a separate untrusted "Server" process) is a
  larger architectural change than "add a crypto module" and is left for a
  future change that discusses that tradeoff explicitly, consistent with
  how the EC-FHE-vs-Paillier swap earlier in this repository's history
  should have been handled the first time.

--------------------------------------------------------------------------
IMPLEMENTATION
--------------------------------------------------------------------------
The protocol runs in Rust (``crates/tokenis-core``, via ``tokenis._core``),
the same code the TypeScript SDK uses. Values are integers mod the
secp256k1 group order ``n`` (`MODULUS`). Beyond the paper, the API makes
misuse impossible rather than merely documented: a `Mask`, `Correction` or
`MultiplicationTriple` is an opaque handle to zeroing Rust memory that is
emptied by the operation using it (a second use raises), and each is bound
to the `Owner` that created it. The mathematics (one-time pads, Beaver
triples) is standard; this particular integration has not been
independently audited.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, NoReturn, Sequence, Tuple

from tokenis import _core
from tokenis._core import (
    Correction,
    Mask,
    MaskedValue,
    MultiplicationOpening,
    MultiplicationTriple,
    TokenisCryptoError,
)
from tokenis.crypto.ec_fhe import CURVE_ORDER

__all__ = [
    "MODULUS",
    "AffineFunctional",
    "Correction",
    "Mask",
    "MaskedValue",
    "MultiplicationOpening",
    "MultiplicationTriple",
    "Owner",
    "TokenisCryptoError",
    "blinded_bootstrap",
    "combine_multiplication",
    "delegate_affine",
    "evaluate_affine_masked",
    "open_multiplication",
    "reconstruct_multiplication",
    "unblind_affine_result",
]

#: Values are integers mod this (secp256k1's group order).
MODULUS = CURVE_ORDER


def _to_bytes(x: int) -> bytes:
    return (x % MODULUS).to_bytes(32, "big")


def _to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(frozen=True)
class AffineFunctional:
    """A public affine functional ``f(x_1, ..., x_t) = sum(a_i * x_i) + b``
    over Z/nZ -- [NOKEY] eq. (5). Coefficients must fit in 64 bits."""

    coefficients: Sequence[int]
    intercept: int = 0

    def evaluate(self, xs: Sequence[int]) -> int:
        """Plaintext reference evaluation (tests only -- the server never
        sees unmasked inputs)."""
        return (sum(a * x for a, x in zip(self.coefficients, xs)) + self.intercept) % MODULUS


class Owner:
    """The key-holding party ([NOKEY] §III.A). Generates and consumes every
    secret; hands the server only `MaskedValue` and `MultiplicationOpening`
    objects."""

    n = MODULUS

    def __init__(self) -> None:
        self._inner = _core.Owner()

    def __repr__(self) -> str:
        return repr(self._inner)

    def __reduce__(self) -> NoReturn:
        raise TypeError("refusing to pickle or copy an Owner")

    def blind(self, value: int) -> Tuple[MaskedValue, Mask]:
        """One-time-pad-mask ``value`` ([NOKEY] Lemma 6). Send the
        `MaskedValue`; keep the `Mask`."""
        return self._inner.blind(_to_bytes(value))

    def unblind(self, masked: MaskedValue, mask: Mask) -> int:
        """Remove (and consume) ``mask``."""
        return _to_int(self._inner.unblind(masked, mask))

    def prepare_triple(self) -> MultiplicationTriple:
        """Precompute one Beaver triple ([NOKEY] Definitions 17-18)."""
        return self._inner.prepare_triple()


# -- Pi_lin: affine evaluation, [NOKEY] Construction 16 ---------------------


def delegate_affine(
    owner: Owner, functional: AffineFunctional, values: Sequence[int]
) -> Tuple[List[MaskedValue], Correction]:
    """Owner, step 1: mask the inputs. Send the list; keep the correction."""
    return owner._inner.delegate_affine(
        list(functional.coefficients), [_to_bytes(v) for v in values]
    )


def evaluate_affine_masked(
    functional: AffineFunctional, masked_values: Sequence[MaskedValue]
) -> MaskedValue:
    """Server, step 2: evaluate on masked inputs only."""
    return _core.evaluate_affine_masked(
        list(functional.coefficients), _to_bytes(functional.intercept), list(masked_values)
    )


def unblind_affine_result(owner: Owner, masked_result: MaskedValue, correction: Correction) -> int:
    """Owner, step 3: recover ``f(values)`` (consumes ``correction``)."""
    return _to_int(owner._inner.unblind_affine(masked_result, correction))


# -- Pi_mult: Beaver-triple multiplication, [NOKEY] Construction 19 ---------


def open_multiplication(
    owner: Owner, s: int, s_prime: int, triple: MultiplicationTriple
) -> MultiplicationOpening:
    """Owner, step 1: blind both operands by the triple. A triple can be
    opened once; a second opening raises (it would reveal ``s1 - s2``)."""
    return owner._inner.open_multiplication(_to_bytes(s), _to_bytes(s_prime), triple)


def combine_multiplication(opening: MultiplicationOpening) -> int:
    """Server, step 2: ``e * g`` -- the one product the server may compute."""
    return _to_int(_core.combine_multiplication(opening))


def reconstruct_multiplication(
    owner: Owner, triple: MultiplicationTriple, opening: MultiplicationOpening, eg: int
) -> int:
    """Owner, step 3 / [NOKEY] eq. (6): ``s*s' = w + e*v + g*u + e*g``
    (consumes ``triple``)."""
    return _to_int(owner._inner.reconstruct_multiplication(triple, opening, _to_bytes(eg)))


# -- Pi_boot: blinded bootstrapping, [NOKEY] Construction 20 ----------------


def blinded_bootstrap(
    owner: Owner,
    masked_x: MaskedValue,
    mask: Mask,
    refresh: Callable[[int], int] = lambda x: x,
) -> Tuple[MaskedValue, Mask]:
    """The owner (never the server) unmasks, applies ``refresh``, and
    re-masks with a fresh pad; the server sees only masked values before
    and after. Consumes ``mask``."""
    return owner.blind(refresh(owner.unblind(masked_x, mask)))
