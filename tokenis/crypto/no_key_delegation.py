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
STILL A REFERENCE INTEGRATION -- READ BEFORE USING FOR REAL SECRETS
--------------------------------------------------------------------------
Plain-Python, non-constant-time modular arithmetic, no independent security
review. The mathematics here (one-time pads, Beaver triples) is genuinely
standard and correctly applied, which is a different and stronger claim
than for :mod:`tokenis.crypto.ec_fhe`'s other modules -- but "the math is
sound" is still not "this specific implementation has been audited."
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Sequence, Set, Tuple

from tokenis.crypto.ec_fhe import DEFAULT_CURVE


def _default_order() -> int:
    return DEFAULT_CURVE.generator.order()


def _random_scalar(n: int, rng: Optional[Any] = None) -> int:
    if rng is None:
        return secrets.randbelow(n)
    if hasattr(rng, "integers"):  # numpy.random.Generator
        return int(rng.integers(0, n))
    return rng.randrange(0, n)  # random.Random-like


@dataclass(frozen=True)
class MaskedValue:
    """A one-time-pad-masked scalar: ``masked = (value + mask) mod n``.
    This is what the untrusted `Server` role holds -- see [NOKEY] Lemma 6
    and Theorem 27 for why this is *exactly* uniform on Z/nZ and
    independent of ``value``, not merely "hard to invert"."""

    masked: int
    n: int


@dataclass(frozen=True)
class MultiplicationTriple:
    """A Beaver triple ``(u, v, w = u*v mod n)`` over Z/nZ, [NOKEY]
    Definitions 17-18. Input-independent -- generate a pool of these ahead
    of time, before any data arrives, via `Owner.prepare_triple`.

    ``id`` is an opaque, per-``Owner`` unique token `Owner.prepare_triple`
    assigns; `open_multiplication` uses it to enforce that each triple is
    consumed by at most one multiplication (see that function's docstring
    for why reuse is a real, not theoretical, secrecy break)."""

    u: int
    v: int
    w: int
    n: int
    id: int

    @classmethod
    def generate(cls, n: int, id: int, rng: Optional[Any] = None) -> "MultiplicationTriple":
        u = _random_scalar(n, rng)
        v = _random_scalar(n, rng)
        return cls(u=u, v=v, w=(u * v) % n, n=n, id=id)


@dataclass(frozen=True)
class MultiplicationOpening:
    """The ``(e, g)`` pair sent to the `Server` in a masked multiplication
    -- [NOKEY] Construction 19 step 1. Individually and jointly uniform on
    ``(Z/nZ)^2`` and independent of the secret operands (Theorem 28): the
    Server sees only the operands blinded by a triple's uniform factors."""

    e: int
    g: int
    n: int


@dataclass(frozen=True)
class AffineFunctional:
    """A public affine functional ``f(x_1, ..., x_t) = sum(a_i * x_i) + b``
    over Z/nZ -- [NOKEY] eq. (5)."""

    coefficients: Sequence[int]
    intercept: int = 0

    def evaluate(self, xs: Sequence[int], n: int) -> int:
        """Plaintext-domain evaluation (for testing/reference only -- the
        Server never has access to unmasked ``xs``)."""
        total = self.intercept
        for a, x in zip(self.coefficients, xs):
            total += a * x
        return total % n


@dataclass
class Owner:
    """The key-holding, offline/guarded party ([NOKEY] §III.A). Generates
    masks, blinds values before they are sent to a `Server`, and is the
    only party that ever unblinds a result. Never transmits ``n`` alone is
    fine (it is public -- the curve order); nothing else in this class's
    state should leave the Owner's boundary."""

    n: int = field(default_factory=_default_order)
    rng: Optional[Any] = None
    _next_triple_id: int = field(default=0, repr=False)
    _consumed_triple_ids: Set[int] = field(default_factory=set, repr=False)

    def blind(self, value: int) -> Tuple[MaskedValue, int]:
        """One-time-pad-mask a scalar ([NOKEY] Construction 16 step 1 /
        Lemma 6). Returns ``(masked_value_to_send_to_server, mask)`` --
        retain the mask; never send it anywhere."""
        value %= self.n
        mask = _random_scalar(self.n, self.rng)
        return MaskedValue((value + mask) % self.n, self.n), mask

    def unblind(self, masked: MaskedValue, mask: int) -> int:
        """Inverse of `blind`."""
        if masked.n != self.n:
            raise ValueError(
                "MaskedValue.n does not match this Owner's modulus -- it was "
                "likely produced by a different Owner (different curve order "
                "or a caller error), and unblinding it here would silently "
                "produce garbage rather than fail loudly."
            )
        return (masked.masked - mask) % self.n

    def prepare_triple(self) -> MultiplicationTriple:
        """Precompute one Beaver triple ([NOKEY] Definitions 17-18) for a
        future masked multiplication. Triples are input-independent:
        generate a pool of these before data arrives, since each one is
        consumed by exactly one `open_multiplication` call -- see that
        function's docstring for why reuse is enforced, not just advised.
        """
        triple = MultiplicationTriple.generate(self.n, self._next_triple_id, self.rng)
        self._next_triple_id += 1
        return triple


# ---------------------------------------------------------------------------
# Pi_lin: non-interactive affine evaluation -- [NOKEY] Construction 16.
# ---------------------------------------------------------------------------


def delegate_affine(
    owner: Owner, functional: AffineFunctional, values: Sequence[int]
) -> Tuple[List[MaskedValue], int]:
    """Owner's side, steps 1: blind every input value and compute the
    public correction the Owner will subtract from the Server's answer.
    Returns ``(masked_values_to_send_to_server, correction)`` -- send only
    the first element to the Server."""
    n = owner.n
    masked_values: List[MaskedValue] = []
    correction = 0
    for a, x in zip(functional.coefficients, values):
        mv, mask = owner.blind(x)
        masked_values.append(mv)
        correction = (correction + a * mask) % n
    return masked_values, correction


def evaluate_affine_masked(
    functional: AffineFunctional, masked_values: Sequence[MaskedValue]
) -> int:
    """Server's side, step 2 -- runs entirely on `masked_values` and the
    public `functional`; the Server never sees an unmasked input."""
    n = masked_values[0].n
    total = functional.intercept
    for a, mv in zip(functional.coefficients, masked_values):
        total += a * mv.masked
    return total % n


def unblind_affine_result(owner: Owner, masked_result: int, correction: int) -> int:
    """Owner's side, step 3: recover ``f(values)`` from the Server's
    masked answer and the correction computed in `delegate_affine`."""
    return (masked_result - correction) % owner.n


# ---------------------------------------------------------------------------
# Pi_mult: Beaver-triple masked multiplication -- [NOKEY] Construction 19.
# ---------------------------------------------------------------------------


def open_multiplication(
    owner: Owner, s: int, s_prime: int, triple: MultiplicationTriple
) -> MultiplicationOpening:
    """Owner's side, step 1: blind the two secret operands by a fresh
    triple's factors.

    Each triple must be used for exactly one multiplication -- this is not
    a stylistic preference. Reusing ``(u, v)`` across two products lets a
    Server that observes both openings ``(e1, g1)`` and ``(e2, g2)``
    recover ``s1 - s2 = e1 - e2`` and ``s1' - s2' = g1 - g2`` outright,
    breaking exactly the independence [NOKEY]'s Theorem 28 depends on
    (its proof requires a *fresh* uniform ``(u, v)``, drawn once). This
    function enforces the requirement rather than merely documenting it:
    every `MultiplicationTriple` carries the id `Owner.prepare_triple`
    assigned it, and a second call with the same triple raises.
    """
    if triple.n != owner.n:
        raise ValueError("MultiplicationTriple.n does not match this Owner's modulus")
    if triple.id in owner._consumed_triple_ids:
        raise ValueError(
            "this MultiplicationTriple has already been consumed by a "
            "previous open_multiplication() call -- reusing a Beaver "
            "triple across two products breaks the secrecy proof (see "
            "this function's docstring); call Owner.prepare_triple() to "
            "get a fresh one for each multiplication."
        )
    owner._consumed_triple_ids.add(triple.id)
    n = owner.n
    e = (s - triple.u) % n
    g = (s_prime - triple.v) % n
    return MultiplicationOpening(e, g, n)


def combine_multiplication(opening: MultiplicationOpening) -> int:
    """Server's side, step 2: the one nonlinear term the Server is allowed
    to compute, ``e * g`` -- a product of two quantities it can see."""
    return (opening.e * opening.g) % opening.n


def reconstruct_multiplication(
    triple: MultiplicationTriple, opening: MultiplicationOpening, eg: int
) -> int:
    """Owner's side, step 3 / [NOKEY] eq. (6): reconstruct ``s * s' mod n``
    from the triple (known only to the Owner) and the Server's returned
    ``e*g``. See that paper's Theorem 24 for the algebraic identity this
    implements: ``s*s' = w + e*v + g*u + e*g (mod n)``."""
    n = triple.n
    return (triple.w + opening.e * triple.v + opening.g * triple.u + eg) % n


# ---------------------------------------------------------------------------
# Pi_boot: blinded bootstrapping -- [NOKEY] Construction 20.
# ---------------------------------------------------------------------------


def blinded_bootstrap(
    owner: Owner,
    masked_x: MaskedValue,
    mask: int,
    refresh: Callable[[int], int] = lambda x: x,
) -> Tuple[MaskedValue, int]:
    """Refresh a Server-held masked value's randomness. The Server sends
    its masked value back; the *Owner* -- never the Server -- removes the
    mask, applies ``refresh`` (identity by default; a caller with an
    actual noise-accumulating encoding, e.g. real-valued approximation
    error, would pass a function that re-derives a fresh, low-error
    representation of the same value), and returns a newly masked value
    plus its new mask. This is [NOKEY] Construction 20, and it is why
    `blinded_bootstrap` -- unlike `tokenis.crypto.ec_fhe.bootstrap` --
    genuinely can be invoked by or on behalf of an untrusted party without
    that party learning the plaintext: the Server only ever sees masked
    values before *and* after, never the value `refresh` operates on.
    """
    x = owner.unblind(masked_x, mask)
    refreshed = refresh(x) % owner.n
    return owner.blind(refreshed)
