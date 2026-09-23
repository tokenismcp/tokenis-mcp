# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The compute module (P2 §3.4, ``G_com``): evaluates aggregate functions
over ``SEALED`` attributes homomorphically, so that the store never holds
and the infrastructure operator never observes a plaintext sensitive value
(P2 Theorem 29). Its adversary is the infrastructure operator, ``A_infra``.

Every method here returns a :class:`~tokenis.crypto.ec_fhe.Ciphertext`
(or, for ``COUNT``, a plain ``int`` -- a set size is public information, not
a function of protected values: P4 §5.2 exempts it from the admission
audit's rowspace basis for exactly this reason). **Decryption happens only
at the disclosure boundary**, after the admission-control layer
(:mod:`tokenis.gateway.admission`) has admitted the call -- see
:mod:`tokenis.gateway.reveal` and P2 Definition 16 (the disclosure trace
covers both explicit ``Reveal`` outputs and the plaintext results of
admitted aggregate calls).

Variance needs a second moment. The EC-FHE scheme this repository uses (see
:mod:`tokenis.crypto.ec_fhe`) has no ciphertext-times-ciphertext
multiplicative homomorphism either -- see that module's docstring for why
-- so ``VAR`` requires a
precomputed, separately-encrypted "squared value" column, populated at
ingest time (when the data owner still holds the plaintext) -- see
:meth:`AggregateEngine.ingest`. This mirrors P2 §3.3's note that a scheme
"supporting a bounded multiplicative depth" would let ``VAR`` be computed
directly; P1 (not included in this repository) is presumably that scheme.
Final variance arithmetic (``E[x^2] - E[x]^2``) is plain post-processing
over two already-decrypted aggregate values, not an operation on hidden
data, so it happens after both sums cross the boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from tokenis.crypto.ec_fhe import Ciphertext, PublicKey, encrypt


@dataclass
class Predicate:
    """A predicate over *public* (OPEN/TOKEN-class) attributes, matching
    P2 §3.5's requirement that the aggregate predicate language is written
    over the exposed vocabulary only -- it cannot name a plaintext value of
    a TOKEN- or SEALED-class attribute, because the model host has never
    seen one. Represented as an explicit matcher function over a row's
    public fields for reference-implementation simplicity; a production
    gateway would compile a structured filter expression to this form and
    validate it against the schema's protection classes before evaluation.
    """

    name: str
    matcher: Callable[[Dict[str, object]], bool]

    def matches(self, public_row: Dict[str, object]) -> bool:
        return self.matcher(public_row)


@dataclass
class _Record:
    record_id: str
    public_fields: Dict[str, object]
    sealed_ciphertext: Ciphertext
    sealed_sq_ciphertext: Optional[Ciphertext] = None


@dataclass
class AggregateEngine:
    """Holds one SEALED column's ciphertexts alongside each record's public
    fields (used only for predicate matching -- the engine never reads the
    plaintext SEALED value after :meth:`ingest`), and evaluates aggregate
    functions over caller-chosen predicates.
    """

    public_key: PublicKey
    _records: List[_Record] = field(default_factory=list)

    def ingest(
        self,
        record_id: str,
        public_fields: Dict[str, object],
        sealed_value: int,
        with_square: bool = False,
    ) -> None:
        """Encrypt and store one record. ``sealed_value`` is plaintext here
        because ingest is, definitionally, the one place the data owner's
        own plaintext enters the gateway (P2 §3.1: the data owner holds the
        plaintext database ``D``) -- after this call returns, only
        ciphertext is retained.
        """
        ct = encrypt(self.public_key, sealed_value)
        sq_ct = encrypt(self.public_key, sealed_value * sealed_value) if with_square else None
        self._records.append(
            _Record(
                record_id=record_id,
                public_fields=dict(public_fields),
                sealed_ciphertext=ct,
                sealed_sq_ciphertext=sq_ct,
            )
        )

    def __len__(self) -> int:
        return len(self._records)

    def matching_ids(self, predicate: Predicate) -> List[str]:
        """The characteristic set ``C_phi`` of a predicate -- public
        information, since it depends only on public fields."""
        return [r.record_id for r in self._records if predicate.matches(r.public_fields)]

    def count(self, predicate: Predicate) -> int:
        """``COUNT`` -- a set size, public, not homomorphically computed."""
        return len(self.matching_ids(predicate))

    def sum(self, predicate: Predicate) -> Ciphertext:
        """``SUM`` over the sealed column, homomorphically. Raises if the
        predicate matches no records (an empty sum has no well-defined
        ciphertext under this construction -- callers should check
        :meth:`count` first, which is exactly what the admission layer's
        minimum-query-set-size rule (P4 D1) already requires them to do)."""
        matched = [r.sealed_ciphertext for r in self._records if predicate.matches(r.public_fields)]
        if not matched:
            raise ValueError("SUM over an empty query set is undefined")
        total = matched[0]
        for ct in matched[1:]:
            total = total + ct
        return total

    def sum_of_squares(self, predicate: Predicate) -> Ciphertext:
        """``SUM`` over the precomputed squared-value column -- see the
        module docstring for why ``VAR`` needs this. Requires the engine to
        have been populated with ``with_square=True``."""
        matched = [
            r.sealed_sq_ciphertext for r in self._records if predicate.matches(r.public_fields)
        ]
        if not matched:
            raise ValueError("SUM over an empty query set is undefined")
        if any(ct is None for ct in matched):
            raise ValueError(
                "sum_of_squares requested but records were ingested without "
                "with_square=True"
            )
        total = matched[0]
        for ct in matched[1:]:
            total = total + ct  # type: ignore[operator]
        return total  # type: ignore[return-value]

    def public_fields_of(self, record_id: str) -> Dict[str, object]:
        for r in self._records:
            if r.record_id == record_id:
                return dict(r.public_fields)
        raise KeyError(record_id)


def average(sealed_sum_plaintext: int, count: int) -> float:
    """``AVG = SUM / COUNT``, computed *after* ``SUM`` has been decrypted at
    the boundary -- ``COUNT`` is already public, so this is plain
    arithmetic over already-disclosed quantities, not a homomorphic
    operation. P4 §5.2 warns explicitly against exempting AVG from the
    admission audit on the theory that it is "just" a derived quantity:
    callers of this function must still route the decrypted ``SUM`` through
    the same admission audit as a bare SUM query would take (see
    :mod:`tokenis.gateway.admission`, first-moment basis) -- this function
    performs no admission check itself.
    """
    if count <= 0:
        raise ValueError("count must be positive")
    return sealed_sum_plaintext / count


def variance(sum_plaintext: int, sum_sq_plaintext: int, count: int) -> float:
    """``VAR = E[x^2] - E[x]^2``, from two already-decrypted sums."""
    if count <= 0:
        raise ValueError("count must be positive")
    mean = sum_plaintext / count
    mean_sq = sum_sq_plaintext / count
    return mean_sq - mean * mean
