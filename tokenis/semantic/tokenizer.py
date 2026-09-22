# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Scope-confined tokenization (P2 §3.2-3.3, Definition 1) and attribute
generalization hierarchies (used by the ``group_by``/``aggregate`` tools and
by the D2 "generalization" defense measured in P3 §8).

A **protection class** (P2 §3.2) is assigned to every attribute in the
schema and determines the form it takes once it leaves the protected
domain:

* ``OPEN``   -- released verbatim; public by construction.
* ``TOKEN``  -- released as a deterministic token that preserves identity
  (equal values -> equal tokens) but not content.
* ``SEALED`` -- never released as an individual value; participates only in
  ciphertext computation (see :mod:`tokenis.gateway.compute`) and in
  aggregates that cross the boundary through an explicit
  :func:`~tokenis.gateway.reveal.reveal` (P2 Definition 15).

The tokenizer here is a **scope-confined pseudorandom function** in the
sense of P2 Definition 1: for a fixed scope, equal inputs map to equal
outputs and the mapping is indistinguishable from a random injection to a
computationally-bounded observer who does not hold the key. It is built
from HMAC-SHA256, which is a standard PRF; truncating its output to
``token_bits`` (default 128) satisfies the ``ell = omega(log(kappa))``
security-parameter condition of Remark 2 for any realistic attribute
domain, and 128 bits keeps the format-preserving-tokenization trap
described in that remark (colliding on a 30-40 bit token) far out of reach.

Per Definition 1, **the scope must always include the attribute name** --
this is what keeps distinct attributes' token spaces independent, so that
(for example) a customer name and a supplier name never collide into the
same token even if their string values happen to match. This module
enforces that structurally: callers cannot tokenize a bare ``(scope, value)``
pair, only ``(attribute, scope_id, value)``, and the attribute name is
mixed into the PRF input with unambiguous, length-prefixed framing (so
``attribute="ab", scope_id="c"`` can never collide with
``attribute="a", scope_id="bc"``).
"""
from __future__ import annotations

import hashlib
import hmac
from enum import Enum
from typing import Callable, Dict, List, Optional


class ProtectionClass(Enum):
    """P2 §3.2: the protection class of a schema attribute."""

    OPEN = "open"
    TOKEN = "token"
    SEALED = "sealed"


def _frame(*parts: bytes) -> bytes:
    """Length-prefix each part so concatenation is unambiguous (no
    delimiter-collision between e.g. attribute name and scope id)."""
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


class ScopedTokenizer:
    """A scope-confined tokenizer (P2 Definition 1).

    Example
    -------
    >>> tok = ScopedTokenizer(key=b"32-byte-or-longer-secret-key!!!!")
    >>> scope = tok.make_scope(tenant="acme", epoch=1)
    >>> tok.tokenize("customer_name", scope, "Acme Corp")
    '...128-bit hex...'
    >>> tok.tokenize("customer_name", scope, "Acme Corp")  # deterministic
    '...same value...'
    """

    def __init__(self, key: bytes, token_bits: int = 128):
        if len(key) < 16:
            raise ValueError(
                "tokenizer key must be at least 16 bytes; this is a PRF key, "
                "generate it with e.g. secrets.token_bytes(32)"
            )
        if not (0 < token_bits <= 256):
            raise ValueError("token_bits must be in (0, 256]")
        self._key = key
        self.token_bits = token_bits

    @staticmethod
    def make_scope(tenant: str, epoch: int, session: Optional[str] = None) -> str:
        """Build a scope identifier from tenant + epoch (+ optional session).

        The *epoch* is the D1 defense's dial (P3 §8, "epoch-scoped tokens"):
        a scope that changes every session (``session`` included, effectively
        ``epoch == session_id``) gives session-scoped tokens (E=1 in the
        paper's notation -- maximum unlinkability, zero cross-session
        analytics); a scope fixed for the tenant's lifetime gives permanently
        stable tokens (E=infinity -- maximum utility, maximum linkability).
        P3's own measurement (§8, D1) is that this dial is a poor
        security/utility trade on its own -- re-identification is driven by
        the disclosure profile (schema leakage), not by token linkage -- so
        treat this as a knob to tune for legitimate cross-session analytics
        requirements, not as the gateway's primary defense.
        """
        parts = [f"tenant={tenant}", f"epoch={epoch}"]
        if session is not None:
            parts.append(f"session={session}")
        return "|".join(parts)

    def tokenize(self, attribute: str, scope: str, value: str) -> str:
        """Deterministically tokenize ``value`` of ``attribute`` within
        ``scope``. Equal ``(attribute, scope, value)`` triples always
        produce the same token; the token reveals nothing about ``value``
        beyond this equality pattern to an observer without ``key``.
        """
        mac = hmac.new(self._key, digestmod=hashlib.sha256)
        mac.update(
            _frame(attribute.encode("utf-8"), scope.encode("utf-8"), value.encode("utf-8"))
        )
        digest = mac.digest()
        n_bytes = (self.token_bits + 7) // 8
        as_int = int.from_bytes(digest[:n_bytes], "big")
        as_int >>= n_bytes * 8 - self.token_bits
        return format(as_int, f"0{(self.token_bits + 3) // 4}x")

    def tokenize_row(
        self, attribute_scopes: Dict[str, str], row: Dict[str, str]
    ) -> Dict[str, str]:
        """Tokenize every attribute named in ``attribute_scopes`` (a map of
        attribute -> scope) present in ``row``, leaving other keys
        untouched. Convenience wrapper over :meth:`tokenize` for gateway
        code that needs to shape a whole record at once.
        """
        out = dict(row)
        for attribute, scope in attribute_scopes.items():
            if attribute in row:
                out[attribute] = self.tokenize(attribute, scope, str(row[attribute]))
        return out


class GeneralizationHierarchy:
    """A per-attribute chain of coarsening maps, indexed by generalization
    level ``g`` (P3 §5, Figure 2 / Appendix B). Level 0 is the identity
    (finest / no generalization); each subsequent level maps a value to a
    coarser bucket, e.g. ``locality -> region -> nation`` or
    ``five-digit industry subclass -> two-digit division``.

    This is the mechanism the D2 defense (P3 §8) sweeps: coarsening
    quasi-identifiers is, per that paper's own measurement, the single most
    effective lever against schema-driven re-identification (far more
    effective than session-scoped tokens), at the cost of collapsing how
    many distinct groups a legitimate analyst can still address.
    """

    def __init__(self, levels: Dict[str, List[Callable[[str], str]]]):
        """``levels`` maps attribute name -> ordered list of coarsening
        functions, one per non-zero generalization level (level 0 is always
        the identity and need not be supplied explicitly)."""
        self._levels = levels

    def max_level(self, attribute: str) -> int:
        return len(self._levels.get(attribute, []))

    def generalize(self, attribute: str, value: str, level: int) -> str:
        if level <= 0:
            return value
        chain = self._levels.get(attribute, [])
        if level > len(chain):
            raise ValueError(
                f"attribute {attribute!r} has only {len(chain)} generalization "
                f"levels above the identity, requested level {level}"
            )
        result = value
        for fn in chain[:level]:
            result = fn(result)
        return result

    def generalize_row(self, row: Dict[str, str], level: int) -> Dict[str, str]:
        return {
            attribute: self.generalize(attribute, value, level) if attribute in self._levels else value
            for attribute, value in row.items()
        }
