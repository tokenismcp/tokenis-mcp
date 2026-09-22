# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""The Reveal operation (P2 Definition 15):

    Reveal: (principal, obj, purpose, policy_version) -> (value, audit_record)

Reveal succeeds only if the policy permits it, and it *always* emits an
audit record -- there is no code path that produces a plaintext value
without one. This is the operation P2 §5.3 (W1, "Closure") says every
individually-disclosed plaintext SEALED value must be typed as: "if an
operation can place a plaintext sensitive value in the exposed region, it
is a Reveal and must be typed as one." Aggregate results are a separate,
already-gated disclosure path (P2 §3.5, "Aggregate tools") logged via
:meth:`tokenis.audit.trace.DisclosureTrace.record_aggregate_result` rather
than through this module -- Reveal is specifically for *named individual*
values (an account balance, a customer's contact detail), the case R2's
tool catalogue calls ``disclose_ratio`` / ``disclose_bucket``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from tokenis.audit.trace import AuditRecord, DisclosureTrace


@dataclass(frozen=True)
class RevealObject:
    """What is being revealed: a token, a ciphertext handle, or an
    aggregate descriptor (P2 Definition 15's ``obj``)."""

    ref: str
    kind: str  # "token" | "ciphertext" | "aggregate"


PolicyFn = Callable[[str, RevealObject, str], bool]
"""``(principal, obj, purpose) -> permit?`` -- P2's ``Pi_pi``. Takes no
argument derived from the protected value itself (Proposition 33-style
simulatability, mirrored from P4's admission policy)."""

DecryptFn = Callable[[RevealObject], Any]
"""Resolves a :class:`RevealObject` to its plaintext value. Only called
after the policy has permitted the reveal."""


class RevealDenied(Exception):
    """Raised when a Reveal is attempted and the policy denies it. The
    denial is still logged to the trace before this is raised -- catching
    this exception does not mean the attempt went unrecorded."""


def reveal(
    principal: str,
    obj: RevealObject,
    purpose: str,
    policy_version: str,
    policy_fn: PolicyFn,
    decrypt_fn: DecryptFn,
    trace: DisclosureTrace,
) -> Any:
    """Perform a gated, audited Reveal. Returns the plaintext value on
    success; raises :class:`RevealDenied` (after logging the denial) on
    failure.
    """
    permitted = policy_fn(principal, obj, purpose)
    decision = "permit" if permitted else "deny"
    audit = AuditRecord(
        principal=principal,
        obj_ref=obj.ref,
        purpose=purpose,
        policy_version=policy_version,
        decision=decision,
    )
    if not permitted:
        trace.record_denial(audit)
        raise RevealDenied(
            f"Reveal denied for principal={principal!r} obj={obj.ref!r} purpose={purpose!r}"
        )
    value = decrypt_fn(obj)
    trace.record_reveal(audit, value)
    return value
