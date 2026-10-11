# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Small helpers for handling untrusted values safely."""
from __future__ import annotations

import hmac


def equal(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality for values an attacker may have chosen.

    ``hmac.compare_digest`` raises ``TypeError`` for a ``str`` holding
    non-ASCII characters, which turned a forged cookie, query parameter or
    audit-trail field into a crash instead of a plain "no". Comparing the
    UTF-8 bytes gives the right answer for any text (lone surrogates
    included, as JSON can carry them).
    """
    left = a if isinstance(a, bytes) else str(a).encode("utf-8", "surrogatepass")
    right = b if isinstance(b, bytes) else str(b).encode("utf-8", "surrogatepass")
    return hmac.compare_digest(left, right)
