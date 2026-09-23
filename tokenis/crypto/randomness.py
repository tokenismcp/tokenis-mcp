# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Single source of randomness for :mod:`tokenis.crypto`.

Every secret this package draws -- private keys, ElGamal encryption
randomness, one-time-pad masks, Beaver triples -- goes through
`random_below`. By default that is the operating system's CSPRNG
(:mod:`secrets`). Callers may pass their own ``rng`` for reproducible tests
and research runs, but anything other than a :class:`random.SystemRandom`
triggers `InsecureRandomnessWarning`: a seeded :class:`random.Random` is a
Mersenne Twister whose entire future output is recoverable from 624
observed outputs, so a predictable mask or encryption nonce is not a
weaker version of the security guarantee -- it is no guarantee at all
(a one-time pad with a predictable pad is plaintext).

Production code should never pass ``rng``. To make that a hard rule rather
than a convention, escalate the warning to an error::

    import warnings
    from tokenis.crypto.randomness import InsecureRandomnessWarning
    warnings.simplefilter("error", InsecureRandomnessWarning)
"""
from __future__ import annotations

import random
import secrets
import warnings
from typing import Any, Optional


class InsecureRandomnessWarning(UserWarning):
    """A caller supplied a non-cryptographic random source for secret
    material. See this module's docstring."""


def random_below(n: int, rng: Optional[Any] = None) -> int:
    """A uniform integer in ``[0, n)``.

    ``rng`` must expose ``randrange`` (the :class:`random.Random` API).
    """
    if n <= 0:
        raise ValueError("n must be positive")
    if rng is None:
        return secrets.randbelow(n)
    if not isinstance(rng, random.SystemRandom):
        warnings.warn(
            f"non-cryptographic random source {type(rng).__name__} used for "
            "secret material; acceptable only for reproducible tests/research, "
            "never in production (see tokenis.crypto.randomness)",
            InsecureRandomnessWarning,
            stacklevel=3,
        )
    return int(rng.randrange(n))


def random_nonzero_below(n: int, rng: Optional[Any] = None) -> int:
    """A uniform integer in ``[1, n)``."""
    return 1 + random_below(n - 1, rng)
