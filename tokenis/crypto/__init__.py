# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additively-homomorphic encryption primitives (Paillier).

See :mod:`tokenis.crypto.paillier` for the reference-integration
disclaimer before using anything in this package.
"""

from tokenis.crypto.paillier import (
    Ciphertext,
    Decryptor,
    KeyPair,
    PrivateKey,
    PublicKey,
    add,
    decrypt,
    encrypt,
    keygen,
    negate,
    scalar_mul,
    subtract,
)

__all__ = [
    "Ciphertext",
    "Decryptor",
    "KeyPair",
    "PrivateKey",
    "PublicKey",
    "add",
    "decrypt",
    "encrypt",
    "keygen",
    "negate",
    "scalar_mul",
    "subtract",
]
