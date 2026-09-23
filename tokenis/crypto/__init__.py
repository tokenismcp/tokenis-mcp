# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additively-homomorphic encryption primitives, over elliptic-curve
ElGamal (EC-FHE).

See :mod:`tokenis.crypto.ec_fhe` for the reference-integration disclaimer,
and for exactly what this module does and does not implement from the
"EC-FHE" / "elliptic rational number" source papers, before using anything
in this package.
"""

from tokenis.crypto.ec_fhe import (
    Ciphertext,
    Decryptor,
    EllipticRational,
    KeyPair,
    PrivateKey,
    PublicKey,
    add,
    bootstrap,
    decrypt,
    decrypt_rational,
    encrypt,
    encrypt_rational,
    keygen,
    multiply,
    negate,
    scalar_mul,
    subtract,
)

__all__ = [
    "Ciphertext",
    "Decryptor",
    "EllipticRational",
    "KeyPair",
    "PrivateKey",
    "PublicKey",
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
