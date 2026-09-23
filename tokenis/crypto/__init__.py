# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Additively-homomorphic encryption primitives, over elliptic-curve
ElGamal (EC-FHE).

See :mod:`tokenis.crypto.ec_fhe` for the reference-integration disclaimer,
and for exactly what this module does and does not implement from the
"EC-FHE" / "elliptic rational number" source papers, before using anything
in this package.

:mod:`tokenis.crypto.no_key_delegation` (not re-exported here -- import it
directly) adds an optional delegation layer on top: an interactive protocol
that lets an untrusted party evaluate affine functions and, via Beaver
triples, products, while provably learning nothing about the plaintext,
without ever holding key material. See that module's docstring for what it
does and does not provide, and how it relates to (and avoids) the specific
problems documented in :mod:`tokenis.crypto.ec_fhe`.
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
