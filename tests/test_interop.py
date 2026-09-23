# Copyright 2026 4Chains Inc.
# SPDX-License-Identifier: Apache-2.0
"""Cross-language interoperability: Python and TypeScript SDKs exchange real
bytes. Python holds the keys (and is the delegation Owner); the TypeScript
peer (tests/interop/ts_peer.mjs) decrypts with an exported key, encrypts
for Python, and acts as the untrusted delegation server.

Skipped unless Node and the built TypeScript SDK are available; CI's
`interop` job builds both."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tokenis.crypto.ec_fhe import Decryptor, encrypt, fixed_point_encode, keygen
from tokenis.crypto.no_key_delegation import (
    AffineFunctional,
    MaskedValue,
    Owner,
    delegate_affine,
    open_multiplication,
    reconstruct_multiplication,
    unblind_affine_result,
)

ROOT = Path(__file__).resolve().parent.parent
PEER = ROOT / "tests" / "interop" / "ts_peer.mjs"
SDK_BUILD = ROOT / "sdk" / "typescript" / "dist" / "index.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not SDK_BUILD.exists(),
    reason="needs node and a built sdk/typescript (npm run build:wasm && npm run build)",
)

FIXED_POINT_CASES = [[12.34567, 2], [-2.5, 0], [2.5, 0], [0.125, 2], [-1.005, 2], [3.0, 6]]


def test_python_and_typescript_interoperate():
    keys = keygen()
    owner = Owner()
    f = AffineFunctional(coefficients=[3, -2, 7], intercept=11)
    values = [100, 250, 42]
    masked, correction = delegate_affine(owner, f, values)
    triple = owner.prepare_triple()
    opening = open_multiplication(owner, 1234, 5678, triple)

    request = {
        "secret_key": keys.private.export_secret_bytes().hex(),
        "public_key": keys.public.to_bytes().hex(),
        "ciphertext": encrypt(keys.public, -31337).to_bytes().hex(),
        "encrypt_a": 40,
        "encrypt_b": 2,
        "fixed_point": FIXED_POINT_CASES,
        "masked_values": [m.to_bytes().hex() for m in masked],
        "coefficients": list(f.coefficients),
        "intercept": f.intercept,
        "opening": opening.to_bytes().hex(),
    }
    proc = subprocess.run(
        ["node", str(PEER)],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    response = json.loads(proc.stdout)

    # TypeScript decrypted Python's ciphertext with Python's exported key.
    assert response["public_key_matches"] is True
    assert int(response["decrypted"]) == -31337

    # Python decrypts TypeScript's homomorphic sum.
    from tokenis.crypto.ec_fhe import Ciphertext

    ts_ct = Ciphertext.from_bytes(bytes.fromhex(response["ciphertext"]), public=keys.public)
    assert Decryptor(keys.private).decrypt(ts_ct) == 42

    # Fixed-point encoding is bit-identical across languages.
    assert [int(v) for v in response["fixed_point"]] == [
        fixed_point_encode(x, p) for x, p in FIXED_POINT_CASES
    ]

    # The TypeScript server's affine result unblinds to f(values) in Python.
    server_result = MaskedValue.from_bytes(bytes.fromhex(response["affine_result"]))
    assert unblind_affine_result(owner, server_result, correction) == f.evaluate(values)

    # ... and its half of the masked multiplication completes in Python.
    product = reconstruct_multiplication(owner, triple, opening, int(response["eg"]))
    assert product == 1234 * 5678
