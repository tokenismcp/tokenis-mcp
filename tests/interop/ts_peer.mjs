// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
// The TypeScript side of tests/test_interop.py. Reads a JSON request on
// stdin, performs the requested operations with the TypeScript SDK, and
// writes a JSON response. All binary values are hex.
import { readFileSync } from "node:fs";

const sdk = await import(new URL("../../sdk/typescript/dist/index.js", import.meta.url).href);

const hex = (b) => Buffer.from(b).toString("hex");
const bytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));

const req = JSON.parse(readFileSync(0, "utf8"));
const res = {};

// 1. Decrypt a ciphertext produced by Python, with a key exported by Python.
const sk = sdk.PrivateKey.fromBytes(bytes(req.secret_key));
const pk = sdk.PublicKey.fromBytes(bytes(req.public_key));
res.public_key_matches = sk.publicKey().equals(pk);
res.decrypted = String(sdk.decrypt(sk, sdk.Ciphertext.fromBytesWithKey(bytes(req.ciphertext), pk)));

// 2. Encrypt values and add them homomorphically, for Python to decrypt.
res.ciphertext = hex(sdk.encrypt(pk, BigInt(req.encrypt_a)).add(sdk.encrypt(pk, BigInt(req.encrypt_b))).toBytes());

// 3. Fixed-point encoding must agree across languages.
res.fixed_point = req.fixed_point.map(([x, p]) => String(sdk.fixedPointEncode(x, p)));

// 4. Act as the untrusted delegation server: evaluate an affine function on
//    masked values produced by a Python Owner, and do the server's half of a
//    masked multiplication.
const masked = req.masked_values.map((h) => sdk.MaskedValue.fromBytes(bytes(h)));
const f = { coefficients: req.coefficients.map(BigInt), intercept: BigInt(req.intercept) };
res.affine_result = hex(sdk.evaluateAffineMasked(f, masked).toBytes());
res.eg = String(sdk.combineMultiplication(sdk.MultiplicationOpening.fromBytes(bytes(req.opening))));

process.stdout.write(JSON.stringify(res));
