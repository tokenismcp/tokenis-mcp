// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  CURVE_ORDER,
  Ciphertext,
  MAX_SUPPORTED_RANGE,
  MAX_TABLE_SIZE,
  Decryptor,
  PrivateKey,
  PublicKey,
  decrypt,
  encrypt,
  encryptFixedPoint,
  fixedPointEncode,
  keygen,
} from "../src/index.ts";

const { privateKey, publicKey } = keygen();
const decryptor = new Decryptor(privateKey, 100_000n);

describe("EC-ElGamal", () => {
  test("roundtrip including zero and negatives", () => {
    for (const m of [0n, 1n, -1n, 42n, -17n, 100_000n, -100_000n]) {
      assert.equal(decryptor.decrypt(encrypt(publicKey, m)), m);
    }
  });

  test("homomorphic operations", () => {
    const a = encrypt(publicKey, 30);
    const b = encrypt(publicKey, 12);
    assert.equal(decryptor.decrypt(a.add(b)), 42n);
    assert.equal(decryptor.decrypt(a.sub(b)), 18n);
    assert.equal(decryptor.decrypt(a.neg()), -30n);
    assert.equal(decryptor.decrypt(a.mul(-3n)), -90n);
    assert.equal(decryptor.decrypt(a.mul(0n)), 0n);
  });

  test("encryption is randomized", () => {
    assert.notDeepEqual(encrypt(publicKey, 5).toBytes(), encrypt(publicKey, 5).toBytes());
  });

  test("out of range throws", () => {
    assert.throws(() => decryptor.decrypt(encrypt(publicKey, 100_001n)), /outside/);
  });

  test("key mismatch detected", () => {
    const other = keygen();
    assert.throws(() => encrypt(publicKey, 1).add(encrypt(other.publicKey, 1)), /different keys/);
    assert.throws(() => decrypt(other.privateKey, encrypt(publicKey, 1)), /different keys/);
  });

  test("plaintext bounds enforced before reaching WASM", () => {
    assert.throws(() => encrypt(publicKey, 1.5), RangeError);
    assert.throws(() => encrypt(publicKey, 1n << 63n), RangeError);
  });

  test("wire format roundtrip, including identity components", () => {
    const ct = encrypt(publicKey, 77);
    const back = Ciphertext.fromBytesWithKey(ct.toBytes(), publicKey);
    assert.ok(back.equals(ct));
    assert.deepEqual(encrypt(publicKey, 1).mul(0n).toBytes(), Uint8Array.from([1, 0, 0]));
    assert.ok(PublicKey.fromBytes(publicKey.toBytes()).equals(publicKey));
  });

  test("malformed input rejected", () => {
    const good = encrypt(publicKey, 7).toBytes();
    assert.throws(() => Ciphertext.fromBytes(Uint8Array.from([2, ...good.slice(1)])), /version/);
    assert.throws(() => Ciphertext.fromBytes(good.slice(0, -1)));
    assert.throws(() => Ciphertext.fromBytes(Uint8Array.from([...good, 0])));
    assert.throws(() => PublicKey.fromBytes(Uint8Array.from([0])), /infinity/);
    const offCurve = [...Array(255).keys()]
      .map((x) => Uint8Array.from([2, ...new Array(31).fill(0), x + 1]))
      .find((b) => {
        try {
          PublicKey.fromBytes(b);
          return false;
        } catch {
          return true;
        }
      });
    assert.ok(offCurve);
  });

  test("private keys: redacted, validated, exportable", () => {
    assert.equal(String(privateKey), "PrivateKey(<redacted>)");
    assert.throws(() => PrivateKey.fromBytes(new Uint8Array(32)));
    const n = new Uint8Array(32);
    let v = CURVE_ORDER;
    for (let i = 31; i >= 0; i--) {
      n[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    assert.throws(() => PrivateKey.fromBytes(n));
    const restored = PrivateKey.fromBytes(privateKey.exportSecretBytes());
    assert.ok(restored.publicKey().equals(publicKey));
  });

  test("refresh rerandomizes", () => {
    const ct = encrypt(publicKey, 123);
    const fresh = decryptor.refresh(ct);
    assert.equal(decryptor.decrypt(fresh), 123n);
    assert.ok(!fresh.equals(ct));
  });

  test("fixed point matches the Rust/Python encoder", () => {
    assert.equal(fixedPointEncode(12.34567, 2), 1235n);
    assert.equal(fixedPointEncode(-2.5, 0), -3n); // half away from zero
    assert.throws(() => fixedPointEncode(Number.NaN, 2));
    const sum = encryptFixedPoint(publicKey, 1.5, 3).add(encryptFixedPoint(publicKey, 2.25, 3));
    assert.equal(decryptor.decrypt(sum), 3750n);
  });

  test("64-bit overflow throws instead of wrapping", () => {
    const tooBig = 2n ** 64n + 5n;
    assert.throws(() => encrypt(publicKey, tooBig), RangeError);
    assert.throws(() => encrypt(publicKey, 2 ** 60), RangeError); // unsafe number
    // The raw classes are guarded in the core too, not just in this wrapper.
    assert.throws(() => encrypt(publicKey, 7n).mul(2n ** 64n + 3n), /64-bit/);
    assert.throws(() => new Decryptor(privateKey, 2n ** 64n + 5n), /64-bit/);
  });

  test("table size trades memory for speed", () => {
    const big = Decryptor.withTableSize(privateKey, 1n << 32n, 1n << 16n);
    assert.equal(big.tableSize, 1n << 16n);
    for (const m of [1n << 32n, -(1n << 32n), 1_234_567_890n]) {
      assert.equal(big.decrypt(encrypt(publicKey, m)), m);
    }
    big.free();
    assert.throws(() => new Decryptor(privateKey, MAX_SUPPORTED_RANGE + 1n), /max_value/);
    assert.throws(() => Decryptor.withTableSize(privateKey, 100n, MAX_TABLE_SIZE + 1n), /table_size/);
  });

  test("property: add/sub/mul are homomorphic on random inputs", () => {
    for (let i = 0; i < 40; i++) {
      const x = BigInt(Math.floor(Math.random() * 40_000) - 20_000);
      const y = BigInt(Math.floor(Math.random() * 40_000) - 20_000);
      const k = BigInt(Math.floor(Math.random() * 9) - 4);
      const a = encrypt(publicKey, x);
      const b = encrypt(publicKey, y);
      assert.equal(decryptor.decrypt(a.add(b)), x + y);
      assert.equal(decryptor.decrypt(a.sub(b)), x - y);
      assert.equal(decryptor.decrypt(a.mul(k)), x * k);
    }
  });
});
