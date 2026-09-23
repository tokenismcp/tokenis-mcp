// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, test } from "node:test";

import {
  CURVE_ORDER,
  MaskedValue,
  Owner,
  combineMultiplication,
  evaluateAffineMasked,
  fromBytes32,
  toBytes32,
} from "../src/index.ts";

const randomValue = (): bigint => fromBytes32(randomBytes(32)) % CURVE_ORDER;

function multiply(owner: Owner, s: bigint, t: bigint): bigint {
  const triple = owner.prepareTriple();
  const opening = owner.openMultiplication(s, t, triple);
  return owner.reconstructMultiplication(triple, opening, combineMultiplication(opening));
}

describe("no-key delegation", () => {
  test("blind/unblind roundtrip; negatives are mod n", () => {
    const owner = new Owner();
    const { masked, mask } = owner.blind(42n);
    assert.equal(owner.unblind(masked, mask), 42n);
    const neg = owner.blind(-5n);
    assert.equal(owner.unblind(neg.masked, neg.mask), CURVE_ORDER - 5n);
  });

  test("masks are one-time and bound to their owner", () => {
    const owner = new Owner();
    const { masked, mask } = owner.blind(1n);
    owner.unblind(masked, mask);
    assert.ok(mask.consumed);
    assert.throws(() => owner.unblind(masked, mask), /already been used/);
    const foreign = new Owner().blind(2n);
    assert.throws(() => owner.unblind(foreign.masked, foreign.mask), /different Owner/);
  });

  test("masked values of one plaintext never repeat", () => {
    const owner = new Owner();
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) seen.add(Buffer.from(owner.blind(7n).masked.toBytes()).toString("hex"));
    assert.equal(seen.size, 300);
  });

  test("affine delegation", () => {
    const owner = new Owner();
    const f = { coefficients: [2, 3, -1], intercept: 5n };
    const { masked, correction } = owner.delegateAffine(f, [10n, 20n, 7n]);
    const result = evaluateAffineMasked(f, masked);
    // Regression: passing handles across the WASM boundary must not
    // invalidate the caller's objects.
    assert.equal(masked[0]?.toBytes().length, 32);
    assert.equal(owner.unblindAffine(result, correction), 2n * 10n + 3n * 20n - 7n + 5n);
    assert.throws(() => owner.unblindAffine(result, correction), /already been used/);
  });

  test("masked multiplication, triple reuse rejected", () => {
    const owner = new Owner();
    assert.equal(multiply(owner, 123n, 456n), 123n * 456n);
    const triple = owner.prepareTriple();
    owner.openMultiplication(1n, 2n, triple);
    assert.throws(() => owner.openMultiplication(3n, 4n, triple), /already consumed/);
    assert.throws(() => new Owner().openMultiplication(1n, 2n, owner.prepareTriple()), /different Owner/);
  });

  test("blinded bootstrap refreshes the pad", () => {
    const owner = new Owner();
    const first = owner.blind(99n);
    const second = owner.refresh(first.masked, first.mask, (x) => x + 1n);
    assert.notDeepEqual(second.masked.toBytes(), first.masked.toBytes());
    assert.equal(owner.unblind(second.masked, second.mask), 100n);
  });

  test("value encodings", () => {
    assert.equal(fromBytes32(toBytes32(-1n)), CURVE_ORDER - 1n);
    assert.throws(() => MaskedValue.fromBytes(new Uint8Array(32).fill(0xff)));
  });

  test("property: delegation identities on random 256-bit inputs", () => {
    const owner = new Owner();
    for (let i = 0; i < 40; i++) {
      const [a, b] = [randomValue(), randomValue()];
      assert.equal(multiply(owner, a, b), (a * b) % CURVE_ORDER);
      const c = BigInt(Math.floor(Math.random() * 2 ** 40)) - 2n ** 39n;
      const f = { coefficients: [c, 1n] };
      const { masked, correction } = owner.delegateAffine(f, [a, b]);
      const expected = (((c * a + b) % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER;
      assert.equal(owner.unblindAffine(evaluateAffineMasked(f, masked), correction), expected);
    }
  });
});
