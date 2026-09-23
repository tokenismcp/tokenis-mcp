// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
/**
 * Tokenis cryptographic SDK for TypeScript/JavaScript.
 *
 * Every operation runs in the Rust core (`crates/tokenis-core`) compiled to
 * WebAssembly -- the same implementation, and the same byte formats, as the
 * Python SDK. Secret material (private keys, masks, corrections, Beaver
 * triples) stays in WebAssembly memory, is zeroed when freed, and is freed
 * automatically when its handle is garbage-collected (or explicitly with
 * `.free()`). Randomness comes from `crypto.getRandomValues`.
 *
 * - {@link encrypt} / {@link Decryptor}: additive EC-ElGamal over secp256k1.
 *   Plaintexts are `bigint` in the signed 64-bit range.
 * - {@link Owner} and friends: no-key delegation (one-time-pad masking and
 *   Beaver-triple multiplication) over integers mod {@link CURVE_ORDER}.
 *
 * @packageDocumentation
 */
import { createRequire } from "node:module";

import type * as Wasm from "../wasm/tokenis_wasm.js";

const wasm = createRequire(import.meta.url)("../wasm/tokenis_wasm.js") as typeof Wasm;

/* Each class is exported as both a value (constructors, static methods,
 * `instanceof`) and a type of the same name. */
export const PrivateKey = wasm.PrivateKey;
export type PrivateKey = Wasm.PrivateKey;
export const PublicKey = wasm.PublicKey;
export type PublicKey = Wasm.PublicKey;
export const Ciphertext = wasm.Ciphertext;
export type Ciphertext = Wasm.Ciphertext;
export const Decryptor = wasm.Decryptor;
export type Decryptor = Wasm.Decryptor;
export const MaskedValue = wasm.MaskedValue;
export type MaskedValue = Wasm.MaskedValue;
export const MultiplicationOpening = wasm.MultiplicationOpening;
export type MultiplicationOpening = Wasm.MultiplicationOpening;
export type Mask = Wasm.Mask;
export type Correction = Wasm.Correction;
export type MultiplicationTriple = Wasm.MultiplicationTriple;

/** Order of the secp256k1 group; delegation values are integers mod this. */
export const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Default decryptable range: plaintexts in [-2^24, 2^24]. */
export const DEFAULT_MAX_VALUE = 1n << 24n;

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

function toI64(m: bigint | number): bigint {
  if (typeof m === "number") {
    if (!Number.isSafeInteger(m)) {
      throw new RangeError(`plaintext ${m} is not a safe integer; pass a bigint`);
    }
    m = BigInt(m);
  }
  if (m < I64_MIN || m > I64_MAX) {
    throw new RangeError("plaintext must fit in a signed 64-bit integer");
  }
  return m;
}

/** A freshly generated key pair. */
export interface KeyPair {
  readonly privateKey: Wasm.PrivateKey;
  readonly publicKey: Wasm.PublicKey;
}

/** Generate a key pair from `crypto.getRandomValues`. */
export function keygen(): KeyPair {
  const privateKey = wasm.PrivateKey.generate();
  return { privateKey, publicKey: privateKey.publicKey() };
}

/** Encrypt an integer plaintext. */
export function encrypt(pk: Wasm.PublicKey, m: bigint | number): Wasm.Ciphertext {
  return wasm.encrypt(pk, toI64(m));
}

/** One-shot decrypt; prefer a long-lived {@link Decryptor} for many values. */
export function decrypt(
  sk: Wasm.PrivateKey,
  ct: Wasm.Ciphertext,
  maxValue: bigint = DEFAULT_MAX_VALUE,
): bigint {
  const decryptor = new wasm.Decryptor(sk, maxValue);
  try {
    return decryptor.decrypt(ct);
  } finally {
    decryptor.free();
  }
}

/** `round(x * 10^precision)`, half away from zero (same as the Python SDK). */
export function fixedPointEncode(x: number, precision: number): bigint {
  return wasm.fixedPointEncode(x, precision);
}

/** Encrypt a real number by fixed-point scaling. */
export function encryptFixedPoint(pk: Wasm.PublicKey, x: number, precision = 6): Wasm.Ciphertext {
  return wasm.encrypt(pk, fixedPointEncode(x, precision));
}

// ---------------------------------------------------------------------------
// No-key delegation
// ---------------------------------------------------------------------------

function mod(x: bigint): bigint {
  const r = x % CURVE_ORDER;
  return r < 0n ? r + CURVE_ORDER : r;
}

/** 32-byte big-endian encoding of `x mod n`. */
export function toBytes32(x: bigint): Uint8Array {
  let v = mod(x);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Inverse of {@link toBytes32}. */
export function fromBytes32(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function concat32(values: readonly bigint[]): Uint8Array {
  const out = new Uint8Array(values.length * 32);
  values.forEach((v, i) => out.set(toBytes32(v), i * 32));
  return out;
}

function coefficientArray(coefficients: readonly (bigint | number)[]): BigInt64Array {
  return BigInt64Array.from(coefficients.map(toI64));
}

/** A public affine functional `sum(a_i * x_i) + intercept` mod n. */
export interface AffineFunctional {
  readonly coefficients: readonly (bigint | number)[];
  readonly intercept?: bigint;
}

/**
 * The key-holding party of the no-key delegation protocol. It hands an
 * untrusted server only {@link MaskedValue}s and
 * {@link MultiplicationOpening}s, whose distribution is independent of the
 * plaintext. Masks, corrections and triples are one-time and bound to the
 * owner that created them; reuse throws.
 */
export class Owner {
  readonly #inner = new wasm.Owner();

  /** Mask `value`. Send `masked`; keep `mask`. */
  blind(value: bigint): { masked: Wasm.MaskedValue; mask: Wasm.Mask } {
    const blinded = this.#inner.blind(toBytes32(value));
    try {
      return { masked: blinded.takeMasked(), mask: blinded.takeMask() };
    } finally {
      blinded.free();
    }
  }

  /** Remove (and consume) `mask`. */
  unblind(masked: Wasm.MaskedValue, mask: Wasm.Mask): bigint {
    return fromBytes32(this.#inner.unblind(masked, mask));
  }

  /** Mask each input of `f`. Send `masked`; keep `correction`. */
  delegateAffine(
    f: AffineFunctional,
    values: readonly bigint[],
  ): { masked: Wasm.MaskedValue[]; correction: Wasm.Correction } {
    const delegation = this.#inner.delegateAffine(coefficientArray(f.coefficients), concat32(values));
    try {
      return { masked: delegation.maskedValues(), correction: delegation.takeCorrection() };
    } finally {
      delegation.free();
    }
  }

  /** Recover `f(values)` from the server's result (consumes `correction`). */
  unblindAffine(result: Wasm.MaskedValue, correction: Wasm.Correction): bigint {
    return fromBytes32(this.#inner.unblindAffine(result, correction));
  }

  /** Precompute one Beaver triple. */
  prepareTriple(): Wasm.MultiplicationTriple {
    return this.#inner.prepareTriple();
  }

  /** Blind `s` and `t` by `triple`. A triple can be opened once. */
  openMultiplication(s: bigint, t: bigint, triple: Wasm.MultiplicationTriple): Wasm.MultiplicationOpening {
    return this.#inner.openMultiplication(toBytes32(s), toBytes32(t), triple);
  }

  /** Recover `s * t` from the server's `e * g` (consumes `triple`). */
  reconstructMultiplication(
    triple: Wasm.MultiplicationTriple,
    opening: Wasm.MultiplicationOpening,
    eg: bigint,
  ): bigint {
    return fromBytes32(this.#inner.reconstructMultiplication(triple, opening, toBytes32(eg)));
  }

  /** Blinded bootstrap: unmask, apply `refresh`, re-mask with a fresh pad. */
  refresh(
    masked: Wasm.MaskedValue,
    mask: Wasm.Mask,
    refresh: (x: bigint) => bigint = (x) => x,
  ): { masked: Wasm.MaskedValue; mask: Wasm.Mask } {
    return this.blind(refresh(this.unblind(masked, mask)));
  }

  /** Release the owner's WebAssembly memory now rather than at GC. */
  free(): void {
    this.#inner.free();
  }
}

/** Server side: evaluate `f` on masked inputs. */
export function evaluateAffineMasked(
  f: AffineFunctional,
  masked: readonly Wasm.MaskedValue[],
): Wasm.MaskedValue {
  const flat = new Uint8Array(masked.length * 32);
  masked.forEach((m, i) => flat.set(m.toBytes(), i * 32));
  return wasm.evaluateAffineMasked(coefficientArray(f.coefficients), toBytes32(f.intercept ?? 0n), flat);
}

/** Server side: the one product it may compute, `e * g`. */
export function combineMultiplication(opening: Wasm.MultiplicationOpening): bigint {
  return fromBytes32(wasm.combineMultiplication(opening));
}
