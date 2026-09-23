// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Tokenis cryptographic core.
//!
//! The single implementation of every cryptographic operation Tokenis
//! performs, shared by the Python SDK (via PyO3, `crates/tokenis-py`) and the
//! TypeScript SDK (via WebAssembly, `crates/tokenis-wasm`):
//!
//! - [`elgamal`]: additive EC-ElGamal over secp256k1 -- what the "ECHC"/
//!   "EC-FHE" source papers' encryption formulas actually compute (see
//!   `tokenis/crypto/ec_fhe.py` for the paper-by-paper analysis).
//! - [`delegation`]: the no-key delegation protocol (one-time-pad masking and
//!   Beaver-triple multiplication) from "No-Key Delegation of Elliptic-Curve
//!   Fully Homomorphic Encryption" (J1729 Labs, 2026).
//!
//! # Security properties
//!
//! - Group and scalar-field arithmetic is RustCrypto's `k256`, audited by NCC
//!   Group (2023) and designed so that secret-dependent operations run in
//!   constant time. Like `k256` itself, this assumes a processor with
//!   constant-time integer multiplication.
//! - Secret material -- private keys, encryption randomness, one-time-pad
//!   masks, Beaver-triple factors, affine corrections, delegated plaintext
//!   [`delegation::Value`]s -- lives only in types that zero their memory on
//!   drop and redact themselves from `Debug`. One-time secrets sit behind a
//!   heap pointer, so moving one never leaves a copy of its bytes behind.
//!   Decrypted `i64` plaintexts returned to a caller are ordinary integers:
//!   zeroing them is the caller's business.
//! - Randomness comes from the operating system (`getrandom`), and a
//!   failure is returned as [`Error::RandomnessUnavailable`] rather than a
//!   panic. The `*_with(rng)` variants accept a caller CSPRNG for
//!   deterministic testing; the Python and TypeScript bindings expose none of
//!   them.
//! - Every point decoded from bytes is validated to be on secp256k1 and in
//!   canonical compressed form.
//! - Decryption walks the same number of giant steps whatever the plaintext,
//!   and its working memory is bounded (a table of at most
//!   [`elgamal::MAX_TABLE_SIZE`] 8-byte entries, plus a fixed-size buffer).
//!   It is *not* constant-time in the stronger sense: which table entries
//!   are probed, and whether the one verification step runs, depend on the
//!   plaintext. Treat decryption timing and cache behaviour as observable by
//!   a co-located attacker, and decrypt only in a process you trust.
//! - The crate forbids `unsafe` and denies `unwrap`/`expect`/`panic`/slice
//!   indexing, and the one dependency panic path we know of (`OsRng`) is
//!   avoided, so failures are returned [`Error`]s. That is a lint-enforced
//!   property of this crate, not a proof about its dependencies.
//!
//! # Not provided
//!
//! Ciphertext-times-ciphertext multiplication (the source paper's Weil-pairing
//! construction does not type-check), hardware-backed key storage (HSM/KMS),
//! and an independent audit of *this* crate.

pub mod delegation;
pub mod elgamal;
mod encoding;
mod error;

pub use error::Error;

/// Result type for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Compiles and runs the README's example as a doctest.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
