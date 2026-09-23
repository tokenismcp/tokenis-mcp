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
//!   masks, Beaver-triple factors, affine corrections -- lives only in types
//!   that zero their memory on drop and redact themselves from `Debug`.
//! - Every point decoded from bytes is validated to be on secp256k1 and in
//!   canonical compressed form.
//! - Decryption walks its entire baby-step-giant-step search regardless of
//!   where (or whether) the plaintext is found, so its work does not depend on
//!   the plaintext.
//! - The crate forbids `unsafe` and denies `unwrap`/`expect`/`panic`/slice
//!   indexing: every failure is a returned [`Error`], never a panic across the
//!   FFI boundary.
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
