// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Every decoder in tokenis-core, on arbitrary bytes: none may panic, and
//! whatever one accepts must re-encode to exactly the same bytes (encodings
//! are canonical, so two byte strings never mean the same object).
#![no_main]

use libfuzzer_sys::fuzz_target;
use tokenis_core::delegation::{MaskedValue, MultiplicationOpening, Value};
use tokenis_core::elgamal::{self, Ciphertext, PrivateKey, PublicKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = PublicKey::from_bytes(data) {
        assert_eq!(pk.to_bytes().as_slice(), data);
    }
    if let Ok(sk) = PrivateKey::from_bytes(data) {
        assert_eq!(sk.export_secret_bytes().as_slice(), data);
        // Its public key must itself round-trip.
        let pk = sk.public_key();
        assert_eq!(PublicKey::from_bytes(&pk.to_bytes()).map(|p| p.to_bytes()), Ok(pk.to_bytes()));
    }
    if let Ok(ct) = Ciphertext::from_bytes(data, None) {
        assert_eq!(ct.to_bytes(), data);
        let (c1, c2) = ct.components();
        assert_eq!(1 + c1.len() + c2.len(), data.len());
    }
    if let Ok(v) = Value::from_bytes(data) {
        assert_eq!(v.to_bytes().as_slice(), data);
    }
    if let Ok(m) = MaskedValue::from_bytes(data) {
        assert_eq!(m.to_bytes().as_slice(), data);
    }
    if let Ok(o) = MultiplicationOpening::from_bytes(data) {
        assert_eq!(o.to_bytes().as_slice(), data);
    }
    let _ = elgamal::base_point_multiple(data);
});
