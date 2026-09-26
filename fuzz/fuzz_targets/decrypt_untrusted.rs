// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Decrypting attacker-supplied ciphertexts (e.g. a tampered ledger that
//! still parses): the decryptor must either return a value inside its
//! declared range or an error -- never panic, loop or return out of range.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokenis_core::elgamal::{Ciphertext, Decryptor, PrivateKey};

const MAX: u64 = 1 << 16;

fn decryptor() -> &'static Decryptor {
    static D: OnceLock<Decryptor> = OnceLock::new();
    D.get_or_init(|| {
        let mut seed = [0u8; 32];
        seed[0] = 0x42;
        seed[31] = 1;
        let sk = PrivateKey::from_bytes(&seed).unwrap_or_else(|_| unreachable!());
        Decryptor::with_table_size(&sk, MAX, 64).unwrap_or_else(|_| unreachable!())
    })
}

fuzz_target!(|data: &[u8]| {
    let d = decryptor();
    // Untagged and tagged with the right key: both must be handled.
    for tagged in [None, Some(d.public_key())] {
        if let Ok(ct) = Ciphertext::from_bytes(data, tagged) {
            if let Ok(v) = d.decrypt(&ct) {
                assert!(v.unsigned_abs() <= MAX, "decrypted {v} outside the range");
            }
        }
    }
});
