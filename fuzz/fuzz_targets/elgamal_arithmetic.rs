// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! The additive homomorphism, end to end: for any key, randomness and
//! plaintexts, decrypting sums, differences, negations and scalar multiples
//! gives the integer result when it is within the decryptor's range, and a
//! range error (never a wrong value, never a panic) when it is not.
#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use tokenis_core::Error;
use tokenis_core::elgamal::{self, Ciphertext, Decryptor, PrivateKey};

const MAX: i64 = 1 << 20;

#[derive(Debug, Arbitrary)]
struct Input {
    rng_seed: [u8; 32],
    a: i32,
    b: i32,
    k: i16,
    extra: Vec<i16>,
}

/// Building a decryptor dominates the cost, so one fixed key serves every
/// run; the randomness (and thus every ciphertext) varies.
fn decryptor() -> &'static Decryptor {
    static D: OnceLock<Decryptor> = OnceLock::new();
    D.get_or_init(|| {
        let mut seed = [0u8; 32];
        seed[31] = 7;
        let sk = PrivateKey::from_bytes(&seed).unwrap_or_else(|_| unreachable!());
        Decryptor::new(&sk, MAX as u64).unwrap_or_else(|_| unreachable!())
    })
}

fn check(d: &Decryptor, ct: &Ciphertext, expected: i128) {
    match d.decrypt(ct) {
        Ok(v) => assert_eq!(i128::from(v), expected, "wrong plaintext"),
        Err(e) => {
            assert_eq!(e, Error::PlaintextOutOfRange, "unexpected error {e:?}");
            assert!(expected.abs() > i128::from(MAX), "in-range value {expected} not decrypted");
        }
    }
}

fuzz_target!(|input: Input| {
    let d = decryptor();
    let pk = d.public_key();
    let mut rng = ChaCha20Rng::from_seed(input.rng_seed);
    let (a, b, k) = (i64::from(input.a), i64::from(input.b), i64::from(input.k));
    let ca = elgamal::encrypt_with(pk, a, &mut rng);
    let cb = elgamal::encrypt_with(pk, b, &mut rng);

    check(d, &ca, a.into());
    let sum = elgamal::add(&ca, &cb).unwrap_or_else(|e| panic!("add: {e:?}"));
    check(d, &sum, i128::from(a) + i128::from(b));
    let diff = elgamal::sub(&ca, &cb).unwrap_or_else(|e| panic!("sub: {e:?}"));
    check(d, &diff, i128::from(a) - i128::from(b));
    check(d, &elgamal::neg(&ca), -i128::from(a));
    check(d, &elgamal::scalar_mul(&ca, k), i128::from(a) * i128::from(k));

    // Serialisation preserves the plaintext.
    let bytes = sum.to_bytes();
    let parsed = Ciphertext::from_bytes(&bytes, Some(pk)).unwrap_or_else(|e| panic!("parse: {e:?}"));
    check(d, &parsed, i128::from(a) + i128::from(b));

    // Re-randomisation changes the ciphertext, not the plaintext.
    if let Ok(fresh) = d.refresh(&ca) {
        check(d, &fresh, a.into());
    }

    // n-ary sums, and the batched encoder agrees with the one-by-one one.
    let cts: Vec<Ciphertext> = input.extra.iter().take(16)
        .map(|&v| elgamal::encrypt_with(pk, i64::from(v), &mut rng)).collect();
    if let Ok(total) = elgamal::sum(&cts) {
        check(d, &total, input.extra.iter().take(16).map(|&v| i128::from(v)).sum());
    } else {
        assert!(cts.is_empty());
    }
    let batched = elgamal::to_bytes_many(&cts);
    for (ct, enc) in cts.iter().zip(&batched) {
        assert_eq!(&ct.to_bytes(), enc);
    }
});
