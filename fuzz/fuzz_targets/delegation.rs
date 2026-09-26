// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! The no-key delegation protocol: for any values and coefficients, the
//! owner recovers exactly the affine combination and the product, the
//! server-side messages survive serialisation, and a triple opens once.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tokenis_core::Error;
use tokenis_core::delegation::{
    self, MaskedValue, MultiplicationOpening, Owner, Value,
};

#[derive(Debug, Arbitrary)]
struct Input {
    terms: Vec<(i64, i64)>,
    intercept: i64,
    s: i64,
    t: i64,
}

fuzz_target!(|input: Input| {
    let Ok(mut owner) = Owner::new() else { return };
    let terms: Vec<(i64, i64)> = input.terms.into_iter().take(32).collect();
    let coefficients: Vec<i64> = terms.iter().map(|&(a, _)| a).collect();
    let values: Vec<Value> = terms.iter().map(|&(_, x)| Value::from_i64(x)).collect();

    // Affine: sum(a_i * x_i) + c, computed by the server on masked inputs.
    let (masked, correction) = owner.delegate_affine(&coefficients, &values)
        .unwrap_or_else(|e| panic!("delegate: {e:?}"));
    let wire: Vec<MaskedValue> = masked.iter()
        .map(|m| MaskedValue::from_bytes(&m.to_bytes()).unwrap_or_else(|e| panic!("wire: {e:?}")))
        .collect();
    let intercept = Value::from_i64(input.intercept);
    let result = delegation::evaluate_affine_masked(&coefficients, &intercept, &wire)
        .unwrap_or_else(|e| panic!("evaluate: {e:?}"));
    let got = owner.unblind_affine(&result, correction).unwrap_or_else(|e| panic!("unblind: {e:?}"));
    let expected = terms.iter().fold(intercept, |acc, &(a, x)| {
        &acc + &(&Value::from_i64(a) * &Value::from_i64(x))
    });
    assert_eq!(got, expected);

    // Multiplication with a Beaver triple, through the wire format.
    let triple = owner.prepare_triple().unwrap_or_else(|e| panic!("triple: {e:?}"));
    let (s, t) = (Value::from_i64(input.s), Value::from_i64(input.t));
    let opening = owner.open_multiplication(&s, &t, &triple).unwrap_or_else(|e| panic!("open: {e:?}"));
    assert_eq!(owner.open_multiplication(&s, &t, &triple), Err(Error::TripleReused));
    let opening = MultiplicationOpening::from_bytes(&opening.to_bytes())
        .unwrap_or_else(|e| panic!("opening wire: {e:?}"));
    let eg = delegation::combine_multiplication(&opening);
    let product = owner.reconstruct_multiplication(triple, &opening, &eg)
        .unwrap_or_else(|e| panic!("reconstruct: {e:?}"));
    assert_eq!(product, &s * &t);
});
