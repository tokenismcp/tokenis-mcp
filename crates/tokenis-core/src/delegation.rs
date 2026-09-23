// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! No-key delegation over `Z/nZ` (n = secp256k1's group order).
//!
//! An [`Owner`] holds every secret; a server holds only one-time-pad-masked
//! values, evaluates public affine functions on them directly, and helps
//! multiply through precomputed Beaver triples. The server's view is uniform
//! and independent of the plaintext (the source paper's Theorems 27-32), so
//! compromising it -- even with a quantum computer -- reveals nothing.
//!
//! Stronger than the reference Python version: masks, corrections and triples
//! are *consumed* by the operation that uses them, so reusing one (which
//! would break the secrecy proof) is impossible through this API, and each
//! is tagged with its owner so values can't be crossed between owners.
//!
//! Every secret lives behind a heap pointer that is zeroed on drop, so
//! moving a secret (for example out of a binding's `Option` slot) copies the
//! pointer, never the secret bytes.

use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};
use std::collections::HashSet;

use k256::Scalar;
use k256::elliptic_curve::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::encoding::{
    random_bytes, random_scalar, scalar_from_bytes, scalar_from_i64, scalar_to_bytes,
};
use crate::{Error, Result};

type OwnerId = [u8; 16];

/// An integer mod n (secp256k1's group order): a plaintext, a masked value's
/// payload, or a server's partial result. Zeroed on drop. A newtype so this
/// crate's public API does not expose its elliptic-curve library's types.
#[derive(Clone, PartialEq, Eq)]
pub struct Value(Scalar);

impl Value {
    /// Zero.
    pub const ZERO: Self = Self(Scalar::ZERO);

    /// A signed 64-bit integer, reduced mod n.
    pub fn from_i64(v: i64) -> Self {
        Self(scalar_from_i64(v))
    }

    /// Decode 32 canonical big-endian bytes (`< n`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        scalar_from_bytes(bytes).map(Self)
    }

    /// Encode as 32 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        scalar_to_bytes(&self.0)
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value(<redacted>)")
    }
}

impl Add for &Value {
    type Output = Value;
    fn add(self, rhs: &Value) -> Value {
        Value(self.0 + rhs.0)
    }
}

impl Sub for &Value {
    type Output = Value;
    fn sub(self, rhs: &Value) -> Value {
        Value(self.0 - rhs.0)
    }
}

impl Mul for &Value {
    type Output = Value;
    fn mul(self, rhs: &Value) -> Value {
        Value(self.0 * rhs.0)
    }
}

impl Neg for &Value {
    type Output = Value;
    fn neg(self) -> Value {
        Value(-self.0)
    }
}

/// Decode a value from 32 canonical big-endian bytes.
pub fn value_from_bytes(bytes: &[u8]) -> Result<Value> {
    Value::from_bytes(bytes)
}

/// Encode a value as 32 big-endian bytes.
pub fn value_to_bytes(value: &Value) -> [u8; 32] {
    value.to_bytes()
}

/// A scalar on the heap, zeroed on drop: moving the owner moves a pointer.
struct Secret(Box<Scalar>);

impl Secret {
    fn new(value: Scalar) -> Self {
        Self(Box::new(value))
    }

    fn get(&self) -> &Scalar {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A secret one-time pad for one [`MaskedValue`]. Consumed on use; zeroed on
/// drop.
pub struct Mask {
    value: Secret,
    owner: OwnerId,
}

/// The secret correction term for one delegated affine evaluation (the
/// coefficient-weighted sum of the masks). Consumed on use; zeroed on drop.
pub struct Correction {
    value: Secret,
    owner: OwnerId,
}

/// A Beaver triple `(u, v, w = u*v)`. Opened once by
/// [`Owner::open_multiplication`], consumed by
/// [`Owner::reconstruct_multiplication`]; zeroed on drop.
pub struct MultiplicationTriple {
    u: Secret,
    v: Secret,
    w: Secret,
    owner: OwnerId,
    id: u64,
}

macro_rules! redacted {
    ($($ty:ident),+) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(<redacted>)", stringify!($ty))
            }
        }
    )+};
}
redacted!(Mask, Correction, MultiplicationTriple);

/// Anything bound to the [`Owner`] that created it.
pub trait OwnedSecret {
    /// The creating owner's identity.
    #[doc(hidden)]
    fn owner_id(&self) -> &[u8; 16];
}

impl OwnedSecret for Mask {
    fn owner_id(&self) -> &[u8; 16] {
        &self.owner
    }
}

impl OwnedSecret for Correction {
    fn owner_id(&self) -> &[u8; 16] {
        &self.owner
    }
}

impl OwnedSecret for MultiplicationTriple {
    fn owner_id(&self) -> &[u8; 16] {
        &self.owner
    }
}

impl MultiplicationTriple {
    /// This triple's per-owner sequence number.
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// A masked value: uniform on `Z/nZ`, independent of the plaintext. Safe to
/// send to an untrusted server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MaskedValue(Scalar);

/// What the server sees in one masked multiplication: `(e, g)`, uniform and
/// independent of the operands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MultiplicationOpening {
    e: Scalar,
    g: Scalar,
}

impl MaskedValue {
    /// 32-byte big-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        scalar_to_bytes(&self.0)
    }

    /// Parse a canonical 32-byte scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        scalar_from_bytes(bytes).map(Self)
    }
}

impl MultiplicationOpening {
    /// `e || g`, 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let (e, g) = out.split_at_mut(32);
        e.copy_from_slice(&scalar_to_bytes(&self.e));
        g.copy_from_slice(&scalar_to_bytes(&self.g));
        out
    }

    /// Parse 64 bytes `e || g`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::MalformedEncoding);
        }
        let (e, g) = bytes.split_at(32);
        Ok(Self {
            e: scalar_from_bytes(e)?,
            g: scalar_from_bytes(g)?,
        })
    }
}

/// Server side of affine evaluation: `sum(a_i * masked_i) + intercept`.
pub fn evaluate_affine_masked(
    coefficients: &[i64],
    intercept: &Value,
    masked: &[MaskedValue],
) -> Result<MaskedValue> {
    if coefficients.len() != masked.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(MaskedValue(
        coefficients
            .iter()
            .zip(masked)
            .fold(intercept.0, |acc, (a, x)| acc + scalar_from_i64(*a) * x.0),
    ))
}

/// Server side of masked multiplication: the one product it may compute.
pub fn combine_multiplication(opening: &MultiplicationOpening) -> Value {
    Value(opening.e * opening.g)
}

/// The key-holding party. Never sends anything but masked values and
/// openings.
pub struct Owner {
    id: OwnerId,
    next_triple: u64,
    /// Triples issued by [`Owner::prepare_triple`] and not yet opened. An
    /// opening removes its id, so this holds only outstanding triples.
    outstanding: HashSet<u64>,
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Owner(triples_issued={}, outstanding={})",
            self.next_triple,
            self.outstanding.len()
        )
    }
}

impl Owner {
    /// A new owner with a random identity.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: random_bytes()?,
            next_triple: 0,
            outstanding: HashSet::new(),
        })
    }

    /// Whether `secret` was created by this owner. Lets callers that hold a
    /// secret in a slot check ownership before moving it out, so a mismatch
    /// doesn't destroy the caller's only copy.
    pub fn owns(&self, secret: &impl OwnedSecret) -> bool {
        secret.owner_id() == &self.id
    }

    fn check(&self, secret: &impl OwnedSecret, err: Error) -> Result<()> {
        if self.owns(secret) { Ok(()) } else { Err(err) }
    }

    /// Mask `x` with OS randomness.
    #[must_use = "the mask is the only way to recover the value"]
    pub fn blind(&self, x: &Value) -> Result<(MaskedValue, Mask)> {
        let mut r = random_scalar()?;
        let out = self.blind_scalar(x, &r);
        r.zeroize();
        Ok(out)
    }

    /// Mask `x` with a caller-supplied CSPRNG (deterministic testing). The
    /// bindings never expose this.
    #[must_use = "the mask is the only way to recover the value"]
    pub fn blind_with<R: RngCore + CryptoRng>(
        &self,
        x: &Value,
        rng: &mut R,
    ) -> (MaskedValue, Mask) {
        let mut r = Scalar::random(rng);
        let out = self.blind_scalar(x, &r);
        r.zeroize();
        out
    }

    fn blind_scalar(&self, x: &Value, r: &Scalar) -> (MaskedValue, Mask) {
        (
            MaskedValue(x.0 + r),
            Mask {
                value: Secret::new(*r),
                owner: self.id,
            },
        )
    }

    /// Remove a mask (consuming it).
    pub fn unblind(&self, masked: &MaskedValue, mask: Mask) -> Result<Value> {
        self.check(&mask, Error::ForeignOwner)?;
        Ok(Value(masked.0 - mask.value.get()))
    }

    /// Owner side of affine delegation: mask every value and compute the
    /// correction to subtract from the server's answer.
    #[must_use = "the correction is the only way to recover the result"]
    pub fn delegate_affine(
        &self,
        coefficients: &[i64],
        values: &[Value],
    ) -> Result<(Vec<MaskedValue>, Correction)> {
        if coefficients.len() != values.len() {
            return Err(Error::LengthMismatch);
        }
        let mut correction = Secret::new(Scalar::ZERO);
        let mut masked = Vec::with_capacity(values.len());
        for (a, x) in coefficients.iter().zip(values) {
            let (m, mask) = self.blind(x)?;
            let mut term = scalar_from_i64(*a) * mask.value.get();
            *correction.0 += term;
            term.zeroize();
            masked.push(m);
        }
        Ok((
            masked,
            Correction {
                value: correction,
                owner: self.id,
            },
        ))
    }

    /// Recover `f(values)` from the server's masked result.
    pub fn unblind_affine(&self, result: &MaskedValue, correction: Correction) -> Result<Value> {
        self.check(&correction, Error::ForeignOwner)?;
        Ok(Value(result.0 - correction.value.get()))
    }

    /// Precompute one Beaver triple.
    #[must_use = "a dropped triple can never be opened"]
    pub fn prepare_triple(&mut self) -> Result<MultiplicationTriple> {
        let u = Secret::new(random_scalar()?);
        let v = Secret::new(random_scalar()?);
        let w = Secret::new(u.get() * v.get());
        let id = self.next_triple;
        self.next_triple = self.next_triple.saturating_add(1);
        self.outstanding.insert(id);
        Ok(MultiplicationTriple {
            u,
            v,
            w,
            owner: self.id,
            id,
        })
    }

    /// Owner side, step 1: blind `s` and `t` by the triple. Each triple may
    /// be opened once; a second opening would let the server learn
    /// `s1 - s2` and `t1 - t2`.
    pub fn open_multiplication(
        &mut self,
        s: &Value,
        t: &Value,
        triple: &MultiplicationTriple,
    ) -> Result<MultiplicationOpening> {
        self.check(triple, Error::ForeignTriple)?;
        if !self.outstanding.remove(&triple.id) {
            return Err(Error::TripleReused);
        }
        Ok(MultiplicationOpening {
            e: s.0 - triple.u.get(),
            g: t.0 - triple.v.get(),
        })
    }

    /// Owner side, step 3: `s*t = w + e*v + g*u + e*g`. Consumes the triple.
    pub fn reconstruct_multiplication(
        &self,
        triple: MultiplicationTriple,
        opening: &MultiplicationOpening,
        eg: &Value,
    ) -> Result<Value> {
        self.check(&triple, Error::ForeignTriple)?;
        // e*v reveals v (e is public); zero the temporaries.
        let mut ev = opening.e * triple.v.get();
        let mut gu = opening.g * triple.u.get();
        let out = Value(*triple.w.get() + ev + gu + eg.0);
        ev.zeroize();
        gu.zeroize();
        Ok(out)
    }

    /// Blinded bootstrap: unmask, apply `refresh`, re-mask with a fresh pad.
    /// Only the owner ever sees the plaintext.
    pub fn refresh<F: FnOnce(&Value) -> Value>(
        &self,
        masked: &MaskedValue,
        mask: Mask,
        refresh: F,
    ) -> Result<(MaskedValue, Mask)> {
        let x = self.unblind(masked, mask)?;
        let refreshed = refresh(&x);
        self.blind(&refreshed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn s(v: i64) -> Value {
        Value::from_i64(v)
    }

    fn owner() -> Owner {
        Owner::new().unwrap()
    }

    #[test]
    fn blind_unblind_roundtrip_and_hides_value() {
        let owner = owner();
        let (masked, mask) = owner.blind(&s(42)).unwrap();
        assert_ne!(masked.to_bytes(), s(42).to_bytes());
        assert_eq!(owner.unblind(&masked, mask).unwrap(), s(42));
    }

    #[test]
    fn masked_values_of_the_same_plaintext_are_distinct() {
        let owner = owner();
        let seen: HashSet<[u8; 32]> = (0..500)
            .map(|_| owner.blind(&s(7)).unwrap().0.to_bytes())
            .collect();
        assert_eq!(seen.len(), 500);
    }

    #[test]
    fn affine_delegation() {
        let owner = owner();
        let coeffs = [2, 3, -1];
        let values = [s(10), s(20), s(7)];
        let (masked, correction) = owner.delegate_affine(&coeffs, &values).unwrap();
        let result = evaluate_affine_masked(&coeffs, &s(5), &masked).unwrap();
        assert_eq!(
            owner.unblind_affine(&result, correction).unwrap(),
            s(2 * 10 + 3 * 20 - 7 + 5)
        );
        assert_eq!(
            owner.delegate_affine(&coeffs, &values[..2]).unwrap_err(),
            Error::LengthMismatch
        );
    }

    #[test]
    fn masked_multiplication() {
        let mut owner = owner();
        let triple = owner.prepare_triple().unwrap();
        let opening = owner
            .open_multiplication(&s(123), &s(-456), &triple)
            .unwrap();
        let eg = combine_multiplication(&opening);
        assert_eq!(
            owner
                .reconstruct_multiplication(triple, &opening, &eg)
                .unwrap(),
            s(123 * -456)
        );
    }

    #[test]
    fn triple_reuse_and_foreign_secrets_rejected() {
        let mut owner = owner();
        let mut other = Owner::new().unwrap();
        let triple = owner.prepare_triple().unwrap();
        assert_eq!(
            other.open_multiplication(&s(1), &s(2), &triple),
            Err(Error::ForeignTriple)
        );
        owner.open_multiplication(&s(1), &s(2), &triple).unwrap();
        assert_eq!(
            owner.open_multiplication(&s(3), &s(4), &triple),
            Err(Error::TripleReused)
        );
        let (masked, mask) = owner.blind(&s(9)).unwrap();
        assert!(owner.owns(&mask));
        assert!(!other.owns(&mask));
        assert_eq!(other.unblind(&masked, mask), Err(Error::ForeignOwner));
        let (_, correction) = owner.delegate_affine(&[1], &[s(1)]).unwrap();
        assert_eq!(
            other.unblind_affine(&masked, correction),
            Err(Error::ForeignOwner)
        );
    }

    #[test]
    fn only_outstanding_triples_are_tracked() {
        let mut owner = owner();
        let triples: Vec<_> = (0..100).map(|_| owner.prepare_triple().unwrap()).collect();
        assert_eq!(owner.outstanding.len(), 100);
        for t in &triples {
            owner.open_multiplication(&s(1), &s(2), t).unwrap();
        }
        assert!(owner.outstanding.is_empty());
    }

    #[test]
    fn refresh_preserves_value_with_new_pad() {
        let owner = owner();
        let (masked, mask) = owner.blind(&s(99)).unwrap();
        let (fresh, fresh_mask) = owner.refresh(&masked, mask, |x| x + &s(1)).unwrap();
        assert_ne!(fresh, masked);
        assert_eq!(owner.unblind(&fresh, fresh_mask).unwrap(), s(100));
    }

    #[test]
    fn secrets_redacted_and_encodings_roundtrip() {
        let mut owner = owner();
        let triple = owner.prepare_triple().unwrap();
        let (masked, mask) = owner.blind(&s(1)).unwrap();
        assert_eq!(format!("{mask:?}"), "Mask(<redacted>)");
        assert_eq!(format!("{triple:?}"), "MultiplicationTriple(<redacted>)");
        assert_eq!(format!("{:?}", s(5)), "Value(<redacted>)");
        assert_eq!(MaskedValue::from_bytes(&masked.to_bytes()).unwrap(), masked);
        let opening = owner.open_multiplication(&s(5), &s(6), &triple).unwrap();
        assert_eq!(
            MultiplicationOpening::from_bytes(&opening.to_bytes()).unwrap(),
            opening
        );
        assert!(MaskedValue::from_bytes(&[0xff; 32]).is_err());
        assert_eq!(Value::from_bytes(&s(-3).to_bytes()).unwrap(), s(-3));
    }

    #[test]
    fn moving_a_secret_moves_only_a_pointer() {
        // The secret's bytes live on the heap; the struct that gets moved
        // (e.g. out of a binding's Option slot) holds a pointer and the
        // owner id, never the scalar itself.
        assert_eq!(
            core::mem::size_of::<Mask>(),
            core::mem::size_of::<usize>() + 16
        );
    }

    proptest! {
        #[test]
        fn delegation_identities(a in any::<i64>(), b in any::<i64>(), c in any::<i64>()) {
            let mut owner = owner();
            let triple = owner.prepare_triple().unwrap();
            let opening = owner.open_multiplication(&s(a), &s(b), &triple).unwrap();
            let eg = combine_multiplication(&opening);
            prop_assert_eq!(
                owner.reconstruct_multiplication(triple, &opening, &eg).unwrap(),
                &s(a) * &s(b)
            );
            let (masked, corr) = owner.delegate_affine(&[c, 1], &[s(a), s(b)]).unwrap();
            let r = evaluate_affine_masked(&[c, 1], &Value::ZERO, &masked).unwrap();
            prop_assert_eq!(owner.unblind_affine(&r, corr).unwrap(), &(&s(c) * &s(a)) + &s(b));
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..100)) {
            let _ = MaskedValue::from_bytes(&bytes);
            let _ = MultiplicationOpening::from_bytes(&bytes);
            let _ = Value::from_bytes(&bytes);
            let _ = crate::elgamal::base_point_multiple(&bytes);
        }
    }
}
