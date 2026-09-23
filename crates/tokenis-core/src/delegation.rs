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

use core::fmt;
use std::collections::HashSet;

use k256::elliptic_curve::Field;
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroize;

use crate::encoding::{scalar_from_bytes, scalar_from_i64, scalar_to_bytes};
use crate::{Error, Result};

pub use k256::Scalar;

type OwnerId = [u8; 16];

/// Decode a value (an integer mod n) from 32 canonical big-endian bytes.
pub fn value_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    scalar_from_bytes(bytes)
}

/// Encode a value (an integer mod n) as 32 big-endian bytes.
pub fn value_to_bytes(value: &Scalar) -> [u8; 32] {
    scalar_to_bytes(value)
}

/// A secret one-time pad for one [`MaskedValue`]. Consumed on use; zeroed on
/// drop.
pub struct Mask {
    value: Scalar,
    owner: OwnerId,
}

/// The public correction term for one delegated affine evaluation. Consumed
/// on use; zeroed on drop.
pub struct Correction {
    value: Scalar,
    owner: OwnerId,
}

/// A Beaver triple `(u, v, w = u*v)`. Consumed by
/// [`Owner::reconstruct_multiplication`]; zeroed on drop.
pub struct MultiplicationTriple {
    u: Scalar,
    v: Scalar,
    w: Scalar,
    owner: OwnerId,
    id: u64,
}

macro_rules! zeroizing_secret {
    ($ty:ident, $($field:ident),+) => {
        impl Drop for $ty {
            fn drop(&mut self) {
                $(self.$field.zeroize();)+
            }
        }
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(<redacted>)", stringify!($ty))
            }
        }
    };
}
zeroizing_secret!(Mask, value);
zeroizing_secret!(Correction, value);
zeroizing_secret!(MultiplicationTriple, u, v, w);

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
    intercept: &Scalar,
    masked: &[MaskedValue],
) -> Result<MaskedValue> {
    if coefficients.len() != masked.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(MaskedValue(
        coefficients
            .iter()
            .zip(masked)
            .fold(*intercept, |acc, (a, x)| acc + scalar_from_i64(*a) * x.0),
    ))
}

/// Server side of masked multiplication: the one product it may compute.
pub fn combine_multiplication(opening: &MultiplicationOpening) -> Scalar {
    opening.e * opening.g
}

/// The key-holding party. Never sends anything but masked values and
/// openings.
pub struct Owner {
    id: OwnerId,
    next_triple: u64,
    consumed: HashSet<u64>,
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Owner(triples_issued={})", self.next_triple)
    }
}

impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}

impl Owner {
    /// A new owner with a random identity.
    pub fn new() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self {
            id,
            next_triple: 0,
            consumed: HashSet::new(),
        }
    }

    /// Mask `x` with OS randomness.
    pub fn blind(&self, x: &Scalar) -> (MaskedValue, Mask) {
        self.blind_with(x, &mut OsRng)
    }

    /// Mask `x` with a caller-supplied CSPRNG.
    pub fn blind_with<R: RngCore + CryptoRng>(
        &self,
        x: &Scalar,
        rng: &mut R,
    ) -> (MaskedValue, Mask) {
        let r = Scalar::random(rng);
        (
            MaskedValue(*x + r),
            Mask {
                value: r,
                owner: self.id,
            },
        )
    }

    /// Remove a mask (consuming it).
    pub fn unblind(&self, masked: &MaskedValue, mask: Mask) -> Result<Scalar> {
        if mask.owner != self.id {
            return Err(Error::ForeignTriple);
        }
        Ok(masked.0 - mask.value)
    }

    /// Owner side of affine delegation: mask every value and compute the
    /// correction to subtract from the server's answer.
    pub fn delegate_affine(
        &self,
        coefficients: &[i64],
        values: &[Scalar],
    ) -> Result<(Vec<MaskedValue>, Correction)> {
        if coefficients.len() != values.len() {
            return Err(Error::LengthMismatch);
        }
        let mut correction = Scalar::ZERO;
        let mut masked = Vec::with_capacity(values.len());
        for (a, x) in coefficients.iter().zip(values) {
            let (m, mask) = self.blind(x);
            correction += scalar_from_i64(*a) * mask.value;
            masked.push(m);
        }
        let result = (
            masked,
            Correction {
                value: correction,
                owner: self.id,
            },
        );
        correction.zeroize();
        Ok(result)
    }

    /// Recover `f(values)` from the server's masked result.
    pub fn unblind_affine(&self, result: &MaskedValue, correction: Correction) -> Result<Scalar> {
        if correction.owner != self.id {
            return Err(Error::ForeignTriple);
        }
        Ok(result.0 - correction.value)
    }

    /// Precompute one Beaver triple.
    pub fn prepare_triple(&mut self) -> MultiplicationTriple {
        let (u, v) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
        let id = self.next_triple;
        self.next_triple = self.next_triple.saturating_add(1);
        MultiplicationTriple {
            u,
            v,
            w: u * v,
            owner: self.id,
            id,
        }
    }

    /// Owner side, step 1: blind `s` and `t` by the triple. Each triple may
    /// be opened once; a second opening would let the server learn
    /// `s1 - s2` and `t1 - t2`.
    pub fn open_multiplication(
        &mut self,
        s: &Scalar,
        t: &Scalar,
        triple: &MultiplicationTriple,
    ) -> Result<MultiplicationOpening> {
        if triple.owner != self.id {
            return Err(Error::ForeignTriple);
        }
        if !self.consumed.insert(triple.id) {
            return Err(Error::TripleReused);
        }
        Ok(MultiplicationOpening {
            e: *s - triple.u,
            g: *t - triple.v,
        })
    }

    /// Owner side, step 3: `s*t = w + e*v + g*u + e*g`. Consumes the triple.
    pub fn reconstruct_multiplication(
        &self,
        triple: MultiplicationTriple,
        opening: &MultiplicationOpening,
        eg: &Scalar,
    ) -> Result<Scalar> {
        if triple.owner != self.id {
            return Err(Error::ForeignTriple);
        }
        Ok(triple.w + opening.e * triple.v + opening.g * triple.u + eg)
    }

    /// Blinded bootstrap: unmask, apply `refresh`, re-mask with a fresh pad.
    /// Only the owner ever sees the plaintext.
    pub fn refresh<F: FnOnce(Scalar) -> Scalar>(
        &self,
        masked: &MaskedValue,
        mask: Mask,
        refresh: F,
    ) -> Result<(MaskedValue, Mask)> {
        let mut x = self.unblind(masked, mask)?;
        let mut refreshed = refresh(x);
        let out = self.blind(&refreshed);
        x.zeroize();
        refreshed.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn s(v: i64) -> Scalar {
        scalar_from_i64(v)
    }

    #[test]
    fn blind_unblind_roundtrip_and_hides_value() {
        let owner = Owner::new();
        let (masked, mask) = owner.blind(&s(42));
        assert_ne!(masked.0, s(42));
        assert_eq!(owner.unblind(&masked, mask).unwrap(), s(42));
    }

    #[test]
    fn masked_values_of_the_same_plaintext_are_distinct() {
        let owner = Owner::new();
        let seen: HashSet<[u8; 32]> = (0..500).map(|_| owner.blind(&s(7)).0.to_bytes()).collect();
        assert_eq!(seen.len(), 500);
    }

    #[test]
    fn affine_delegation() {
        let owner = Owner::new();
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
        let mut owner = Owner::new();
        let triple = owner.prepare_triple();
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
    fn triple_reuse_and_foreign_triples_rejected() {
        let mut owner = Owner::new();
        let mut other = Owner::new();
        let triple = owner.prepare_triple();
        owner.open_multiplication(&s(1), &s(2), &triple).unwrap();
        assert_eq!(
            owner.open_multiplication(&s(3), &s(4), &triple),
            Err(Error::TripleReused)
        );
        assert_eq!(
            other.open_multiplication(&s(1), &s(2), &triple),
            Err(Error::ForeignTriple)
        );
        let (masked, mask) = owner.blind(&s(9));
        assert_eq!(other.unblind(&masked, mask), Err(Error::ForeignTriple));
    }

    #[test]
    fn refresh_preserves_value_with_new_pad() {
        let owner = Owner::new();
        let (masked, mask) = owner.blind(&s(99));
        let (fresh, fresh_mask) = owner.refresh(&masked, mask, |x| x + s(1)).unwrap();
        assert_ne!(fresh, masked);
        assert_eq!(owner.unblind(&fresh, fresh_mask).unwrap(), s(100));
    }

    #[test]
    fn secrets_redacted_and_encodings_roundtrip() {
        let mut owner = Owner::new();
        let triple = owner.prepare_triple();
        let (masked, mask) = owner.blind(&s(1));
        assert_eq!(format!("{mask:?}"), "Mask(<redacted>)");
        assert_eq!(format!("{triple:?}"), "MultiplicationTriple(<redacted>)");
        assert_eq!(MaskedValue::from_bytes(&masked.to_bytes()).unwrap(), masked);
        let opening = owner.open_multiplication(&s(5), &s(6), &triple).unwrap();
        assert_eq!(
            MultiplicationOpening::from_bytes(&opening.to_bytes()).unwrap(),
            opening
        );
        assert!(MaskedValue::from_bytes(&[0xff; 32]).is_err());
    }

    proptest! {
        #[test]
        fn delegation_identities(a in any::<i64>(), b in any::<i64>(), c in any::<i64>()) {
            let mut owner = Owner::new();
            let triple = owner.prepare_triple();
            let opening = owner.open_multiplication(&s(a), &s(b), &triple).unwrap();
            let eg = combine_multiplication(&opening);
            prop_assert_eq!(
                owner.reconstruct_multiplication(triple, &opening, &eg).unwrap(),
                s(a) * s(b)
            );
            let (masked, corr) = owner.delegate_affine(&[c, 1], &[s(a), s(b)]).unwrap();
            let r = evaluate_affine_masked(&[c, 1], &Scalar::ZERO, &masked).unwrap();
            prop_assert_eq!(owner.unblind_affine(&r, corr).unwrap(), s(c) * s(a) + s(b));
        }
    }
}
