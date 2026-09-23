// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Canonical point and scalar encodings shared by every binding.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::{Reduce, ReduceNonZero};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, WideBytes};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Length of a SEC1 compressed point.
pub(crate) const COMPRESSED_LEN: usize = 33;
/// SEC1 encoding of the point at infinity.
pub(crate) const IDENTITY: u8 = 0x00;

/// SEC1 compressed bytes, or `[0x00]` for the identity.
pub(crate) fn encode_point(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// Fixed-width canonical key: compressed bytes, or all zeros for the
/// identity (no valid compressed point starts with 0x00).
pub(crate) fn point_key(p: &ProjectivePoint) -> [u8; COMPRESSED_LEN] {
    let mut key = [0u8; COMPRESSED_LEN];
    let encoded = p.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() == COMPRESSED_LEN {
        key.copy_from_slice(bytes);
    }
    key
}

/// Decode a canonical compressed point or the identity, validating that it
/// lies on secp256k1.
pub(crate) fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    match bytes {
        [IDENTITY] => Ok(ProjectivePoint::IDENTITY),
        [0x02 | 0x03, ..] if bytes.len() == COMPRESSED_LEN => {
            let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
            Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
                .map(ProjectivePoint::from)
                .ok_or(Error::InvalidPoint)
        }
        _ => Err(Error::InvalidPoint),
    }
}

/// Split one encoded point off the front of `buf`.
pub(crate) fn split_point(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let len = match buf.first() {
        None => return Err(Error::MalformedEncoding),
        Some(&IDENTITY) => 1,
        Some(_) => COMPRESSED_LEN,
    };
    if buf.len() < len {
        return Err(Error::MalformedEncoding);
    }
    Ok(buf.split_at(len))
}

/// Signed 64-bit integer as a scalar mod n. Branch-free in the sign, since
/// `m` is often a plaintext.
pub(crate) fn scalar_from_i64(m: i64) -> Scalar {
    let magnitude = Scalar::from(m.unsigned_abs());
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let negative = Choice::from(((m as u64) >> 63) as u8);
    Scalar::conditional_select(&magnitude, &-magnitude, negative)
}

/// 64 bytes from the operating system's CSPRNG, zeroed after use by the
/// caller's reduction. Unlike `rand_core::OsRng::fill_bytes`, a failure is an
/// error rather than a panic, so it can never unwind across an FFI boundary.
fn os_wide_bytes() -> crate::Result<WideBytes> {
    let mut wide = WideBytes::default();
    getrandom::getrandom(AsMut::<[u8]>::as_mut(&mut wide))
        .map_err(|_| crate::Error::RandomnessUnavailable)?;
    Ok(wide)
}

/// A uniformly random scalar in `[0, n)` from OS randomness (512 bits reduced
/// mod n: statistical distance from uniform below 2^-256).
pub(crate) fn random_scalar() -> crate::Result<Scalar> {
    let mut wide = os_wide_bytes()?;
    let s = <Scalar as Reduce<U512>>::reduce_bytes(&wide);
    AsMut::<[u8]>::as_mut(&mut wide).zeroize();
    Ok(s)
}

/// A uniformly random scalar in `[1, n)` from OS randomness.
pub(crate) fn random_nonzero_scalar() -> crate::Result<Scalar> {
    let mut wide = os_wide_bytes()?;
    let s = <Scalar as ReduceNonZero<U512>>::reduce_nonzero_bytes(&wide);
    AsMut::<[u8]>::as_mut(&mut wide).zeroize();
    Ok(s)
}

/// Random bytes from the OS CSPRNG, as an error rather than a panic on
/// failure.
pub(crate) fn random_bytes<const N: usize>() -> crate::Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| crate::Error::RandomnessUnavailable)?;
    Ok(out)
}

/// 32-byte big-endian scalar encoding.
pub(crate) fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes().into()
}

/// Decode a canonical 32-byte big-endian scalar in `[0, n)`.
pub(crate) fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    Option::from(Scalar::from_repr(FieldBytes::from(array))).ok_or(Error::InvalidScalar)
}
