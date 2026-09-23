// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Canonical point and scalar encodings shared by every binding.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

use crate::{Error, Result};

/// Length of a SEC1 compressed point.
pub(crate) const COMPRESSED_LEN: usize = 33;
/// SEC1 encoding of the point at infinity.
pub(crate) const IDENTITY: u8 = 0x00;

/// SEC1 compressed bytes, or `[0x00]` for the identity.
pub(crate) fn encode_point(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

/// Fixed-width key for hash-table lookups: compressed bytes, or all zeros
/// for the identity (no valid compressed point starts with 0x00).
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

/// Signed 64-bit integer as a scalar mod n.
pub(crate) fn scalar_from_i64(m: i64) -> Scalar {
    let magnitude = Scalar::from(m.unsigned_abs());
    if m < 0 { -magnitude } else { magnitude }
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
