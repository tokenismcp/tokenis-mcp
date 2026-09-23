// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! Additively homomorphic EC-ElGamal over secp256k1.
//!
//! `Enc(m) = (r*G, r*Q + m*G)`; `Enc(a) + Enc(b) = Enc(a + b)`; decryption
//! recovers `m*G` and solves the bounded discrete log by baby-step-giant-step.
//! Wire format: `0x01 || c1 || c2`, each component a 33-byte SEC1 compressed
//! point or `0x00` for the identity -- identical across the Rust, Python and
//! TypeScript SDKs.

use core::fmt;
use std::collections::HashMap;

use k256::elliptic_curve::BatchNormalize;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{
    COMPRESSED_LEN, decode_point, encode_point, point_key, scalar_from_i64, split_point,
};
use crate::{Error, Result};

/// Ciphertext wire-format version byte.
pub const CIPHERTEXT_VERSION: u8 = 1;
/// Default decryptable range `[-2^24, 2^24]`.
pub const DEFAULT_MAX_VALUE: u64 = 1 << 24;
/// Largest supported decryptable range (the baby-step table has
/// `sqrt(max_value)` entries).
pub const MAX_SUPPORTED_RANGE: u64 = 1 << 48;

/// A secp256k1 private key. Zeroed on drop, redacted from `Debug`.
#[derive(Clone)]
pub struct PrivateKey {
    secret: SecretKey,
}

impl PrivateKey {
    /// A fresh key from the operating system's CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    /// A fresh key from a caller-supplied CSPRNG.
    pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            secret: SecretKey::random(rng),
        }
    }

    /// Import a 32-byte big-endian scalar in `[1, n)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidPrivateKey);
        }
        SecretKey::from_slice(bytes)
            .map(|secret| Self { secret })
            .map_err(|_| Error::InvalidPrivateKey)
    }

    /// Export the 32-byte big-endian scalar, in a buffer zeroed on drop.
    /// Deliberately named: key export should be rare and auditable.
    pub fn export_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes().into())
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_point(self.secret.public_key().to_projective())
    }

    fn scalar(&self) -> NonZeroScalar {
        self.secret.to_nonzero_scalar()
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

/// A secp256k1 public key (never the identity).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    point: ProjectivePoint,
    encoded: [u8; COMPRESSED_LEN],
}

impl PublicKey {
    fn from_point(point: ProjectivePoint) -> Self {
        Self {
            point,
            encoded: point_key(&point),
        }
    }

    /// 33-byte SEC1 compressed encoding.
    pub fn to_bytes(&self) -> [u8; COMPRESSED_LEN] {
        self.encoded
    }

    /// Parse and validate a 33-byte SEC1 compressed encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let point = decode_point(bytes)?;
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::IdentityPublicKey);
        }
        Ok(Self::from_point(point))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(")?;
        for b in &self.encoded {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// An EC-ElGamal ciphertext, optionally tagged with the public key it was
/// produced under so that mixing keys is caught instead of decrypting to
/// garbage. The tag is not part of the wire format.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext {
    c1: ProjectivePoint,
    c2: ProjectivePoint,
    key: Option<[u8; COMPRESSED_LEN]>,
}

impl Ciphertext {
    /// `0x01 || c1 || c2`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![CIPHERTEXT_VERSION];
        out.extend_from_slice(&encode_point(&self.c1));
        out.extend_from_slice(&encode_point(&self.c2));
        out
    }

    /// Parse and validate; pass `public` to tag the result with its key.
    pub fn from_bytes(bytes: &[u8], public: Option<&PublicKey>) -> Result<Self> {
        let (version, rest) = bytes.split_first().ok_or(Error::MalformedEncoding)?;
        if *version != CIPHERTEXT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let (c1, rest) = split_point(rest)?;
        let (c2, rest) = split_point(rest)?;
        if !rest.is_empty() {
            return Err(Error::MalformedEncoding);
        }
        Ok(Self {
            c1: decode_point(c1)?,
            c2: decode_point(c2)?,
            key: public.map(|p| p.encoded),
        })
    }

    /// Encoded `(c1, c2)` components.
    pub fn components(&self) -> (Vec<u8>, Vec<u8>) {
        (encode_point(&self.c1), encode_point(&self.c2))
    }

    /// The public key this ciphertext is tagged with, if any.
    pub fn public_key_bytes(&self) -> Option<[u8; COMPRESSED_LEN]> {
        self.key
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ciphertext")
            .field("tagged", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

/// Encrypt `m` under `pk` with OS randomness.
pub fn encrypt(pk: &PublicKey, m: i64) -> Ciphertext {
    encrypt_with(pk, m, &mut OsRng)
}

/// Encrypt `m` under `pk` with a caller-supplied CSPRNG.
pub fn encrypt_with<R: RngCore + CryptoRng>(pk: &PublicKey, m: i64, rng: &mut R) -> Ciphertext {
    let mut r = NonZeroScalar::random(rng);
    let mut m_scalar = scalar_from_i64(m);
    let c1 = ProjectivePoint::GENERATOR * *r;
    let c2 = pk.point * *r + ProjectivePoint::GENERATOR * m_scalar;
    r.zeroize();
    m_scalar.zeroize();
    Ciphertext {
        c1,
        c2,
        key: Some(pk.encoded),
    }
}

fn merge_key(a: &Ciphertext, b: &Ciphertext) -> Result<Option<[u8; COMPRESSED_LEN]>> {
    match (a.key, b.key) {
        (Some(x), Some(y)) if x != y => Err(Error::KeyMismatch),
        (x, y) => Ok(x.or(y)),
    }
}

/// `Dec(add(Enc(x), Enc(y))) == x + y`.
pub fn add(a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
    Ok(Ciphertext {
        c1: a.c1 + b.c1,
        c2: a.c2 + b.c2,
        key: merge_key(a, b)?,
    })
}

/// `Dec(sub(Enc(x), Enc(y))) == x - y`.
pub fn sub(a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
    Ok(Ciphertext {
        c1: a.c1 - b.c1,
        c2: a.c2 - b.c2,
        key: merge_key(a, b)?,
    })
}

/// `Dec(neg(Enc(x))) == -x`.
pub fn neg(a: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c1: -a.c1,
        c2: -a.c2,
        key: a.key,
    }
}

/// Multiply by a *public* integer `k`: `Dec(scalar_mul(Enc(x), k)) == k*x`.
pub fn scalar_mul(a: &Ciphertext, k: i64) -> Ciphertext {
    let k = scalar_from_i64(k);
    Ciphertext {
        c1: a.c1 * k,
        c2: a.c2 * k,
        key: a.key,
    }
}

/// Decrypts ciphertexts whose plaintext lies in `[-max_value, max_value]`.
/// Holds a copy of the private key (zeroed on drop).
pub struct Decryptor {
    secret: PrivateKey,
    public: PublicKey,
    max_value: u64,
    m: u64,
    giant: ProjectivePoint,
    table: HashMap<[u8; COMPRESSED_LEN], u64>,
}

/// Canonical keys for a sequence of points, sharing one field inversion.
///
/// k256 0.13's batch normalization inverts every `z` coordinate at once and
/// panics if one of them is zero -- which it fails to detect when the
/// identity was produced by arithmetic (an unnormalised zero). Identities
/// are therefore swapped for the generator before normalising and mapped
/// back to the all-zero key afterwards, both branch-free.
fn batch_keys(points: &[ProjectivePoint]) -> Vec<[u8; COMPRESSED_LEN]> {
    let is_identity: Vec<Choice> = points.iter().map(|p| p.is_identity()).collect();
    let safe: Vec<ProjectivePoint> = points
        .iter()
        .zip(&is_identity)
        .map(|(p, id)| ProjectivePoint::conditional_select(p, &ProjectivePoint::GENERATOR, *id))
        .collect();
    let affine: Vec<AffinePoint> =
        <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(safe.as_slice());
    affine
        .iter()
        .zip(is_identity)
        .map(|(p, id)| {
            let mut key = [0u8; COMPRESSED_LEN];
            let encoded = p.to_encoded_point(true);
            if encoded.as_bytes().len() == COMPRESSED_LEN {
                key.copy_from_slice(encoded.as_bytes());
            }
            key.iter_mut().for_each(|b| b.conditional_assign(&0, id));
            key
        })
        .collect()
}

impl Decryptor {
    /// Build the baby-step table (`sqrt(max_value) + 2` points).
    pub fn new(sk: &PrivateKey, max_value: u64) -> Result<Self> {
        if max_value == 0 || max_value > MAX_SUPPORTED_RANGE {
            return Err(Error::InvalidRange);
        }
        let m = max_value.isqrt().saturating_add(1);
        let mut steps = Vec::new();
        let mut point = ProjectivePoint::IDENTITY;
        for _ in 0..=m {
            steps.push(point);
            point += ProjectivePoint::GENERATOR;
        }
        let table = batch_keys(&steps).into_iter().zip(0u64..).collect();
        Ok(Self {
            secret: sk.clone(),
            public: sk.public_key(),
            max_value,
            m,
            giant: -(ProjectivePoint::GENERATOR * Scalar::from(m)),
            table,
        })
    }

    /// The decryptable range bound.
    pub fn max_value(&self) -> u64 {
        self.max_value
    }

    /// The public key matching this decryptor's private key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Recover the plaintext. The search work is identical for every
    /// ciphertext (see the crate docs).
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<i64> {
        if ct.key.is_some_and(|k| k != self.public.encoded) {
            return Err(Error::KeyMismatch);
        }
        let mut sk = self.secret.scalar();
        let m_point = ct.c2 - ct.c1 * *sk;
        sk.zeroize();
        let (positive, _) = self.search(m_point);
        let (negative, _) = self.search(-m_point);
        let to_i64 = |v: u64| i64::try_from(v).map_err(|_| Error::PlaintextOutOfRange);
        match (positive, negative) {
            (Some(v), _) => to_i64(v),
            (None, Some(v)) => to_i64(v)?.checked_neg().ok_or(Error::PlaintextOutOfRange),
            (None, None) => Err(Error::PlaintextOutOfRange),
        }
    }

    /// Re-encrypt under this decryptor's own public key with fresh
    /// randomness ([ECFHE] Algorithm 5). Requires the private key -- only
    /// the key holder can run it.
    pub fn refresh(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        Ok(encrypt(&self.public, self.decrypt(ct)?))
    }

    /// Find `v <= max_value` with `v*G == target`, walking all `m + 1` giant
    /// steps. Returns the match and the number of steps taken.
    fn search(&self, target: ProjectivePoint) -> (Option<u64>, u64) {
        let mut walk = Vec::new();
        let mut point = target;
        for _ in 0..=self.m {
            walk.push(point);
            point += self.giant;
        }
        let mut found = None;
        let mut steps = 0u64;
        for (i, key) in (0u64..).zip(batch_keys(&walk)) {
            if let Some(&j) = self.table.get(&key) {
                let candidate = i.checked_mul(self.m).and_then(|v| v.checked_add(j));
                if found.is_none() && candidate.is_some_and(|c| c <= self.max_value) {
                    found = candidate;
                }
            }
            steps = steps.saturating_add(1);
        }
        (found, steps)
    }
}

impl fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Decryptor(max_value={})", self.max_value)
    }
}

/// `k*G` for a public 32-byte big-endian scalar `k` in `[0, n)`, encoded like
/// a ciphertext component (the identity for `k = 0`). Used to render the
/// source papers' `(aP, bP)` notation; not for secret scalars.
pub fn base_point_multiple(k: &[u8]) -> Result<Vec<u8>> {
    let k = crate::encoding::scalar_from_bytes(k)?;
    Ok(encode_point(&(ProjectivePoint::GENERATOR * k)))
}

/// Fixed-point encoding of a real number: `round(x * 10^precision)`
/// (the source paper's "standard mode"). Values sharing a `precision` can be
/// added under encryption.
pub fn fixed_point_encode(x: f64, precision: u32) -> Result<i64> {
    if precision > 18 || !x.is_finite() {
        return Err(Error::FixedPointOverflow);
    }
    let scaled =
        (x * 10f64.powi(i32::try_from(precision).map_err(|_| Error::FixedPointOverflow)?)).round();
    // i64::MAX as f64 rounds up to 2^63, so the bound must be strict.
    if !scaled.is_finite() || scaled.abs() >= 9_223_372_036_854_775_808.0 {
        return Err(Error::FixedPointOverflow);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(scaled as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn keys() -> (PrivateKey, PublicKey, Decryptor) {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        let dec = Decryptor::new(&sk, 100_000).unwrap();
        (sk, pk, dec)
    }

    #[test]
    fn roundtrip_including_zero_and_negative() {
        let (_, pk, dec) = keys();
        for m in [0, 1, -1, 42, -17, 100_000, -100_000] {
            assert_eq!(dec.decrypt(&encrypt(&pk, m)).unwrap(), m);
        }
    }

    #[test]
    fn out_of_range_is_an_error() {
        let (_, pk, dec) = keys();
        assert_eq!(
            dec.decrypt(&encrypt(&pk, 100_001)),
            Err(Error::PlaintextOutOfRange)
        );
    }

    #[test]
    fn homomorphic_operations() {
        let (_, pk, dec) = keys();
        let (a, b) = (encrypt(&pk, 30), encrypt(&pk, 12));
        assert_eq!(dec.decrypt(&add(&a, &b).unwrap()).unwrap(), 42);
        assert_eq!(dec.decrypt(&sub(&a, &b).unwrap()).unwrap(), 18);
        assert_eq!(dec.decrypt(&neg(&a)).unwrap(), -30);
        assert_eq!(dec.decrypt(&scalar_mul(&a, -3)).unwrap(), -90);
        assert_eq!(dec.decrypt(&scalar_mul(&a, 0)).unwrap(), 0);
    }

    #[test]
    fn key_mismatch_detected() {
        let (_, pk, dec) = keys();
        let other = PrivateKey::generate().public_key();
        let (a, b) = (encrypt(&pk, 1), encrypt(&other, 1));
        assert_eq!(add(&a, &b), Err(Error::KeyMismatch));
        assert_eq!(dec.decrypt(&b), Err(Error::KeyMismatch));
    }

    #[test]
    fn encryption_is_randomized() {
        let (_, pk, _) = keys();
        assert_ne!(encrypt(&pk, 5).to_bytes(), encrypt(&pk, 5).to_bytes());
    }

    #[test]
    fn serialization_roundtrip_including_identity() {
        let (_, pk, dec) = keys();
        for ct in [encrypt(&pk, 77), scalar_mul(&encrypt(&pk, 77), 0)] {
            let bytes = ct.to_bytes();
            let back = Ciphertext::from_bytes(&bytes, Some(&pk)).unwrap();
            assert_eq!(back, ct);
            assert_eq!(dec.decrypt(&back).unwrap(), dec.decrypt(&ct).unwrap());
        }
        assert_eq!(scalar_mul(&encrypt(&pk, 1), 0).to_bytes(), vec![1, 0, 0]);
        assert_eq!(PublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
    }

    fn off_curve() -> Vec<u8> {
        (1u8..=255)
            .map(|x| {
                let mut b = vec![0x02];
                b.extend_from_slice(&[0u8; 31]);
                b.push(x);
                b
            })
            .find(|b| decode_point(b).is_err())
            .unwrap()
    }

    #[test]
    fn malformed_inputs_rejected() {
        let (_, pk, _) = keys();
        let good = encrypt(&pk, 7).to_bytes();
        let mut bad_version = good.clone();
        bad_version[0] = 2;
        assert_eq!(
            Ciphertext::from_bytes(&bad_version, None),
            Err(Error::UnsupportedVersion)
        );
        assert!(Ciphertext::from_bytes(&good[..good.len() - 1], None).is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            Ciphertext::from_bytes(&trailing, None),
            Err(Error::MalformedEncoding)
        );
        let mut bad_prefix = good.clone();
        bad_prefix[1] = 0x05;
        assert!(Ciphertext::from_bytes(&bad_prefix, None).is_err());
        let mut forged = vec![1];
        forged.extend_from_slice(&off_curve());
        forged.push(0);
        assert_eq!(
            Ciphertext::from_bytes(&forged, None),
            Err(Error::InvalidPoint)
        );
        assert_eq!(
            PublicKey::from_bytes(&off_curve()),
            Err(Error::InvalidPoint)
        );
        assert_eq!(PublicKey::from_bytes(&[0]), Err(Error::IdentityPublicKey));
        // Uncompressed encodings are valid SEC1 but not canonical here.
        let uncompressed = pk.point.to_affine().to_encoded_point(false);
        assert_eq!(
            PublicKey::from_bytes(uncompressed.as_bytes()),
            Err(Error::InvalidPoint)
        );
    }

    #[test]
    fn private_key_validation_and_redaction() {
        assert!(PrivateKey::from_bytes(&[0u8; 32]).is_err());
        assert!(PrivateKey::from_bytes(&[0xffu8; 32]).is_err());
        assert!(PrivateKey::from_bytes(&[1u8; 31]).is_err());
        let sk = PrivateKey::generate();
        let exported = sk.export_secret_bytes();
        let again = PrivateKey::from_bytes(exported.as_ref()).unwrap();
        assert_eq!(again.public_key(), sk.public_key());
        assert_eq!(format!("{sk:?}"), "PrivateKey(<redacted>)");
        let dec = Decryptor::new(&sk, 10).unwrap();
        assert_eq!(format!("{dec:?}"), "Decryptor(max_value=10)");
    }

    #[test]
    fn decryptor_range_validated() {
        let sk = PrivateKey::generate();
        assert!(Decryptor::new(&sk, 0).is_err());
        assert!(Decryptor::new(&sk, MAX_SUPPORTED_RANGE + 1).is_err());
    }

    #[test]
    fn search_work_is_independent_of_plaintext() {
        let (sk, pk, dec) = keys();
        let mut step_counts = Vec::new();
        for m in [0i64, 1, 99_999, -99_999, 5_000_000] {
            let ct = encrypt(&pk, m);
            let mut s = sk.scalar();
            let m_point = ct.c2 - ct.c1 * *s;
            s.zeroize();
            let (_, pos_steps) = dec.search(m_point);
            let (_, neg_steps) = dec.search(-m_point);
            step_counts.push(pos_steps + neg_steps);
        }
        assert!(
            step_counts.windows(2).all(|w| w[0] == w[1]),
            "{step_counts:?}"
        );
    }

    #[test]
    fn refresh_preserves_plaintext_and_rerandomizes() {
        let (_, pk, dec) = keys();
        let ct = encrypt(&pk, 123);
        let fresh = dec.refresh(&ct).unwrap();
        assert_eq!(dec.decrypt(&fresh).unwrap(), 123);
        assert_ne!(fresh.to_bytes(), ct.to_bytes());
    }

    #[test]
    fn fixed_point() {
        assert_eq!(fixed_point_encode(12.345_67, 2).unwrap(), 1235);
        assert_eq!(fixed_point_encode(-2.5, 1).unwrap(), -25);
        assert!(fixed_point_encode(f64::NAN, 2).is_err());
        assert!(fixed_point_encode(1e300, 6).is_err());
        assert!(fixed_point_encode(1.0, 19).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn add_sub_scalar_mul_are_homomorphic(
            x in -20_000i64..20_000, y in -20_000i64..20_000, k in -4i64..=4
        ) {
            let (_, pk, dec) = keys();
            let (a, b) = (encrypt(&pk, x), encrypt(&pk, y));
            prop_assert_eq!(dec.decrypt(&add(&a, &b).unwrap()).unwrap(), x + y);
            prop_assert_eq!(dec.decrypt(&sub(&a, &b).unwrap()).unwrap(), x - y);
            prop_assert_eq!(dec.decrypt(&scalar_mul(&a, k)).unwrap(), x * k);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
            let _ = Ciphertext::from_bytes(&bytes, None);
            let _ = PublicKey::from_bytes(&bytes);
            let _ = PrivateKey::from_bytes(&bytes);
        }
    }
}
