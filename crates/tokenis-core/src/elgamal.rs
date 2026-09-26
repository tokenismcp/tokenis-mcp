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

use k256::elliptic_curve::BatchNormalize;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{LinearCombination, MulByGenerator};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, Zeroizing};

use crate::encoding::{
    COMPRESSED_LEN, decode_point, encode_point, point_key, random_nonzero_scalar, scalar_from_i64,
    split_point,
};
use crate::{Error, Result};

/// Ciphertext wire-format version byte.
pub const CIPHERTEXT_VERSION: u8 = 1;
/// Default decryptable range `[-2^24, 2^24]`.
pub const DEFAULT_MAX_VALUE: u64 = 1 << 24;
/// Largest supported decryptable range `[-2^40, 2^40]`.
pub const MAX_SUPPORTED_RANGE: u64 = 1 << 40;
/// Largest supported baby-step table: 2^24 entries, 8 bytes each (128 MiB).
pub const MAX_TABLE_SIZE: u64 = 1 << 24;
/// Largest number of giant steps one decryption may walk.
pub const MAX_GIANT_STEPS: u64 = 1 << 24;
/// Points normalised per batch inversion while building and searching; keeps
/// the search's working memory constant whatever the range.
const CHUNK: u64 = 1024;
/// Low bits of a packed table entry that hold the baby-step index.
const INDEX_BITS: u32 = 24;

/// A secp256k1 private key. Zeroed on drop, redacted from `Debug`.
#[derive(Clone)]
pub struct PrivateKey {
    secret: SecretKey,
}

impl PrivateKey {
    /// A fresh key from the operating system's CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut s = random_nonzero_scalar()?;
        let nz = Option::<NonZeroScalar>::from(NonZeroScalar::new(s));
        s.zeroize();
        let mut nz = nz.ok_or(Error::InvalidPrivateKey)?;
        let secret = SecretKey::from(nz);
        nz.zeroize();
        Ok(Self { secret })
    }

    /// A fresh key from a caller-supplied CSPRNG (deterministic testing,
    /// hardware RNGs). The bindings never expose this.
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
        let mut bytes = self.secret.to_bytes();
        let out = Zeroizing::new(bytes.into());
        AsMut::<[u8]>::as_mut(&mut bytes).zeroize();
        out
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        let mut s = self.scalar();
        let point = ProjectivePoint::mul_by_generator(&*s);
        s.zeroize();
        PublicKey::from_point(point)
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
pub fn encrypt(pk: &PublicKey, m: i64) -> Result<Ciphertext> {
    let mut r = random_nonzero_scalar()?;
    let ct = encrypt_with_scalar(pk, m, &r);
    r.zeroize();
    Ok(ct)
}

/// Encrypt `m` under `pk` with a caller-supplied CSPRNG (deterministic
/// testing). The bindings never expose this.
pub fn encrypt_with<R: RngCore + CryptoRng>(pk: &PublicKey, m: i64, rng: &mut R) -> Ciphertext {
    let mut r = NonZeroScalar::random(rng);
    let ct = encrypt_with_scalar(pk, m, &r);
    r.zeroize();
    ct
}

fn encrypt_with_scalar(pk: &PublicKey, m: i64, r: &Scalar) -> Ciphertext {
    let mut m_scalar = scalar_from_i64(m);
    // Both constant-time in k256: a precomputed-table fixed-base
    // multiplication, and a Straus-style two-point linear combination.
    let c1 = ProjectivePoint::mul_by_generator(r);
    let c2 = ProjectivePoint::lincomb(&pk.point, r, &ProjectivePoint::GENERATOR, &m_scalar);
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

/// `Dec(sum(cts)) == sum of the plaintexts`: one accumulation instead of a
/// chain of [`add`] calls. Errors on an empty input or mixed keys.
pub fn sum<'a>(cts: impl IntoIterator<Item = &'a Ciphertext>) -> Result<Ciphertext> {
    let mut iter = cts.into_iter();
    let first = iter.next().ok_or(Error::EmptyInput)?;
    let (mut c1, mut c2, mut key) = (first.c1, first.c2, first.key);
    for ct in iter {
        key = match (key, ct.key) {
            (Some(x), Some(y)) if x != y => return Err(Error::KeyMismatch),
            (x, y) => x.or(y),
        };
        c1 += ct.c1;
        c2 += ct.c2;
    }
    Ok(Ciphertext { c1, c2, key })
}

/// Wire encodings of many ciphertexts, normalising all their points with
/// one shared field inversion per batch instead of one per point. Output is
/// byte-identical to calling [`Ciphertext::to_bytes`] on each.
pub fn to_bytes_many(cts: &[Ciphertext]) -> Vec<Vec<u8>> {
    let mut points = Vec::with_capacity(cts.len() * 2);
    for ct in cts {
        points.push(ct.c1);
        points.push(ct.c2);
    }
    let keys = batch_keys(&points);
    keys.chunks_exact(2)
        .map(|pair| {
            let mut out = vec![CIPHERTEXT_VERSION];
            for key in pair {
                if key.iter().all(|b| *b == 0) {
                    out.push(crate::encoding::IDENTITY);
                } else {
                    out.extend_from_slice(key);
                }
            }
            out
        })
        .collect()
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

/// Canonical keys for a sequence of points, sharing one field inversion.
///
/// k256 0.13's batch normalization inverts every `z` coordinate at once and
/// panics if one of them is zero -- which it fails to detect when the
/// identity was produced by arithmetic (an unnormalised zero). Identities
/// are therefore swapped for the generator before normalising and mapped
/// back to the all-zero key afterwards, both branch-free.
fn batch_keys(points: &[ProjectivePoint]) -> Vec<[u8; COMPRESSED_LEN]> {
    // k256's batch inversion panics on an empty batch (found by fuzzing).
    if points.is_empty() {
        return Vec::new();
    }
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

/// The table's 40-bit tag for a point: bytes 1..6 of its canonical key (the
/// top of the x-coordinate). Tags can collide; every tag hit is verified
/// against the full point before it is accepted.
fn tag(key: &[u8; COMPRESSED_LEN]) -> u64 {
    key.iter()
        .skip(1)
        .take(5)
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

/// Walk `count` points `start, start + step, ...` in batches of [`CHUNK`],
/// calling `visit(index, key)` for each. Working memory is O(CHUNK).
fn walk(
    start: ProjectivePoint,
    step: ProjectivePoint,
    count: u64,
    mut visit: impl FnMut(u64, &[u8; COMPRESSED_LEN]),
) {
    let mut point = start;
    let mut index = 0u64;
    let mut batch = Vec::new();
    while index < count {
        let len = CHUNK.min(count - index);
        batch.clear();
        for _ in 0..len {
            batch.push(point);
            point += step;
        }
        for (offset, key) in (0u64..).zip(batch_keys(&batch)) {
            visit(index + offset, &key);
        }
        index += len;
    }
}

/// Decrypts ciphertexts whose plaintext lies in `[-max_value, max_value]`
/// by baby-step-giant-step over the shifted range `[0, 2*max_value]`.
/// Holds a copy of the private key (zeroed on drop).
///
/// Memory: 8 bytes per baby-step table entry plus a constant-size search
/// buffer. Time per decryption: one pass over `ceil((2*max_value+1) /
/// table_size)` giant steps. The default table size balances the two;
/// [`Decryptor::with_table_size`] trades memory for speed.
pub struct Decryptor {
    secret: PrivateKey,
    public: PublicKey,
    max_value: u64,
    table_size: u64,
    giant_steps: u64,
    offset: ProjectivePoint,
    giant: ProjectivePoint,
    /// Sorted `(tag << INDEX_BITS) | j` for `j*G`, `j < table_size`.
    table: Vec<u64>,
}

impl Decryptor {
    /// A decryptor with a table of about `sqrt(2*max_value)` entries.
    pub fn new(sk: &PrivateKey, max_value: u64) -> Result<Self> {
        if max_value == 0 || max_value > MAX_SUPPORTED_RANGE {
            return Err(Error::InvalidRange);
        }
        let span = 2 * max_value + 1;
        Self::with_table_size(sk, max_value, (span.isqrt() + 1).min(MAX_TABLE_SIZE))
    }

    /// A decryptor with an explicit baby-step table size (clamped to the
    /// range): larger tables make each decryption proportionally faster.
    pub fn with_table_size(sk: &PrivateKey, max_value: u64, table_size: u64) -> Result<Self> {
        if max_value == 0 || max_value > MAX_SUPPORTED_RANGE {
            return Err(Error::InvalidRange);
        }
        if table_size == 0 || table_size > MAX_TABLE_SIZE {
            return Err(Error::InvalidRange);
        }
        let span = 2 * max_value + 1;
        let table_size = table_size.min(span);
        let giant_steps = span.div_ceil(table_size);
        if giant_steps > MAX_GIANT_STEPS {
            return Err(Error::InvalidRange);
        }
        let capacity = usize::try_from(table_size).map_err(|_| Error::InvalidRange)?;
        let mut table = Vec::with_capacity(capacity);
        walk(
            ProjectivePoint::IDENTITY,
            ProjectivePoint::GENERATOR,
            table_size,
            |j, key| table.push((tag(key) << INDEX_BITS) | j),
        );
        table.sort_unstable();
        Ok(Self {
            secret: sk.clone(),
            public: sk.public_key(),
            max_value,
            table_size,
            giant_steps,
            offset: ProjectivePoint::GENERATOR * Scalar::from(max_value),
            giant: -(ProjectivePoint::GENERATOR * Scalar::from(table_size)),
            table,
        })
    }

    /// The decryptable range bound.
    pub fn max_value(&self) -> u64 {
        self.max_value
    }

    /// The baby-step table size in entries.
    pub fn table_size(&self) -> u64 {
        self.table_size
    }

    /// The public key matching this decryptor's private key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Recover the plaintext. Every call walks the same number of giant
    /// steps (see the crate docs for what that does and does not hide).
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<i64> {
        if ct.key.is_some_and(|k| k != self.public.encoded) {
            return Err(Error::KeyMismatch);
        }
        let mut sk = self.secret.scalar();
        let m_point = ct.c2 - ct.c1 * *sk;
        sk.zeroize();
        let (found, _) = self.search(m_point + self.offset);
        let shifted = found.ok_or(Error::PlaintextOutOfRange)?;
        let shifted = i64::try_from(shifted).map_err(|_| Error::PlaintextOutOfRange)?;
        let max = i64::try_from(self.max_value).map_err(|_| Error::PlaintextOutOfRange)?;
        Ok(shifted - max)
    }

    /// Re-encrypt under this decryptor's own public key with fresh
    /// randomness ([ECFHE] Algorithm 5). Requires the private key -- only
    /// the key holder can run it.
    pub fn refresh(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        encrypt(&self.public, self.decrypt(ct)?)
    }

    /// Find `v <= 2*max_value` with `v*G == target`, walking all giant
    /// steps whether or not (and wherever) it is found. Returns the match
    /// and the number of giant steps taken.
    fn search(&self, target: ProjectivePoint) -> (Option<u64>, u64) {
        let span = 2 * self.max_value + 1;
        let mut found = None;
        let mut steps = 0u64;
        walk(target, self.giant, self.giant_steps, |i, key| {
            steps += 1;
            let wanted = tag(key) << INDEX_BITS;
            let first = self.table.partition_point(|e| *e < wanted);
            for entry in self.table.iter().skip(first) {
                if entry >> INDEX_BITS != wanted >> INDEX_BITS {
                    break;
                }
                let j = entry & ((1 << INDEX_BITS) - 1);
                let verified = point_key(&(ProjectivePoint::GENERATOR * Scalar::from(j))) == *key;
                let candidate = i
                    .checked_mul(self.table_size)
                    .and_then(|v| v.checked_add(j));
                if verified && found.is_none() && candidate.is_some_and(|c| c < span) {
                    found = candidate;
                }
            }
        });
        (found, steps)
    }
}

impl fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Decryptor(max_value={}, table_size={})",
            self.max_value, self.table_size
        )
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
        let sk = PrivateKey::generate().unwrap();
        let pk = sk.public_key();
        let dec = Decryptor::new(&sk, 100_000).unwrap();
        (sk, pk, dec)
    }

    fn enc(pk: &PublicKey, m: i64) -> Ciphertext {
        encrypt(pk, m).unwrap()
    }

    #[test]
    fn roundtrip_including_zero_and_negative() {
        let (_, pk, dec) = keys();
        for m in [0, 1, -1, 42, -17, 99_999, 100_000, -100_000] {
            assert_eq!(dec.decrypt(&enc(&pk, m)).unwrap(), m);
        }
    }

    #[test]
    fn out_of_range_is_an_error() {
        let (_, pk, dec) = keys();
        for m in [100_001, -100_001, i64::MAX, i64::MIN] {
            assert_eq!(dec.decrypt(&enc(&pk, m)), Err(Error::PlaintextOutOfRange));
        }
    }

    #[test]
    fn every_value_at_the_range_edges_decrypts_for_many_table_sizes() {
        let sk = PrivateKey::generate().unwrap();
        let pk = sk.public_key();
        for (max, table) in [
            (1, 1),
            (7, 2),
            (7, 15),
            (300, 1),
            (300, 17),
            (300, 1000),
            (1000, 64),
        ] {
            let dec = Decryptor::with_table_size(&sk, max, table).unwrap();
            let max_i = i64::try_from(max).unwrap();
            for m in [-max_i, -max_i + 1, -1, 0, 1, max_i - 1, max_i] {
                assert_eq!(
                    dec.decrypt(&enc(&pk, m)).unwrap(),
                    m,
                    "max={max} table={table}"
                );
            }
            for m in [-max_i - 1, max_i + 1] {
                assert_eq!(dec.decrypt(&enc(&pk, m)), Err(Error::PlaintextOutOfRange));
            }
        }
    }

    #[test]
    fn large_tables_decrypt_large_values() {
        let sk = PrivateKey::generate().unwrap();
        let pk = sk.public_key();
        let dec = Decryptor::with_table_size(&sk, 1 << 36, 1 << 20).unwrap();
        for m in [(1i64 << 36), -(1i64 << 36), 12_345_678_901, -987_654_321] {
            assert_eq!(dec.decrypt(&enc(&pk, m)).unwrap(), m);
        }
    }

    #[test]
    fn homomorphic_operations() {
        let (_, pk, dec) = keys();
        let (a, b) = (enc(&pk, 30), enc(&pk, 12));
        assert_eq!(dec.decrypt(&add(&a, &b).unwrap()).unwrap(), 42);
        assert_eq!(dec.decrypt(&sub(&a, &b).unwrap()).unwrap(), 18);
        assert_eq!(dec.decrypt(&neg(&a)).unwrap(), -30);
        assert_eq!(dec.decrypt(&scalar_mul(&a, -3)).unwrap(), -90);
        assert_eq!(dec.decrypt(&scalar_mul(&a, 0)).unwrap(), 0);
    }

    #[test]
    fn sum_matches_repeated_add_and_rejects_bad_input() {
        let (_, pk, dec) = keys();
        let cts: Vec<Ciphertext> = (-5..=20).map(|m| enc(&pk, m * 37)).collect();
        let expected: i64 = (-5..=20).map(|m| m * 37).sum();
        assert_eq!(dec.decrypt(&sum(&cts).unwrap()).unwrap(), expected);
        assert_eq!(sum(std::iter::empty()), Err(Error::EmptyInput));
        let other = enc(&PrivateKey::generate().unwrap().public_key(), 1);
        assert_eq!(sum([&cts[0], &other]), Err(Error::KeyMismatch));
    }

    #[test]
    fn fast_paths_match_the_textbook_formulas() {
        // mul_by_generator / lincomb must agree with plain scalar
        // multiplication, or ciphertexts would not decrypt.
        let sk = PrivateKey::generate().unwrap();
        let pk = sk.public_key();
        let s = sk.scalar();
        assert_eq!(pk.point, ProjectivePoint::GENERATOR * *s);
        let r = Scalar::from(123_456_789u64);
        let ct = encrypt_with_scalar(&pk, -42, &r);
        assert_eq!(ct.c1, ProjectivePoint::GENERATOR * r);
        assert_eq!(
            ct.c2,
            pk.point * r - ProjectivePoint::GENERATOR * Scalar::from(42u64)
        );
    }

    #[test]
    fn batched_encoding_of_nothing_is_nothing() {
        // Regression: k256's batch inversion panicked on an empty batch
        // (found by fuzz/fuzz_targets/elgamal_arithmetic.rs).
        assert!(to_bytes_many(&[]).is_empty());
    }

    #[test]
    fn batched_encoding_matches_one_by_one() {
        let (_, pk, _) = keys();
        let mut cts: Vec<Ciphertext> = (-20..20).map(|m| enc(&pk, m)).collect();
        cts.push(scalar_mul(&enc(&pk, 5), 0)); // identity components
        let batched = to_bytes_many(&cts);
        for (ct, bytes) in cts.iter().zip(&batched) {
            assert_eq!(&ct.to_bytes(), bytes);
        }
    }

    #[test]
    fn key_mismatch_detected() {
        let (_, pk, dec) = keys();
        let other = PrivateKey::generate().unwrap().public_key();
        let (a, b) = (enc(&pk, 1), enc(&other, 1));
        assert_eq!(add(&a, &b), Err(Error::KeyMismatch));
        assert_eq!(dec.decrypt(&b), Err(Error::KeyMismatch));
    }

    #[test]
    fn encryption_is_randomized() {
        let (_, pk, _) = keys();
        assert_ne!(enc(&pk, 5).to_bytes(), enc(&pk, 5).to_bytes());
    }

    #[test]
    fn serialization_roundtrip_including_identity() {
        let (_, pk, dec) = keys();
        for ct in [enc(&pk, 77), scalar_mul(&enc(&pk, 77), 0)] {
            let bytes = ct.to_bytes();
            let back = Ciphertext::from_bytes(&bytes, Some(&pk)).unwrap();
            assert_eq!(back, ct);
            assert_eq!(dec.decrypt(&back).unwrap(), dec.decrypt(&ct).unwrap());
        }
        assert_eq!(scalar_mul(&enc(&pk, 1), 0).to_bytes(), vec![1, 0, 0]);
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
        let good = enc(&pk, 7).to_bytes();
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
        let sk = PrivateKey::generate().unwrap();
        let exported = sk.export_secret_bytes();
        let again = PrivateKey::from_bytes(exported.as_ref()).unwrap();
        assert_eq!(again.public_key(), sk.public_key());
        assert_eq!(
            sk.public_key(),
            PublicKey::from_point(sk.secret.public_key().to_projective())
        );
        assert_eq!(format!("{sk:?}"), "PrivateKey(<redacted>)");
        let dec = Decryptor::new(&sk, 10).unwrap();
        assert_eq!(format!("{dec:?}"), "Decryptor(max_value=10, table_size=5)");
    }

    #[test]
    fn decryptor_bounds_validated() {
        let sk = PrivateKey::generate().unwrap();
        assert_eq!(Decryptor::new(&sk, 0).unwrap_err(), Error::InvalidRange);
        assert_eq!(
            Decryptor::new(&sk, MAX_SUPPORTED_RANGE + 1).unwrap_err(),
            Error::InvalidRange
        );
        assert_eq!(
            Decryptor::with_table_size(&sk, 100, 0).unwrap_err(),
            Error::InvalidRange
        );
        assert_eq!(
            Decryptor::with_table_size(&sk, 100, MAX_TABLE_SIZE + 1).unwrap_err(),
            Error::InvalidRange
        );
        // A tiny table over a huge range would mean an unbounded walk.
        assert_eq!(
            Decryptor::with_table_size(&sk, MAX_SUPPORTED_RANGE, 1).unwrap_err(),
            Error::InvalidRange
        );
        // Oversized tables are clamped to the range.
        assert_eq!(
            Decryptor::with_table_size(&sk, 3, 1000)
                .unwrap()
                .table_size(),
            7
        );
    }

    #[test]
    fn search_step_count_is_independent_of_plaintext() {
        // Pins the claim the crate docs make -- a constant number of giant
        // steps -- and no more: memory access patterns still depend on the
        // plaintext (see lib.rs).
        let (sk, pk, dec) = keys();
        let mut step_counts = Vec::new();
        for m in [0i64, 1, 99_999, -99_999, 5_000_000] {
            let ct = enc(&pk, m);
            let mut s = sk.scalar();
            let m_point = ct.c2 - ct.c1 * *s;
            s.zeroize();
            step_counts.push(dec.search(m_point + dec.offset).1);
        }
        assert!(
            step_counts.iter().all(|c| *c == dec.giant_steps),
            "{step_counts:?}"
        );
    }

    #[test]
    fn negative_plaintexts_are_branch_free_encoded() {
        for m in [i64::MIN, -1, 0, 1, i64::MAX] {
            let expected = if m < 0 {
                -Scalar::from(m.unsigned_abs())
            } else {
                Scalar::from(m.unsigned_abs())
            };
            assert_eq!(scalar_from_i64(m), expected);
        }
    }

    #[test]
    fn refresh_preserves_plaintext_and_rerandomizes() {
        let (_, pk, dec) = keys();
        let ct = enc(&pk, 123);
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
            let (a, b) = (enc(&pk, x), enc(&pk, y));
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
