// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
use core::fmt;

/// Every failure this crate can report. Deliberately coarse: error values
/// never carry secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Bytes are not a canonical SEC1 compressed secp256k1 point (or the
    /// one-byte identity encoding where the identity is allowed).
    InvalidPoint,
    /// A public key was the point at infinity.
    IdentityPublicKey,
    /// Bytes are not a valid private scalar in `[1, n)`.
    InvalidPrivateKey,
    /// Bytes are not a canonical scalar in `[0, n)`.
    InvalidScalar,
    /// Unknown ciphertext wire-format version.
    UnsupportedVersion,
    /// Input ended early or had trailing bytes.
    MalformedEncoding,
    /// Ciphertexts (or a ciphertext and a key) belong to different keys.
    KeyMismatch,
    /// The plaintext is outside the decryptor's `[-max_value, max_value]`.
    PlaintextOutOfRange,
    /// A decryptor range or table size outside the supported bounds (see
    /// [`crate::elgamal::MAX_SUPPORTED_RANGE`] and
    /// [`crate::elgamal::MAX_TABLE_SIZE`]).
    InvalidRange,
    /// A Beaver triple was opened a second time, or was never issued by
    /// this owner's current session.
    TripleReused,
    /// A Beaver triple produced by a different owner.
    ForeignTriple,
    /// A mask or affine correction produced by a different owner.
    ForeignOwner,
    /// The operating system's random number generator failed.
    RandomnessUnavailable,
    /// Affine coefficient and value counts differ.
    LengthMismatch,
    /// A fixed-point input was not finite or does not fit after scaling.
    FixedPointOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidPoint => "not a canonical compressed secp256k1 point",
            Self::IdentityPublicKey => "a public key cannot be the point at infinity",
            Self::InvalidPrivateKey => "private key must be a scalar in [1, n)",
            Self::InvalidScalar => "not a canonical scalar in [0, n)",
            Self::UnsupportedVersion => "unsupported ciphertext encoding version",
            Self::MalformedEncoding => "truncated input or trailing bytes",
            Self::KeyMismatch => "ciphertext and key (or two ciphertexts) belong to different keys",
            Self::PlaintextOutOfRange => "plaintext outside the decryptor's range",
            Self::InvalidRange => {
                "max_value must be in [1, 2^40], table_size in [1, 2^24], and the \
                 giant-step count they imply at most 2^24"
            }
            Self::TripleReused => {
                "Beaver triple already consumed; reusing one breaks the secrecy proof"
            }
            Self::ForeignTriple => "Beaver triple was produced by a different Owner",
            Self::ForeignOwner => "mask or correction was produced by a different Owner",
            Self::RandomnessUnavailable => "the operating system's random number generator failed",
            Self::LengthMismatch => "coefficient and value counts differ",
            Self::FixedPointOverflow => "fixed-point value not finite or out of i64 range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
