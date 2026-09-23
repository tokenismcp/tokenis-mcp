// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! WebAssembly bindings for `tokenis-core`, consumed by the TypeScript SDK
//! (`sdk/typescript`). Same core, same wire format as the Python SDK.
//!
//! Secrets (private keys, masks, corrections, Beaver triples) live in WASM
//! linear memory and are zeroed when freed; JavaScript holds opaque handles.
//! Randomness comes from `crypto.getRandomValues`. Plaintexts and other
//! integers cross as `bigint` and are range-checked here: wasm-bindgen's own
//! `i64` conversion silently wraps values outside 64 bits, so no exported
//! function takes a raw `i64`.

use js_sys::{Array, BigInt, Uint8Array};
use tokenis_core::delegation as dl;
use tokenis_core::elgamal as eg;
use wasm_bindgen::prelude::*;

fn to_i64(value: BigInt, what: &str) -> Result<i64, JsError> {
    i64::try_from(value)
        .map_err(|_| JsError::new(&format!("{what} must fit in a signed 64-bit integer")))
}

fn to_u64(value: BigInt, what: &str) -> Result<u64, JsError> {
    u64::try_from(value)
        .map_err(|_| JsError::new(&format!("{what} must fit in an unsigned 64-bit integer")))
}

/// Coefficients arrive as an array of `bigint`s (not a `BigInt64Array`,
/// whose element assignment already wraps silently).
fn coefficients_from(array: &Array) -> Result<Vec<i64>, JsError> {
    array
        .iter()
        .map(|v| {
            i64::try_from(v).map_err(|_| {
                JsError::new("coefficients must be bigints in the signed 64-bit range")
            })
        })
        .collect()
}

fn err(e: tokenis_core::Error) -> JsError {
    JsError::new(&e.to_string())
}

fn consumed(what: &str) -> JsError {
    JsError::new(&format!(
        "this {what} has already been used; one-time values cannot be reused"
    ))
}

/// A secp256k1 private key held in WASM memory (zeroed when freed).
#[wasm_bindgen]
pub struct PrivateKey(eg::PrivateKey);

#[wasm_bindgen]
impl PrivateKey {
    /// Generate a key from `crypto.getRandomValues`.
    pub fn generate() -> Result<PrivateKey, JsError> {
        eg::PrivateKey::generate().map(PrivateKey).map_err(err)
    }

    /// Import a 32-byte big-endian scalar in [1, n).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<PrivateKey, JsError> {
        eg::PrivateKey::from_bytes(data)
            .map(PrivateKey)
            .map_err(err)
    }

    /// Export the 32-byte secret scalar (the returned array is ordinary JS
    /// memory; overwrite it when done). Copied straight from a buffer that is
    /// zeroed on drop, so no copy is left behind in WASM memory.
    #[wasm_bindgen(js_name = exportSecretBytes)]
    pub fn export_secret_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.0.export_secret_bytes().as_slice())
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        "PrivateKey(<redacted>)".into()
    }
}

/// A secp256k1 public key (33-byte SEC1 compressed).
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicKey(eg::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<PublicKey, JsError> {
        eg::PublicKey::from_bytes(data).map(PublicKey).map_err(err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn equals(&self, other: &PublicKey) -> bool {
        self.0 == other.0
    }
}

/// An EC-ElGamal ciphertext.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Ciphertext(eg::Ciphertext);

#[wasm_bindgen]
impl Ciphertext {
    /// Parse and validate the versioned wire format.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<Ciphertext, JsError> {
        eg::Ciphertext::from_bytes(data, None)
            .map(Ciphertext)
            .map_err(err)
    }

    /// Parse and validate, tagging the result with `public` so key
    /// mismatches are caught. Borrows `public` (an owned parameter would
    /// invalidate the caller's handle).
    #[wasm_bindgen(js_name = fromBytesWithKey)]
    pub fn from_bytes_with_key(data: &[u8], public: &PublicKey) -> Result<Ciphertext, JsError> {
        eg::Ciphertext::from_bytes(data, Some(&public.0))
            .map(Ciphertext)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Homomorphic addition.
    pub fn add(&self, other: &Ciphertext) -> Result<Ciphertext, JsError> {
        eg::add(&self.0, &other.0).map(Ciphertext).map_err(err)
    }

    /// Homomorphic subtraction.
    pub fn sub(&self, other: &Ciphertext) -> Result<Ciphertext, JsError> {
        eg::sub(&self.0, &other.0).map(Ciphertext).map_err(err)
    }

    /// Homomorphic negation.
    pub fn neg(&self) -> Ciphertext {
        Ciphertext(eg::neg(&self.0))
    }

    /// Multiply by a public integer (a signed 64-bit `bigint`).
    pub fn mul(&self, k: BigInt) -> Result<Ciphertext, JsError> {
        Ok(Ciphertext(eg::scalar_mul(
            &self.0,
            to_i64(k, "multiplier")?,
        )))
    }

    pub fn equals(&self, other: &Ciphertext) -> bool {
        self.0 == other.0
    }
}

/// Decrypts ciphertexts with plaintexts in [-maxValue, maxValue].
#[wasm_bindgen]
pub struct Decryptor(eg::Decryptor);

#[wasm_bindgen]
impl Decryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(sk: &PrivateKey, max_value: Option<BigInt>) -> Result<Decryptor, JsError> {
        let max_value = match max_value {
            Some(v) => to_u64(v, "maxValue")?,
            None => eg::DEFAULT_MAX_VALUE,
        };
        eg::Decryptor::new(&sk.0, max_value)
            .map(Decryptor)
            .map_err(err)
    }

    /// A decryptor with an explicit baby-step table size: 8 bytes per entry,
    /// and each decryption gets proportionally faster.
    #[wasm_bindgen(js_name = withTableSize)]
    pub fn with_table_size(
        sk: &PrivateKey,
        max_value: BigInt,
        table_size: BigInt,
    ) -> Result<Decryptor, JsError> {
        eg::Decryptor::with_table_size(
            &sk.0,
            to_u64(max_value, "maxValue")?,
            to_u64(table_size, "tableSize")?,
        )
        .map(Decryptor)
        .map_err(err)
    }

    pub fn decrypt(&self, ct: &Ciphertext) -> Result<i64, JsError> {
        self.0.decrypt(&ct.0).map_err(err)
    }

    /// Re-encrypt under this key with fresh randomness (key holder only).
    pub fn refresh(&self, ct: &Ciphertext) -> Result<Ciphertext, JsError> {
        self.0.refresh(&ct.0).map(Ciphertext).map_err(err)
    }

    #[wasm_bindgen(getter, js_name = maxValue)]
    pub fn max_value(&self) -> u64 {
        self.0.max_value()
    }

    #[wasm_bindgen(getter, js_name = tableSize)]
    pub fn table_size(&self) -> u64 {
        self.0.table_size()
    }
}

/// Encrypt `m` (a signed 64-bit `bigint`) under `pk`.
#[wasm_bindgen]
pub fn encrypt(pk: &PublicKey, m: BigInt) -> Result<Ciphertext, JsError> {
    eg::encrypt(&pk.0, to_i64(m, "plaintext")?)
        .map(Ciphertext)
        .map_err(err)
}

/// `round(x * 10^precision)`, half away from zero -- identical to the Rust
/// and Python encoders.
#[wasm_bindgen(js_name = fixedPointEncode)]
pub fn fixed_point_encode(x: f64, precision: u32) -> Result<i64, JsError> {
    eg::fixed_point_encode(x, precision).map_err(err)
}

// ---------------------------------------------------------------------------
// No-key delegation. Values cross as 32-byte big-endian integers mod n; the
// TypeScript wrapper converts to and from bigint.
// ---------------------------------------------------------------------------

/// A one-time pad (consumed by `Owner.unblind` / `Owner.refresh`).
#[wasm_bindgen]
pub struct Mask(Option<dl::Mask>);

/// An affine correction (consumed by `Owner.unblindAffine`).
#[wasm_bindgen]
pub struct Correction(Option<dl::Correction>);

/// A Beaver triple (consumed by `Owner.reconstructMultiplication`).
#[wasm_bindgen]
pub struct MultiplicationTriple(Option<dl::MultiplicationTriple>);

macro_rules! consumable {
    ($ty:ident) => {
        #[wasm_bindgen]
        impl $ty {
            #[wasm_bindgen(getter)]
            pub fn consumed(&self) -> bool {
                self.0.is_none()
            }
        }
    };
}
consumable!(Mask);
consumable!(Correction);
consumable!(MultiplicationTriple);

/// A masked value: uniform, safe to hand to an untrusted server.
#[wasm_bindgen]
#[derive(Clone)]
pub struct MaskedValue(dl::MaskedValue);

#[wasm_bindgen]
impl MaskedValue {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MaskedValue, JsError> {
        dl::MaskedValue::from_bytes(data)
            .map(MaskedValue)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// The (e, g) opening a server sees in one masked multiplication.
#[wasm_bindgen]
#[derive(Clone)]
pub struct MultiplicationOpening(dl::MultiplicationOpening);

#[wasm_bindgen]
impl MultiplicationOpening {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MultiplicationOpening, JsError> {
        dl::MultiplicationOpening::from_bytes(data)
            .map(MultiplicationOpening)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

fn scalar(data: &[u8]) -> Result<dl::Value, JsError> {
    dl::value_from_bytes(data).map_err(err)
}

fn bytes(value: &dl::Value) -> Vec<u8> {
    dl::value_to_bytes(value).to_vec()
}

/// Move a one-time secret out of its handle -- but only after checking it
/// belongs to `owner`, so a mismatch leaves the caller's handle intact.
fn take_owned<T: dl::OwnedSecret>(
    owner: &dl::Owner,
    slot: &mut Option<T>,
    what: &str,
    foreign: tokenis_core::Error,
) -> Result<T, JsError> {
    match slot.as_ref() {
        None => Err(consumed(what)),
        Some(secret) if !owner.owns(secret) => Err(err(foreign)),
        Some(_) => slot.take().ok_or_else(|| consumed(what)),
    }
}

/// Result of `Owner.blind`: the masked value to send, and the mask to keep.
#[wasm_bindgen]
pub struct Blinded {
    masked: Option<MaskedValue>,
    mask: Option<Mask>,
}

#[wasm_bindgen]
impl Blinded {
    /// The masked value (safe to send). Can be taken once.
    #[wasm_bindgen(js_name = takeMasked)]
    pub fn take_masked(&mut self) -> Result<MaskedValue, JsError> {
        self.masked.take().ok_or_else(|| consumed("masked value"))
    }

    /// The mask (keep secret). Can be taken once.
    #[wasm_bindgen(js_name = takeMask)]
    pub fn take_mask(&mut self) -> Result<Mask, JsError> {
        self.mask.take().ok_or_else(|| consumed("mask"))
    }
}

/// Result of `Owner.delegateAffine`.
#[wasm_bindgen]
pub struct AffineDelegation {
    masked: Vec<MaskedValue>,
    correction: Option<Correction>,
}

#[wasm_bindgen]
impl AffineDelegation {
    /// The masked inputs to send to the server.
    #[wasm_bindgen(js_name = maskedValues)]
    pub fn masked_values(&self) -> Vec<MaskedValue> {
        self.masked.clone()
    }

    /// The correction to keep. Can be taken once.
    #[wasm_bindgen(js_name = takeCorrection)]
    pub fn take_correction(&mut self) -> Result<Correction, JsError> {
        self.correction.take().ok_or_else(|| consumed("correction"))
    }
}

/// The key-holding party of the no-key delegation protocol.
#[wasm_bindgen]
pub struct Owner(dl::Owner);

#[wasm_bindgen]
impl Owner {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Owner, JsError> {
        dl::Owner::new().map(Owner).map_err(err)
    }

    pub fn blind(&self, value: &[u8]) -> Result<Blinded, JsError> {
        let (masked, mask) = self.0.blind(&scalar(value)?).map_err(err)?;
        Ok(Blinded {
            masked: Some(MaskedValue(masked)),
            mask: Some(Mask(Some(mask))),
        })
    }

    pub fn unblind(&self, masked: &MaskedValue, mask: &mut Mask) -> Result<Vec<u8>, JsError> {
        let mask = take_owned(
            &self.0,
            &mut mask.0,
            "mask",
            tokenis_core::Error::ForeignOwner,
        )?;
        self.0
            .unblind(&masked.0, mask)
            .map(|v| bytes(&v))
            .map_err(err)
    }

    /// `coefficients`: an array of `bigint`s. `values`: the inputs as
    /// consecutive 32-byte big-endian integers.
    #[wasm_bindgen(js_name = delegateAffine)]
    pub fn delegate_affine(
        &self,
        coefficients: &Array,
        values: &[u8],
    ) -> Result<AffineDelegation, JsError> {
        let coefficients = coefficients_from(coefficients)?;
        if values.len() % 32 != 0 {
            return Err(JsError::new("values must be consecutive 32-byte integers"));
        }
        let values = values
            .chunks_exact(32)
            .map(scalar)
            .collect::<Result<Vec<_>, _>>()?;
        let (masked, correction) = self
            .0
            .delegate_affine(&coefficients, &values)
            .map_err(err)?;
        Ok(AffineDelegation {
            masked: masked.into_iter().map(MaskedValue).collect(),
            correction: Some(Correction(Some(correction))),
        })
    }

    #[wasm_bindgen(js_name = unblindAffine)]
    pub fn unblind_affine(
        &self,
        result: &MaskedValue,
        correction: &mut Correction,
    ) -> Result<Vec<u8>, JsError> {
        let correction = take_owned(
            &self.0,
            &mut correction.0,
            "correction",
            tokenis_core::Error::ForeignOwner,
        )?;
        self.0
            .unblind_affine(&result.0, correction)
            .map(|v| bytes(&v))
            .map_err(err)
    }

    #[wasm_bindgen(js_name = prepareTriple)]
    pub fn prepare_triple(&mut self) -> Result<MultiplicationTriple, JsError> {
        self.0
            .prepare_triple()
            .map(|t| MultiplicationTriple(Some(t)))
            .map_err(err)
    }

    #[wasm_bindgen(js_name = openMultiplication)]
    pub fn open_multiplication(
        &mut self,
        s: &[u8],
        t: &[u8],
        triple: &MultiplicationTriple,
    ) -> Result<MultiplicationOpening, JsError> {
        let triple = triple.0.as_ref().ok_or_else(|| consumed("triple"))?;
        self.0
            .open_multiplication(&scalar(s)?, &scalar(t)?, triple)
            .map(MultiplicationOpening)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = reconstructMultiplication)]
    pub fn reconstruct_multiplication(
        &self,
        triple: &mut MultiplicationTriple,
        opening: &MultiplicationOpening,
        eg_value: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let eg_scalar = scalar(eg_value)?;
        let triple = take_owned(
            &self.0,
            &mut triple.0,
            "triple",
            tokenis_core::Error::ForeignTriple,
        )?;
        self.0
            .reconstruct_multiplication(triple, &opening.0, &eg_scalar)
            .map(|v| bytes(&v))
            .map_err(err)
    }
}

/// Server side of affine delegation. `coefficients`: an array of `bigint`s.
/// `masked`: the masked inputs as consecutive 32-byte encodings (taking
/// handles by value would invalidate the caller's objects).
#[wasm_bindgen(js_name = evaluateAffineMasked)]
pub fn evaluate_affine_masked(
    coefficients: &Array,
    intercept: &[u8],
    masked: &[u8],
) -> Result<MaskedValue, JsError> {
    let coefficients = coefficients_from(coefficients)?;
    if masked.len() % 32 != 0 {
        return Err(JsError::new(
            "masked values must be consecutive 32-byte encodings",
        ));
    }
    let masked = masked
        .chunks_exact(32)
        .map(|c| dl::MaskedValue::from_bytes(c).map_err(err))
        .collect::<Result<Vec<_>, _>>()?;
    dl::evaluate_affine_masked(&coefficients, &scalar(intercept)?, &masked)
        .map(MaskedValue)
        .map_err(err)
}

/// Server side of masked multiplication.
#[wasm_bindgen(js_name = combineMultiplication)]
pub fn combine_multiplication(opening: &MultiplicationOpening) -> Vec<u8> {
    bytes(&dl::combine_multiplication(&opening.0))
}
