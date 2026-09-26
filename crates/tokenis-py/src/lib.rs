// Copyright 2026 4Chains Inc.
// SPDX-License-Identifier: Apache-2.0
//! `tokenis._core`: Python bindings for `tokenis-core`.
//!
//! Secret material (private keys, masks, corrections, Beaver triples) stays
//! in Rust memory that is zeroed on drop; Python only ever holds opaque
//! handles. None of these handles can be pickled or copied. Consumable
//! handles (masks, corrections, triples) are emptied by the operation that
//! uses them, so a second use raises instead of silently reusing a pad; a
//! handle offered to the wrong `Owner` is rejected *before* it is emptied.
//!
//! Re-entrant use of one `Owner` (for example from an `__index__` hook that
//! calls back into the same owner mid-operation) raises PyO3's
//! `RuntimeError: Already borrowed` rather than `TokenisCryptoError`; the
//! operation is refused either way.

use pyo3::create_exception;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokenis_core::delegation as dl;
use tokenis_core::elgamal as eg;

create_exception!(
    _core,
    TokenisCryptoError,
    PyValueError,
    "A tokenis cryptographic operation failed (invalid input, key mismatch, reuse of a one-time value, ...)."
);

fn err(e: tokenis_core::Error) -> PyErr {
    TokenisCryptoError::new_err(e.to_string())
}

fn consumed(what: &str) -> PyErr {
    TokenisCryptoError::new_err(format!(
        "this {what} has already been used; one-time values cannot be reused"
    ))
}

// ---------------------------------------------------------------------------
// EC-ElGamal
// ---------------------------------------------------------------------------

/// A secp256k1 private key held in Rust memory (zeroed on drop).
#[pyclass(module = "tokenis._core", frozen)]
struct PrivateKey(eg::PrivateKey);

#[pymethods]
impl PrivateKey {
    /// Generate a key from the operating system's CSPRNG.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        eg::PrivateKey::generate().map(Self).map_err(err)
    }

    /// Import a 32-byte big-endian scalar in [1, n).
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        eg::PrivateKey::from_bytes(data).map(Self).map_err(err)
    }

    /// Export the 32-byte secret scalar. Use sparingly: the returned `bytes`
    /// object is ordinary Python memory and cannot be zeroed.
    fn export_secret_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.0.export_secret_bytes().as_ref())
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    fn __repr__(&self) -> &'static str {
        "PrivateKey(<redacted>)"
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "refusing to pickle or copy a PrivateKey",
        ))
    }
}

/// A secp256k1 public key (33-byte SEC1 compressed).
#[pyclass(module = "tokenis._core", frozen, eq, hash, from_py_object)]
#[derive(Clone, PartialEq, Eq)]
struct PublicKey(eg::PublicKey);

impl core::hash::Hash for PublicKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        eg::PublicKey::from_bytes(data).map(Self).map_err(err)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }
}

/// An EC-ElGamal ciphertext.
#[pyclass(module = "tokenis._core", frozen, eq, from_py_object)]
#[derive(Clone, PartialEq)]
struct Ciphertext(eg::Ciphertext);

#[pymethods]
impl Ciphertext {
    /// Parse and validate the versioned wire format; pass `public` to tag the
    /// result with its key so key mismatches are caught.
    #[staticmethod]
    #[pyo3(signature = (data, public=None))]
    fn from_bytes(data: &[u8], public: Option<&PublicKey>) -> PyResult<Self> {
        eg::Ciphertext::from_bytes(data, public.map(|p| &p.0))
            .map(Self)
            .map_err(err)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    #[getter]
    fn c1<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.components().0)
    }

    #[getter]
    fn c2<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.components().1)
    }

    /// The public key this ciphertext is tagged with, if any.
    #[getter]
    fn public(&self) -> PyResult<Option<PublicKey>> {
        self.0
            .public_key_bytes()
            .map(|b| eg::PublicKey::from_bytes(&b).map(PublicKey).map_err(err))
            .transpose()
    }

    fn __add__(&self, other: &Ciphertext) -> PyResult<Self> {
        eg::add(&self.0, &other.0).map(Self).map_err(err)
    }

    fn __sub__(&self, other: &Ciphertext) -> PyResult<Self> {
        eg::sub(&self.0, &other.0).map(Self).map_err(err)
    }

    fn __neg__(&self) -> Self {
        Self(eg::neg(&self.0))
    }

    fn __mul__(&self, k: i64) -> Self {
        Self(eg::scalar_mul(&self.0, k))
    }

    fn __rmul__(&self, k: i64) -> Self {
        Self(eg::scalar_mul(&self.0, k))
    }

    fn __repr__(&self) -> String {
        format!("Ciphertext({} bytes)", self.0.to_bytes().len())
    }
}

/// Decrypts ciphertexts with plaintexts in [-max_value, max_value]. Holds a
/// copy of the private key in Rust memory. `table_size` (default about
/// sqrt(2 * max_value)) trades memory, 8 bytes per entry, for speed.
#[pyclass(module = "tokenis._core", frozen)]
struct Decryptor(eg::Decryptor);

#[pymethods]
impl Decryptor {
    #[new]
    #[pyo3(signature = (sk, max_value=eg::DEFAULT_MAX_VALUE, table_size=None))]
    fn new(
        py: Python<'_>,
        sk: &PrivateKey,
        max_value: u64,
        table_size: Option<u64>,
    ) -> PyResult<Self> {
        let key = sk.0.clone();
        py.detach(move || match table_size {
            None => eg::Decryptor::new(&key, max_value),
            Some(t) => eg::Decryptor::with_table_size(&key, max_value, t),
        })
        .map(Self)
        .map_err(err)
    }

    fn decrypt(&self, py: Python<'_>, ct: &Ciphertext) -> PyResult<i64> {
        let ct = ct.0.clone();
        py.detach(|| self.0.decrypt(&ct)).map_err(err)
    }

    /// Re-encrypt under this key with fresh randomness (key holder only).
    fn refresh(&self, py: Python<'_>, ct: &Ciphertext) -> PyResult<Ciphertext> {
        let ct = ct.0.clone();
        py.detach(|| self.0.refresh(&ct))
            .map(Ciphertext)
            .map_err(err)
    }

    #[getter]
    fn max_value(&self) -> u64 {
        self.0.max_value()
    }

    #[getter]
    fn table_size(&self) -> u64 {
        self.0.table_size()
    }

    fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key().clone())
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "refusing to pickle or copy a Decryptor",
        ))
    }
}

/// Worker threads for batch operations: the machine's parallelism, capped.
fn workers(items: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    cores.min(16).min(items / 256 + 1).max(1)
}

/// A column of ciphertexts held in Rust: batch encryption runs on all cores
/// with the GIL released, and masked sums never create a Python object per
/// element.
#[pyclass(module = "tokenis._core")]
struct CiphertextVector {
    public: eg::PublicKey,
    items: Vec<eg::Ciphertext>,
}

#[pymethods]
impl CiphertextVector {
    #[new]
    fn new(public: &PublicKey) -> Self {
        Self {
            public: public.0.clone(),
            items: Vec::new(),
        }
    }

    fn __len__(&self) -> usize {
        self.items.len()
    }

    /// Encrypt `values` (in parallel) and append them, in order.
    fn extend_encrypt(&mut self, py: Python<'_>, values: Vec<i64>) -> PyResult<()> {
        let public = &self.public;
        let encrypted = py.detach(|| -> tokenis_core::Result<Vec<eg::Ciphertext>> {
            let chunk = values.len().div_ceil(workers(values.len())).max(1);
            std::thread::scope(|scope| {
                let handles: Vec<_> = values
                    .chunks(chunk)
                    .map(|part| {
                        scope.spawn(move || {
                            part.iter()
                                .map(|m| eg::encrypt(public, *m))
                                .collect::<tokenis_core::Result<Vec<_>>>()
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(values.len());
                for handle in handles {
                    let part = handle
                        .join()
                        .map_err(|_| tokenis_core::Error::RandomnessUnavailable)??;
                    out.extend(part);
                }
                Ok(out)
            })
        });
        self.items.extend(encrypted.map_err(err)?);
        Ok(())
    }

    /// Sum of the elements whose byte in `mask` is non-zero (`mask` has one
    /// byte per element). Errors on a length mismatch or an empty selection.
    fn sum_where(&self, py: Python<'_>, mask: &[u8]) -> PyResult<Ciphertext> {
        if mask.len() != self.items.len() {
            return Err(err(tokenis_core::Error::LengthMismatch));
        }
        let items = &self.items;
        let total = py.detach(|| -> tokenis_core::Result<eg::Ciphertext> {
            let chunk = items.len().div_ceil(workers(items.len())).max(1);
            let partials = std::thread::scope(|scope| {
                let handles: Vec<_> = items
                    .chunks(chunk)
                    .zip(mask.chunks(chunk))
                    .map(|(cts, bits)| {
                        scope.spawn(move || {
                            let selected = cts.iter().zip(bits).filter(|(_, b)| **b != 0);
                            match eg::sum(selected.map(|(ct, _)| ct)) {
                                Ok(partial) => Ok(Some(partial)),
                                Err(tokenis_core::Error::EmptyInput) => Ok(None),
                                Err(e) => Err(e),
                            }
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().map_err(|_| tokenis_core::Error::EmptyInput)?)
                    .collect::<tokenis_core::Result<Vec<Option<eg::Ciphertext>>>>()
            })?;
            eg::sum(partials.iter().flatten())
        });
        total.map(Ciphertext).map_err(err)
    }

    /// Move every element of `other` (same public key) onto the end of
    /// this vector, leaving `other` empty.
    fn extend(&mut self, mut other: PyRefMut<'_, CiphertextVector>) -> PyResult<()> {
        if other.public != self.public {
            return Err(err(tokenis_core::Error::KeyMismatch));
        }
        self.items.append(&mut other.items);
        Ok(())
    }

    /// Serialize: ``u64`` count, then each ciphertext's wire encoding
    /// prefixed by its one-byte length.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let items = &self.items;
        let out = py.detach(|| -> Option<Vec<u8>> {
            let chunk = items.len().div_ceil(workers(items.len())).max(1);
            // A worker that failed must fail the call: dropping its chunk
            // would write a count that no longer matches the items.
            let parts: Vec<Vec<Vec<u8>>> = std::thread::scope(|scope| {
                let handles: Vec<_> = items
                    .chunks(chunk)
                    .map(|part| scope.spawn(move || eg::to_bytes_many(part)))
                    .collect();
                handles.into_iter().map(|h| h.join().ok()).collect::<Option<Vec<_>>>()
            })?;
            let mut out = Vec::with_capacity(8 + items.len() * 68);
            out.extend_from_slice(&(items.len() as u64).to_le_bytes());
            for bytes in parts.iter().flatten() {
                // A ciphertext encoding is at most 1 + 33 + 33 bytes.
                out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(bytes);
            }
            Some(out)
        });
        let out = out.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("ciphertext encoding failed in a worker thread")
        })?;
        Ok(PyBytes::new(py, &out))
    }

    /// Parse what :meth:`to_bytes` wrote, validating every point (in
    /// parallel) and tagging each ciphertext with ``public``.
    #[staticmethod]
    fn from_bytes(py: Python<'_>, public: &PublicKey, data: &[u8]) -> PyResult<Self> {
        let malformed = || err(tokenis_core::Error::MalformedEncoding);
        let (count, mut rest) = data.split_at_checked(8).ok_or_else(malformed)?;
        let count = u64::from_le_bytes(count.try_into().map_err(|_| malformed())?);
        let count = usize::try_from(count).map_err(|_| malformed())?;
        let mut slices: Vec<&[u8]> = Vec::with_capacity(count.min(1 << 26));
        for _ in 0..count {
            let (len, tail) = rest.split_first().ok_or_else(malformed)?;
            let (item, tail) = tail
                .split_at_checked(usize::from(*len))
                .ok_or_else(malformed)?;
            slices.push(item);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(malformed());
        }
        let key = &public.0;
        let items = py.detach(|| -> tokenis_core::Result<Vec<eg::Ciphertext>> {
            let chunk = slices.len().div_ceil(workers(slices.len())).max(1);
            std::thread::scope(|scope| {
                let handles: Vec<_> = slices
                    .chunks(chunk)
                    .map(|part| {
                        scope.spawn(move || {
                            part.iter()
                                .map(|b| eg::Ciphertext::from_bytes(b, Some(key)))
                                .collect::<tokenis_core::Result<Vec<_>>>()
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(slices.len());
                for handle in handles {
                    out.extend(
                        handle
                            .join()
                            .map_err(|_| tokenis_core::Error::MalformedEncoding)??,
                    );
                }
                Ok(out)
            })
        });
        Ok(Self {
            public: public.0.clone(),
            items: items.map_err(err)?,
        })
    }

    fn __getitem__(&self, index: isize) -> PyResult<Ciphertext> {
        let len = isize::try_from(self.items.len()).unwrap_or(isize::MAX);
        let i = if index < 0 { index + len } else { index };
        usize::try_from(i)
            .ok()
            .and_then(|i| self.items.get(i))
            .map(|ct| Ciphertext(ct.clone()))
            .ok_or_else(|| pyo3::exceptions::PyIndexError::new_err("index out of range"))
    }

    fn __repr__(&self) -> String {
        format!("CiphertextVector(len={})", self.items.len())
    }
}

/// Sum a list of ciphertexts in one pass.
#[pyfunction]
fn sum_ciphertexts(cts: Vec<Ciphertext>) -> PyResult<Ciphertext> {
    eg::sum(cts.iter().map(|c| &c.0))
        .map(Ciphertext)
        .map_err(err)
}

#[pyfunction]
fn encrypt(pk: &PublicKey, m: i64) -> PyResult<Ciphertext> {
    eg::encrypt(&pk.0, m).map(Ciphertext).map_err(err)
}

#[pyfunction]
fn base_point_multiple<'py>(py: Python<'py>, k: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    eg::base_point_multiple(k)
        .map(|b| PyBytes::new(py, &b))
        .map_err(err)
}

#[pyfunction]
fn fixed_point_encode(x: f64, precision: u32) -> PyResult<i64> {
    eg::fixed_point_encode(x, precision).map_err(err)
}

// ---------------------------------------------------------------------------
// No-key delegation
// ---------------------------------------------------------------------------

/// A one-time pad (opaque; consumed by `Owner.unblind`/`Owner.refresh`).
#[pyclass(module = "tokenis._core")]
struct Mask(Option<dl::Mask>);

/// The affine correction term (opaque; consumed by `Owner.unblind_affine`).
#[pyclass(module = "tokenis._core")]
struct Correction(Option<dl::Correction>);

/// A Beaver triple (opaque; consumed by `Owner.reconstruct_multiplication`).
#[pyclass(module = "tokenis._core")]
struct MultiplicationTriple(Option<dl::MultiplicationTriple>);

macro_rules! opaque_repr {
    ($ty:ident, $name:literal) => {
        #[pymethods]
        impl $ty {
            fn __repr__(&self) -> String {
                let state = if self.0.is_some() {
                    "unused"
                } else {
                    "consumed"
                };
                format!("{}(<redacted>, {state})", $name)
            }
            fn __reduce__(&self) -> PyResult<()> {
                Err(PyTypeError::new_err(concat!(
                    "refusing to pickle or copy a ",
                    $name
                )))
            }
            #[getter]
            fn consumed(&self) -> bool {
                self.0.is_none()
            }
        }
    };
}
opaque_repr!(Mask, "Mask");
opaque_repr!(Correction, "Correction");
opaque_repr!(MultiplicationTriple, "MultiplicationTriple");

/// A masked value: uniform, safe to hand to an untrusted server.
#[pyclass(module = "tokenis._core", frozen, eq, from_py_object)]
#[derive(Clone, PartialEq)]
struct MaskedValue(dl::MaskedValue);

#[pymethods]
impl MaskedValue {
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        dl::MaskedValue::from_bytes(data).map(Self).map_err(err)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }

    fn __repr__(&self) -> &'static str {
        "MaskedValue(<32 bytes>)"
    }
}

/// The (e, g) opening a server sees in one masked multiplication.
#[pyclass(module = "tokenis._core", frozen, eq, from_py_object)]
#[derive(Clone, PartialEq)]
struct MultiplicationOpening(dl::MultiplicationOpening);

#[pymethods]
impl MultiplicationOpening {
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        dl::MultiplicationOpening::from_bytes(data)
            .map(Self)
            .map_err(err)
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.to_bytes())
    }
}

fn scalar(data: &[u8]) -> PyResult<dl::Value> {
    dl::value_from_bytes(data).map_err(err)
}

/// Move a one-time secret out of its handle -- but only after checking it
/// belongs to `owner`, so a mismatch leaves the caller's handle intact.
fn take_owned<T: dl::OwnedSecret>(
    owner: &dl::Owner,
    slot: &mut Option<T>,
    what: &str,
    foreign: tokenis_core::Error,
) -> PyResult<T> {
    match slot.as_ref() {
        None => Err(consumed(what)),
        Some(secret) if !owner.owns(secret) => Err(err(foreign)),
        Some(_) => slot.take().ok_or_else(|| consumed(what)),
    }
}

/// The key-holding party of the no-key delegation protocol. Values cross
/// this API as 32-byte big-endian encodings of integers mod n.
#[pyclass(module = "tokenis._core")]
struct Owner(dl::Owner);

#[pymethods]
impl Owner {
    #[new]
    fn new() -> PyResult<Self> {
        dl::Owner::new().map(Self).map_err(err)
    }

    fn blind(&self, value: &[u8]) -> PyResult<(MaskedValue, Mask)> {
        let (m, mask) = self.0.blind(&scalar(value)?).map_err(err)?;
        Ok((MaskedValue(m), Mask(Some(mask))))
    }

    fn unblind<'py>(
        &self,
        py: Python<'py>,
        masked: &MaskedValue,
        mut mask: PyRefMut<'_, Mask>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mask = take_owned(
            &self.0,
            &mut mask.0,
            "Mask",
            tokenis_core::Error::ForeignOwner,
        )?;
        let value = self.0.unblind(&masked.0, mask).map_err(err)?;
        Ok(PyBytes::new(py, &dl::value_to_bytes(&value)))
    }

    fn delegate_affine(
        &self,
        coefficients: Vec<i64>,
        values: Vec<Vec<u8>>,
    ) -> PyResult<(Vec<MaskedValue>, Correction)> {
        let values = values
            .iter()
            .map(|v| scalar(v))
            .collect::<PyResult<Vec<_>>>()?;
        let (masked, correction) = self
            .0
            .delegate_affine(&coefficients, &values)
            .map_err(err)?;
        Ok((
            masked.into_iter().map(MaskedValue).collect(),
            Correction(Some(correction)),
        ))
    }

    fn unblind_affine<'py>(
        &self,
        py: Python<'py>,
        result: &MaskedValue,
        mut correction: PyRefMut<'_, Correction>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let correction = take_owned(
            &self.0,
            &mut correction.0,
            "Correction",
            tokenis_core::Error::ForeignOwner,
        )?;
        let value = self.0.unblind_affine(&result.0, correction).map_err(err)?;
        Ok(PyBytes::new(py, &dl::value_to_bytes(&value)))
    }

    fn prepare_triple(&mut self) -> PyResult<MultiplicationTriple> {
        self.0
            .prepare_triple()
            .map(|t| MultiplicationTriple(Some(t)))
            .map_err(err)
    }

    fn open_multiplication(
        &mut self,
        s: &[u8],
        t: &[u8],
        triple: PyRef<'_, MultiplicationTriple>,
    ) -> PyResult<MultiplicationOpening> {
        let triple = triple
            .0
            .as_ref()
            .ok_or_else(|| consumed("MultiplicationTriple"))?;
        self.0
            .open_multiplication(&scalar(s)?, &scalar(t)?, triple)
            .map(MultiplicationOpening)
            .map_err(err)
    }

    fn reconstruct_multiplication<'py>(
        &self,
        py: Python<'py>,
        mut triple: PyRefMut<'_, MultiplicationTriple>,
        opening: &MultiplicationOpening,
        eg_value: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let eg_scalar = scalar(eg_value)?;
        let triple = take_owned(
            &self.0,
            &mut triple.0,
            "MultiplicationTriple",
            tokenis_core::Error::ForeignTriple,
        )?;
        let value = self
            .0
            .reconstruct_multiplication(triple, &opening.0, &eg_scalar)
            .map_err(err)?;
        Ok(PyBytes::new(py, &dl::value_to_bytes(&value)))
    }

    /// Blinded bootstrap: re-mask the same value with a fresh pad, without
    /// the plaintext ever leaving Rust. Consumes `mask`.
    fn refresh(
        &self,
        masked: &MaskedValue,
        mut mask: PyRefMut<'_, Mask>,
    ) -> PyResult<(MaskedValue, Mask)> {
        let mask = take_owned(
            &self.0,
            &mut mask.0,
            "Mask",
            tokenis_core::Error::ForeignOwner,
        )?;
        let (m, fresh) = self
            .0
            .refresh(&masked.0, mask, dl::Value::clone)
            .map_err(err)?;
        Ok((MaskedValue(m), Mask(Some(fresh))))
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("refusing to pickle or copy an Owner"))
    }
}

#[pyfunction]
fn evaluate_affine_masked(
    coefficients: Vec<i64>,
    intercept: &[u8],
    masked: Vec<MaskedValue>,
) -> PyResult<MaskedValue> {
    let masked: Vec<dl::MaskedValue> = masked.into_iter().map(|m| m.0).collect();
    dl::evaluate_affine_masked(&coefficients, &scalar(intercept)?, &masked)
        .map(MaskedValue)
        .map_err(err)
}

#[pyfunction]
fn combine_multiplication<'py>(
    py: Python<'py>,
    opening: &MultiplicationOpening,
) -> Bound<'py, PyBytes> {
    let v = dl::combine_multiplication(&opening.0);
    PyBytes::new(py, &dl::value_to_bytes(&v))
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add(
        "TokenisCryptoError",
        m.py().get_type::<TokenisCryptoError>(),
    )?;
    m.add("DEFAULT_MAX_VALUE", eg::DEFAULT_MAX_VALUE)?;
    m.add("MAX_SUPPORTED_RANGE", eg::MAX_SUPPORTED_RANGE)?;
    m.add("MAX_TABLE_SIZE", eg::MAX_TABLE_SIZE)?;
    m.add("CIPHERTEXT_VERSION", eg::CIPHERTEXT_VERSION)?;
    m.add_class::<PrivateKey>()?;
    m.add_class::<PublicKey>()?;
    m.add_class::<Ciphertext>()?;
    m.add_class::<Decryptor>()?;
    m.add_class::<CiphertextVector>()?;
    m.add_class::<Mask>()?;
    m.add_class::<Correction>()?;
    m.add_class::<MultiplicationTriple>()?;
    m.add_class::<MaskedValue>()?;
    m.add_class::<MultiplicationOpening>()?;
    m.add_class::<Owner>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sum_ciphertexts, m)?)?;
    m.add_function(wrap_pyfunction!(fixed_point_encode, m)?)?;
    m.add_function(wrap_pyfunction!(base_point_multiple, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_affine_masked, m)?)?;
    m.add_function(wrap_pyfunction!(combine_multiplication, m)?)?;
    Ok(())
}
