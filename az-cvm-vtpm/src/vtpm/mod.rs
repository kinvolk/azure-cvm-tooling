// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};
use thiserror::Error;

mod tpms_attest;
pub use tpms_attest::AttestError;
use tpms_attest::TpmsAttest;

#[cfg(feature = "tpm")]
mod tpm;
#[cfg(feature = "tpm")]
pub use tpm::*;

#[cfg(feature = "verifier")]
mod verify;

#[cfg(feature = "verifier")]
pub use verify::VerifyError;

/// A tss-esapi error, carried as a boxed source so the error enums keep
/// the same shape whether or not the `tpm` feature is enabled. Downcast
/// to `tss_esapi::Error` for typed access.
type TpmError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("tpm error")]
    Tpm(#[source] TpmError),
    #[error("Failed to write value to nvindex")]
    NvWriteFailed,
}

#[derive(Error, Debug)]
pub enum ExtendError {
    #[error("tpm error")]
    Tpm(#[source] TpmError),
    #[error("invalid pcr number (expected 0-23)")]
    InvalidPcr,
}

#[derive(Error, Debug)]
pub enum AKPubError {
    #[error("tpm error")]
    Tpm(#[source] TpmError),
    #[error("asn1 der error")]
    WrongKeyType,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl PublicKey {
    /// Get the modulus of the public key as big-endian unsigned bytes
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// Get the public exponent of the public key as big-endian unsigned bytes
    pub fn exponent(&self) -> &[u8] {
        &self.e
    }
}

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum QuoteError {
    #[error("tpm error")]
    Tpm(#[source] TpmError),
    #[error("TPMS_ATTEST parse error")]
    Attest(#[from] AttestError),
    #[error("data too large")]
    DataTooLarge,
    #[error("Not a quote, that should not occur")]
    NotAQuote,
    #[error("Wrong signature, that should not occur")]
    WrongSignature,
    #[error("PCR bank not found")]
    PcrBankNotFound,
    #[error("PCR reading error")]
    PcrRead,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Quote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
}

impl Quote {
    /// Retrieve sha256 PCR values from a Quote
    pub fn pcrs_sha256(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.pcrs.iter()
    }

    /// Extract signature from a Quote
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    /// Extract nonce from a Quote
    pub fn nonce(&self) -> Result<Vec<u8>, QuoteError> {
        let attest = TpmsAttest::parse(&self.message)?;
        let nonce = attest.extra_data().to_vec();
        Ok(nonce)
    }

    /// Extract message from a Quote
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}
