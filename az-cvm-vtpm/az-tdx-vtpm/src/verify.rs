// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_snp_vtpm::vtpm;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use thiserror::Error;
use tss_esapi::structures::Attest;
use tss_esapi::traits::UnMarshall;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("tss error")]
    Tss(#[from] tss_esapi::Error),
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("quote is not signed by key")]
    SignatureMismatch,
    #[error("nonce mismatch")]
    NonceMismatch,
}

pub trait Verify {
    fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), VerifyError>;
}

impl Verify for vtpm::Quote {
    fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), VerifyError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;
        let is_verified = verifier.verify(&self.signature)?;
        if !is_verified {
            return Err(VerifyError::SignatureMismatch);
        }
        let attest = Attest::unmarshall(&self.message)?;
        if nonce != attest.extra_data().as_slice() {
            return Err(VerifyError::NonceMismatch);
        }
        Ok(())
    }
}
