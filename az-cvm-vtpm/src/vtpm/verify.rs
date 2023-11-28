// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Quote;
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

impl Quote {
    /// Verifies the quote's signature and nonce.
    pub fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), VerifyError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "verifier")]
    #[test]
    fn test_quote_validation() {
        // Can be retrieved by `get_ak_pub()` or via tpm2-tools:
        // `tpm2_readpublic -c 0x81000003 -f pem -o akpub.pem`

        let pem = include_bytes!("../../test/akpub.pem");
        let pkey = PKey::public_key_from_pem(pem).unwrap();

        // Can be retrieved by `get_quote()` or via tpm2-tools:
        // `tpm2_quote -c 0x81000003 -l sha256:5,8 -q cafe -m quote_msg -s quote_sig`
        let message = include_bytes!("../../test/quote_msg").to_vec();
        let signature = include_bytes!("../../test/quote_sig").to_vec();
        let quote = Quote { signature, message };

        // proper nonce in message
        let nonce = vec![1, 2, 3];
        let result = quote.verify(&pkey, &nonce);
        assert!(result.is_ok(), "Quote verification should not fail");

        // wrong signature
        let mut wrong_quote = quote.clone();
        wrong_quote.signature.reverse();
        let result = wrong_quote.verify(&pkey, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::SignatureMismatch),
            "Expected signature mismatch"
        );

        // improper nonce
        let nonce = vec![1, 2, 3, 4];
        let result = quote.verify(&pkey, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::NonceMismatch),
            "Expected nonce verification error"
        );
    }
}
