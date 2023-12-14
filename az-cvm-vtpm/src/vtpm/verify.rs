// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{Quote, QuoteError};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use thiserror::Error;

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
    #[error("quote error")]
    Quote(#[from] QuoteError),
}

impl Quote {
    /// Verify a Quote's signature and nonce
    ///
    /// # Arguments
    ///
    /// * `pub_key` - A public key to verify the Quote's signature
    ///
    /// * `nonce` - A byte slice to verify the Quote's nonce
    pub fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), VerifyError> {
        self.verify_signature(pub_key)?;

        let quote_nonce = &self.nonce()?;
        if nonce != quote_nonce {
            return Err(VerifyError::NonceMismatch);
        }
        Ok(())
    }

    /// Verify a Quote's signature
    ///
    /// # Arguments
    ///
    /// * `pub_key` - A public key to verify the Quote's signature
    pub fn verify_signature(&self, pub_key: &PKey<Public>) -> Result<(), VerifyError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;
        let is_verified = verifier.verify(&self.signature)?;
        if !is_verified {
            return Err(VerifyError::SignatureMismatch);
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
