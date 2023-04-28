// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(feature = "verifier")]
use openssl::hash::MessageDigest;
#[cfg(feature = "verifier")]
use openssl::pkey::{PKey, Public};
#[cfg(feature = "verifier")]
use openssl::sign::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tss_esapi::abstraction::nv;
use tss_esapi::abstraction::public::DecodedKey;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
#[cfg(feature = "verifier")]
use tss_esapi::structures::Attest;
use tss_esapi::structures::SignatureScheme;
use tss_esapi::structures::{AttestInfo, Data, Signature};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
#[cfg(feature = "verifier")]
use tss_esapi::traits::UnMarshall;
use tss_esapi::Context;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const VTPM_AK_HANDLE: u32 = 0x81000003;
const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 9] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot14,
];

pub fn get_report() -> Result<Vec<u8>, tss_esapi::Error> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    nv::read_full(&mut context, NvAuth::Owner, nv_index)
}

#[derive(Error, Debug)]
pub enum AKPubError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("asn1 der error")]
    WrongKeyType,
    #[error("rsa error")]
    OpenSsl(#[from] rsa::errors::Error),
}

pub fn get_ak_pub() -> Result<RsaPublicKey, AKPubError> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        return Err(AKPubError::WrongKeyType);
    };

    let bytes = rsa_pk.modulus.as_unsigned_bytes_be();
    let n = BigUint::from_bytes_be(bytes);
    let bytes = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let e = BigUint::from_bytes_be(bytes);

    let pkey = RsaPublicKey::new(n, e)?;
    Ok(pkey)
}

#[derive(Error, Debug)]
pub enum QuoteError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("data too large")]
    DataTooLarge,
    #[error("Not a quote, that should not occur")]
    NotAQuote,
    #[error("Wrong signature, that should not occur")]
    WrongSignature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Quote {
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
}

pub fn get_quote(data: &[u8]) -> Result<Quote, QuoteError> {
    if data.len() > Data::MAX_SIZE {
        return Err(QuoteError::DataTooLarge);
    }
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;

    let quote_data: Data = data.try_into()?;
    let scheme = SignatureScheme::Null;
    let hash_algo = HashingAlgorithm::Sha256;
    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(hash_algo, &VTPM_QUOTE_PCR_SLOTS)
        .build()?;

    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let (attest, signature) =
        context.quote(key_handle.into(), quote_data, scheme, selection_list)?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(QuoteError::NotAQuote);
    };
    let Signature::RsaSsa(rsa_sig) = signature else {
        return Err(QuoteError::WrongSignature);
    };

    let signature = rsa_sig.signature().to_vec();
    let message = attest.marshall()?;

    Ok(Quote { signature, message })
}

#[cfg(feature = "verifier")]
#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("tss error")]
    Tss(#[from] tss_esapi::Error),
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("quote is not signed by the public key")]
    SignatureMismatch,
}

#[cfg(feature = "verifier")]
pub trait VerifyVTpmQuote {
    fn verify_quote(&self, quote: &Quote, nonce: &[u8]) -> Result<(), VerifyError>;
}

#[cfg(feature = "verifier")]
impl VerifyVTpmQuote for PKey<Public> {
    fn verify_quote(&self, quote: &Quote, nonce: &[u8]) -> Result<(), VerifyError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), self)?;
        verifier.update(&quote.message)?;
        let is_verified = verifier.verify(&quote.signature)?;
        if !is_verified {
            return Err(VerifyError::SignatureMismatch);
        }

        let attest = Attest::unmarshall(&quote.message)?;
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

        let pem = include_bytes!("../test/akpub.pem");
        let pkey = PKey::public_key_from_pem(pem).unwrap();

        // Can be retrieved by `get_quote()` or via tpm2-tools:
        // `tpm2_quote -c 0x81000003 -l sha256:5,8 -q cafe -m quote_msg -s quote_sig`
        let message = include_bytes!("../test/quote_msg").to_vec();
        let signature = include_bytes!("../test/quote_sig").to_vec();
        let quote = Quote { signature, message };

        // proper nonce in message
        let nonce = vec![1, 2, 3];
        let result = pkey.verify_quote(&quote, &nonce);
        assert!(result.is_ok(), "Quote verification should not fail");

        // wrong signature
        let mut wrong_quote = quote.clone();
        wrong_quote.signature.reverse();
        let result = pkey.verify_quote(&wrong_quote, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::SignatureMismatch),
            "Expected signature mismatch"
        );

        // improper nonce
        let nonce = vec![1, 2, 3, 4];
        let result = pkey.verify_quote(&quote, &nonce);
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerifyError::NonceMismatch),
            "Expected nonce verification error"
        );
    }
}
