use memoffset::offset_of;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use sev::firmware::guest::types::AttestationReport;
use thiserror::Error;
use tss_esapi::abstraction::nv;
use tss_esapi::abstraction::public::DecodedKey;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
use tss_esapi::structures::SignatureScheme;
use tss_esapi::structures::{Attest, AttestInfo, Data, Signature};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

use crate::hcl;

const SNP_REPORT_SIZE: usize = std::mem::size_of::<AttestationReport>();
const VTPM_NV_INDEX: u32 = 0x01400001;
const VTPM_AK_HANDLE: u32 = 0x81000003;
const VTPM_REPORT_OFFSET: usize = offset_of!(hcl::HclAttestationReport, hw_report);

pub fn get_report() -> Result<Vec<u8>, tss_esapi::Error> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let bytes = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(bytes[VTPM_REPORT_OFFSET..(VTPM_REPORT_OFFSET + SNP_REPORT_SIZE)].to_vec())
}

#[derive(Error, Debug)]
pub enum AKPubError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("asn1 der error")]
    WrongKeyType,
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

pub fn get_ak_pub() -> Result<PKey<Public>, AKPubError> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        return Err(AKPubError::WrongKeyType);
    };

    let modulus = BigNum::from_slice(&rsa_pk.modulus)?;
    let public_exponent = BigNum::from_slice(&rsa_pk.public_exponent)?;

    let rsa = Rsa::from_public_components(modulus, public_exponent)?;
    let pkey = PKey::from_rsa(rsa)?;

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
        .with_selection(
            hash_algo,
            &[PcrSlot::Slot15, PcrSlot::Slot16, PcrSlot::Slot22],
        )
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

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("tss error")]
    Tss(#[from] tss_esapi::Error),
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
}

pub trait VerifyVTpmQuote {
    fn verify_quote(&self, quote: &Quote, nonce: Option<&[u8]>) -> Result<bool, VerifyError>;
}

impl VerifyVTpmQuote for PKey<Public> {
    fn verify_quote(&self, quote: &Quote, nonce: Option<&[u8]>) -> Result<bool, VerifyError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), self)?;
        verifier.update(&quote.message)?;
        let is_verified = verifier.verify(&quote.signature)?;

        let Some(nonce) = nonce else {
            return Ok(is_verified);
        };

        let attest = Attest::unmarshall(&quote.message)?;
        let nonce_matches = nonce == attest.extra_data().as_slice();

        Ok(nonce_matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // ignore nonce
        let result = pkey.verify_quote(&quote, None).unwrap();
        assert!(result, "Quote validation should not fail");

        // proper nonce in message
        let nonce = vec![1, 2, 3];
        let result = pkey.verify_quote(&quote, Some(&nonce)).unwrap();
        assert!(result, "Quote verification should not fail");

        // improper nonce
        let nonce = vec![1, 2, 3, 4];
        let result = pkey.verify_quote(&quote, Some(&nonce)).unwrap();
        assert!(!result, "Quote validation should fail");
    }
}
