// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
use tss_esapi::structures::{AttestInfo, Data, Signature, SignatureScheme};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context;

#[cfg(feature = "verifier")]
mod verify;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const VTPM_AK_HANDLE: u32 = 0x81000003;
const VTPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
}

/// Get a HCL report from an nvindex
pub fn get_report() -> Result<Vec<u8>, ReportError> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
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

/// Get the AK pub of the vTPM
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

/// Get a signed vTPM quote
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
