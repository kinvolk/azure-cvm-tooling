// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::time::Duration;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::thread;
use thiserror::Error;
use tss_esapi::abstraction::{nv, pcr, public::DecodedKey};
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::{NvIndexTpmHandle, PcrHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::pcr_selection_list::PcrSelectionListBuilder;
use tss_esapi::structures::pcr_slot::PcrSlot;
use tss_esapi::structures::{
    Attest, AttestInfo, Data, DigestValues, NvPublicBuilder, Signature, SignatureScheme,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

#[cfg(feature = "verifier")]
mod verify;

#[cfg(feature = "verifier")]
pub use verify::VerifyError;

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const INDEX_REPORT_DATA: u32 = 0x01400002;
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

fn to_pcr_handle(pcr: u8) -> Result<PcrHandle, ExtendError> {
    match pcr {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        _ => Err(ExtendError::InvalidPcr),
    }
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("Failed to write value to nvindex")]
    NvWriteFailed,
}

/// Get a HCL report from an nvindex
pub fn get_report() -> Result<Vec<u8>, ReportError> {
    let (nv_index, mut context) = get_session_context()?;

    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
}

/// Retrieve a fresh HCL report from a nvindex. The specified report_data will be reflected
/// in the HCL report in its user_data field and mixed into a hash in the TEE report's report_data.
/// The Function contains a 3 seconds delay to avoid retrieving a stale report.
pub fn get_report_with_report_data(report_data: &[u8]) -> Result<Vec<u8>, ReportError> {
    let (nv_index, mut context) = get_session_context()?;

    let nv_index_report_data = NvIndexTpmHandle::new(INDEX_REPORT_DATA)?;
    write_nv_index(&mut context, nv_index_report_data, report_data)?;

    thread::sleep(Duration::new(3, 0));

    let report = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(report)
}

fn get_session_context() -> Result<(NvIndexTpmHandle, Context), ReportError> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));
    Ok((nv_index, context))
}

fn write_nv_index(
    context: &mut Context,
    nv_index: NvIndexTpmHandle,
    data: &[u8],
) -> Result<(), ReportError> {
    let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_pp_read(true)
        .build()?;

    let owner_nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(owner_nv_index_attributes)
        .with_data_area_size(data.len())
        .build()?;

    let mut rw = match nv::list(context)?
        .iter()
        .find(|(public, _)| public.nv_index() == nv_index)
    {
        Some(_) => nv::NvOpenOptions::ExistingIndex {
            nv_index_handle: nv_index,
            auth_handle: NvAuth::Owner,
        },
        None => nv::NvOpenOptions::NewIndex {
            nv_public: owner_nv_public,
            auth_handle: NvAuth::Owner,
        },
    }
    .open(context)?;

    rw.write_all(data).map_err(|_| ReportError::NvWriteFailed)
}

#[derive(Error, Debug)]
pub enum ExtendError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
    #[error("invalid pcr number (expected 0-23)")]
    InvalidPcr,
}

/// Extend a PCR register with a sha256 digest
pub fn extend_pcr(pcr: u8, digest: &[u8; 32]) -> Result<(), ExtendError> {
    let pcr_handle = to_pcr_handle(pcr)?;

    let mut vals = DigestValues::new();
    let sha256_digest = digest.to_vec().try_into()?;
    vals.set(HashingAlgorithm::Sha256, sha256_digest);

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;

    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));
    context.pcr_extend(pcr_handle, vals)?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum AKPubError {
    #[error("tpm error")]
    Tpm(#[from] tss_esapi::Error),
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

/// Get the AK pub of the vTPM
pub fn get_ak_pub() -> Result<PublicKey, AKPubError> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        return Err(AKPubError::WrongKeyType);
    };

    let bytes_n = rsa_pk.modulus.as_unsigned_bytes_be();
    let bytes_e = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let pkey = PublicKey {
        n: bytes_n.into(),
        e: bytes_e.into(),
    };
    Ok(pkey)
}

#[non_exhaustive]
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

    /// Extract nonce from a Quote
    pub fn nonce(&self) -> Result<Vec<u8>, QuoteError> {
        let attest = Attest::unmarshall(&self.message)?;
        let nonce = attest.extra_data().to_vec();
        Ok(nonce)
    }

    /// Extract message from a Quote
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

/// Get a signed vTPM Quote
///
/// # Arguments
///
/// * `data` - A byte slice to use as nonce
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

    let (attest, signature) = context.quote(
        key_handle.into(),
        quote_data,
        scheme,
        selection_list.clone(),
    )?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(QuoteError::NotAQuote);
    };
    let Signature::RsaSsa(rsa_sig) = signature else {
        return Err(QuoteError::WrongSignature);
    };

    let signature = rsa_sig.signature().to_vec();
    let message = attest.marshall()?;

    context.clear_sessions();
    let pcr_data = pcr::read_all(&mut context, selection_list)?;

    let pcr_bank = pcr_data
        .pcr_bank(hash_algo)
        .ok_or(QuoteError::PcrBankNotFound)?;

    let pcrs: Result<Vec<[u8; 32]>, _> = pcr_bank
        .into_iter()
        .map(|(_, digest)| digest.clone().try_into().map_err(|_| QuoteError::PcrRead))
        .collect();
    let pcrs = pcrs?;

    Ok(Quote {
        signature,
        message,
        pcrs,
    })
}
