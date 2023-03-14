use memoffset::offset_of;
use sev::firmware::guest::types::AttestationReport;
use thiserror::Error;
use tss_esapi::abstraction::nv;
use tss_esapi::abstraction::public::DecodedKey;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
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
    Der(#[from] picky_asn1_der::Asn1DerError),
    #[error("not an rsa public key")]
    WrongKeyType,
}

pub fn get_ak_pub() -> Result<Vec<u8>, AKPubError> {
    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let tpm_handle: TpmHandle = VTPM_AK_HANDLE.try_into()?;
    let key_handle = context.tr_from_tpm_public(tpm_handle)?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        return Err(AKPubError::WrongKeyType); 
    };

    let bytes: Vec<u8> = picky_asn1_der::to_vec(&rsa_pk)?;

    Ok(bytes)
}
