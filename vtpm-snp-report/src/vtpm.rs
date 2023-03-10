use sev::firmware::guest::types::AttestationReport;
use std::error::Error;
use tss_esapi::abstraction::nv;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::Context;

const SNP_REPORT_SIZE: usize = std::mem::size_of::<AttestationReport>();
const VTPM_NV_INDEX: u32 = 0x01400001;
const VTPM_REPORT_OFFSET: usize = 32;

pub fn get_report() -> Result<Vec<u8>, Box<dyn Error>> {
    use tss_esapi::handles::NvIndexTpmHandle;
    let nv_index = NvIndexTpmHandle::new(VTPM_NV_INDEX)?;

    let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::default());
    let mut context = Context::new(conf)?;
    let auth_session = AuthSession::Password;
    context.set_sessions((Some(auth_session), None, None));

    let bytes = nv::read_full(&mut context, NvAuth::Owner, nv_index)?;
    Ok(bytes[VTPM_REPORT_OFFSET..(VTPM_REPORT_OFFSET + SNP_REPORT_SIZE)].to_vec())
}
