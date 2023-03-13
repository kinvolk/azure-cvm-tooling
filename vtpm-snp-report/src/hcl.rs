use jsonwebkey;
use memoffset::offset_of;
use sev::firmware::guest::types::AttestationReport;
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;


#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum IgvmHashType {
    Invalid = 0,
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum IgvmReportType {
    Invalid = 0,
    Reserved = 1,
    Snp = 2,
    Tvm = 3,
}

const HCL_ATTESTATION_SIGNATURE: u32 = 0x414C4348;
const HCL_ATTESTATION_VERSION: u32 = 0x1;
#[repr(C)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct HclAttestationHeader {
    pub signature: u32,
    pub version: u32,
    pub report_size: u32,
    pub request_type: IgvmReportType,
    pub reserved: [u32; 4], //<- this looks wrong
}

const IGVM_ATTEST_VERSION_CURRENT: u32 = 0x1;
#[repr(C)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct IgvmRequestData {
    pub data_size: u32,
    pub version: u32,
    pub report_type: IgvmReportType,
    pub report_data_hash_type: IgvmHashType,
    pub variable_data_size: u32,
    pub variable_data: [u8; 0],
}

#[repr(C)]
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct HclAttestationReport {
    pub header: HclAttestationHeader,
    pub hw_report: AttestationReport,
    pub hcl_data: IgvmRequestData,
}

const_assert!(std::mem::size_of::<HclAttestationHeader>() == 32);

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VmConfiguration {
    #[serde(rename = "console-enabled")]
    pub console_enabled: bool,
    #[serde(rename = "current-time")]
    pub current_time: u32,
    #[serde(rename = "secure-boot")]
    pub secure_boot: bool,
    #[serde(rename = "tpm-enabled")]
    pub tpm_enabled: bool,
    #[serde(rename = "vmUniqueId")]
    pub vm_unique_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReportData {
    pub keys: Vec<jsonwebkey::JsonWebKey>,
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
}

mod tests {
    use super::*;

    #[test]
    fn test_hcl_report() {
        let bytes = include_bytes!("../test/hcl-report.bin");
        let hcl_report : HclAttestationReport = bincode::deserialize(bytes).unwrap();
        let var_data_offset = offset_of!(HclAttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let var_data = &bytes[var_data_offset..];
        let var_data = &var_data[..hcl_report.hcl_data.variable_data_size as usize];
        let r: ReportData = serde_json::from_slice(var_data).unwrap();
        let key = r.keys.first().unwrap().key.as_ref();
        let pubkey = key.to_pem();
        println!("{:?}", pubkey);
    }
}