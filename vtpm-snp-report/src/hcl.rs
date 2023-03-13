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