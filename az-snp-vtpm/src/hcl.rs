// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use memoffset::offset_of;
use openssl::pkey::{PKey, Public};
use openssl::{self, sha::sha256};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::types::AttestationReport;
use static_assertions::const_assert;
use std::convert::TryFrom;
use std::error;
use thiserror::Error;

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

#[allow(dead_code)]
const HCL_ATTESTATION_SIGNATURE: u32 = 0x414C4348;

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    pub keys: [jsonwebkey::JsonWebKey; 1],
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HclReportWithRuntimeData {
    pub hcl_report: HclAttestationReport,
    pub runtime_data: ReportData,
}

impl HclReportWithRuntimeData {
    pub fn snp_report(&self) -> &AttestationReport {
        &self.hcl_report.hw_report
    }
}

#[derive(Debug, Error)]
#[error("ReportData field does not match RuntimeData hash")]
pub struct ReportDataMismatchError;

pub fn buf_to_hcl_data(
    bytes: &[u8],
) -> Result<(HclAttestationReport, &[u8]), Box<bincode::ErrorKind>> {
    let hcl_report: HclAttestationReport = bincode::deserialize(bytes)?;
    let var_data_offset =
        offset_of!(HclAttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
    let var_data = &bytes[var_data_offset..];
    let var_data = &var_data[..hcl_report.hcl_data.variable_data_size as usize];
    Ok((hcl_report, var_data))
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("bincode error")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("json parse error")]
    Report(#[from] serde_json::Error),
}

impl TryFrom<&[u8]> for HclReportWithRuntimeData {
    type Error = ParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (hcl_report, var_data) = buf_to_hcl_data(bytes)?;
        let runtime_data: ReportData = serde_json::from_slice(var_data)?;
        Ok(HclReportWithRuntimeData {
            hcl_report,
            runtime_data,
        })
    }
}

impl HclReportWithRuntimeData {
    pub fn get_attestation_key(&self) -> Result<PKey<Public>, openssl::error::ErrorStack> {
        let key = self.runtime_data.keys[0].key.as_ref();
        let pubkey = key.to_pem();
        let pubkey = openssl::pkey::PKey::public_key_from_pem(pubkey.as_bytes())?;
        Ok(pubkey)
    }

    pub fn verify_report_data(bytes: &[u8]) -> Result<(), Box<dyn error::Error>> {
        let (hcl_report, var_data) = buf_to_hcl_data(bytes)?;
        let report_data = &hcl_report.hw_report.report_data[..32];
        let hash = sha256(var_data);
        if hash != report_data {
            return Err(Box::new(ReportDataMismatchError));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_data_hash() {
        let bytes = include_bytes!("../test/hcl-report.bin");
        let res = HclReportWithRuntimeData::verify_report_data(bytes);
        assert!(res.is_ok());
    }
    #[test]
    fn test_hcl_report() {
        let bytes: &[u8] = include_bytes!("../test/hcl-report.bin");
        let hcl_report: HclReportWithRuntimeData = bytes.try_into().unwrap();
        println!("{:?}", hcl_report.runtime_data);
        let pubkey = hcl_report.get_attestation_key().unwrap();
        assert!(pubkey.size() == 256);
    }
}
