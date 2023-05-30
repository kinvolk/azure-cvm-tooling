// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use memoffset::offset_of;
#[cfg(feature = "verifier")]
use openssl::pkey::{PKey, Public};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha256};
use static_assertions::const_assert;
use std::convert::TryFrom;
use thiserror::Error;

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
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
pub struct RuntimeData {
    pub keys: [jsonwebkey::JsonWebKey; 1],
    #[serde(rename = "vm-configuration")]
    pub vm_configuration: VmConfiguration,
}

impl HclAttestationReport {
    pub fn snp_report(&self) -> &AttestationReport {
        &self.hw_report
    }

    pub fn verify_report_data(&self, var_data: &VarData) -> Result<(), ValidationError> {
        if self.hcl_data.report_data_hash_type != IgvmHashType::Sha256 {
            unimplemented!();
        }

        let report_data = &self.hw_report.report_data[..32];
        let hash = var_data.sha256();

        if hash.as_slice() != report_data {
            return Err(ValidationError::ReportDataMismatchError);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct VarData(Vec<u8>);

impl VarData {
    pub fn sha256(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        hasher.finalize().to_vec()
    }
}

#[derive(Debug)]
pub struct HclData(HclAttestationReport, VarData);

impl HclData {
    pub fn report(&self) -> &HclAttestationReport {
        &self.0
    }

    pub fn var_data(&self) -> &VarData {
        &self.1
    }
}

impl TryFrom<&[u8]> for HclData {
    type Error = Box<bincode::ErrorKind>;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let hcl_report: HclAttestationReport = bincode::deserialize(bytes)?;
        let var_data_offset =
            offset_of!(HclAttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let var_data_end = var_data_offset + hcl_report.hcl_data.variable_data_size as usize;
        let var_data = VarData(bytes[var_data_offset..var_data_end].to_vec());
        Ok(HclData(hcl_report, var_data))
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("json parse error")]
    Report(#[from] serde_json::Error),
    #[cfg(feature = "verifier")]
    #[error("openssl error")]
    OpenSSL(#[from] openssl::error::ErrorStack),
}

impl TryFrom<&VarData> for RuntimeData {
    type Error = ParseError;

    fn try_from(var_data: &VarData) -> Result<Self, Self::Error> {
        let runtime_data: Self = serde_json::from_slice(&var_data.0)?;
        Ok(runtime_data)
    }
}

#[cfg(feature = "verifier")]
impl RuntimeData {
    /// Parse the the vTPM public Attestation Key PEM
    pub fn get_attestation_key(&self) -> Result<PKey<Public>, ParseError> {
        let key = self.keys[0].key.as_ref();
        let pubkey = key.to_pem();
        let pubkey = PKey::public_key_from_pem(pubkey.as_bytes())?;
        Ok(pubkey)
    }
}

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("bincode error")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("ReportData field does not match HCL RuntimeData hash")]
    ReportDataMismatchError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_data_hash() {
        let bytes = include_bytes!("../test/hcl-report.bin");
        let HclData(hcl_report, var_data) = bytes.as_slice().try_into().unwrap();
        let res = hcl_report.verify_report_data(&var_data);
        assert!(res.is_ok());
    }

    #[cfg(feature = "verifier")]
    #[test]
    fn test_hcl_report() {
        let bytes: &[u8] = include_bytes!("../test/hcl-report.bin");
        let HclData(_, ref var_data) = bytes.try_into().unwrap();
        let runtime_data: RuntimeData = var_data.try_into().unwrap();
        println!("{:?}", runtime_data);
        let pubkey = runtime_data.get_attestation_key().unwrap();
        assert!(pubkey.size() == 256);
    }
}
