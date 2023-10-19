// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tdx::TdxVmReport;
use jsonwebkey::JsonWebKey;
use memoffset::offset_of;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sev::firmware::guest::AttestationReport as SnpVmReport;
use sha2::{Digest, Sha256};
use std::mem;
use thiserror::Error;

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
const MAX_REPORT_SIZE: usize = mem::size_of::<SnpVmReport>();
const MIN_REPORT_SIZE: usize = mem::size_of::<TdxVmReport>();
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;

#[derive(Error, Debug)]
pub enum HclError {
    #[error("invalid report type")]
    InvalidReportType,
    #[error("AkPub not found")]
    AkPubNotFound,
    #[error("binary parse error")]
    BinaryParseError(#[from] bincode::Error),
    #[error("JSON parse error")]
    JsonParseError(#[from] serde_json::Error),
}

#[derive(Deserialize, Debug)]
struct VarDataKeys {
    keys: Vec<JsonWebKey>,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
enum IgvmHashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct IgvmRequestData {
    data_size: u32,
    version: u32,
    report_type: u32,
    report_data_hash_type: IgvmHashType,
    variable_data_size: u32,
    variable_data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationHeader {
    signature: u32,
    version: u32,
    report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct HwReport {
    tdx_vm_report: TdxVmReport,
    #[serde(with = "BigArray")]
    _padding: [u8; MAX_REPORT_SIZE - MIN_REPORT_SIZE],
}

#[repr(C)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationReport {
    header: AttestationHeader,
    hw_report: HwReport,
    hcl_data: IgvmRequestData,
}

pub struct HclReport {
    bytes: Vec<u8>,
    attestation_report: AttestationReport,
    report_type: ReportType,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReportType {
    Tdx,
    Snp,
}

impl HclReport {
    pub fn new(bytes: Vec<u8>) -> Result<Self, HclError> {
        let attestation_report: AttestationReport = bincode::deserialize(&bytes)?;
        let report_type = match attestation_report.hcl_data.report_type {
            TDX_REPORT_TYPE => ReportType::Tdx,
            SNP_REPORT_TYPE => ReportType::Snp,
            _ => return Err(HclError::InvalidReportType),
        };

        let report = Self {
            bytes,
            attestation_report,
            report_type,
        };
        Ok(report)
    }

    pub fn report_type(&self) -> ReportType {
        self.report_type
    }

    pub fn tdx_report_slice(&self) -> &[u8] {
        let tdx_report_offset = offset_of!(AttestationReport, hw_report);
        let tdx_report_end = tdx_report_offset + mem::size_of::<TdxVmReport>();
        &self.bytes[tdx_report_offset..tdx_report_end]
    }

    pub fn var_data_sha256(&self) -> [u8; 32] {
        if self.attestation_report.hcl_data.report_data_hash_type != IgvmHashType::Sha256 {
            unimplemented!(
                "Only SHA256 is supported, got {:?}",
                self.attestation_report.hcl_data.report_data_hash_type
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(self.var_data_slice());
        let hash = hasher.finalize();
        hash.into()
    }

    fn var_data_slice(&self) -> &[u8] {
        let var_data_offset =
            offset_of!(AttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let hcl_data = &self.attestation_report.hcl_data;
        let var_data_end = var_data_offset + hcl_data.variable_data_size as usize;
        &self.bytes[var_data_offset..var_data_end]
    }

    pub fn ak_pub(&self) -> Result<JsonWebKey, HclError> {
        let VarDataKeys { keys } = serde_json::from_slice(self.var_data_slice())?;
        let ak_pub = keys
            .into_iter()
            .find(|key| {
                let Some(ref key_id) = key.key_id else {
                    return false;
                };
                key_id == HCL_AKPUB_KEY_ID
            })
            .ok_or(HclError::AkPubNotFound)?;
        Ok(ak_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hcl_report() {
        let bytes: &[u8] = include_bytes!("../test/hcl_report.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let _ = hcl_report.ak_pub().unwrap();
    }
}
