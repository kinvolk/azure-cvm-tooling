// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tdx::TdReport;
use jsonwebkey::JsonWebKey;
use memoffset::offset_of;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sev::firmware::guest::AttestationReport as SnpReport;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::mem::size_of;
use std::ops::Range;
use thiserror::Error;

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
const TD_REPORT_SIZE: usize = size_of::<TdReport>();
const SNP_REPORT_SIZE: usize = size_of::<SnpReport>();
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        return a;
    }
    b
}
const MAX_REPORT_SIZE: usize = max(SNP_REPORT_SIZE, TD_REPORT_SIZE);
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;
const HW_REPORT_OFFSET: usize = offset_of!(AttestationReport, hw_report);
const fn report_range(report_size: usize) -> Range<usize> {
    HW_REPORT_OFFSET..(HW_REPORT_OFFSET + report_size)
}
const TD_REPORT_RANGE: Range<usize> = report_range(TD_REPORT_SIZE);
const SNP_REPORT_RANGE: Range<usize> = report_range(SNP_REPORT_SIZE);

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
struct AttestationReport {
    header: AttestationHeader,
    #[serde(with = "BigArray")]
    hw_report: [u8; MAX_REPORT_SIZE],
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

pub enum HwReport {
    Tdx(TdReport),
    Snp(SnpReport),
}

impl HclReport {
    /// Parse a HCL report from a byte slice.
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

    /// Get the type of the nested hardware report
    pub fn report_type(&self) -> ReportType {
        self.report_type
    }

    fn report_slice(&self) -> &[u8] {
        match self.report_type {
            ReportType::Tdx => self.bytes[TD_REPORT_RANGE].as_ref(),
            ReportType::Snp => self.bytes[SNP_REPORT_RANGE].as_ref(),
        }
    }

    /// Get the SHA256 hash of the VarData section
    pub fn var_data_sha256(&self) -> [u8; 32] {
        if self.attestation_report.hcl_data.report_data_hash_type != IgvmHashType::Sha256 {
            unimplemented!(
                "Only SHA256 is supported, got {:?}",
                self.attestation_report.hcl_data.report_data_hash_type
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(self.var_data());
        hasher.finalize().into()
    }

    /// Get the slice of the VarData section
    pub fn var_data(&self) -> &[u8] {
        let var_data_offset =
            offset_of!(AttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let hcl_data = &self.attestation_report.hcl_data;
        let var_data_end = var_data_offset + hcl_data.variable_data_size as usize;
        &self.bytes[var_data_offset..var_data_end]
    }

    /// Get the vTPM's AKpub from the VarData section
    pub fn ak_pub(&self) -> Result<JsonWebKey, HclError> {
        let VarDataKeys { keys } = serde_json::from_slice(self.var_data())?;
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

impl TryFrom<&HclReport> for TdReport {
    type Error = HclError;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Tdx {
            return Err(HclError::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        let td_report = bincode::deserialize::<TdReport>(bytes)?;
        Ok(td_report)
    }
}

impl TryFrom<HclReport> for TdReport {
    type Error = HclError;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

impl TryFrom<&HclReport> for SnpReport {
    type Error = HclError;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Snp {
            return Err(HclError::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        let snp_report = bincode::deserialize::<SnpReport>(bytes)?;
        Ok(snp_report)
    }
}

impl TryFrom<HclReport> for SnpReport {
    type Error = HclError;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hcl_report() {
        let bytes: &[u8] = include_bytes!("../../test/hcl-report-snp.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let _ = hcl_report.ak_pub().unwrap();

        let bytes: &[u8] = include_bytes!("../../test/hcl-report-tdx.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let _ = hcl_report.ak_pub().unwrap();
    }
}
