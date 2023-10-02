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

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";

#[derive(Deserialize, Debug)]
struct VarDataKeys {
    keys: Vec<jsonwebkey::JsonWebKey>,
}

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
    #[error("missing attestation key in runtime data")]
    MissingAkPub,
    #[error("json parse error")]
    Report(#[from] serde_json::Error),
    #[cfg(feature = "verifier")]
    #[error("openssl error")]
    OpenSSL(#[from] openssl::error::ErrorStack),
}

#[cfg(feature = "verifier")]
impl VarData {
    pub fn ak_pub(&self) -> Result<PKey<Public>, ParseError> {
        let VarDataKeys { keys } = serde_json::from_slice(&self.0)?;

        let ak_pub = keys
            .into_iter()
            .find(|key| key.key_id.as_ref().is_some_and(|id| id == HCL_AKPUB_KEY_ID))
            .ok_or(ParseError::MissingAkPub)?;

        let pubkey = ak_pub.key.to_pem();
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
        let pubkey = var_data.ak_pub().unwrap();
        assert!(pubkey.size() == 256);
    }

    #[test]
    fn test_var_data() {
        // this is a var data sample containing ak_pub and ek_pub
        let bytes = include_bytes!("../test/var-data.bin");
        let var_data = VarData(bytes.to_vec());
        let _key = var_data.ak_pub().unwrap();
    }
}
