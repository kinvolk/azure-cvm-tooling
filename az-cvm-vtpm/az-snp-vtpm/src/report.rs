// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(feature = "verifier")]
use super::certs::Vcek;
use az_cvm_vtpm::hcl::{self, HclReport, SNP_REPORT_SIZE};
use az_cvm_vtpm::vtpm;
#[cfg(feature = "verifier")]
use openssl::{ecdsa::EcdsaSig, sha::Sha384};
pub use sev::firmware::guest::AttestationReport;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidateError {
    #[cfg(feature = "verifier")]
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("TCB data is not valid")]
    Tcb,
    #[error("Measurement signature is not valid")]
    MeasurementSignature,
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("bincode error")]
    Bincode(#[from] Box<bincode::ErrorKind>),
}

#[cfg(feature = "verifier")]
pub trait Validateable {
    fn validate(&self, vcek: &Vcek) -> Result<(), ValidateError>;
}

#[cfg(feature = "verifier")]
impl Validateable for AttestationReport {
    fn validate(&self, vcek: &Vcek) -> Result<(), ValidateError> {
        if !is_tcb_data_valid(self) {
            return Err(ValidateError::Tcb);
        }

        let report_sig: EcdsaSig = (&self.signature).try_into()?;
        let vcek_pubkey = vcek.0.public_key()?.ec_key()?;

        let mut hasher = Sha384::new();
        let base_message = get_report_base(self)?;
        hasher.update(&base_message);
        let base_message_digest = hasher.finish();

        if !report_sig.verify(&base_message_digest, &vcek_pubkey)? {
            return Err(ValidateError::MeasurementSignature);
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("deserialization error")]
    Parse(#[from] Box<bincode::ErrorKind>),
    #[error("vTPM error")]
    Vtpm(#[from] vtpm::ReportError),
    #[error("HCL error")]
    Hcl(#[from] hcl::HclError),
}

pub fn parse(bytes: &[u8]) -> Result<AttestationReport, ReportError> {
    // Use the sev's from_bytes method(since sev-6) which handles dynamic parsing
    // of different SNP report versions (v2, v3-PreTurin, v3-Turin)
    let snp_report = AttestationReport::from_bytes(bytes)
        .map_err(|e| ReportError::Parse(Box::new(bincode::ErrorKind::Io(e))))?;
    Ok(snp_report)
}

#[cfg(feature = "verifier")]
fn is_tcb_data_valid(report: &AttestationReport) -> bool {
    report.reported_tcb == report.committed_tcb
}

#[cfg(feature = "verifier")]
fn get_report_base(report: &AttestationReport) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    // Use sev's write_bytes method (since SEV-6) for serializing SNP reports to ensure full compatibility
    // Original bincode::serialize + size_of calculation is inaccurate on SEV 6.x
    let mut raw_bytes = Vec::with_capacity(SNP_REPORT_SIZE);
    report
        .write_bytes(&mut raw_bytes)
        .map_err(|e| Box::new(bincode::ErrorKind::Io(e)))?;
    let report_bytes_without_sig = &raw_bytes[0..0x2a0];
    Ok(report_bytes_without_sig.to_vec())
}

/// Fetch TdReport from vTPM and parse it
pub fn get_report() -> Result<AttestationReport, ReportError> {
    let bytes = vtpm::get_report()?;
    let hcl_report = HclReport::new(bytes)?;
    let snp_report = hcl_report.try_into()?;
    Ok(snp_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hcl::HclReport;

    #[test]
    fn test_report_data_hash() {
        let bytes: &[u8] = include_bytes!("../../test/hcl-report-snp.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report: AttestationReport = hcl_report.try_into().unwrap();
        assert!(var_data_hash == snp_report.report_data[..32]);
    }
}
