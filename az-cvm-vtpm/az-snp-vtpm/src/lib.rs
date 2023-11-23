// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//!  This library enables guest attestation flows for [SEV-SNP CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview). Please refer to the documentation in [this repository](https://github.com/Azure/confidential-computing-cvm-guest-attestation) for details on the attestation procedure.
//!
//!  # SNP Report Validation
//!
//!  The following code will retrieve an SNP report from the vTPM device, parse it, and validate it against the AMD certificate chain. Finally it will verify that a hash of a raw HCL report's Variable Data is equal to the `report_data` field in an embedded [Attestation Report](sev::firmware::guest::AttestationReport) structure.
//!
//!  #
//!  ```no_run
//!  use az_snp_vtpm::{amd_kds, hcl, vtpm};
//!  use az_snp_vtpm::report::{AttestationReport, Validateable};
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!    let bytes = vtpm::get_report()?;
//!    let hcl_report = hcl::HclReport::new(bytes)?;
//!    let var_data_hash = hcl_report.var_data_sha256();
//!    let snp_report: AttestationReport = hcl_report.try_into()?;
//!
//!    let vcek = amd_kds::get_vcek(&snp_report)?;
//!    let cert_chain = amd_kds::get_cert_chain()?;
//!
//!    cert_chain.validate()?;
//!    vcek.validate(&cert_chain)?;
//!    snp_report.validate(&vcek)?;
//!
//!    if var_data_hash != snp_report.report_data[..32] {
//!      return Err("var_data_hash mismatch".into());
//!    }
//!
//!    Ok(())
//!  }
//!  ```

pub use az_cvm_vtpm::{hcl, vtpm};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("HTTP error")]
    Http(#[from] Box<ureq::Error>),
    #[error("failed to read HTTP response")]
    Io(#[from] std::io::Error),
}

/// Determines if the current VM is an SEV-SNP CVM.
/// Returns `Ok(true)` if the VM is an SEV-SNP CVM, `Ok(false)` if it is not,
/// and `Err` if an error occurs.
pub fn is_snp_cvm() -> Result<bool, vtpm::ReportError> {
    let bytes = vtpm::get_report()?;
    let Ok(hcl_report) = hcl::HclReport::new(bytes) else {
        return Ok(false);
    };
    let is_snp = hcl_report.report_type() == hcl::ReportType::Snp;
    Ok(is_snp)
}

#[cfg(feature = "verifier")]
pub mod amd_kds;
#[cfg(feature = "verifier")]
pub mod certs;
#[cfg(feature = "attester")]
pub mod imds;
pub mod report;
