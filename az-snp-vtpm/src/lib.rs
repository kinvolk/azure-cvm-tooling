// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//!  This library enables guest attestation flows for [SEV-SNP CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview). Please refer to the documentation in [this repository](https://github.com/Azure/confidential-computing-cvm-guest-attestation) for details on the attestation procedure.
//!
//!  # SNP Report Validation
//!
//!  The following code will retrieve an SNP report from the vTPM device, parse it, and validate it against the AMD certificate chain. Finally it will verify that a hash of a raw HCL report's [RuntimeData](hcl::RuntimeData) is equal to the `report_data` field in an embedded [Attestation Report](sev::firmware::guest::types::AttestationReport) structure.
//!
//!  #
//!  ```no_run
//!  use az_snp_vtpm::vtpm::get_report;
//!  use az_snp_vtpm::amd_kds;
//!  use az_snp_vtpm::report::Validateable;
//!  use az_snp_vtpm::hcl::{self, HclData};
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!    let bytes = get_report()?;
//!    let hcl_data: HclData = bytes[..].try_into()?;
//!    let snp_report = hcl_data.report().snp_report();
//!
//!    let vcek = amd_kds::get_vcek(&snp_report)?;
//!    let cert_chain = amd_kds::get_cert_chain()?;
//!
//!    cert_chain.validate()?;
//!    vcek.validate(&cert_chain)?;
//!    snp_report.validate(&vcek)?;
//!
//!    let var_data = hcl_data.var_data();
//!    hcl_data.report().verify_report_data(&var_data)?;
//!
//!    Ok(())
//!  }
//!  ```

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HttpError {
    #[error("HTTP error")]
    Http(#[from] Box<ureq::Error>),
    #[error("failed to read HTTP response")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "verifier")]
pub mod amd_kds;
#[cfg(feature = "verifier")]
pub mod certs;
pub mod hcl;
#[cfg(feature = "attester")]
pub mod imds;
pub mod report;
pub mod vtpm;
