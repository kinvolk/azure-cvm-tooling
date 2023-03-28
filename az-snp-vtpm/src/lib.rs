// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//!  This library enables guest attestation flows for [SEV-SNP CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview). Please refer to the documentation in [this repository](https://github.com/Azure/confidential-computing-cvm-guest-attestation) for details on the attestation procedure.
//!
//!  # SNP Report Validation
//!
//!  The following code will retrieve an SNP report from the vTPM device, parse it, and validate it against the AMD certificate chain. Finally it will verify that a hash of a raw HCL report's [ReportData](hcl::ReportData) is equal to the `report_data` field in an embedded [Attestation Report](sev::firmware::guest::types::AttestationReport) structure.
//!
//!  ```no_run
//!  use az_snp_vtpm::{certs, hcl, vtpm};
//!  use az_snp_vtpm::report::Validateable;
//!  use az_snp_vtpm::hcl::HclReportWithRuntimeData;
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!    let bytes = vtpm::get_report()?;
//!    let hcl_report: HclReportWithRuntimeData = bytes[..].try_into()?;
//!    let snp_report = hcl_report.snp_report();
//!
//!    let vcek = certs::get_vcek_from_amd(snp_report)?;
//!    let cert_chain = certs::get_chain_from_amd()?;
//!
//!    cert_chain.validate()?;
//!    vcek.validate(&cert_chain)?;
//!    snp_report.validate(&vcek)?;
//!
//!    hcl::verify_report_data(&bytes)?;
//!
//!    Ok(())
//!  }
//!  ```

pub mod certs;
pub mod hcl;
pub mod report;
pub mod vtpm;
