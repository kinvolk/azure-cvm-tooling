// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//!  This library enables guest attestation flows for [TDX CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/tdx-confidential-vm-overview).
//!
//!  A TD report can be retrieved in parsed form using `report::get_report()` function, or as
//!  raw bytes including the hcl envelope using `vtpm::get_report()`. The library provides a
//!  function to retrieve the TD quote from the Azure Instance Metadata Service (IMDS) using
//!  `imds::get_td_quote()`, produce returning a quote signed by a TDX Quoting Enclave.
//!
//!  Variable Data is part of the HCL envelope and holds the public part of the vTPM Attestation
//!  Key (AK). A hash of the Variable Data block is included in the TD report as `reportdata`.
//!  TPM quotes retrieved with `vtpm::get_quote()` should be signed by this AK. A verification
//!  function would need to check this to ensure the TD report is linked to this unique TDX CVM.
//!  
//!  #
//!  ```no_run
//!  use az_tdx_vtpm::{hcl, imds, report, tdx, vtpm};
//!  use openssl::pkey::{PKey, Public};
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!    let td_report = report::get_report()?;
//!    let td_quote_bytes = imds::get_td_quote(&td_report)?;
//!    std::fs::write("td_quote.bin", td_quote_bytes)?;
//!
//!    let bytes = vtpm::get_report()?;
//!    let hcl_report = hcl::HclReport::new(bytes)?;
//!    let var_data_hash = hcl_report.var_data_sha256();
//!    let ak_pub = hcl_report.ak_pub()?;
//!
//!    let td_report: tdx::TdReport = hcl_report.try_into()?;
//!    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
//!    let nonce = "a nonce".as_bytes();
//!
//!    let tpm_quote = vtpm::get_quote(nonce)?;
//!    let der = ak_pub.key.try_to_der()?;
//!    let pub_key = PKey::public_key_from_der(&der)?;
//!    tpm_quote.verify(&pub_key, nonce)?;
//!
//!    Ok(())
//!  }
//!  ```

pub mod imds;
pub mod report;
pub use az_cvm_vtpm::{hcl, tdx, vtpm};

/// Determines if the current VM is a TDX CVM.
/// Returns `Ok(true)` if the VM is a TDX CVM, `Ok(false)` if it is not,
/// and `Err` if an error occurs.
pub fn is_tdx_cvm() -> Result<bool, vtpm::ReportError> {
    let bytes = vtpm::get_report()?;
    let Ok(hcl_report) = hcl::HclReport::new(bytes) else {
        return Ok(false);
    };
    let is_tdx = hcl_report.report_type() == hcl::ReportType::Tdx;
    Ok(is_tdx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hcl::HclReport;
    use tdx::TdReport;

    #[test]
    fn test_report_data_hash() {
        let bytes: &[u8] = include_bytes!("../../test/hcl-report-tdx.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let td_report: TdReport = hcl_report.try_into().unwrap();
        assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    }
}
