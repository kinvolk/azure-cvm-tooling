// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//!  This library enables guest attestation flows for [TDX CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/tdx-confidential-vm-overview). TDX CVMs are currently in limited preview and hence the library is considered experimental and subject to change.
//!  #
//!  ```no_run
//!  use az_tdx_vtpm::{imds, hcl, vtpm};
//!  use std::error::Error;
//!
//!  fn main() -> Result<(), Box<dyn Error>> {
//!    let bytes = vtpm::get_report()?;
//!    let hcl_report = hcl::HclReport::new(bytes)?;
//!    let tdx_report_slice = hcl_report.tdx_report_slice();
//!    let report_body = imds::ReportBody::new(tdx_report_slice);
//!    let td_quote_bytes = imds::get_td_quote(report_body)?;
//!    let hash = hcl_report.var_data_sha256();
//!    println!("var_data hash: {:x?}", hash);
//!    std::fs::write("td_quote.bin", td_quote_bytes)?;
//!    Ok(())
//!  }
//!  ```

pub use az_snp_vtpm::vtpm;

pub mod hcl;
pub mod imds;
pub mod tdx;
#[cfg(feature = "verifier")]
pub mod verify;

pub fn is_tdx_cvm() -> Result<bool, tss_esapi::Error> {
    let bytes = vtpm::get_report()?;
    let Ok(hcl_report) = hcl::HclReport::new(bytes) else {
        return Ok(false);
    };
    let is_tdx = hcl_report.report_type() == hcl::ReportType::Tdx;
    Ok(is_tdx)
}
