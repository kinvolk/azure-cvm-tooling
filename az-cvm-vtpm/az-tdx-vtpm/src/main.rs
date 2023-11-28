// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = vtpm::get_report()?;
    let hcl_report = hcl::HclReport::new(bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();
    let ak_pub = hcl_report.ak_pub()?;

    let td_report: tdx::TdReport = hcl_report.try_into()?;
    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);
    println!("vTPM AK_pub: {:?}", ak_pub);
    let td_quote_bytes = imds::get_td_quote(&td_report)?;
    std::fs::write("td_quote.bin", td_quote_bytes)?;

    Ok(())
}
