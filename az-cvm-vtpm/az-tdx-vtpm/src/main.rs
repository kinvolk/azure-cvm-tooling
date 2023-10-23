// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Result;
use az_tdx_vtpm::{hcl, imds, vtpm};

fn main() -> Result<()> {
    let bytes = vtpm::get_report()?;
    let hcl_report = hcl::HclReport::new(bytes)?;

    let hash = hcl_report.var_data_sha256();
    println!("var_data hash: {:x?}", hash);

    let tdx_report_slice = hcl_report.tdx_report_slice();
    let report_body = imds::ReportBody::new(tdx_report_slice);
    let td_quote_bytes = imds::get_td_quote(report_body)?;
    std::fs::write("td_quote.bin", td_quote_bytes)?;

    Ok(())
}
