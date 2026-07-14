// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_cvm_vtpm::tdx::TdReport;
use serde::Deserialize;
use std::convert::From;
use thiserror::Error;
use zerocopy::IntoBytes;

const IMDS_QUOTE_URL: &str = "http://169.254.169.254/acc/tdquote";

#[derive(Error, Debug)]
pub enum ImdsError {
    #[error("http error")]
    HttpError(#[from] Box<ureq::Error>),
    #[error("base64 error")]
    Base64Error(#[from] base64_url::base64::DecodeError),
    #[error("io error")]
    IoError(#[from] std::io::Error),
}

struct ReportBody {
    report: String,
}

impl From<ReportBody> for String {
    fn from(val: ReportBody) -> Self {
        format!(r#"{{"report":"{}"}}"#, val.report)
    }
}

impl ReportBody {
    fn new(report_bytes: &[u8]) -> Self {
        let report = base64_url::encode(report_bytes);
        Self { report }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct QuoteResponse {
    quote: String,
}

/// Retrieves a TDX quote from the Azure Instance Metadata Service (IMDS) using a provided TD
/// report.
pub fn get_td_quote(td_report: &TdReport) -> Result<Vec<u8>, ImdsError> {
    let bytes = td_report.as_bytes();
    let report_body = ReportBody::new(bytes);
    let raw_body: String = report_body.into();
    let mut response = ureq::post(IMDS_QUOTE_URL)
        .header("Metadata", "true")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send(raw_body)
        .map_err(Box::new)?;

    let response: QuoteResponse = response.body_mut().read_json().map_err(Box::new)?;
    let quote = base64_url::decode(&response.quote)?;

    Ok(quote)
}
