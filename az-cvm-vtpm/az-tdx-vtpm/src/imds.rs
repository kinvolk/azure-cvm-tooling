// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::Deserialize;
use thiserror::Error;

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

pub struct ReportBody {
    report: String,
}

impl ReportBody {
    pub fn new(report_bytes: &[u8]) -> Self {
        let report = base64_url::encode(report_bytes);
        Self { report }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct QuoteResponse {
    quote: String,
}

pub fn get_td_quote(report_body: ReportBody) -> Result<Vec<u8>, ImdsError> {
    let response: QuoteResponse = ureq::post(IMDS_QUOTE_URL)
        .send_json(ureq::json!({
            "report": report_body.report,
        }))
        .map_err(Box::new)?
        .into_json()?;
    let quote = base64_url::decode(&response.quote)?;
    Ok(quote)
}
