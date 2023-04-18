// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::HttpError;
use serde::Deserialize;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

/// PEM encoded VCEK certificate and AMD certificate chain.
#[derive(Deserialize)]
pub struct Certificates {
    #[serde(rename = "vcekCert")]
    pub vcek: String,
    #[serde(rename = "certificateChain")]
    pub amd_chain: String,
}

/// Get the VCEK certificate and the certificate chain from the Azure IMDS.
/// **Note:** this can only be called from a Confidential VM.
pub fn get_certs() -> Result<Certificates, HttpError> {
    let res: Certificates = ureq::get(IMDS_CERT_URL)
        .set("Metadata", "true")
        .call()
        .map_err(Box::new)?
        .into_json()?;
    Ok(res)
}
