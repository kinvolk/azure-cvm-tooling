use serde::Deserialize;
use thiserror::Error;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub vcek_cert: String,
    pub certificate_chain: String,
}

#[derive(Error, Debug)]
pub enum ImdsError {
    #[error("HTTP error")]
    Http(#[from] ureq::Error),
    #[error("failed to read IMDS response")]
    Io(#[from] std::io::Error),
}

pub fn retrieve_certs() -> Result<Response, ImdsError> {
    let response = ureq::get(IMDS_CERT_URL)
        .set("Metadata", "true")
        .call()?
        .into_json()?;
    Ok(response)
}
