use serde::Deserialize;
use thiserror::Error;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificates {
    pub vcek_cert: Vec<u8>,
    pub certificate_chain: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum ImdsError {
    #[error("HTTP error")]
    Http(#[from] Box<ureq::Error>),
    #[error("failed to read IMDS response")]
    Io(#[from] std::io::Error),
}

pub fn get_certs() -> Result<Certificates, ImdsError> {
    let res: Certificates = ureq::get(IMDS_CERT_URL)
        .set("Metadata", "true")
        .call()
        .map_err(Box::new)?
        .into_json()?;
    Ok(res)
}
