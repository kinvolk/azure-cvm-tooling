// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::imds;
use openssl::x509::X509;
use sev::firmware::guest::types::AttestationReport;
use thiserror::Error;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const SEV_PROD_NAME: &str = "Milan";
const KDS_CERT_CHAIN: &str = "cert_chain";

pub struct AmdChain {
    pub ask: X509,
    pub ark: X509,
}

#[derive(Error, Debug)]
pub enum ValidateError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("ARK is not self-signed")]
    ArkNotSelfSigned,
    #[error("ASK is not signed by ARK")]
    AskNotSignedByArk,
    #[error("VCEK is not signed by ASK")]
    VcekNotSignedByAsk,
}

#[derive(Error, Debug)]
pub enum CertError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("AMD KDS error")]
    AmdKdsError(#[from] AmdKdsError),
    #[error("IMDS error")]
    Imds(#[from] imds::ImdsError),
    #[error("parsing error")]
    Parse(#[from] ParseError),
}

impl AmdChain {
    pub fn validate(&self) -> Result<(), ValidateError> {
        let ark_pubkey = self.ark.public_key()?;

        let ark_signed = self.ark.verify(&ark_pubkey)?;
        if !ark_signed {
            return Err(ValidateError::ArkNotSelfSigned);
        }

        let ask_signed = self.ask.verify(&ark_pubkey)?;
        if !ask_signed {
            return Err(ValidateError::AskNotSignedByArk);
        }

        Ok(())
    }
}

pub struct Vcek(pub X509);

impl Vcek {
    pub fn validate(&self, amd_chain: &AmdChain) -> Result<(), ValidateError> {
        let ask_pubkey = amd_chain.ask.public_key()?;
        let vcek_signed = self.0.verify(&ask_pubkey)?;
        if !vcek_signed {
            return Err(ValidateError::VcekNotSignedByAsk);
        }

        Ok(())
    }
}

pub struct AmdKds<'a>(&'a AttestationReport);

#[derive(Error, Debug)]
pub enum AmdKdsError {
    #[error("HTTP error")]
    Http(#[from] ureq::Error),
    #[error("io error")]
    Io(#[from] std::io::Error),
}

impl<'a> AmdKds<'a> {
    pub fn new(report: &'a AttestationReport) -> Self {
        Self(report)
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, AmdKdsError> {
        let mut body = ureq::get(url).call()?.into_reader();
        let mut buffer = Vec::new();
        body.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

pub trait CertProvider {
    fn get_chain(&self) -> Result<AmdChain, CertError>;
    fn get_vcek(&self) -> Result<Vcek, CertError>;
}

impl CertProvider for imds::Response {
    fn get_chain(&self) -> Result<AmdChain, CertError> {
        let chain = build_chain(self.certificate_chain.as_bytes())?;
        Ok(chain)
    }

    fn get_vcek(&self) -> Result<Vcek, CertError> {
        let vcek = Vcek(X509::from_pem(self.vcek_cert.as_bytes())?);
        Ok(vcek)
    }
}

impl<'a> CertProvider for AmdKds<'a> {
    fn get_chain(&self) -> Result<AmdChain, CertError> {
        let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
        let bytes = self.get(&url)?;

        let certs = X509::stack_from_pem(&bytes)?;
        let ask = certs[0].clone();
        let ark = certs[1].clone();

        let chain = AmdChain { ask, ark };

        Ok(chain)
    }

    fn get_vcek(&self) -> Result<Vcek, CertError> {
        let hw_id = hexify(&self.0.chip_id);
        let url = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            self.0.reported_tcb.boot_loader,
            self.0.reported_tcb.tee,
            self.0.reported_tcb.snp,
            self.0.reported_tcb.microcode
        );

        let bytes = self.get(&url)?;
        let cert = X509::from_der(&bytes)?;
        let vcek = Vcek(cert);
        Ok(vcek)
    }
}

fn hexify(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("wrong amount of certificates (expected {0:?}, found {1:?})")]
    WrongAmount(usize, usize),
}

fn build_chain(bytes: &[u8]) -> Result<AmdChain, ParseError> {
    let certs = X509::stack_from_pem(bytes)?;

    if certs.len() != 2 {
        return Err(ParseError::WrongAmount(2, certs.len()));
    }

    let ask = certs[0].clone();
    let ark = certs[1].clone();

    let chain = AmdChain { ask, ark };

    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_certificates() {
        let bytes = include_bytes!("../test/certs.pem");
        let certs = X509::stack_from_pem(bytes).unwrap();
        let (vcek, ask, ark) = (certs[0].clone(), certs[1].clone(), certs[2].clone());
        let vcek = Vcek(vcek);
        let cert_chain = AmdChain { ask, ark };
        cert_chain.validate().unwrap();
        vcek.validate(&cert_chain).unwrap();
    }
}
