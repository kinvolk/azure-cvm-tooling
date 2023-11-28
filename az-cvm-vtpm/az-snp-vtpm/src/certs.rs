// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub use openssl::x509::X509;
use thiserror::Error;

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
    pub fn from_pem(pem: &str) -> Result<Self, ParseError> {
        let cert = X509::from_pem(pem.as_bytes())?;
        Ok(Self(cert))
    }

    pub fn validate(&self, amd_chain: &AmdChain) -> Result<(), ValidateError> {
        let ask_pubkey = amd_chain.ask.public_key()?;
        let vcek_signed = self.0.verify(&ask_pubkey)?;
        if !vcek_signed {
            return Err(ValidateError::VcekNotSignedByAsk);
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("wrong amount of certificates (expected {0:?}, found {1:?})")]
    WrongAmount(usize, usize),
}

/// build ASK + ARK certificate chain from a multi-pem string
pub fn build_cert_chain(pem: &str) -> Result<AmdChain, ParseError> {
    let certs = X509::stack_from_pem(pem.as_bytes())?;

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
        let bytes = include_bytes!("../../test/certs.pem");
        let certs = X509::stack_from_pem(bytes).unwrap();
        let (vcek, ask, ark) = (certs[0].clone(), certs[1].clone(), certs[2].clone());
        let vcek = Vcek(vcek);
        let cert_chain = AmdChain { ask, ark };
        cert_chain.validate().unwrap();
        vcek.validate(&cert_chain).unwrap();
    }
}
