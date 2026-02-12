// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use openssl::asn1::Asn1Time;
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
    #[error("VCEK is not signed by ASK (or not valid at verification time)")]
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

        let now = Asn1Time::days_from_now(0)?;
        let valid_range = self.0.not_before()..self.0.not_after();
        if !valid_range.contains(&now) {
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
    use crate::certs::{AmdChain, Vcek};
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn build_dummy_chain() -> (Vcek, AmdChain) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "test-expired")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        let not_before = Asn1Time::from_str("20200101000000Z").unwrap();
        let not_after = Asn1Time::from_str("20210101000000Z").unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder.sign(&pkey, MessageDigest::sha384()).unwrap();
        let expired_cert = builder.build();

        let vcek = Vcek(expired_cert);
        let chain = AmdChain {
            ask: vcek.0.clone(),
            ark: vcek.0.clone(),
        };
        (vcek, chain)
    }

    fn build_chain_from_pem() -> (Vcek, AmdChain) {
        let bytes = include_bytes!("../../test/certs.pem");
        let certs = X509::stack_from_pem(bytes).unwrap();
        let (vcek, ask, ark) = (certs[0].clone(), certs[1].clone(), certs[2].clone());
        let vcek = Vcek(vcek);
        let cert_chain = AmdChain { ask, ark };
        (vcek, cert_chain)
    }

    #[test]
    fn test_validate_certificates() {
        // test valid chain
        let (vcek, mut chain) = build_chain_from_pem();
        chain.validate().unwrap();
        vcek.validate(&chain).unwrap();

        // test invalid chain
        chain.ark = chain.ask.clone();
        let result = chain.validate();
        assert!(
            result.is_err(),
            "should fail validation since ASK is not self-signed"
        );

        // test expired vcek
        let (expired_vcek, chain) = build_dummy_chain();
        let result = expired_vcek.validate(&chain);
        assert!(
            result.is_err(),
            "should fail validation for expired certificate"
        );
    }
}
