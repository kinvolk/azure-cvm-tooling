use openssl::x509::X509;
use reqwest::blocking::get as http_get;
use reqwest::blocking::Client as http_client;
use serde::Deserialize;
use sev::firmware::guest::types::AttestationReport;
use std::error::Error;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";
const KDS_VCEK: &str = "/vcek/v1";
const SEV_PROD_NAME: &str = "Milan";
const KDS_CERT_CHAIN: &str = "cert_chain";

pub struct AmdChain {
    pub ask: X509,
    pub ark: X509,
}

impl AmdChain {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        let ark_pubkey = self.ark.public_key()?;

        let ark_signed = self.ark.verify(&ark_pubkey)?;
        if !ark_signed {
            return Err("ARK is not self-signed".into());
        }

        let ask_signed = self.ask.verify(&ark_pubkey)?;
        if !ask_signed {
            return Err("ASK is not signed by ARK".into());
        }

        Ok(())
    }
}

pub struct Vcek(pub X509);

impl Vcek {
    pub fn validate(&self, amd_chain: &AmdChain) -> Result<(), Box<dyn Error>> {
        let ask_pubkey = amd_chain.ask.public_key()?;
        let vcek_signed = self.0.verify(&ask_pubkey)?;
        if !vcek_signed {
            return Err("VCEK is not signed by ASK".into());
        }

        Ok(())
    }
}

pub fn get_chain_from_amd() -> Result<AmdChain, Box<dyn Error>> {
    let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
    let resp = http_get(url)?;
    let status = resp.status();
    if status != 200 {
        let err_str = format!("Failed to get certificate chain from AMD: HTTP {status}");
        return Err(err_str.into());
    }
    let bytes = resp.bytes()?;
    let certs = X509::stack_from_pem(&bytes)?;

    let ask = certs[0].clone();
    let ark = certs[1].clone();

    let chain = AmdChain { ask, ark };

    Ok(chain)
}

fn hexify(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for byte in bytes {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

pub fn get_vcek_from_amd(report: &AttestationReport) -> Result<Vcek, Box<dyn Error>> {
    let hw_id = hexify(&report.chip_id);
    let url = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        report.reported_tcb.boot_loader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    let resp = http_get(url)?;
    let status = resp.status();
    if status != 200 {
        let err_str = format!("Failed to get VCEK from AMD: HTTP {status}");
        return Err(err_str.into());
    }
    let bytes = resp.bytes()?;
    let cert = X509::from_der(&bytes)?;
    Ok(Vcek(cert))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsResponse {
    vcek_cert: String,
    certificate_chain: String,
}

pub fn get_from_imds() -> Result<(Vcek, AmdChain), Box<dyn Error>> {
    let client = http_client::new();
    let resp = client
        .get(IMDS_CERT_URL)
        .header("Metadata", "true")
        .send()?;

    let status = resp.status();
    if status != 200 {
        let err_str = format!("Failed to get certificates from IMDS endpoint: HTTP {status}");
        return Err(err_str.into());
    }
    let text = resp.text()?;
    let res: ImdsResponse = serde_json::from_str(&text)?;

    let vcek = Vcek(X509::from_pem(res.vcek_cert.as_bytes())?);
    let cert_chain = build_chain(res.certificate_chain.as_bytes())?;

    Ok((vcek, cert_chain))
}

fn build_chain(bytes: &[u8]) -> Result<AmdChain, Box<dyn Error>> {
    let certs = X509::stack_from_pem(bytes)?;

    if certs.len() != 2 {
        let err_str = format!("Expected 2 certificates in chain, got {}", certs.len());
        return Err(err_str.into());
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
