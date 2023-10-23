// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::certs::{AmdChain, Vcek};
use crate::HttpError;
use openssl::x509::X509;
use sev::firmware::guest::AttestationReport;
use thiserror::Error;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const SEV_PROD_NAME: &str = "Milan";
const KDS_CERT_CHAIN: &str = "cert_chain";

fn get(url: &str) -> Result<Vec<u8>, HttpError> {
    let mut body = ureq::get(url).call().map_err(Box::new)?.into_reader();
    let mut buffer = Vec::new();
    body.read_to_end(&mut buffer)?;
    Ok(buffer)
}

#[derive(Error, Debug)]
pub enum AmdKdsError {
    #[error("openssl error")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("Http error")]
    Http(#[from] HttpError),
}

/// Retrieve the AMD chain of trust (ASK & ARK) from AMD's KDS
pub fn get_cert_chain() -> Result<AmdChain, AmdKdsError> {
    let url = format!("{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{KDS_CERT_CHAIN}");
    let bytes = get(&url)?;

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

/// Retrieve a VCEK cert from AMD's KDS, based on an AttestationReport's platform information
pub fn get_vcek(report: &AttestationReport) -> Result<Vcek, AmdKdsError> {
    let hw_id = hexify(&report.chip_id);
    let url = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        report.reported_tcb.bootloader,
        report.reported_tcb.tee,
        report.reported_tcb.snp,
        report.reported_tcb.microcode
    );

    let bytes = get(&url)?;
    let cert = X509::from_der(&bytes)?;
    let vcek = Vcek(cert);
    Ok(vcek)
}
