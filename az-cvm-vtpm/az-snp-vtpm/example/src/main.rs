// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_snp_vtpm::amd_kds;
use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl;
use az_snp_vtpm::imds;
use az_snp_vtpm::report::Validateable;
use az_snp_vtpm::vtpm;
use az_snp_vtpm::vtpm::VerifyVTpmQuote;
use std::error::Error;

struct Evidence {
    report: Vec<u8>,
    quote: vtpm::Quote,
    certs: imds::Certificates,
}

struct Attester;

impl Attester {
    fn gather_evidence(nonce: &[u8]) -> Result<Evidence, Box<dyn Error>> {
        let report = vtpm::get_report()?;
        let quote = vtpm::get_quote(nonce)?;
        let certs = imds::get_certs()?;

        Ok(Evidence {
            report,
            quote,
            certs,
        })
    }
}

struct Verifier;

impl Verifier {
    fn verify(nonce: &[u8], evidence: &Evidence) -> Result<(), Box<dyn Error>> {
        let hcl_data: hcl::HclData = evidence.report[..].try_into()?;
        let snp_report = hcl_data.report().snp_report();

        let cert_chain = amd_kds::get_cert_chain()?;
        let vcek = Vcek::from_pem(&evidence.certs.vcek)?;

        cert_chain.validate()?;
        vcek.validate(&cert_chain)?;
        snp_report.validate(&vcek)?;

        let var_data = hcl_data.var_data();
        hcl_data.report().verify_report_data(var_data)?;

        let ak_pub = var_data.ak_pub()?;
        ak_pub.verify_quote(&evidence.quote, nonce)?;

        Ok(())
    }
}

#[derive(Default)]
struct RelyingParty {
    nonce: Vec<u8>,
}

impl RelyingParty {
    pub fn request_secret(&mut self) -> Vec<u8> {
        // placeholder for a real nonce, it is usually randomly generated ephemeral value.
        let nonce = "challenge".as_bytes().to_vec();
        self.nonce = nonce.clone();
        nonce
    }

    pub fn release_secret(&self, evidence: &Evidence) -> Result<&'static str, Box<dyn Error>> {
        Verifier::verify(&self.nonce, evidence)?;
        Ok("secret")
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut rp = RelyingParty::default();
    let nonce = rp.request_secret();

    let evidence = Attester::gather_evidence(&nonce)?;
    let secret = rp.release_secret(&evidence)?;

    println!("Secret: {}", secret);
    Ok(())
}
