// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_cvm_vtpm::hcl::HclReport;
use az_cvm_vtpm::vtpm;
use az_snp_vtpm::{amd_kds, certs, imds, report};
use clap::Parser;
use report::{AttestationReport, Validateable};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    Report {
        /// Raw unmodified report bytes
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Print the report to stdout
        #[arg(short, long)]
        print: bool,

        /// Retrieve certificates from IMDS endpoint
        #[arg(short, long)]
        imds: bool,
    },
    Quote {
        /// A nonce to use for the quote
        #[arg(short, long)]
        nonce: String,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    match args.action {
        Action::Report { file, imds, print } => {
            let bytes = match file {
                Some(file_name) => read_file(&file_name)?,
                None => vtpm::get_report()?,
            };
            let hcl_report = HclReport::new(bytes)?;
            let snp_report: AttestationReport = hcl_report.try_into()?;

            let (vcek, cert_chain) = if imds {
                let pem_certs = imds::get_certs()?;
                let vcek = certs::Vcek::from_pem(&pem_certs.vcek)?;
                let cert_chain = certs::build_cert_chain(&pem_certs.amd_chain)?;
                (vcek, cert_chain)
            } else {
                let vcek = amd_kds::get_vcek(&snp_report)?;
                let cert_chain = amd_kds::get_cert_chain()?;
                (vcek, cert_chain)
            };

            cert_chain.validate()?;
            vcek.validate(&cert_chain)?;
            snp_report.validate(&vcek)?;

            if print {
                println!("{}", snp_report);
            }
        }
        Action::Quote { nonce } => {
            println!("quote byte size: {}", nonce.as_bytes().len());
            let quote = vtpm::get_quote(nonce.as_bytes())?;
            println!("{:02X?}", quote.message());
        }
    }

    Ok(())
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
