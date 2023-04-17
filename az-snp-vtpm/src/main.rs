// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use az_snp_vtpm::certs::CertProvider;
use az_snp_vtpm::hcl::HclReportWithRuntimeData;
use az_snp_vtpm::{certs, imds, report, vtpm};
use clap::Parser;
use report::Validateable;
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
            let hcl_report: HclReportWithRuntimeData = bytes[..].try_into()?;
            let snp_report = hcl_report.snp_report();

            let cert_provider: Box<dyn CertProvider> = if imds {
                let response = imds::retrieve_certs()?;
                Box::new(response)
            } else {
                let amd_kds = certs::AmdKds::new(&snp_report);
                Box::new(amd_kds)
            };

            let vcek = cert_provider.get_vcek()?;
            let cert_chain = cert_provider.get_chain()?;

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
            println!("{:02X?}", quote.message);
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
