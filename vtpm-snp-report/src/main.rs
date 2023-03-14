use clap::Parser;
use report::Validateable;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

mod certs;
mod hcl;
mod report;
mod vtpm;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Raw unmodified report bytes
    #[arg(short, long)]
    file_name: Option<PathBuf>,

    /// Print the report to stdout
    #[arg(short, long)]
    print_report: bool,

    /// Retrieve certificates from IMDS endpoint
    #[arg(short, long)]
    imds: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let bytes = match args.file_name {
        Some(file_name) => read_file(&file_name)?,
        None => vtpm::get_report()?,
    };
    let report = report::parse(&bytes)?;

    let (vcek, cert_chain) = if args.imds {
        certs::get_from_imds()?
    } else {
        let vcek = certs::get_vcek_from_amd(&report)?;
        let cert_chain = certs::get_chain_from_amd()?;
        (vcek, cert_chain)
    };

    cert_chain.validate()?;
    vcek.validate(&cert_chain)?;
    report.validate(&vcek)?;

    if args.print_report {
        println!("{}", report);
    }

    Ok(())
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
