use crate::hcl::{self, HclReport};
use crate::tdx::TdReport;
use crate::vtpm;
use bincode::deserialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("deserialization error")]
    Parse(#[from] Box<bincode::ErrorKind>),
    #[error("vTPM error")]
    Vtpm(#[from] vtpm::ReportError),
    #[error("HCL error")]
    Hcl(#[from] hcl::HclError),
}

/// Parse raw bytes into TdReport
pub fn parse(bytes: &[u8]) -> Result<TdReport, ReportError> {
    deserialize::<TdReport>(bytes).map_err(|e| e.into())
}

/// Fetch TdReport from vTPM and parse it
pub fn get_report() -> Result<TdReport, ReportError> {
    let bytes = vtpm::get_report()?;
    let hcl_report = HclReport::new(bytes)?;
    let td_report = hcl_report.try_into()?;
    Ok(td_report)
}
