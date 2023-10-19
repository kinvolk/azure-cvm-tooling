// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

const TDX_REPORT_DATA_LENGTH: usize = 64;

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TdxReportMac {
    pub report_type: u8,
    pub report_sub_type: u8,
    pub report_version: u8,
    pub reserved_type_mbz: u8,
    pub reserved_mbz1: [u8; 12],
    pub cpu_svn: [u8; 16],
    #[serde(with = "BigArray")]
    pub tee_tcb_info_hash: [u8; 48],
    #[serde(with = "BigArray")]
    pub tee_info_hash: [u8; 48],
    #[serde(with = "BigArray")]
    pub report_data: [u8; TDX_REPORT_DATA_LENGTH],
    pub reserved_mbz2: [u8; 32],
    pub mac: [u8; 32],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TdxTeeTcbInfo {
    pub tee_valid: [u8; 8],
    pub tee_tcb_svn: [u8; 16],
    #[serde(with = "BigArray")]
    pub tee_mr_seam: [u8; 48],
    #[serde(with = "BigArray")]
    pub tee_mr_seam_signer: [u8; 48],
    pub tee_attributes: [u8; 8],
    pub tee_tcb_svn2: [u8; 16],
    #[serde(with = "BigArray")]
    pub tee_reserved: [u8; 95],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TdxRtmr {
    #[serde(with = "BigArray")]
    pub register_data: [u8; 48],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TdxTdInfo {
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    #[serde(with = "BigArray")]
    pub mrtd: [u8; 48],
    #[serde(with = "BigArray")]
    pub mr_config_id: [u8; 48],
    #[serde(with = "BigArray")]
    pub mr_owner: [u8; 48],
    #[serde(with = "BigArray")]
    pub mr_owner_config: [u8; 48],
    pub rtrm: [TdxRtmr; 4],
    #[serde(with = "BigArray")]
    pub serv_td: [u8; 48],
    #[serde(with = "BigArray")]
    pub reserved_mbz: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TdxVmReport {
    pub tdx_report_mac: TdxReportMac,
    pub tdx_tee_tcb_info: TdxTeeTcbInfo,
    pub tdx_reserved: [u8; 17],
    pub tdx_td_info: TdxTdInfo,
}
