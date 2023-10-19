// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use raw_cpuid::{cpuid, CpuId, Hypervisor};
use thiserror::Error;

// https://elixir.bootlin.com/linux/v6.6-rc6/source/arch/x86/include/asm/hyperv-tlfs.h#L169
const HYPERV_CPUID_ISOLATION_CONFIG: u32 = 0x4000000C;
const HV_ISOLATION_TYPE: u32 = 0xF;
const HYPERV_CPUID_FEATURES: u32 = 0x40000003;
const HV_ISOLATION: u32 = 1 << 22;
const HV_ISOLATION_TYPE_SNP: u32 = 2;
const HV_ISOLATION_TYPE_TDX: u32 = 3;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Not a VM")]
    NoVM,
    #[error("Not running on Hyper-V")]
    NotHyperV,
    #[error("VM is not an CVM")]
    NotCVM,
    #[error("Unknown CVM type")]
    UnknownCVMType,
}

#[derive(Debug)]
pub enum CvmType {
    SNP,
    TDX,
}

pub fn detect() -> Result<CvmType, DetectionError> {
    let cpuid = CpuId::new();
    let Some(hyper_info) = cpuid.get_hypervisor_info() else {
        return Err(DetectionError::NoVM);
    };
    let hypervisor = hyper_info.identify();
    if hypervisor != Hypervisor::HyperV {
        return Err(DetectionError::NotHyperV);
    }

    let hv_features = cpuid!(HYPERV_CPUID_FEATURES);
    if hv_features.ebx & HV_ISOLATION == 0 {
        return Err(DetectionError::NotCVM);
    }

    let hv_isol_config = cpuid!(HYPERV_CPUID_ISOLATION_CONFIG);
    let isolation_type = hv_isol_config.ebx & HV_ISOLATION_TYPE;
    let cvm_type = match isolation_type {
        HV_ISOLATION_TYPE_SNP => CvmType::SNP,
        HV_ISOLATION_TYPE_TDX => CvmType::TDX,
        _ => panic!("Unknown CVM type"),
    };
    Ok(cvm_type)
}
