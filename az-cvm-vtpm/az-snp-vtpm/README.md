[![Rust](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml/badge.svg)](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml)
[![Crate](https://img.shields.io/crates/v/az-snp-vtpm.svg)](https://crates.io/crates/az-snp-vtpm)
[![Docs](https://docs.rs/rand/badge.svg)](https://docs.rs/az-snp-vtpm)

# az-snp-vtpm

This library enables guest attestation flows for [SEV-SNP CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview). Please refer to the documentation in [this repository](https://github.com/Azure/confidential-computing-cvm-guest-attestation) for details on the attestation procedure.

## Create a CVM

Default image is Ubuntu 22.04 cvm

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/.../images/.../versions/1.0.0
make deploy
```

## Build & Install

```bash
cargo b --release -p az-snp-vtpm
scp ../target/release/snp-vtpm azureuser@$CONFIDENTIAL_VM:
```

## Run Binary

Retrieve SEV-SNP report, validate and print it:

```bash
sudo ./snp-vtpm -p
```

## Example Project

There is a project in the `./example` folder depicting how the crate can be leveraged in a Remote Attestation flow. **Note:** the code is merely illustrative and doesn't feature exhaustive validation, which would be required in a production scenario.

```bash
cargo b -p snp-example
```

## SEV-SNP Report & vTPM 

The vTPM is linked to the SEV-SNP report via the vTPM Attestation Key (AK). The public AK is part of a Runtime Data struct, which is hashed and submitted as Report Data when generating the SNP report. To provide freshness guarantees in an attestation exchange we can request a vTPM quote with a nonce. The resulting message is signed by the AK.

```
                              ┌────────────────────────┐
                              │ HCL Data               │
                              │                        │
                              │ ┌──────────────────────┴─┐  ─┐
                              │ │ Runtime Data           │   │
                              │ │                        │   │
    ┌──────────────────────┐  │ │ ┌────────────────────┐ │   ├─┐
  ┌─┤ vTPM AK              ├──┼─┼─┤ vTPM Public AK     │ │   │ │
  │ └──────────────────────┘  │ │ └────────────────────┘ │   │ │
  │         ┌──────────────┐  │ └──────────────────────┬─┘  ─┘ │
  │         │ vTPM Quote   │  │ ┌────────────────────┐ │       │
  │         │              │  │ │ HCL Report         │ │       │
signs ┌─  ┌─┴────────────┐ │  │ │                    │ │     sha256
  │   │   │ Message      │ │  │ │ ┌────────────────┐ │ │       │
  │   │   │              │ │  │ │ │ SEV-SNP Report │ │ │       │
  │   │   │ ┌──────────┐ │ │  │ │ │                │ │ │       │
  │   │   │ │ PCR0     │ │ │  │ │ │ ┌──────────────┴─┴─┴─┐     │
  │   │   │ └──────────┘ │ │  │ │ │ │ Report Data        │ ◄───┘
  │   │   │   ...        │ │  │ │ │ └──────────────┬─┬─┬─┘
  │   │   │ ┌──────────┐ │ │  │ │ └────────────────┘ │ │
  └─► │   │ │ PCRn     │ │ │  │ └────────────────────┘ │
      │   │ └──────────┘ │ │  └────────────────────────┘
      │   │ ┌──────────┐ │ │ 
      │   │ │ Nonce    │ │ │
      │   │ └──────────┘ │ │
      └─  └─┬────────────┘ │
            └──────────────┘
```
