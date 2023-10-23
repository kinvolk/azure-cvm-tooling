# az-tdx-vtpm

[![Rust](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml/badge.svg)](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml)

> [!WARNING]  
> This library enables guest attestation and verification for [TDX CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/tdx-confidential-vm-overview). TDX CVMs are currently in limited preview and hence the library is considered experimental and subject to change.

## Build & Install

```bash
cargo b --release -p az-tdx-vtpm
scp ../target/release/tdx-vtpm azureuser@$CONFIDENTIAL_VM:
```

## Run Binary

On the TDX CVM, retrieve a TD Quote and write it to disk:

```bash
sudo ./tdx-vtpm
```
