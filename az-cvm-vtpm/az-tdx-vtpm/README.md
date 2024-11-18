# az-tdx-vtpm

[![Rust](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml/badge.svg)](https://github.com/kinvolk/azure-cvm-tooling/actions/workflows/rust.yml)
[![Crate](https://img.shields.io/crates/v/az-tdx-vtpm.svg)](https://crates.io/crates/az-tdx-vtpm)
[![Docs](https://docs.rs/rand/badge.svg)](https://docs.rs/az-tdx-vtpm)

This library enables guest attestation and verification for [TDX CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/tdx-confidential-vm-overview).

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

## Integration Tests

The integration test suite can run on a TDX CVM. It needs to be executed as root and the tests have to run sequentially.

```bash
sudo -E env "PATH=$PATH" cargo t --features integration_test -- --test-threads 1
```

