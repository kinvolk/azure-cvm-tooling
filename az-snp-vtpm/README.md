# vTPM based SEV-SNP attestation for Azure Confidential VMs

This library enables guest attestation flows for [SEV-SNP CVMs on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview). Please refer to the documentation in [this repository](https://github.com/Azure/confidential-computing-cvm-guest-attestation) for details on the attestation procedure.

## Create a CVM

Default image is Ubuntu 22.04 cvm

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/.../images/.../versions/1.0.0
make deploy
```

## Build & Install

```bash
cargo b --release
scp target/release/snp-vtpm azureuser@$CONFIDENTIAL_VM:
```

## Run Binary

Retrieve SEV-SNP report, validate and print it:

```bash
sudo ./snp-vtpm -p
```
