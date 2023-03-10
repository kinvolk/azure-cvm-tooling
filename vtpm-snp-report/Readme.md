# vTPM based SNP reports in GA Confidential VMs

The following has been tested on Ubuntu and Redhat

## Create a CVM

This will use a RHEL cvm image, default is Ubuntu 22.04 cvm.

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/rhelcvm/images/rhelcvmimage/versions/1.0.0
make deploy
```

## Build & Install

```
cargo b --release
scp target/release/vtpm-snp azureuser@$CONFIDENTIAL_VM
```

## Run

```
sudo tpm2_nvread -C o 0x01400001 > vtpm_snp_report.bin
./vtpm-snp vtpm_snp_report.bin
```
