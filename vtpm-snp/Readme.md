# vTPM based SEV-SNP attestation for CVMs

## Create a CVM

Default image is Ubuntu 22.04 cvm

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/.../images/.../versions/1.0.0
make deploy
```

## Build & Install

```
cargo b --release
scp target/release/vtpm-snp azureuser@$CONFIDENTIAL_VM
```

## Run

```
sudo ./vtpm-snp -i -p
```
