# CoCo End to End Testing

In this document you will build and deploy Key Broker Service (KBS) & Attestation Agent. The KBS will host a secret which will be released only when Attestation Agent sends a valid attestation package. In the end we verify if the secret deployed on KBS matches the secret downloaded after successful attestation. For the demo purposes we will deploy everything on the same Confidential Virtual Machine (CVM).

The following instructions have been tested on a Ubuntu 22 Azure CVM. It currently requires forks of the following CoCo upstream repositories, the KBS fork will pull the proper dependencies.

* cc/kbs
* cc/attestation-service
* cc/attestation-agent
* cc/kbs-types

## Deploy CVM on Azure

The configuration to deploy CVM on Azure are in the directory `vtpm-snp`. Make changes as you prefer in the following environment variables:

```bash
cd vtpm-snp

export CVM_RESOURCE_GROUP="cvm-vtpm-e2e"
export VM_NAME="cvm"
export SSH_PUB_KEY_PATH=$HOME/.ssh/id_rsa.pub
export ASSIGN_PUBLIC_IP=true
export VNET_NAME="cvmtest"
export SUBNET_NAME="cvmtest"
```

If you are testing a custom CVM image then export the following environment variable or skip this step:

```bash
export IMAGE_ID=/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/galleries/.../images/.../versions/0.0.1
```

Create a VNET, if you want to reuse an existing VNET then just export the ID in the following environment variable:

```bash
export VNET_ID=$(az network vnet create \
    -g "${CVM_RESOURCE_GROUP}" \
    -n "${VNET_NAME}" \
    --subnet-name "${SUBNET_NAME}" \
    --query=newVNet.id \
    -o tsv)
```

Deploy the CVM:

```bash
make deploy
```

Fetch the public IP of the VM and SSH into the machine:

```bash
export CVM_IP=$(az vm show \
    -d -g "${CVM_RESOURCE_GROUP}" \
    -n "${VM_NAME}" \
    --query=publicIps \
    -o tsv)

ssh -i "${SSH_PUB_KEY_PATH%.pub}" azureuser@"${CVM_IP}"
```

## Install Dependencies

> **NOTE:** Attestation Agent (and also, unfortunately at the moment, Attestation Service) code is linked to `tss-esapi` (TPM2 library) and OpenSSL, so we need to install the development packages.

```bash
sudo apt update
sudo apt install -y \
    gcc \
    make \
    automake \
    golang \
    protobuf-compiler \
    libtss2-dev \
    libssl-dev \
    tpm2-tools \
    tss2 \
    build-essential \
    pkg-config \
    jq \
    build-essential

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

cd $(mktemp -d)
curl -LO https://github.com/fullstorydev/grpcurl/releases/download/v1.8.7/grpcurl_1.8.7_linux_x86_64.tar.gz
tar -xvzf grpcurl_1.8.7_linux_x86_64.tar.gz
sudo mv grpcurl /usr/local/bin
```

## Key Broker Service (KBS)

### Download KBS fork

```bash
cd /var/tmp
mkdir kbs
curl -fL "https://github.com/mkulke/kbs/tarball/mkulke%2Fadd-az-snp-vtpm-support" \
  | tar -xz --strip-components 1 -C kbs
```

### Build KBS

```bash
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR=1
cd kbs
cargo b --release --no-default-features \
  --features native-as-az-snp-vtpm-verifier \
  --bin kbs
cargo b --release --no-default-features \
  --features native-as-az-snp-vtpm-verifier,attestation_agent/cc_kbc,attestation_agent/az-snp-vtpm-attester \
  --bin client
```

### Create a secret that will be released by KBS

Create a folder to hold a file-backed secret:

```bash
sudo mkdir -p /opt/confidential-containers/kbs/repository/my_repo/resource_type
echo -n "a secret" | sudo tee /opt/confidential-containers/kbs/repository/my_repo/resource_type/123abc
```

### Run KBS

We run the KBS on the same node as the client and skip proper security. An actual setup would have to setup certificates, enable HTTPS and of course run the KBS on a remote machine. Create Key pair:

```bash
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
sudo ./target/release/kbs --socket 127.0.0.1:8080 --auth-public-key kbs.pem --insecure-http
```

## Attestation Agent (AA)

> **NOTE**: In an actual scenario AA would be running on the CVM. And the workload (or the kata-agent) would talk to AA to get secret released from KBS. But here for demo purposes we are running it on the same host.

### Download the AA fork code

```bash
cd /var/tmp
mkdir attestation-agent
curl -fL "https://github.com/mkulke/attestation-agent/tarball/mkulke%2Fadd-az-snp-vtpm-attester" |
    tar -xz --strip-components 1 -C attestation-agent
```

### Build the AA

```bash
cd attestation-agent/
export PKG_CONFIG_SYSROOT_DIR=/
make LIBC=gnu features=rust-crypto,grpc,cc_kbc_az_snp_vtpm
```

### Run Attestation Agent

```bash
sudo ./app/target/x86_64-unknown-linux-gnu/release/attestation-agent --keyprovider_sock 127.0.0.1:60000 --getresource_sock 127.0.0.1:60001
```

## Simulate Key / Secret Release

Download the proto file to talk to AA:

```bash
curl -LO https://raw.githubusercontent.com/confidential-containers/attestation-agent/main/protos/getresource.proto
```

Get the secret from KBS but by talking to the AA:

```bash
grpcurl -proto getresource.proto -plaintext -d @ 127.0.0.1:60001 getresource.GetResourceService.GetResource <<EOM | jq -r '.Resource' | base64 -d >123abc_downloaded
{
  "ResourcePath": "/my_repo/resource_type/123abc",
  "KbcName":"cc_kbc",
  "KbsUri": "http://127.0.0.1:8080"
}
EOM
```

Verify the secret:

```bash
sudo diff /opt/confidential-containers/kbs/repository/my_repo/resource_type/123abc 123abc_downloaded
```
