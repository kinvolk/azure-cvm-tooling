# az-report-ready

The program implements a [ceremony](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/no-agent) required on Azure VMs that do not run walinuxagent or a cloud-init service. The VM needs to report itself as ready otherwise a reboot will be triggered.

## Build

```bash
cargo b --release
```

Statically w/ musl:

```bash
cargo b --release --target x86_64-unknown-linux-musl
```

Statically w/ glibc:

```bash
RUSTFLAGS='-C target-feature=+crt-static' cargo b --release --target x86_64-unknown-linux-gnu
```

## Run

The tool is supposed to run on an Azure VM.

```
cargo r --release -- -h
```
