# Watch Packets Drop via eBPF

## Prerequisites

```sh
cargo install --version=0.12.0 libbpf-cargo
```

## Build

```sh
cargo libbpf make
```

## Run

```sh
./target/debug/dropwatch
```
