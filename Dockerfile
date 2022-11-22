FROM rust:bullseye AS builder

WORKDIR /dropwatch

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
    build-essential \
    make clang llvm \
    libelf-dev \
    libpcap-dev \
    binutils-dev

RUN cargo install --version=0.12.0 libbpf-cargo
RUN rustup component add rustfmt
COPY . .
RUN cargo libbpf make

FROM gcr.io/distroless/base
COPY --from=builder /dropwatch/target/debug/dropwatch /dropwatch
COPY --from=builder /usr/lib/x86_64-linux-gnu/libelf.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libm.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so* /lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libz.so* /usr/lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libz.so* /lib/x86_64-linux-gnu/

ENTRYPOINT ["/dropwatch"]