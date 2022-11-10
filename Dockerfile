FROM ubuntu:jammy AS builder

WORKDIR /dropwatch

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
    build-essential \
    make clang llvm \
    libelf-dev \
    libpcap-dev \
    binutils-dev

COPY . .
RUN make && make install

FROM gcr.io/distroless/static
COPY --from=builder /usr/bin/dropwatch /dropwatch
ENTRYPOINT ["/dropwatch"]
