FROM ubuntu:jammy AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
    build-essential \
    asciidoctor \
    bison \
    cmake \
    binutils-dev \
    flex \
    git \
    xxd \
    libelf-dev \
    libdw-dev \
    zlib1g-dev \
    libiberty-dev \
    libbfd-dev \
    libcereal-dev \
    libedit-dev \
    libpcap-dev \
    libbz2-dev \
    libgmock-dev \
    llvm-12-dev \
    llvm-12-runtime \
    libclang-12-dev \
    clang-12 \
    systemtap-sdt-dev \
    python3 \
    python3-setuptools \
    quilt \
    libssl-dev \
    && apt-get install --no-install-recommends -y \
    pkg-config

RUN git clone https://github.com/iovisor/bpftrace --recurse-submodules

COPY 0001-Fix-ubuntu-build.patch /bpftrace/0001-Fix-ubuntu-build.patch

RUN cd /bpftrace \
    && git config --global user.name 'ebpf' \
    && git config --global user.email 'ebpf@bpftace' \
    && git am 0001-Fix-ubuntu-build.patch \
    && mkdir build \
    && cd build \
    && ../build-libs.sh \
    && cmake -DCMAKE_BUILD_TYPE=Release \
        -DSTATIC_LINKING:BOOL=OFF \
        -DSTATIC_LIBC:BOOL=OFF \
        -DBUILD_TESTING:BOOL=OFF \
        -DVENDOR_GTEST=OFF \
        -DALLOW_UNSAFE_PROBE:BOOL=on .. \
    && make -j8 \
    && make install


FROM ubuntu:jammy
COPY --from=builder /usr/local/bin/bpftrace /usr/local/bin/bpftrace
COPY --from=builder /usr/local/share/bpftrace/tools/ /programs/

RUN apt-get update \
    && apt-get install -y  binutils \
    libelf1 \
    libdw1 \
    zlib1g \
    binutils-dev \
    libiberty-dev \
    libedit2 \
    libpcap-dev \
    libbz2-1.0 \
    libllvm12 \
    libclang1-12 \
    clang-12 \
    systemtap-sdt-dev \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY dropwatch.bt /programs/
CMD ["/usr/local/bin/bpftrace", "/programs/dropwatch.bt"]
