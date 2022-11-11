# DropWatch

eBPF program to watch packet drops.

## Pre-requisites

To use BTF and CO-RE, `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y` need to be enabled. If you don't want to rebuild the kernel, the following distos have enabled those options by default:

* Ubuntu 20.10+
* Fedora 31+
* RHEL 8.2+
* Debian 11+

And to build bpf applications, the following development tools should also be installed:

```sh
# Ubuntu
sudo apt-get install -y make clang llvm libelf-dev linux-tools-$(uname -r)

# RHEL
sudo yum install -y make clang llvm elfutils-libelf-devel bpftool
```

## Build and Run Locally

```sh
make
sudo ./out/dropwatch
```

## Run in Docker

```
docker build -t dropwatch .
docker run -it --rm -v /usr/src:/usr/src:ro -v /lib/modules/:/lib/modules:ro -v /sys/:/sys/:rw --net=host --pid=host --privileged dropwatch
```

## Run in Kubernetes

```sh
kubectl apply -f kubernetes/
```
