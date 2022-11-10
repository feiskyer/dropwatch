# DropWatch

eBPF program with bpftrace to watch packet drops.

## Build and Run Locally

```
docker build -t dropwatch .
docker run -it --rm -v /usr/src:/usr/src:ro -v /lib/modules/:/lib/modules:ro -v /sys/:/sys/:rw --net=host --pid=host --privileged dropwatch
```

## Run in Kubernetes

```sh
kubectl apply -f kubernetes.yaml
```
