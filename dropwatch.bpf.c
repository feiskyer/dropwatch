/* Watching TCP drop via kfree_skb, "reason" requires kernel >= 5.19 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "dropwatch.h"

// extern __u32 LINUX_KERNEL_VERSION __kconfig;
#define AF_INET 2
#define AF_INET6 10

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// ebpf program to trace tracepoint:skb:kfree_skb
SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);

    struct event_t event =
        {
            .ts = bpf_ktime_get_ns(),
            .pid = bpf_get_current_pid_tgid() >> 32,
            .protocol = ctx->protocol,
        };

    if (bpf_core_field_exists(ctx->reason)) // Alternative:  LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 19, 0)
    {
        event.reason = ctx->reason;
    }

    if (bpf_core_field_exists(ctx->reason) && event.reason <= SKB_DROP_REASON_NOT_SPECIFIED)
    {
        return 0;
    }

    /* note: the following steps would not work for containers because sk is NULL */
    bpf_probe_read(&event.family, sizeof(event.family), &sk->__sk_common.skc_family);
    if (event.family != AF_INET && event.family != AF_INET6)
    {
        return 0;
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
    event.dport = bpf_ntohs(event.dport);

    if (event.family == AF_INET)
    {
        bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    }
    else
    {
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }

    // submit to perf event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
