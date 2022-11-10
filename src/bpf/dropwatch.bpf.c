/* Watching TCP drop via kfree_skb, "reason" requires kernel >= 5.19 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern u32 LINUX_KERNEL_VERSION __kconfig;

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct event_t
{
    u8 comm[TASK_COMM_LEN];
    u64 ts;
    u64 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    u16 protocol;
    u16 reason;
    unsigned __int128 saddr6;
    unsigned __int128 daddr6;
};

// Dummy instance to get skeleton to generate definition for `struct event_t`
struct event_t _event = {0};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
// {
//     // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
//     return (struct tcphdr *)(skb->head + skb->transport_header);
// }

// static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
// {
//     // unstable API. verify logic in ip_hdr() -> skb_network_header().
//     return (struct iphdr *)(skb->head + skb->network_header);
// }

// ebpf program to trace tracepoint:skb:kfree_skb
SEC("tracepoint/skb/kfree_skb")
int tracepoint__skb__kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    // struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
    struct sock *sk;
    bpf_probe_read(&sk, sizeof(sk), &skb->sk);

    struct event_t event =
        {
            .ts = bpf_ktime_get_ns(),
            .pid = bpf_get_current_pid_tgid() >> 32,
            .protocol = ctx->protocol,
        };

    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 19, 0)) //(bpf_core_field_exists(ctx->reason))
    {
        event.reason = ctx->reason;
    }

    if ((LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 19, 0)) && event.reason <= SKB_DROP_REASON_NOT_SPECIFIED)
    {
        return 0;
    }

    bpf_probe_read(&event.family, sizeof(event.family), &sk->__sk_common.skc_family);
    if (event.family != AF_INET && event.family != AF_INET6)
    {
        return 0;
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read(&event.sport, sizeof(event.sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);

    if (event.family == AF_INET)
    {
        bpf_probe_read(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    }
    else
    {
        bpf_probe_read(&event.daddr6, sizeof(event.daddr6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read(&event.saddr6, sizeof(event.saddr6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }

    // submit to perf event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
