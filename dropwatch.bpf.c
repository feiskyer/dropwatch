/* Watching TCP drop via kfree_skb */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "dropwatch.h"

#define AF_INET 2
#define AF_INET6 10

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} drop_watch_events SEC(".maps");

static __always_inline __u32 get_netns(struct sk_buff *skb, struct sock *sk)
{
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    __u32 netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
    if (netns == 0 && sk != NULL)
    {
        netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    }

    return netns;
}

static int do_trace_skb(void *ctx, struct sk_buff *skb, __u16 reason)
{
    struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 mac_header = BPF_CORE_READ(skb, mac_header);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    struct event_t event =
        {
            .reason = reason,
            .ts = bpf_ktime_get_ns(),
            .pid = bpf_get_current_pid_tgid() >> 32,
            .netns = get_netns(skb, sk),
        };


    /* get the ip_version from first byte of iphdr */
    __u8 ip_version;
    bpf_probe_read(&ip_version, sizeof(u8), head + network_header);
    ip_version = ip_version >> 4 & 0xf;

    /* get the ip address from iphdr */
    if (ip_version == 4)
    {
        struct iphdr iph;
        bpf_probe_read(&iph, sizeof(iph), head + network_header);
        event.saddr = iph.saddr;
        event.daddr = iph.daddr;
        event.protocol = iph.protocol;
        event.family = AF_INET;
    }
    else if (ip_version == 6)
    {
        struct ipv6hdr ip6h;
        bpf_probe_read(&ip6h, sizeof(ip6h), head + network_header);
        bpf_probe_read(&event.saddr6, sizeof(event.saddr6), &ip6h.saddr);
        bpf_probe_read(&event.daddr6, sizeof(event.daddr6), &ip6h.daddr);
        event.protocol = ip6h.nexthdr;
        event.family = AF_INET6;
    }
    else
    {
        return 0;
    }

    /* get the ports from transport header */
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    if (event.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcph = {};
        bpf_probe_read(&tcph, sizeof(tcph), head + transport_header);
        event.sport = bpf_ntohs(tcph.source);
        event.dport = bpf_ntohs(tcph.dest);
        event.tcp_flags = ((__u8 *)&tcph)[13];
    }
    else if (event.protocol == IPPROTO_UDP)
    {
        struct udphdr udph = {};
        bpf_probe_read(&udph, sizeof(udph), head + transport_header);
        event.sport = bpf_ntohs(udph.source);
        event.dport = bpf_ntohs(udph.dest);
    }
    else
    {
        return 0;
    }

    /* submit to perf event */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &drop_watch_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

/* ebpf program to trace tracepoint:skb:kfree_skb */
SEC("tracepoint/skb/kfree_skb")
int trace_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

    /* only query reason when it is available */
    __u16 reason;
    if (bpf_core_field_exists(ctx->reason))
    {
        reason = ctx->reason;
    }

    /* skip if the socket is not dropped ("reason" requires kernel >= 5.19) */
    if (bpf_core_field_exists(ctx->reason) && reason <= SKB_DROP_REASON_NOT_SPECIFIED)
    {
        return 0;
    }

    return do_trace_skb(ctx, skb, reason);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
