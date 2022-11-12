#ifndef __HELLO_H
#define __HELLO_H

#define TASK_COMM_LEN 16

// TCP flags (from include/net/tcp.h)
#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

struct event_t
{
    __u8 comm[TASK_COMM_LEN];
    __u8 tcp_flags;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u16 reason;
    __u32 netns;
    __u32 saddr;
    __u32 daddr;
    __u32 saddr6[4];
    __u32 daddr6[4];
    __u64 ts;
    __u64 pid;
};

#endif /* __HELLO_H */
