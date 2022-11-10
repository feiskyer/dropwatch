#ifndef __HELLO_H
#define __HELLO_H

#define TASK_COMM_LEN 16

struct event_t
{
    __u8 comm[TASK_COMM_LEN];
    __u64 ts;
    __u64 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u16 reason;
    unsigned __int128 saddr6;
    unsigned __int128 daddr6;
};

#endif /* __HELLO_H */