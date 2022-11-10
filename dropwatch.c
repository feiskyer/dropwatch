#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <arpa/inet.h>
#include "dropwatch.h"
#include "dropwatch.skel.h"

const char *DROP_REASONS[] = {
	"SKB_NOT_DROPPED_YET",
	"NOT_SPECIFIED",
	"NO_SOCKET",
	"PKT_TOO_SMALL",
	"TCP_CSUM",
	"SOCKET_FILTER",
	"UDP_CSUM",
	"NETFILTER_DROP",
	"OTHERHOST",
	"IP_CSUM",
	"IP_INHDR",
	"IP_RPFILTER",
	"UNICAST_IN_L2_MULTICAST",
	"XFRM_POLICY",
	"IP_NOPROTO",
	"SOCKET_RCVBUFF",
	"PROTO_MEM",
	"TCP_MD5NOTFOUND",
	"TCP_MD5UNEXPECTED",
	"TCP_MD5FAILURE",
	"SOCKET_BACKLOG",
	"TCP_FLAGS",
	"TCP_ZEROWINDOW",
	"TCP_OLD_DATA",
	"TCP_OVERWINDOW",
	"TCP_OFOMERGE",
	"TCP_RFC7323_PAWS",
	"TCP_INVALID_SEQUENCE",
	"TCP_RESET",
	"TCP_INVALID_SYN",
	"TCP_CLOSE",
	"TCP_FASTOPEN",
	"TCP_OLD_ACK",
	"TCP_TOO_OLD_ACK",
	"TCP_ACK_UNSENT_DATA",
	"TCP_OFO_QUEUE_PRUNE",
	"TCP_OFO_DROP",
	"IP_OUTNOROUTES",
	"BPF_CGROUP_EGRESS",
	"IPV6DISABLED",
	"NEIGH_CREATEFAIL",
	"NEIGH_FAILED",
	"NEIGH_QUEUEFULL",
	"NEIGH_DEAD",
	"TC_EGRESS",
	"QDISC_DROP",
	"CPU_BACKLOG",
	"XDP",
	"TC_INGRESS",
	"UNHANDLED_PROTO",
	"SKB_CSUM",
	"SKB_GSO_SEG",
	"SKB_UCOPY_FAULT",
	"DEV_HDR",
	"DEV_READY",
	"FULL_RING",
	"NOMEM",
	"HDR_TRUNC",
	"TAP_FILTER",
	"TAP_TXFILTER",
	"ICMP_CSUM",
	"INVALID_PROTO",
	"IP_INADDRERRORS",
	"IP_INNOROUTES",
	"PKT_TOO_BIG",
	"MAX",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
						   va_list args)
{
#ifdef DEBUGBPF
	return vfprintf(stderr, format, args);
#else
	return 0;
#endif
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event_t *e = data;
	char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];

	// Convert addresses to strings.
	if (e->family == AF_INET)
	{
		inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
		inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
	}
	else
	{
		inet_ntop(AF_INET6, &e->saddr6, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &e->daddr6, daddr, sizeof(daddr));
	}

	// Get local time.
	struct tm *tm;
	time_t t;
	char ts[32];
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-16s %-16s %-8lld %-12s:%-5d -> %-12s:%-5d %-12s", ts, e->comm, e->pid, saddr, ntohs(e->sport), daddr, ntohs(e->dport), DROP_REASONS[e->reason]);
	putchar('\n');
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct dropwatch_bpf *skel;
	struct perf_buffer *pb = NULL;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = dropwatch_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = dropwatch_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = dropwatch_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, handle_lost_events, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err)
	{
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Started to watch TCP drops!\n");
	printf("%-16s %-16s %-8s %-17s -> %-17s %-12s\n", "TIME", "COMM", "PID", "SADDR:SPORT", "DADDR:DPORT", "REASON");

	/* main: poll perf events*/
	while ((err = perf_buffer__poll(pb, 100)) >= 0)
		;
	printf("Error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	dropwatch_bpf__destroy(skel);
	return err != 0;
}
