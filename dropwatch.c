#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <arpa/inet.h>
#include "dropwatch.h"
#include "dropwatch.skel.h"

#define MAX_DROP_REASON 256
static char DROP_REASONS[MAX_DROP_REASON][256] = {};

// Parse the drop reason from the kernel. This is required because the reason number
// is different in different kernel versions.
static int parse_drop_reasons()
{
	FILE *fp = fopen("/sys/kernel/debug/tracing/events/skb/kfree_skb/format", "r");
	if (!fp)
	{
		fprintf(stderr, "Failed to open /tracing/events/skb/kfree_skb/format file");
		return -1;
	}

	// Parse the file to get the drop reasons.
	// Sample contenct: ..., __print_symbolic(REC->reason, { 0, "NOT_SPECIFIED" }, { 1, "NO_SOCKET" },...
	char line[2048];
	while (fgets(line, sizeof(line), fp))
	{
		if (strstr(line, "__print_symbolic(REC->reason, {"))
		{
			char *p = line;
			int i = 0;
			while (p && i < MAX_DROP_REASON)
			{
				p++;

				// Find the index of the reason.
				p = strstr(p, "{");
				if (!p)
				{
					break;
				}
				p++;
				char *q = strstr(p, ",");
				if (!q)
				{
					break;
				}
				*q = 0;
				int reason = atoi(p);

				// Find the name of the reason.
				p = q + 1;
				p = strstr(p, "\"");
				if (!p)
				{
					break;
				}
				p++;
				q = strstr(p, "\"");
				if (!q)
				{
					break;
				}
				*q = 0;

				// Save the reason.
				strncpy(DROP_REASONS[reason], p, sizeof(DROP_REASONS[reason]));
				i++;
				p = q;
			}
			break;
		}
	}

	fclose(fp);
	return 0;
}

static char *get_drop_reason(int reason)
{
	if (reason < 0 || reason >= MAX_DROP_REASON)
	{
		return "UNKNOWN";
	}
	return DROP_REASONS[reason];
}

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
	inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
	inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

	// Get local time.
	struct tm *tm;
	time_t t;
	char ts[32];
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-16s %-16s %-8lld %12s:%-5d -> %12s:%-5d %-12s", ts, e->comm, e->pid, saddr, e->sport, daddr, e->dport, get_drop_reason(e->reason));
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

	/* Parse drop reasons */
	if (parse_drop_reasons() != 0)
	{
		return 1;
	}

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
