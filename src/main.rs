use core::time::Duration;
use anyhow::{bail, Result};
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::ffi::CString;
use time::OffsetDateTime;
use time::macros::format_description;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod bpf;
use bpf::*;

unsafe impl Plain for dropwatch_bss_types::event_t {}

const DROP_REASONS: [&str; 66] = [
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
];


fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = dropwatch_bss_types::event_t::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

    let now = if let Ok(now) = OffsetDateTime::now_local() {
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    } else {
        "00:00:00".to_string()
    };

    let task = std::str::from_utf8(&event.comm).unwrap();

    println!(
        "{:8} {:<16} {:<8} {}:{}->{}:{} {:<16}",
        now,
        task.trim_end_matches(char::from(0)),
        event.pid,
        Ipv4Addr::from(event.saddr),
        event.sport.to_be(),
        Ipv4Addr::from(event.daddr),
        event.dport.to_be(),
        DROP_REASONS[event.reason as usize],
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let mut builder = DropwatchSkelBuilder::default();
	let btf_custom_path = "/dropwatch.btf";
	let _path = CString::new(btf_custom_path).unwrap();
	let btf_custom_path_fd = _path.as_ptr();
	let mut open_opts = builder.obj_builder.opts(std::ptr::null());
	open_opts.btf_custom_path = btf_custom_path_fd;
    let open = builder.open_opts(open_opts)?;
    let mut skel = open.load()?;

	// skel.progs_mut().tracepoint__skb__kfree_skb().attach_tracepoint("skb", "kfree_skb")?;
	skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!("{:8} {:<16} {:<8} {}->{} {:<16}", "TIME", "COMM", "PID", "SADDR:PORT", "DADDR:PORT", "REASON");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}