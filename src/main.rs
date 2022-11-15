use anyhow::{bail, Result};
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use time::macros::format_description;
use time::OffsetDateTime;

mod bpf;
use bpf::*;

unsafe impl Plain for dropwatch_bss_types::event_t {}

// get tcp flags as a string
fn get_tcp_flags(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x01 != 0 {
        s.push('F'); // FIN
    }
    if flags & 0x02 != 0 {
        s.push('S'); // SYN
    }
    if flags & 0x04 != 0 {
        s.push('R'); // RST
    }
    if flags & 0x08 != 0 {
        s.push('P'); // PSH
    }
    if flags & 0x10 != 0 {
        s.push('A'); // ACK
    }
    if flags & 0x20 != 0 {
        s.push('U'); // URG
    }
    if flags & 0x40 != 0 {
        s.push('E'); // ECE
    }
    if flags & 0x80 != 0 {
        s.push('C'); // CWR
    }
    s
}

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

    let mut drop_reasons: [&str; 128] = [""; 128];
    let mut f = File::open("/sys/kernel/debug/tracing/events/skb/kfree_skb/format").unwrap();
    let mut buf = String::new();
    f.read_to_string(&mut buf).unwrap();

    let mut lines = buf.lines().skip_while(|l| !l.contains("__print_symbolic"));
    while let Some(line) = lines.next() {
        let mut tuple_list = line.split('{').skip(1);
        while let Some(tuple) = tuple_list.next() {
            let mut tuple = tuple.split(',');
            let reason = tuple.next().unwrap().trim().parse::<usize>().unwrap();
            let desc = tuple.next().unwrap().trim().trim_end_matches("}").trim();
            drop_reasons[reason] = desc;
        }
    }

    let task = std::str::from_utf8(&event.comm).unwrap();
    println!(
        "{:8} {:<16} {:<8} {:>13}:{:<5}->{:>13}:{:<5} {:<8} {:<16}",
        now,
        task.trim_end_matches(char::from(0)),
        event.pid,
        Ipv4Addr::from(event.saddr),
        event.sport,
        Ipv4Addr::from(event.daddr),
        event.dport,
        get_tcp_flags(event.tcp_flags),
        drop_reasons[event.reason as usize],
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let builder = DropwatchSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;

    // skel.progs_mut().tracepoint__skb__kfree_skb().attach_tracepoint("skb", "kfree_skb")?;
    skel.attach()?;

    let perf = PerfBufferBuilder::new(&skel.maps_mut().drop_watch_events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    println!(
        "{:8} {:<16} {:<8} {:<40} {:<8} {:<16}",
        "TIME", "COMM", "PID", "SADDR:PORT->DADDR:PORT", "TCP_FLAGS", "REASON"
    );

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
