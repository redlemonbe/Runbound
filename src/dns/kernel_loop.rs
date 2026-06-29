// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Kernel UDP fast path — Step 2 of the slow-path optimisation (#kernel-fastloop).
//
// Problem (measured, dual Xeon E5-2690 v2 + X520, dnsmark 200k qps fixed):
//   runbound slow path : 72.8G instructions / 159G cycles / IPC 0.46
//   unbound reference :  40.8G instructions /  83G cycles / IPC 0.49
//   → 1.78× more instructions per query; root cause = hickory ServerFuture
//     (1 tokio::spawn per UDP query + Message::emit generic codec on hot path).
//
// Solution: for each physical NUMA-local core, bind one SO_REUSEPORT UDP socket
// and run a tight OS-thread loop:
//   recv_from → answer_dns_wire (zero alloc, wire-direct) → send_to   [fast]
//             → answer_from_cache (SIMD lookup, zero hickory)  → send_to   [fast]
//             → fallback to the wire serving core via tokio channel     [slow, rare]
//
// The serving-core fallback (handle_request_wire → serve_wire) handles the
// cases the fast path cannot (EDNS DO=1 signed zones, CNAME, MX, TSIG, AXFR,
// forwarding) — it never sees the local-zone hot path.
//
// SO_RCVBUF/SO_SNDBUF set to 8 MiB per socket (fixes udp_RcvbufErrors=93k/s
// measured on the Xeon v2 rig with the previous default-buffer path).
//
// Non-XDP-specific: no AF_XDP, no UMEM, no BPF — pure kernel UDP sockets.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use crate::dns::acl::Acl;
use crate::dns::local::LocalZoneSet;

/// Message sent to the wire serving-core fallback reader when the wire fast path
/// cannot answer a query (EDNS DO=1, CNAME, MX, TSIG, AXFR, recursion…).
pub struct FallbackMsg {
    pub query:  Vec<u8>,
    pub peer:   SocketAddr,
    /// The socket to reply on (Arc so we can clone it across threads).
    pub socket: Arc<UdpSocket>,
}

/// Global sender so XDP workers (no kernel arrival socket) can hand
/// recursion/complex misses to the same wire serving-core fallback reader.
/// Set once by run_dns_server(); None until then (early-startup misses dropped).
pub static XDP_FALLBACK_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<FallbackMsg>> =
    std::sync::OnceLock::new();

/// Shared reply socket for XDP-mode recursion-miss fallbacks (#167). XDP workers
/// have no kernel arrival socket, so replies must leave from a socket bound to
/// the server port (:53) — NOT an ephemeral port, which clients reject (silent
/// timeout). Set once by run_dns_server() when cfg.xdp is true.
pub static XDP_FALLBACK_REPLY_SOCK: std::sync::OnceLock<std::sync::Arc<std::net::UdpSocket>> =
    std::sync::OnceLock::new();

/// Handle returned by `start_kernel_fast_loop`.
/// Dropping it signals shutdown to the worker threads (best-effort via flag).
pub struct KernelLoopHandle {
    _threads: Vec<thread::JoinHandle<()>>,
}

const RCVBUF_SIZE: usize = 32 * 1024 * 1024; // 32 MiB (#slowpath: absorb RX bursts; needs net.core.rmem_max raised — auto-set in server.rs)
const DNS_BUF_SIZE: usize = 4096;

/// Bind a blocking SO_REUSEPORT UDP socket with explicit buffer sizes.
fn bind_kernel_udp(addr: &str) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_port(true)?;
    sock.set_reuse_address(true)?; // #167b: coexist 0.0.0.0:53 (reply) + 127.0.0.1:53 (lo)
    sock.set_recv_buffer_size(RCVBUF_SIZE)?;
    sock.set_send_buffer_size(RCVBUF_SIZE)?;

    // Warn if the kernel clamps our buffer (net.core.rmem_max too low).
    let actual = sock.recv_buffer_size().unwrap_or(0);
    if actual < RCVBUF_SIZE {
        warn!(
            requested = RCVBUF_SIZE,
            actual,
            "SO_RCVBUF clamped by net.core.rmem_max — raise with: sysctl -w net.core.rmem_max={}",
            RCVBUF_SIZE
        );
    }

    let addr: std::net::SocketAddr = addr.parse()?;
    sock.bind(&addr.into())?;

    // #slowpath-spread: spread incoming datagrams EVENLY across the SO_REUSEPORT group,
    // INDEPENDENT of flow count. The kernel's default 4-tuple hash confines a few-flow load
    // (e.g. a benchmark's 5 source ports, or a single big NAT/forwarder) to a handful of
    // sockets while the rest idle. A by-CPU cBPF (SKF_AD_CPU) only spreads with RPS, which
    // collapses on i40e/X710 (35M softnet drops). Instead the 2-insn cBPF returns
    // SKF_AD_RANDOM (prandom_u32): socket = random % nsockets, so every datagram lands on a
    // random worker — flat per-socket load on all cores with NO RPS and NO flow dependence,
    // exactly what RPS gave the X520 but without its i40e collapse. DNS is stateless, so the
    // lack of per-flow socket affinity is irrelevant. RUNBOUND_DISABLE_CBPF=1 → default hash.
    if std::env::var_os("RUNBOUND_DISABLE_CBPF").is_none() {
        use std::os::fd::AsRawFd;
        #[repr(C)]
        struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
        #[repr(C)]
        struct SockFprog { len: u16, filter: *const SockFilter }
        const SKF_AD_OFF: u32 = 0xffff_f000; // -0x1000
        const SKF_AD_RANDOM: u32 = 56; // BPF_ANC | prandom_u32()
        const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
        const BPF_RET_A: u16 = 0x16;    // BPF_RET | BPF_A
        const SO_ATTACH_REUSEPORT_CBPF: libc::c_int = 51;
        let prog = [
            SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: SKF_AD_OFF + SKF_AD_RANDOM },
            SockFilter { code: BPF_RET_A,    jt: 0, jf: 0, k: 0 },
        ];
        let fprog = SockFprog { len: prog.len() as u16, filter: prog.as_ptr() };
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_ATTACH_REUSEPORT_CBPF,
                &fprog as *const SockFprog as *const libc::c_void,
                std::mem::size_of::<SockFprog>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            debug!("SO_ATTACH_REUSEPORT_CBPF (by-CPU) not applied: {}", std::io::Error::last_os_error());
        }
    }

    Ok(sock.into())
}

/// Start the kernel UDP fast loop: one blocking OS thread per physical
/// NUMA-local core.  Each thread owns one SO_REUSEPORT socket.
///
/// Returns a `KernelLoopHandle` whose lifetime keeps the threads alive,
/// and a `tokio::sync::mpsc::Sender` for the wire serving-core fallback channel.
#[allow(clippy::too_many_arguments)]
pub fn start_kernel_fast_loop(
    bind_addr: &str,           // e.g. "0.0.0.0:53"
    cores: &[usize],           // physical NUMA-local cores (from cpu::physical_cores_numa_sorted)
    zones: Arc<ArcSwap<LocalZoneSet>>,
    acl: Arc<Acl>,
    rate_limiter: Arc<crate::dns::ratelimit::RateLimiter>,
    icmp_stats: Arc<crate::icmp::IcmpStats>,
    fallback_tx: tokio::sync::mpsc::Sender<FallbackMsg>,
    cache_snapshot: Option<Arc<arc_swap::ArcSwap<crate::dns::cache_snapshot::CacheSnapshot>>>,
    stats: Option<Arc<crate::stats::Stats>>,
    domain_stats: Option<Arc<crate::domain_stats::DomainStats>>,
) -> anyhow::Result<KernelLoopHandle> {
    let n = cores.len().max(1);
    info!(
        threads = n,
        addr = bind_addr,
        "kernel UDP fast loop: starting {n} worker threads"
    );

    let mut handles = Vec::with_capacity(n);

    for (i, &core_id) in cores.iter().enumerate() {
        let addr = bind_addr.to_owned();
        let zones2       = Arc::clone(&zones);
        let acl2         = Arc::clone(&acl);
        let rl2          = Arc::clone(&rate_limiter);
        let icmp2        = Arc::clone(&icmp_stats);
        let fallback_tx2 = fallback_tx.clone();
        let cache2       = cache_snapshot.clone();
        let stats2       = stats.clone();
        let domain_stats2 = domain_stats.clone();

        let sock = bind_kernel_udp(&addr).map_err(|e| {
            anyhow::anyhow!("kernel fast loop thread {i} socket bind {addr}: {e}")
        })?;
        let sock_arc = Arc::new(sock);

        let h = thread::Builder::new()
            .name(format!("kloop-{i}"))
            .spawn(move || {
                // Pin to physical core (best-effort — same logic as XDP workers).
                #[cfg(target_os = "linux")]
                {
                    use libc::{cpu_set_t, sched_setaffinity, CPU_SET};
                    // Guard CPU_SET against an out-of-range core_id (would write past the
                    // stack cpu_set_t on >CPU_SETSIZE-core hosts / an enumeration bug).
                    if core_id < libc::CPU_SETSIZE as usize {
                        let mut set: cpu_set_t = unsafe { std::mem::zeroed() };
                        unsafe { CPU_SET(core_id, &mut set) };
                        unsafe { sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set) };
                    }
                }

                worker_loop(
                    i,
                    core_id,
                    Arc::clone(&sock_arc),
                    zones2,
                    acl2,
                    rl2,
                    icmp2,
                    fallback_tx2,
                    cache2,
                    stats2,
                    domain_stats2,
                );
            })
            .map_err(|e| anyhow::anyhow!("thread spawn kloop-{i}: {e}"))?;

        handles.push(h);
        debug!(thread = i, core = core_id, "kernel fast loop thread spawned");
    }

    Ok(KernelLoopHandle { _threads: handles })
}

/// Tight recv→dispatch→send loop for one socket/core.
fn worker_loop(
    thread_idx: usize,
    _core_id: usize,
    sock: Arc<UdpSocket>,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    acl: Arc<Acl>,
    rate_limiter: Arc<crate::dns::ratelimit::RateLimiter>,
    icmp_stats: Arc<crate::icmp::IcmpStats>,
    fallback_tx: tokio::sync::mpsc::Sender<FallbackMsg>,
    cache_snapshot: Option<Arc<arc_swap::ArcSwap<crate::dns::cache_snapshot::CacheSnapshot>>>,
    stats: Option<Arc<crate::stats::Stats>>,
    domain_stats: Option<Arc<crate::domain_stats::DomainStats>>,
) {
    // I/O buffers — heap-allocated once (never per-iteration). recvmmsg drains the
    // kernel-UDP socket in batches (one syscall per N datagrams instead of one per
    // datagram), which is otherwise what fills the rcvbuf as UdpRcvbufErrors under
    // burst. MSG_WAITFORONE returns as soon as >=1 datagram is ready, so a lone query
    // (e.g. dig) is answered immediately — no single-query stall, no lost behaviour.
    // Slow path only; the AF_XDP fast path is untouched.
    // Escape hatch: RUNBOUND_NO_RECVMMSG=1 falls back to one recv_from per datagram.
    const BATCH: usize = 64; // #slowpath: larger recvmmsg batch drains the socket faster, fewer UdpRcvbufErrors
    let mut rx_bufs: Vec<[u8; DNS_BUF_SIZE]> = vec![[0u8; DNS_BUF_SIZE]; BATCH];
    // TX batch: collect answered responses and flush them with ONE sendmmsg per recv
    // batch (instead of one send_to per datagram). Fewer syscalls on the serving cores
    // = faster socket drain = fewer UdpRcvbufErrors under burst. All scratch pre-allocated
    // once (no per-batch alloc on the hot path).
    let mut tx_bufs: Vec<[u8; DNS_BUF_SIZE]> = vec![[0u8; DNS_BUF_SIZE]; BATCH];
    let mut tx_lens = [0usize; BATCH];
    let mut tx_peers: [Option<std::net::SocketAddr>; BATCH] = [None; BATCH];
    let mut tx_addrs = vec![unsafe { std::mem::zeroed::<libc::sockaddr_in>() }; BATCH];
    let mut tx_iovs =
        vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; BATCH];
    let mut tx_msgs: Vec<libc::mmsghdr> =
        (0..BATCH).map(|_| unsafe { std::mem::zeroed::<libc::mmsghdr>() }).collect();
    let mut lens = [0usize; BATCH];
    let mut peers: [Option<std::net::SocketAddr>; BATCH] = [None; BATCH];

    let use_mmsg = std::env::var_os("RUNBOUND_NO_RECVMMSG").is_none();
    let fd = {
        use std::os::fd::AsRawFd;
        sock.as_raw_fd()
    };
    let mut addrs = vec![unsafe { std::mem::zeroed::<libc::sockaddr_storage>() }; BATCH];
    let mut iovecs = vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; BATCH];
    let mut msgs: Vec<libc::mmsghdr> =
        (0..BATCH).map(|_| unsafe { std::mem::zeroed::<libc::mmsghdr>() }).collect();

    loop {
        // ── Receive a batch (recvmmsg) or a single datagram (escape hatch) ───
        let count: usize = if use_mmsg {
            for i in 0..BATCH {
                iovecs[i].iov_base = rx_bufs[i].as_mut_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = DNS_BUF_SIZE;
                msgs[i].msg_hdr.msg_iov = &mut iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_len = 0;
            }
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    msgs.as_mut_ptr(),
                    BATCH as libc::c_uint,
                    libc::MSG_WAITFORONE as _,
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::WouldBlock
                        && e.kind() != std::io::ErrorKind::Interrupted
                    {
                        warn!("kloop recvmmsg: {e}");
                    }
                }
                continue;
            }
            let n = n as usize;
            for i in 0..n {
                lens[i] = msgs[i].msg_len as usize;
                peers[i] = sockaddr_to_std(&addrs[i]);
            }
            n
        } else {
            match sock.recv_from(&mut rx_bufs[0]) {
                Ok((len, peer)) => {
                    lens[0] = len;
                    peers[0] = Some(peer);
                    1
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock
                        && e.kind() != std::io::ErrorKind::Interrupted
                    {
                        warn!("kloop recv_from: {e}");
                    }
                    continue;
                }
            }
        };

        // ── Process each datagram in the batch → collect into the TX batch ───
        // #perf: snapshot the cache ONCE per recvmmsg batch (a single
        // ArcSwap::load_full / Arc refcount bump) instead of once per datagram.
        // Per-datagram load_full bounced the snapshot's atomic refcount across
        // every serving core, capping the per-core-queue spread; one bump per
        // batch removes that contention on the cache hot path.
        let cache_batch = cache_snapshot.as_ref().map(|c| c.load_full());
        let mut tx_n = 0usize;
        for i in 0..count {
            let len = lens[i];
            let peer = match peers[i] {
                Some(p) => p,
                None => continue,
            };
            let query = &rx_bufs[i][..len];
            let src_ip: Option<IpAddr> = Some(peer.ip());

            // Banned source -> drop (same authoritative set as the XDP
            // icmp_banned map; enforced here so bans work in xdp:no too).
            if icmp_stats.is_banned(peer.ip()) {
                continue;
            }

            // Shared rate-limit gate (same helper + RateLimiter as the XDP
            // fast path): over-limit source IPs are ignored until the window
            // rolls over.
            if crate::dns::xdp::worker::rl_should_drop(&rate_limiter, peer.ip()) {
                continue;
            }

            // ── Fast path A: wire builder (zero hickory, zero alloc) ─────────
            // answer_dns_wire: parse_query + WireRecordIndex CRC32c lookup +
            // build_answer_a_aaaa_wire — all SIMD, stack-only.
            {
                let zones_snap = zones.load();
                use crate::dns::xdp::worker::{answer_dns_wire_pub, WireResultPub};
                match answer_dns_wire_pub(query, &mut tx_bufs[tx_n], &zones_snap, &acl, src_ip) {
                    WireResultPub::Answered(resp_len) => {
                        tx_lens[tx_n] = resp_len;
                        tx_peers[tx_n] = Some(peer);
                        tx_n += 1;
                        continue;
                    }
                    WireResultPub::Drop => continue, // ACL Deny — silent drop
                    WireResultPub::Fallback => {}     // try cache, then the wire serving core
                }
            }

            // ── Fast path B: cache snapshot (SIMD lookup, zero hickory) ──────
            if let Some(ref snap) = cache_batch {
                use crate::dns::xdp::worker::answer_from_cache_pub;
                if let Some(resp_len) = answer_from_cache_pub(
                    query,
                    snap,
                    &acl,
                    src_ip,
                    &mut tx_bufs[tx_n],
                    stats.as_ref(),
                    domain_stats.as_ref(),
                ) {
                    tx_lens[tx_n] = resp_len;
                    tx_peers[tx_n] = Some(peer);
                    tx_n += 1;
                    // Count this fast-path cache hit. `stats.cache_hits` is reported as
                    // `ch_slow + Σ XDP_WORKER_PKTS`; the AF_XDP loop bumps that per-worker
                    // counter (worker.rs), but the kernel-fast-loop datapath did not — so
                    // cache_hits / cache_hit_rate read 0 here despite real hits. Same
                    // contention-free per-worker slot, indexed by this thread.
                    if thread_idx < crate::dns::cache_snapshot::XDP_WORKER_PKTS.len() {
                        crate::dns::cache_snapshot::XDP_WORKER_PKTS[thread_idx]
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    continue;
                }
            }

            // ── Slow path: wire serving-core fallback (CNAME, MX, TSIG, recursion…) ────
            // Clone the query bytes and send to the async serving-core reader
            // (handle_request_wire). The handler replies directly on sock_clone.
            let msg = FallbackMsg {
                query:  query.to_vec(), // one alloc per fallback query — acceptable
                peer,
                socket: Arc::clone(&sock),
            };
            if fallback_tx.try_send(msg).is_err() {
                // Channel full — drop rather than block the fast loop.
                debug!("kloop fallback channel full — dropping query from {peer}");
            }
        }

        // ── Flush the TX batch: one sendmmsg for all answered IPv4 datagrams ──
        if tx_n > 0 {
            let mut m = 0usize;
            for i in 0..tx_n {
                match tx_peers[i] {
                    Some(std::net::SocketAddr::V4(v4)) => {
                        tx_addrs[m].sin_family = libc::AF_INET as libc::sa_family_t;
                        tx_addrs[m].sin_port = v4.port().to_be();
                        tx_addrs[m].sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                        tx_iovs[m].iov_base = tx_bufs[i].as_ptr() as *mut libc::c_void;
                        // Clamp to the buffer size: sendmmsg reads iov_len bytes raw, so a
                        // (hypothetical) oversized resp_len must never read past the frame.
                        tx_iovs[m].iov_len = tx_lens[i].min(DNS_BUF_SIZE);
                        tx_msgs[m].msg_hdr.msg_name =
                            &mut tx_addrs[m] as *mut _ as *mut libc::c_void;
                        tx_msgs[m].msg_hdr.msg_namelen =
                            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                        tx_msgs[m].msg_hdr.msg_iov = &mut tx_iovs[m];
                        tx_msgs[m].msg_hdr.msg_iovlen = 1;
                        m += 1;
                    }
                    // IPv6 (rare on this path): send individually.
                    Some(peer) => {
                        let _ = sock.send_to(&tx_bufs[i][..tx_lens[i]], peer);
                    }
                    None => {}
                }
            }
            let mut sent = 0usize;
            while sent < m {
                // SAFETY: tx_msgs[sent..m] are fully initialised; their msg_name/msg_iov
                // point into tx_addrs/tx_iovs, which outlive this call and never realloc.
                let r = unsafe {
                    libc::sendmmsg(
                        fd,
                        tx_msgs[sent..].as_mut_ptr(),
                        (m - sent) as libc::c_uint,
                        0,
                    )
                };
                if r <= 0 {
                    break;
                }
                sent += r as usize;
            }
        }
    }
}

/// Convert a kernel `sockaddr_storage` (filled by recvmmsg) into a std `SocketAddr`.
fn sockaddr_to_std(ss: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let a = unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), u16::from_be(a.sin_port)))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(ss as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), u16::from_be(a.sin6_port)))
        }
        _ => None,
    }
}


#[cfg(test)]
mod sockaddr_parse_tests {
    use super::sockaddr_to_std;
    use std::net::Ipv4Addr;

    fn v4(ip: Ipv4Addr, port: u16) -> libc::sockaddr_storage {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: writing the sockaddr_in view of a zeroed sockaddr_storage.
        let sin = unsafe { &mut *(&mut ss as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = port.to_be();
        sin.sin_addr.s_addr = u32::from(ip).to_be();
        ss
    }

    #[test]
    fn fuzz_sockaddr_to_std_never_panics() {
        // 1M fully-random sockaddr_storage byte patterns must yield Some/None without
        // panic or UB (the recvmmsg source-addr parser). #SEC-H8.
        let mut st: u64 = 0x1234_5678_9abc_def0;
        let mut rng = || { st ^= st << 13; st ^= st >> 7; st ^= st << 17; st };
        let sz = std::mem::size_of::<libc::sockaddr_storage>();
        for _ in 0..1_000_000 {
            let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let p = &mut ss as *mut libc::sockaddr_storage as *mut u8;
            for i in 0..sz { unsafe { *p.add(i) = (rng() & 0xff) as u8; } }
            let _ = sockaddr_to_std(&ss);
        }
    }

    #[test]
    fn ipv4_round_trips() {
        let ss = v4(Ipv4Addr::new(1, 2, 3, 4), 53);
        assert_eq!(sockaddr_to_std(&ss), Some("1.2.3.4:53".parse().unwrap()));
    }

    #[test]
    fn unspec_and_unknown_family_are_rejected() {
        // AF_UNSPEC (zeroed) and a garbage family must yield None (never panic / UB).
        let zero: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        assert_eq!(sockaddr_to_std(&zero), None);
        let mut garbage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        garbage.ss_family = 4242;
        assert_eq!(sockaddr_to_std(&garbage), None);
    }
}
