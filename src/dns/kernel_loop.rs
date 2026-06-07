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
//             → fallback to hickory via tokio channel                  [slow, rare]
//
// The hickory ServerFuture is demoted to a pure fallback (EDNS DO=1, CNAME,
// MX, TSIG, AXFR, TCP, recursion) — it never sees the local-zone hot path.
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

/// Message sent to the hickory fallback handler when the wire fast path
/// cannot answer a query (EDNS DO=1, CNAME, MX, TSIG, AXFR, recursion…).
pub struct FallbackMsg {
    pub query:  Vec<u8>,
    pub peer:   SocketAddr,
    /// The socket to reply on (Arc so we can clone it across threads).
    pub socket: Arc<UdpSocket>,
}

/// Global sender so XDP workers (no kernel arrival socket) can hand
/// recursion/complex misses to the same hickory fallback reader.
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

const RCVBUF_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
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

    // #183: spread incoming datagrams EVENLY across the SO_REUSEPORT group by the CPU
    // that processes them, instead of the kernel's default 4-tuple hash (which is uneven
    // for a benchmark's few flows → some sockets overflow while others idle, dropping
    // packets even with spare CPU). The 2-insn cBPF returns SKF_AD_CPU; the kernel maps
    // socket = cpu % nsockets. Combined with RPS (softirq spread across all cores) this
    // gives a flat per-socket load. Best-effort: ignore errors on kernels without it.
    {
        use std::os::fd::AsRawFd;
        #[repr(C)]
        struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
        #[repr(C)]
        struct SockFprog { len: u16, filter: *const SockFilter }
        const SKF_AD_OFF: u32 = 0xffff_f000; // -0x1000
        const SKF_AD_CPU: u32 = 36;
        const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
        const BPF_RET_A: u16 = 0x16;    // BPF_RET | BPF_A
        const SO_ATTACH_REUSEPORT_CBPF: libc::c_int = 51;
        let prog = [
            SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: SKF_AD_OFF + SKF_AD_CPU },
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
/// and a `tokio::sync::mpsc::Sender` for the hickory fallback channel.
#[allow(clippy::too_many_arguments)]
pub fn start_kernel_fast_loop(
    bind_addr: &str,           // e.g. "0.0.0.0:53"
    cores: &[usize],           // physical NUMA-local cores (from cpu::physical_cores_numa_sorted)
    zones: Arc<ArcSwap<LocalZoneSet>>,
    acl: Arc<Acl>,
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
                    let mut set: cpu_set_t = unsafe { std::mem::zeroed() };
                    unsafe { CPU_SET(core_id, &mut set) };
                    unsafe { sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set) };
                }

                worker_loop(
                    i,
                    core_id,
                    Arc::clone(&sock_arc),
                    zones2,
                    acl2,
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
    _thread_idx: usize,
    _core_id: usize,
    sock: Arc<UdpSocket>,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    acl: Arc<Acl>,
    fallback_tx: tokio::sync::mpsc::Sender<FallbackMsg>,
    cache_snapshot: Option<Arc<arc_swap::ArcSwap<crate::dns::cache_snapshot::CacheSnapshot>>>,
    stats: Option<Arc<crate::stats::Stats>>,
    domain_stats: Option<Arc<crate::domain_stats::DomainStats>>,
) {
    // Stack-allocated I/O buffers — never heap on the hot path.
    let mut rx_buf = [0u8; DNS_BUF_SIZE];
    let mut tx_buf = [0u8; DNS_BUF_SIZE];

    loop {
        // ── Receive ──────────────────────────────────────────────────────────
        let (len, peer) = match sock.recv_from(&mut rx_buf) {
            Ok(r) => r,
            Err(e) => {
                // EAGAIN/EINTR are benign; anything else is worth logging.
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::Interrupted
                {
                    warn!("kloop recv_from: {e}");
                }
                continue;
            }
        };
        let query = &rx_buf[..len];
        let src_ip: Option<IpAddr> = Some(peer.ip());

        // ── Fast path A: wire builder (zero hickory, zero alloc) ─────────────
        // answer_dns_wire: parse_query + WireRecordIndex CRC32c lookup +
        // build_answer_a_aaaa_wire — all SIMD, stack-only.
        {
            let zones_snap = zones.load();
            use crate::dns::xdp::worker::{answer_dns_wire_pub, WireResultPub};
            match answer_dns_wire_pub(query, &mut tx_buf, &zones_snap, &acl, src_ip) {
                WireResultPub::Answered(resp_len) => {
                    let _ = sock.send_to(&tx_buf[..resp_len], peer);
                    continue;
                }
                WireResultPub::Drop => continue, // ACL Deny — silent drop
                WireResultPub::Fallback => {}     // try cache, then hickory
            }
        }

        // ── Fast path B: cache snapshot (SIMD lookup, zero hickory) ──────────
        if let Some(ref cache_arc) = cache_snapshot {
            let snap = cache_arc.load_full();
            use crate::dns::xdp::worker::answer_from_cache_pub;
            if let Some(resp_len) = answer_from_cache_pub(
                query,
                &snap,
                &acl,
                src_ip,
                &mut tx_buf,
                stats.as_ref(),
                domain_stats.as_ref(),
            ) {
                let _ = sock.send_to(&tx_buf[..resp_len], peer);
                continue;
            }
        }

        // ── Slow path: hickory fallback (CNAME, MX, TSIG, recursion…) ────────
        // Clone the query bytes and send to the async hickory handler.
        // The handler replies directly on sock_clone.
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
}
