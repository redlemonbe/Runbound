// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// XDP worker: poll loop that reads raw Ethernet frames from the AF_XDP RX
// ring, processes local-zone DNS queries entirely in user space, and writes
// DNS responses back to the TX ring.
//
// Each worker owns one XskSocket (one NIC queue).  Workers run on dedicated
// OS threads so the hot path never contends with the Tokio executor.
//
// Fast path (local query answered here):
//   poll() → consume_rx() → parse eth/ip/udp/dns → LocalZoneSet lookup →
//   build response → craft reply frame → enqueue_tx() → kick if needed →
//   return frames to fill ring
//
// Slow path (recursive / unknown name):
//   The XDP program was configured with XDP_PASS fallback, so these packets
//   never reached the AF_XDP socket — hickory-server handles them normally.
//   Within the worker, a query whose name isn't found locally returns None
//   from process_packet(); the frame is recycled without a TX response.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::LowerName,
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};

use crate::dns::acl::{Acl, AclAction};
use crate::dns::local::{LocalZoneSet, ZoneAction};
use crate::dns::RateLimiter;
use super::loader::XdpHandle;
use super::socket::{
    XskSocket, create_xsk_socket, get_rx_queue_count, iface_index,
    is_virtual_interface, parent_interface,
};
use super::umem::{XdpDesc, FRAME_SIZE};

const ETH_HDR: usize = 14;
const IPV4_HDR_MIN: usize = 20;
const IPV6_HDR: usize = 40;
const UDP_HDR: usize = 8;

const ETH_P_IP:   u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const PROTO_UDP:   u8 = 17;

/// Load the XDP program onto `iface`, open one AF_XDP socket per RX queue,
/// and spawn a dedicated OS thread for each.  Returns `Ok(Some(handle))` when
/// the fast path is active, `Ok(None)` when XDP is cleanly disabled (virtual
/// interface with no detectable parent, or self-test failure), or `Err` for
/// unexpected errors.
///
/// If `iface` is a virtual interface (bridge, veth, ipvlan, macvlan), the
/// function automatically retries on the physical parent before giving up.
pub fn start_xdp(
    iface:        &str,
    zones:        Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl:          Arc<Acl>,
) -> Result<Option<XdpHandle>, String> {
    if is_virtual_interface(iface) {
        match parent_interface(iface) {
            Some(ref parent) => {
                tracing::warn!(
                    virt = %iface, parent = %parent,
                    "XDP: virtual interface detected — retrying on parent"
                );
                let result = start_xdp_on_iface(parent, zones, rate_limiter, acl);
                if result.as_ref().map(|r| r.is_some()).unwrap_or(false) {
                    tracing::info!(parent = %parent, "XDP active on parent interface");
                }
                return result;
            }
            None => {
                tracing::warn!(
                    iface = %iface,
                    "XDP: virtual interface with no detectable parent — \
                     disabling XDP, falling back to UDP"
                );
                return Ok(None);
            }
        }
    }
    start_xdp_on_iface(iface, zones, rate_limiter, acl)
}

fn start_xdp_on_iface(
    iface:        &str,
    zones:        Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl:          Arc<Acl>,
) -> Result<Option<XdpHandle>, String> {
    let ifidx = iface_index(iface)
        .ok_or_else(|| format!("interface {iface} not found"))?;

    let mut handle = XdpHandle::load(iface)?;

    let queue_count = get_rx_queue_count(iface).max(1);
    tracing::info!(iface = %iface, queues = queue_count, "Starting XDP workers");

    let cores = crate::cpu::physical_cores();

    // Create all sockets before spawning threads so we can run the self-test.
    let mut sockets: Vec<(u32, XskSocket)> = Vec::with_capacity(queue_count as usize);
    for q in 0..queue_count {
        let sock = unsafe { create_xsk_socket(ifidx, q, true) }
            .or_else(|_| unsafe { create_xsk_socket(ifidx, q, false) })
            .map_err(|e| format!("AF_XDP socket creation failed: {e}"))?;
        handle.register_socket(q, sock.fd)?;
        sockets.push((q, sock));
    }

    // Self-test on the first socket before committing threads.
    if let Some((_, first_sock)) = sockets.first_mut() {
        if let Err(msg) = xdp_fill_ring_self_test(iface, first_sock) {
            tracing::warn!("{msg}");
            return Ok(None);
        }
    }

    for (q, sock) in sockets {
        let z       = Arc::clone(&zones);
        let rl      = Arc::clone(&rate_limiter);
        let acl     = Arc::clone(&acl);
        let core_id = if cores.is_empty() { 0 } else { cores[q as usize % cores.len()] };
        std::thread::Builder::new()
            .name(format!("xdp-{iface}-q{q}"))
            .spawn(move || xdp_worker(sock, z, rl, acl, core_id))
            .map_err(|e| format!("thread spawn: {e}"))?;
    }

    Ok(Some(handle))
}

/// Verify the UMEM fill ring was seeded, then inject 3 synthetic DNS frames and
/// poll the RX ring for up to 200 ms.  Returns `Ok(())` if any RX frames arrive
/// or if the TX pool was empty (can't inject — skip loopback check).
/// Returns `Err` if the fill ring was never seeded (UMEM misconfiguration) or
/// if no frames arrive within 200 ms (socket not receiving — possible
/// misconfiguration or isolated network).
fn xdp_fill_ring_self_test(iface: &str, sock: &mut XskSocket) -> Result<(), String> {
    use libc::{POLLIN, poll, pollfd};

    // Hard check: fill ring must have been seeded by Umem::new().
    if sock.umem.fill.producer_count() == 0 {
        return Err(format!(
            "XDP self-test failed: fill ring empty or UMEM misconfigured on '{iface}' \
             — disabling XDP, falling back to kernel UDP path"
        ));
    }

    // Inject up to 3 synthetic DNS frames into the TX ring.
    let mut injected = 0u32;
    for _ in 0..3 {
        if let Some(tx_addr) = sock.umem.tx_free.pop_front() {
            if let Some(frame) = unsafe { sock.umem.frame_mut(tx_addr, FRAME_SIZE as usize) } {
                let len = build_test_frame(frame);
                if len > 0 {
                    sock.tx.enqueue_tx(&[XdpDesc { addr: tx_addr, len: len as u32, options: 0 }]);
                    injected += 1;
                } else {
                    sock.umem.tx_free.push_back(tx_addr);
                }
            } else {
                sock.umem.tx_free.push_back(tx_addr);
            }
        }
    }
    // Kick the driver if needed.
    if sock.tx.needs_wakeup() {
        unsafe {
            libc::sendto(sock.fd, std::ptr::null(), 0, libc::MSG_DONTWAIT,
                         std::ptr::null(), 0);
        }
    }
    // If TX pool was exhausted we can't inject — skip loopback check.
    if injected == 0 {
        return Ok(());
    }

    // Poll RX ring for up to 200 ms — any incoming frame confirms the socket works.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    let mut rx_descs: Vec<XdpDesc> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { break; }
        let mut pfd = pollfd { fd: sock.fd, events: POLLIN, revents: 0 };
        let timeout_ms = (remaining.as_millis() as i32).min(20).max(1);
        let ret = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 && (pfd.revents & POLLIN) != 0 {
            sock.rx.consume_rx_into(&mut rx_descs);
            if !rx_descs.is_empty() {
                let addrs: Vec<u64> = rx_descs.iter().map(|d| d.addr).collect();
                sock.umem.fill.enqueue_batch(&addrs);
                tracing::info!(iface = %iface, rx_frames = rx_descs.len(), "XDP self-test passed");
                return Ok(());
            }
        }
        if ret < 0 { break; }
    }
    Err(format!(
        "XDP self-test failed: fill ring empty or UMEM misconfigured on '{iface}' \
         — disabling XDP, falling back to kernel UDP path"
    ))
}

/// Build a minimal Ethernet/IPv4/UDP/DNS query frame for the self-test.
/// Destination: 192.0.2.2 (TEST-NET-1, RFC 5737 — not routable).
/// Returns the total frame length, or 0 if `buf` is too small.
fn build_test_frame(buf: &mut [u8]) -> usize {
    // DNS query: A record for "xdp.test." (ID=0xDEAD)
    const DNS: &[u8] = &[
        0xDE, 0xAD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3, b'x', b'd', b'p', 4, b't', b'e', b's', b't', 0,
        0x00, 0x01, 0x00, 0x01,
    ];
    const ETH: usize = 14;
    const IP:  usize = 20;
    const UDP: usize = 8;
    let total = ETH + IP + UDP + DNS.len();
    if buf.len() < total { return 0; }

    // Ethernet: broadcast dst, fake src, EtherType=IPv4
    buf[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    buf[6..12].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4: src=192.0.2.1, dst=192.0.2.2, proto=UDP
    let ip_total = (IP + UDP + DNS.len()) as u16;
    buf[ETH]     = 0x45; // version=4, IHL=5
    buf[ETH + 1] = 0;
    buf[ETH + 2..ETH + 4].copy_from_slice(&ip_total.to_be_bytes());
    buf[ETH + 4..ETH + 6].copy_from_slice(&[0xDE, 0xAD]); // ID
    buf[ETH + 6..ETH + 8].copy_from_slice(&[0x40, 0x00]); // DF
    buf[ETH + 8]  = 64; // TTL
    buf[ETH + 9]  = 17; // UDP
    buf[ETH + 10..ETH + 12].fill(0); // checksum placeholder
    buf[ETH + 12..ETH + 16].copy_from_slice(&[192, 0, 2, 1]); // src
    buf[ETH + 16..ETH + 20].copy_from_slice(&[192, 0, 2, 2]); // dst
    let cksum = ipv4_checksum(&buf[ETH..ETH + IP]);
    buf[ETH + 10..ETH + 12].copy_from_slice(&cksum.to_be_bytes());

    // UDP: src_port=12345, dst_port=53
    let udp_len = (UDP + DNS.len()) as u16;
    buf[ETH + IP..ETH + IP + 2].copy_from_slice(&12345u16.to_be_bytes());
    buf[ETH + IP + 2..ETH + IP + 4].copy_from_slice(&53u16.to_be_bytes());
    buf[ETH + IP + 4..ETH + IP + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[ETH + IP + 6..ETH + IP + 8].fill(0); // no UDP checksum

    // DNS payload
    buf[ETH + IP + UDP..total].copy_from_slice(DNS);
    total
}

/// Poll loop for one NIC queue. Runs until the socket fd is closed.
fn xdp_worker(
    mut sock:     XskSocket,
    zones:        Arc<ArcSwap<LocalZoneSet>>,
    rate_limiter: Arc<RateLimiter>,
    acl:          Arc<Acl>,
    core_id:      usize,
) {
    use libc::{poll, pollfd, POLLIN};
    use super::umem::RING_SIZE;

    crate::cpu::pin_to_cpu(core_id);

    // Pre-allocate scratch buffers outside the hot loop to avoid per-batch
    // heap allocations.  Each Vec retains its capacity across iterations;
    // clear() resets length without releasing memory.
    let mut rxds:       Vec<XdpDesc> = Vec::with_capacity(RING_SIZE as usize);
    let mut tx_descs:   Vec<XdpDesc> = Vec::with_capacity(RING_SIZE as usize);
    let mut rx_addrs:   Vec<u64>     = Vec::with_capacity(RING_SIZE as usize);
    let mut dns_scratch: Vec<u8>     = Vec::with_capacity(512);

    loop {
        sock.umem.reclaim_tx();

        let mut pfd = pollfd { fd: sock.fd, events: POLLIN, revents: 0 };
        let ret = unsafe { poll(&mut pfd, 1, 1 /* ms timeout */) };
        if ret < 0 {
            break;
        }

        rxds.clear();
        sock.rx.consume_rx_into(&mut rxds);
        if rxds.is_empty() {
            continue;
        }

        let snapshot = zones.load();
        tx_descs.clear();
        rx_addrs.clear();

        for desc in &rxds {
            rx_addrs.push(desc.addr);

            if let Some(tx_addr) = sock.umem.tx_free.pop_front() {
                // FIX 2.1: release-mode bounds check on kernel-provided descriptor.
                // desc.addr/len come from the XDP RX ring (kernel-controlled); a
                // corrupted or malicious kernel could supply out-of-bounds values.
                // Silently skip — never panic, never access memory outside UMEM.
                if desc.addr as usize + desc.len as usize > sock.umem.area_len {
                    sock.umem.tx_free.push_back(tx_addr);
                    continue;
                }
                let (rx_frame, tx_frame) = unsafe {
                    let rx = std::slice::from_raw_parts(
                        sock.umem.area.add(desc.addr as usize),
                        desc.len as usize,
                    );
                    let tx = std::slice::from_raw_parts_mut(
                        sock.umem.area.add(tx_addr as usize),
                        FRAME_SIZE as usize,
                    );
                    (rx, tx)
                };

                // Rate-limit check before processing: extract source IP from
                // the raw frame and consume a token from the shared bucket.
                // Dropped frames are silently recycled — no REFUSED response
                // is crafted in the XDP path (matches `deny` ACL semantics).
                let src_ip = extract_src_ip(rx_frame);
                if src_ip.map(|ip| !rate_limiter.check(ip)).unwrap_or(false) {
                    sock.umem.tx_free.push_back(tx_addr);
                    continue;
                }

                dns_scratch.clear();
                match process_packet(rx_frame, tx_frame, &snapshot, &acl, src_ip, &mut dns_scratch) {
                    Some(tx_len) => tx_descs.push(XdpDesc {
                        addr: tx_addr,
                        len:  tx_len as u32,
                        options: 0,
                    }),
                    None => {
                        sock.umem.tx_free.push_back(tx_addr);
                    }
                }
            }
        }

        // Return consumed RX frames to the kernel fill ring.
        sock.umem.fill.enqueue_batch(&rx_addrs);

        if !tx_descs.is_empty() {
            sock.tx.enqueue_tx(&tx_descs);

            // Kick the driver if it set the NEED_WAKEUP flag.
            if sock.tx.needs_wakeup() {
                unsafe {
                    libc::sendto(
                        sock.fd,
                        std::ptr::null(),
                        0,
                        libc::MSG_DONTWAIT,
                        std::ptr::null(),
                        0,
                    );
                }
            }
        }
    }
}

/// Extract the source IP address from a raw Ethernet frame (IPv4 or IPv6).
/// Returns None for non-IP frames or frames that are too short.
#[inline]
fn extract_src_ip(rx: &[u8]) -> Option<IpAddr> {
    if rx.len() < ETH_HDR { return None; }
    let ethertype = u16::from_be_bytes([rx[12], rx[13]]);
    match ethertype {
        ETH_P_IP => {
            if rx.len() < ETH_HDR + 20 { return None; }
            let src: [u8; 4] = rx[ETH_HDR + 12..ETH_HDR + 16].try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(src)))
        }
        ETH_P_IPV6 => {
            if rx.len() < ETH_HDR + 40 { return None; }
            let src: [u8; 16] = rx[ETH_HDR + 8..ETH_HDR + 24].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(src)))
        }
        _ => None,
    }
}

/// Parse a raw Ethernet frame, answer the DNS query from `zones`, and write
/// the response frame into `tx`.  Returns the number of bytes written on
/// success, or `None` if this frame should not receive an XDP reply.
///
/// `dns_scratch` is a caller-supplied buffer (cleared before each call) used
/// for DNS response serialisation.  Passing a pre-allocated Vec avoids a heap
/// allocation on every packet.
fn process_packet(
    rx:          &[u8],
    tx:          &mut [u8],
    zones:       &LocalZoneSet,
    acl:         &Acl,
    src_ip:      Option<IpAddr>,
    dns_scratch: &mut Vec<u8>,
) -> Option<usize> {
    // ── Ethernet ─────────────────────────────────────────────────────────────
    if rx.len() < ETH_HDR { return None; }
    let ethertype = u16::from_be_bytes([rx[12], rx[13]]);

    let (ip_off, is_v6) = match ethertype {
        ETH_P_IP   => (ETH_HDR, false),
        ETH_P_IPV6 => (ETH_HDR, true),
        _          => return None,
    };

    // ── IP ───────────────────────────────────────────────────────────────────
    let (udp_off, ip_hdr_len, src_ip_off, dst_ip_off, ip_len_off) = if !is_v6 {
        if rx.len() < ip_off + IPV4_HDR_MIN { return None; }
        if rx[ip_off + 9] != PROTO_UDP { return None; }
        let ihl = (rx[ip_off] & 0x0F) as usize * 4;
        if ihl < 20 || ihl > 60 { return None; }
        (ip_off + ihl, ihl, ip_off + 12, ip_off + 16, ip_off + 2)
    } else {
        if rx.len() < ip_off + IPV6_HDR { return None; }
        if rx[ip_off + 6] != PROTO_UDP { return None; }
        (ip_off + IPV6_HDR, IPV6_HDR, ip_off + 8, ip_off + 24, ip_off + 4)
    };

    // ── UDP ──────────────────────────────────────────────────────────────────
    if rx.len() < udp_off + UDP_HDR { return None; }
    let src_port = u16::from_be_bytes([rx[udp_off],     rx[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([rx[udp_off + 2], rx[udp_off + 3]]);
    if dst_port != 53 { return None; }

    let dns_off = udp_off + UDP_HDR;
    if rx.len() <= dns_off { return None; }
    let dns_in = &rx[dns_off..];

    // ── DNS ──────────────────────────────────────────────────────────────────
    if !answer_dns(dns_in, zones, acl, src_ip, dns_scratch) {
        return None; // not a local query or ACL deny — let it fall through / drop
    }

    // ── Build reply frame ────────────────────────────────────────────────────
    let reply_len = dns_off + dns_scratch.len();
    if reply_len > tx.len() { return None; }

    // Ethernet: swap src ↔ dst MAC
    tx[0..6].copy_from_slice(&rx[6..12]);
    tx[6..12].copy_from_slice(&rx[0..6]);
    tx[12..14].copy_from_slice(&rx[12..14]);

    if !is_v6 {
        // IPv4: copy then fix length, swap src/dst, recompute checksum
        tx[ip_off..ip_off + ip_hdr_len].copy_from_slice(&rx[ip_off..ip_off + ip_hdr_len]);
        let new_tot = (ip_hdr_len + UDP_HDR + dns_scratch.len()) as u16;
        tx[ip_len_off..ip_len_off + 2].copy_from_slice(&new_tot.to_be_bytes());

        let src: [u8; 4] = rx[src_ip_off..src_ip_off + 4].try_into().ok()?;
        let dst: [u8; 4] = rx[dst_ip_off..dst_ip_off + 4].try_into().ok()?;
        tx[ip_off + 12..ip_off + 16].copy_from_slice(&dst);
        tx[ip_off + 16..ip_off + 20].copy_from_slice(&src);

        // Clear then recompute IPv4 header checksum
        tx[ip_off + 10..ip_off + 12].fill(0);
        let cksum = ipv4_checksum(&tx[ip_off..ip_off + ip_hdr_len]);
        tx[ip_off + 10..ip_off + 12].copy_from_slice(&cksum.to_be_bytes());
    } else {
        // IPv6: copy, set payload length, swap src/dst
        tx[ip_off..ip_off + IPV6_HDR].copy_from_slice(&rx[ip_off..ip_off + IPV6_HDR]);
        let payload_len = (UDP_HDR + dns_scratch.len()) as u16;
        tx[ip_len_off..ip_len_off + 2].copy_from_slice(&payload_len.to_be_bytes());

        let src: [u8; 16] = rx[src_ip_off..src_ip_off + 16].try_into().ok()?;
        let dst: [u8; 16] = rx[dst_ip_off..dst_ip_off + 16].try_into().ok()?;
        tx[ip_off + 8..ip_off + 24].copy_from_slice(&dst);
        tx[ip_off + 24..ip_off + 40].copy_from_slice(&src);
    }

    // UDP: swap ports, set length
    let udp_len = (UDP_HDR + dns_scratch.len()) as u16;
    tx[udp_off..udp_off + 2].copy_from_slice(&dst_port.to_be_bytes()); // src = 53
    tx[udp_off + 2..udp_off + 4].copy_from_slice(&src_port.to_be_bytes());
    tx[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());

    // Compute UDP checksum using the reply frame already in tx
    tx[udp_off + 6..udp_off + 8].fill(0);
    let cksum = if !is_v6 {
        let si: [u8; 4] = tx[ip_off + 12..ip_off + 16].try_into().ok()?;
        let di: [u8; 4] = tx[ip_off + 16..ip_off + 20].try_into().ok()?;
        udp_checksum_v4(&si, &di, &tx[udp_off..udp_off + UDP_HDR + dns_scratch.len()])
    } else {
        let si: [u8; 16] = tx[ip_off + 8..ip_off + 24].try_into().ok()?;
        let di: [u8; 16] = tx[ip_off + 24..ip_off + 40].try_into().ok()?;
        udp_checksum_v6(&si, &di, &tx[udp_off..udp_off + UDP_HDR + dns_scratch.len()])
    };
    tx[udp_off + 6..udp_off + 8].copy_from_slice(&cksum.to_be_bytes());

    // DNS payload
    tx[dns_off..dns_off + dns_scratch.len()].copy_from_slice(dns_scratch);

    Some(reply_len)
}

/// Parse `query_bytes` as a DNS query, look it up in `zones`, write the
/// serialised response into `out`.  Returns false if the query should be
/// forwarded to the kernel (non-local name, not a standard query, ACL deny, etc.).
///
/// ACL enforcement in the XDP path:
///   Allow  → proceed normally.
///   Deny   → silent drop (return false, no TX frame crafted).
///   Refuse → craft a REFUSED response and return true so the TX path sends it.
fn answer_dns(
    query_bytes: &[u8],
    zones:       &LocalZoneSet,
    acl:         &Acl,
    src_ip:      Option<IpAddr>,
    out:         &mut Vec<u8>,
) -> bool {
    let msg = match Message::from_bytes(query_bytes) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if msg.message_type != MessageType::Query { return false; }
    if msg.op_code != OpCode::Query { return false; }

    let q = match msg.queries.first() {
        Some(q) => q,
        None    => return false,
    };

    // ── ACL check ─────────────────────────────────────────────────────────
    // Applied before zone lookup so that Deny/Refuse clients cannot probe
    // local zone membership even in the XDP fast path.
    if let Some(ip) = src_ip {
        match acl.check(ip) {
            AclAction::Allow  => {}
            AclAction::Deny   => return false, // silent drop — no response
            AclAction::Refuse => {
                // Craft a minimal REFUSED response and send it.
                let mut refused = Message::new(msg.id, MessageType::Response, OpCode::Query);
                refused.metadata.response_code = ResponseCode::Refused;
                refused.metadata.recursion_desired = msg.recursion_desired;
                refused.add_query(q.clone());
                let mut enc = BinEncoder::new(out);
                return refused.emit(&mut enc).is_ok();
            }
        }
    }

    let name  = LowerName::from(q.name());
    let rtype = q.query_type();

    // ANY queries go to the normal server (which returns NOTIMP per RFC 8482)
    if rtype == hickory_proto::rr::RecordType::ANY { return false; }

    let mut resp = Message::new(msg.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = msg.recursion_desired;
    resp.metadata.recursion_available = false;
    resp.add_query(q.clone());

    match zones.find(&name) {
        Some(ZoneAction::Refuse) => {
            resp.metadata.response_code = ResponseCode::Refused;
            resp.metadata.authoritative = false;
        }
        Some(ZoneAction::NxDomain) => {
            resp.metadata.response_code = ResponseCode::NXDomain;
            resp.metadata.authoritative = true;
        }
        Some(ZoneAction::Static) | Some(ZoneAction::Redirect) => {
            resp.metadata.authoritative = true;
            let records = zones.local_records(&name, rtype);
            if !records.is_empty() {
                resp.metadata.response_code = ResponseCode::NoError;
                for r in records {
                    resp.add_answer(r.clone());
                }
            } else if zones.name_has_records(&name) {
                // NODATA — name exists, wrong type (RFC 2308)
                resp.metadata.response_code = ResponseCode::NoError;
            } else {
                resp.metadata.response_code = ResponseCode::NXDomain;
            }
        }
        // Name not in any local zone — forward to kernel / hickory-server
        None => return false,
    }

    let mut enc = BinEncoder::new(out);
    resp.emit(&mut enc).is_ok()
}

// ── Checksum helpers ──────────────────────────────────────────────────────────

fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    sum
}

fn fold_checksum(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    let r = !(s as u16);
    if r == 0 { 0xFFFF } else { r } // RFC 768: 0 is transmitted as all-ones
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    fold_checksum(ones_complement_sum(header))
}

fn udp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    let udp_len = udp.len() as u32;
    let s = ones_complement_sum(src)
          + ones_complement_sum(dst)
          + PROTO_UDP as u32
          + udp_len
          + ones_complement_sum(udp);
    fold_checksum(s)
}

fn udp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    // IPv6 pseudo-header: src(16) + dst(16) + UDP length(4) + zeros(3) + next-header(1)
    let udp_len = udp.len() as u32;
    let udp_len_bytes = udp_len.to_be_bytes();
    let s = ones_complement_sum(src)
          + ones_complement_sum(dst)
          + ones_complement_sum(&udp_len_bytes)
          + PROTO_UDP as u32
          + ones_complement_sum(udp);
    fold_checksum(s)
}
