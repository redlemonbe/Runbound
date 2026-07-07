// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// In-house iterative recursive resolver with DNSSEC validation.
//
// Resolves a query from the IANA root servers without any third-party DNS
// library: it sends raw wire queries (built/parsed by `dns::wire`), follows
// referrals (NS + glue), chases CNAMEs, and returns the answer or an
// authoritative negative. Security defaults:
//   - random 16-bit transaction id per query + strict id/question matching on
//     the connected UDP socket (off-path spoofing resistance);
//   - nameserver IPs are filtered against private/special-use ranges (anti-SSRF:
//     an NS pointing at an internal address is never queried);
//   - a global query budget and a delegation/CNAME depth cap (anti-DoS);
//   - referrals must move *down* the tree (never sideways/up → no loops).
//
// DNSSEC: `resolve_validated` is the validating entry point, dispatched from
// `server.rs` under `resolution: full-recursion` + `dnssec-validation: yes`;
// it validates the chain and yields the AD verdict. The raw `resolve` /
// `resolve_message` entry points are non-validating and used by tests/oracles.

// Some entry points (raw `resolve`, helpers) are only reached from tests in the
// default build, so keep the module-level dead-code allowance.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::dns::infra_cache;
use crate::dns::wire::{self, consts, Name, Rdata, Record};

/// IANA root servers (IPv4) — the recursion bootstrap ("hints").
const ROOT_HINTS_V4: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),
    Ipv4Addr::new(170, 247, 170, 2),
    Ipv4Addr::new(192, 33, 4, 12),
    Ipv4Addr::new(199, 7, 91, 13),
    Ipv4Addr::new(192, 203, 230, 10),
    Ipv4Addr::new(192, 5, 5, 241),
    Ipv4Addr::new(192, 112, 36, 4),
    Ipv4Addr::new(198, 97, 190, 53),
    Ipv4Addr::new(192, 36, 148, 17),
    Ipv4Addr::new(192, 58, 128, 30),
    Ipv4Addr::new(193, 0, 14, 129),
    Ipv4Addr::new(199, 7, 83, 42),
    Ipv4Addr::new(202, 12, 27, 33),
];

/// The root hint IPs as a fresh `Vec` — the descent bootstrap when nothing
/// closer is cached (#230).
fn root_hints() -> Vec<IpAddr> {
    ROOT_HINTS_V4.iter().copied().map(IpAddr::V4).collect()
}

/// Where to begin the descent for `(qname, qtype)` using the #230 zone-cut cache,
/// or `None` to start from the root.
///
/// A DS record is authoritative in the PARENT zone, not in the zone it names, so a
/// DS query must never jump to `qname`'s own cached cut — that would ask the child
/// for its own DS (answered NODATA there) and wrongly fail the chain to Bogus.
/// For DS we therefore anchor the lookup at the parent; every other type is served
/// by the zone itself, so we anchor at `qname`.
fn cached_start(qname: &Name, qtype: u16) -> Option<(Name, Vec<IpAddr>)> {
    let anchor = if qtype == consts::rtype::DS {
        qname.parent()?
    } else {
        qname.clone()
    };
    infra_cache::zone_cut_start(&anchor)
}

/// TTL to cache a learned zone cut under (#230): the min TTL of the referral's NS
/// RRset (owner == the delegated `zone`) and of any glue A/AAAA for those NS
/// names. Falls back to a conservative default if the referral carried no TTL.
fn cut_ttl(msg: &wire::Message, zone: &Name, ns_names: &[Name]) -> u32 {
    let mut ttl = u32::MAX;
    for r in &msg.authority {
        if r.rtype == consts::rtype::NS && r.name.eq_ignore_ascii_case(zone) {
            ttl = ttl.min(r.ttl);
        }
    }
    for r in &msg.additional {
        if record_ip(r).is_some() && ns_names.iter().any(|n| n.eq_ignore_ascii_case(&r.name)) {
            ttl = ttl.min(r.ttl);
        }
    }
    if ttl == u32::MAX {
        3600
    } else {
        ttl
    }
}

const QUERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Hedge delay: if the current authoritative server hasn't answered within this,
/// fire the next one in parallel (the fastest reply wins). Bounds the worst case to
/// roughly the best server's RTT instead of QUERY_TIMEOUT per mute server (#slow-path).
const HEDGE_DELAY: Duration = Duration::from_millis(300);
/// Total upstream queries allowed for one user query (anti-DoS budget).
const MAX_QUERIES: u32 = 80;
/// Maximum delegation depth (root → TLD → … ) before giving up.
const MAX_DEPTH: u8 = 24;
/// Maximum CNAME indirections followed for one user query.
const MAX_CNAME: u8 = 12;

/// QNAME minimisation (RFC 9156, #231). When on, the iterative descent does not
/// send the full QNAME to every intermediate authoritative server: it probes only
/// the next label toward the target (QTYPE A) to discover the delegation, revealing
/// the full name+type solely to the final authoritative server. This is the
/// **relaxed** variant — any anomaly on a probe (NXDOMAIN, an unexpected answer, or
/// a mute server) falls back to the full QNAME at that same cut, so minimisation can
/// only add privacy, never break a resolution that would otherwise succeed. Default
/// on: like Unbound, once full-recursion is enabled, minimisation is enabled unless
/// explicitly disabled with `qname-minimisation: no`.
static QMIN_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Set QNAME minimisation on/off at runtime (from `qname-minimisation` in the
/// config, applied at startup). #231.
pub fn set_qname_minimisation(on: bool) {
    QMIN_ON.store(on, std::sync::atomic::Ordering::Relaxed);
}

fn qmin_on() -> bool {
    QMIN_ON.load(std::sync::atomic::Ordering::Relaxed)
}

/// QTYPE used for a minimised probe. RFC 9156 §2.3 recommends a type other than NS
/// (a plain A) so a lame/misbehaving authoritative that mishandles a non-terminal NS
/// query does not derail the descent; delegations are still discovered from the
/// AUTHORITY NS RRset regardless of the probe QTYPE.
const QMIN_PROBE_TYPE: u16 = consts::rtype::A;

/// Cap on how many labels are added one-by-one under a single cut before the
/// resolver gives up minimising and sends the full QNAME (RFC 9156 §2.3,
/// anti-amplification for a deep name held flat with no intermediate delegations).
const MAX_MINIMISE: usize = 10;

/// The minimised query name at the current `zone` cut: `zone` extended by
/// `1 + extra` labels toward `qname` (one label past the cut, plus any labels
/// already added while probing empty non-terminals under the same cut). Returns
/// `qname` itself once the target is reached or the `MAX_MINIMISE` cap is hit — the
/// caller treats a returned name equal to `qname` as "send the real question".
fn minimised(qname: &Name, zone: &Name, extra: usize) -> Name {
    let want = zone.label_count() + 1 + extra;
    let have = qname.label_count();
    if extra >= MAX_MINIMISE || want >= have {
        return qname.clone();
    }
    // Drop leftmost labels of qname until exactly `want` remain. `want < have`
    // guarantees each `parent()` unwraps (we strip strictly fewer than `have`).
    let mut n = qname.clone();
    for _ in 0..(have - want) {
        n = n.parent().expect("want < have keeps at least one label");
    }
    n
}

/// The outcome of an iterative resolution.
#[derive(Debug)]
pub enum Outcome {
    /// NOERROR with the answer RRset (CNAMEs followed, final records included).
    Answer(Vec<Record>),
    /// Authoritative negative: NXDOMAIN, or NOERROR + empty answer (NODATA).
    Negative { rcode: u16 },
    /// Could not resolve (all servers failed / budget exhausted / malformed).
    Failure,
}

// The anti-SSRF address filter (`is_public_ip`) is the single source of truth in
// the standalone `crate::ssrf` module (shared with the feed fetcher and the
// webhook client, and reachable from the fuzz lib). Re-exported for the recursor.
pub(crate) use crate::ssrf::is_public_ip;

/// Build an iterative query: random id, RD=0, one question, and an EDNS(0) OPT
/// with DO=1 (advertises a 1232-byte UDP buffer and requests RRSIG/DS so the
/// answer can be DNSSEC-validated). Oversized replies set TC and we retry over TCP.
fn build_query(qname: &Name, qtype: u16) -> (u16, Vec<u8>) {
    let mut idb = [0u8; 2];
    let id = if getrandom::fill(&mut idb).is_ok() {
        u16::from_be_bytes(idb)
    } else {
        // getrandom failing is near-impossible on Linux, but never emit a constant
        // id: a predictable transaction id collapses off-path spoof resistance.
        use std::sync::atomic::{AtomicU16, Ordering};
        static FALLBACK: AtomicU16 = AtomicU16::new(0x1357);
        FALLBACK.fetch_add(0x9e37, Ordering::Relaxed) ^ qtype.rotate_left(7)
    };
    let header = wire::Header {
        id,
        flags: 0, // QR=0, opcode=QUERY, RD=0 (iterative), rcode=0
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 1, // the OPT pseudo-RR below
    };
    let mut enc = wire::Encoder::uncompressed();
    header.emit(&mut enc);
    wire::Question::new(qname.clone(), qtype).emit(&mut enc);
    // EDNS(0) OPT with DO=1: ask authoritative servers to include RRSIGs (and DS
    // in referrals) so the answer can be DNSSEC-validated, and advertise a larger
    // UDP buffer; oversized replies still set TC and we retry over TCP.
    enc.u8(0); // root owner name
    enc.u16(consts::rtype::OPT);
    enc.u16(1232); // UDP payload size
    enc.u32(0x0000_8000); // extended-rcode/version 0, DO bit set
    enc.u16(0); // rdlen
    (id, enc.into_vec())
}

/// Send one query to `addr` (UDP, falling back to TCP on a truncated reply) and
/// return the parsed response, validated against `id` and the question.
async fn query_server(addr: SocketAddr, qname: &Name, qtype: u16) -> Option<wire::Message> {
    let (id, q) = build_query(qname, qtype);
    let resp = timeout(QUERY_TIMEOUT, udp_exchange(addr, &q, id, qname, qtype)).await.ok()??;
    let msg = wire::Message::parse(&resp).ok()?;
    if msg.header.id != id || !question_matches(&msg, qname, qtype) {
        return None;
    }
    if msg.header.tc() {
        // Truncated — retry over TCP for the full answer.
        let resp = timeout(QUERY_TIMEOUT, tcp_exchange(addr, &q)).await.ok()??;
        let msg = wire::Message::parse(&resp).ok()?;
        if msg.header.id != id || !question_matches(&msg, qname, qtype) {
            return None;
        }
        return Some(msg);
    }
    Some(msg)
}

fn question_matches(msg: &wire::Message, qname: &Name, qtype: u16) -> bool {
    match msg.first_question() {
        Some(q) => q.qtype == qtype && q.qclass == consts::class::IN && q.name.eq_ignore_ascii_case(qname),
        None => false,
    }
}

async fn udp_exchange(
    addr: SocketAddr,
    q: &[u8],
    id: u16,
    qname: &Name,
    qtype: u16,
) -> Option<Vec<u8>> {
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(addr).await.ok()?;
    sock.send(q).await.ok()?;
    let mut buf = vec![0u8; 4096];
    // M2: read until a datagram matching our transaction id + question arrives.
    // The socket is connect()ed so only the queried server's datagrams reach us;
    // a single spoofed/stray non-matching datagram no longer aborts resolution —
    // we keep waiting for the real answer, bounded by the caller's QUERY_TIMEOUT.
    loop {
        let n = sock.recv(&mut buf).await.ok()?;
        if let Ok(msg) = wire::Message::parse(&buf[..n]) {
            if msg.header.id == id && question_matches(&msg, qname, qtype) {
                return Some(buf[..n].to_vec());
            }
        }
    }
}

async fn tcp_exchange(addr: SocketAddr, q: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    // RFC 1035 §4.2.2: 2-byte length prefix.
    let len = u16::try_from(q.len()).ok()?;
    stream.write_all(&len.to_be_bytes()).await.ok()?;
    stream.write_all(q).await.ok()?;
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await.ok()?;
    let rlen = u16::from_be_bytes(lenbuf) as usize;
    let mut resp = vec![0u8; rlen];
    stream.read_exact(&mut resp).await.ok()?;
    Some(resp)
}

/// Resolve `qname`/`qtype` iteratively from the root. Entry point.
pub async fn resolve(qname: &Name, qtype: u16) -> Outcome {
    let mut budget = MAX_QUERIES;
    let mut cname_left = MAX_CNAME;
    let mut answers: Vec<Record> = Vec::new();
    let mut target = qname.clone();

    loop {
        match resolve_once(&target, qtype, &mut budget).await {
            StepOutcome::Answer(recs) => {
                answers.extend(recs);
                return Outcome::Answer(answers);
            }
            StepOutcome::Cname { chain, next } => {
                answers.extend(chain);
                if cname_left == 0 {
                    return Outcome::Failure;
                }
                cname_left -= 1;
                target = next;
                // Re-resolve the CNAME target from the root.
            }
            StepOutcome::Negative { rcode } => return Outcome::Negative { rcode },
            StepOutcome::Failure => return Outcome::Failure,
        }
    }
}

enum StepOutcome {
    Answer(Vec<Record>),
    Cname { chain: Vec<Record>, next: Name },
    Negative { rcode: u16 },
    Failure,
}

/// One iterative descent for a single `(qname, qtype)`: walk referrals from the
/// deepest cached enclosing cut (or the root) down to the authoritative server and
/// return its terminal message (answer / CNAME / NXDOMAIN / NODATA). With QNAME
/// minimisation on (#231), intermediate servers are probed with a minimised name
/// (QTYPE A); the full `(qname, qtype)` question is asked only of the final
/// authoritative server — or, in relaxed fallback, of a cut whose probe misbehaved.
/// `budget` bounds the total upstream queries (shared with out-of-band NS-address
/// resolution). `None` on a hard failure (all servers mute / budget spent).
///
/// This is the single descent engine shared by `resolve_once` (which interprets the
/// terminal message into a `StepOutcome`) and `resolve_message` / the DNSSEC
/// validator (which consume the message directly).
async fn descend(qname: &Name, qtype: u16, budget: &mut u32) -> Option<wire::Message> {
    // #230: start at the deepest cached enclosing zone cut instead of always the
    // root. A stale/dead cached cut (its first query fails) is forgotten and we
    // restart from the root, so the cache can only speed resolution up, never break
    // it. Every answer is still DNSSEC-validated by the caller.
    let (mut zone, mut ns_ips, mut from_cache) = match cached_start(qname, qtype) {
        Some((z, ips)) => (z, ips, true),
        None => (Name::root(), root_hints(), false),
    };
    // #231: labels added one-by-one while probing empty non-terminals under the
    // current cut; reset to 0 on every referral (the cut has moved down).
    let mut extra = 0usize;
    // #231: latched once a probe misbehaves at THIS cut — ask the full QNAME here.
    // Reset on every referral and on a root restart so the fallback stays cut-local
    // (a misbehaving cut must not force the full name onto deeper cuts — audit F1).
    let mut full = false;
    // Real delegation steps taken (root → TLD → …). Kept separate from the loop
    // guard so per-cut minimisation probing (ENT lengthening, relaxed fallback) no
    // longer eats into the delegation budget — a deep but legal name could otherwise
    // exhaust MAX_DEPTH and SERVFAIL (audit F-1). Bounds the chain against loops/lame
    // servers; real delegation depth is a handful of levels.
    let mut delegations: u8 = 0;

    // The loop is hard-bounded by the query budget: every iteration spends ≥1 upstream
    // query via query_ns_set (ns_ips is never empty), so it cannot run more than
    // MAX_QUERIES times. MAX_QUERIES is the aligned absolute guard.
    for _step in 0..MAX_QUERIES {
        // Decide what to actually put on the wire for this cut.
        let probing = qmin_on() && !full && {
            !minimised(qname, &zone, extra).eq_ignore_ascii_case(qname)
        };
        let (send_name, send_type) = if probing {
            (minimised(qname, &zone, extra), QMIN_PROBE_TYPE)
        } else {
            (qname.clone(), qtype)
        };

        let msg = match query_ns_set(&ns_ips, &send_name, send_type, budget).await {
            Some(m) => m,
            None => {
                // A mute probe must never fail an otherwise-resolvable name: retry
                // the full QNAME at this same cut before giving up on the cut.
                if probing {
                    full = true;
                    continue;
                }
                if from_cache {
                    infra_cache::zone_cut_forget(&zone);
                    zone = Name::root();
                    ns_ips = root_hints();
                    from_cache = false;
                    // Restart minimisation cleanly from the root: a dead cached cut's
                    // fallback/ENT state must not force the full name at the root/TLD
                    // (privacy) nor skip labels via a stale `extra` (audit F1).
                    full = false;
                    extra = 0;
                    continue;
                }
                return None;
            }
        };
        from_cache = false;
        let rcode = msg.header.rcode_low();

        // Terminal for the REAL question (only when we actually asked it): an answer
        // for qname (qtype or CNAME) or NXDOMAIN ends the descent.
        if !probing {
            let has_answer = msg.answers.iter().any(|r| {
                (r.rtype == qtype || r.rtype == consts::rtype::CNAME)
                    && r.name.eq_ignore_ascii_case(qname)
            });
            if has_answer || rcode == consts::rcode::NXDOMAIN {
                return Some(msg);
            }
        }

        // Referral strictly down the tree. Works for a minimised probe too: the
        // delegation owner is a suffix of the probe, hence of qname.
        let referral_zone = msg
            .authority
            .iter()
            .filter(|r| r.rtype == consts::rtype::NS)
            .map(|r| &r.name)
            .find(|nm| qname.is_in_zone(nm) && nm.is_in_zone(&zone) && !nm.eq_ignore_ascii_case(&zone))
            .cloned();

        if let Some(next_zone) = referral_zone {
            let ns_names: Vec<Name> = msg
                .authority
                .iter()
                .filter(|r| r.rtype == consts::rtype::NS && r.name.eq_ignore_ascii_case(&next_zone))
                .filter_map(|r| match &r.rdata {
                    Rdata::Ns(n) => Some(n.clone()),
                    _ => None,
                })
                .collect();

            // Glue from ADDITIONAL: A/AAAA for the referral's NS names.
            let mut next_ips: Vec<IpAddr> = msg
                .additional
                .iter()
                .filter(|r| ns_names.iter().any(|ns| ns.eq_ignore_ascii_case(&r.name)))
                .filter_map(record_ip)
                .filter(|ip| is_public_ip(*ip))
                .collect();

            // No usable glue → resolve one NS name's address out-of-band (bounded).
            if next_ips.is_empty() {
                for ns in &ns_names {
                    if *budget == 0 {
                        return None;
                    }
                    if let Some(ips) = resolve_ns_addr(ns, budget).await {
                        next_ips = ips.into_iter().filter(|ip| is_public_ip(*ip)).collect();
                        if !next_ips.is_empty() {
                            break;
                        }
                    }
                }
            }

            if next_ips.is_empty() {
                return None;
            }
            // #230: remember this cut so the next miss under it skips the root walk.
            infra_cache::zone_cut_learn(&next_zone, &next_ips, cut_ttl(&msg, &next_zone, &ns_names));
            ns_ips = next_ips;
            zone = next_zone;
            // Cut moved down: restart minimisation from the new cut and drop the
            // relaxed-fallback latch so a misbehaving parent cut does not force the
            // full QNAME onto every deeper cut — the fallback stays cut-local (audit F1).
            extra = 0;
            full = false;
            delegations += 1;
            if delegations >= MAX_DEPTH {
                return None; // too many delegation steps — loop / lame chain guard
            }
            continue;
        }

        // No referral.
        if probing {
            // The minimised probe is not a delegation point. Decide how to advance.
            let probe_answered = msg
                .answers
                .iter()
                .any(|r| r.name.eq_ignore_ascii_case(&send_name));
            if rcode == consts::rcode::NXDOMAIN || probe_answered {
                // NXDOMAIN on a prefix (a conformant server implies NXDOMAIN below,
                // RFC 8020, but a broken one may lie), or an unexpected answer on the
                // probe (e.g. a CNAME at an intermediate name): re-ask the real
                // question at this same cut and let it decide the truth.
                full = true;
                continue;
            }
            // NOERROR, no answer, no referral = empty non-terminal (the prefix exists
            // in this zone but has no A here): lengthen by one label and probe again
            // at the same cut. Bounded by MAX_MINIMISE via `minimised`.
            extra += 1;
            continue;
        }

        // Full question asked, no terminal answer, no referral → NODATA (the message
        // carries the zone SOA / NSEC*). Hand it back.
        return Some(msg);
    }
    None
}

/// One full descent for a single (name, type), following referrals until an
/// answer / negative / failure. Does not follow CNAMEs across the tree — that is
/// the caller's loop. Interprets the terminal message from [`descend`].
async fn resolve_once(qname: &Name, qtype: u16, budget: &mut u32) -> StepOutcome {
    let Some(msg) = descend(qname, qtype, budget).await else {
        return StepOutcome::Failure;
    };
    let rcode = msg.header.rcode_low();

    // CNAME for our exact name (even when the type differs) → hand back to caller.
    if let Some(cn) = msg
        .answers
        .iter()
        .find(|r| r.rtype == consts::rtype::CNAME && r.name.eq_ignore_ascii_case(qname))
    {
        if let Rdata::Cname(next) = &cn.rdata {
            return StepOutcome::Cname { chain: vec![cn.clone()], next: next.clone() };
        }
    }

    // Direct answer of the requested type for our name.
    let direct: Vec<Record> = msg
        .answers
        .iter()
        .filter(|r| r.rtype == qtype && r.name.eq_ignore_ascii_case(qname))
        .cloned()
        .collect();
    if !direct.is_empty() {
        return StepOutcome::Answer(direct);
    }

    if rcode == consts::rcode::NXDOMAIN {
        return StepOutcome::Negative { rcode };
    }
    // No answer, no CNAME, not NXDOMAIN → NODATA.
    StepOutcome::Negative { rcode: consts::rcode::NOERROR }
}

/// query_server + RTT measurement, for hedged selection feedback.
async fn query_server_timed(
    addr: SocketAddr,
    qname: &Name,
    qtype: u16,
) -> (SocketAddr, Option<wire::Message>, u32) {
    let start = tokio::time::Instant::now();
    let resp = query_server(addr, qname, qtype).await;
    let rtt_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    (addr, resp, rtt_ms)
}

/// Query a nameserver set with RTT-based ordering + hedging, bounded by `budget`.
/// Servers are tried fastest-known-first; if one is slow (HEDGE_DELAY), the next is
/// fired in parallel and the first valid reply wins. This turns a mute/slow first NS
/// from a QUERY_TIMEOUT stall into ~best-RTT + one hedge delay (#slow-path).
async fn query_ns_set(
    ns_ips: &[IpAddr],
    qname: &Name,
    qtype: u16,
    budget: &mut u32,
) -> Option<wire::Message> {
    use futures_util::stream::{FuturesUnordered, StreamExt};

    // #3 RTT order: fastest known servers first, never-seen ones after.
    let mut ips: Vec<IpAddr> = ns_ips.to_vec();
    ips.sort_by_key(|ip| infra_cache::rtt_of(ip).unwrap_or(u32::MAX));

    let mut inflight = FuturesUnordered::new();
    let mut next = 0usize;

    loop {
        // Launch the next server if the list and the query budget allow.
        if next < ips.len() && *budget > 0 {
            *budget -= 1;
            let addr = SocketAddr::new(ips[next], 53);
            next += 1;
            inflight.push(query_server_timed(addr, qname, qtype));
        }
        if inflight.is_empty() {
            return None;
        }
        let more = next < ips.len() && *budget > 0;
        tokio::select! {
            biased;
            Some((addr, resp, rtt_ms)) = inflight.next() => {
                if let Some(msg) = resp {
                    infra_cache::record_rtt(addr.ip(), rtt_ms);
                    return Some(msg);
                }
                // this server failed/timed out — loop to launch the next / await the rest
            }
            _ = tokio::time::sleep(HEDGE_DELAY), if more => {
                // hedge timer fired: the loop launches the next server in parallel
            }
        }
    }
}

/// Resolve a nameserver's A records via a fresh descent (no-glue case).
/// Boxed because `resolve_once` is mutually recursive through this.
fn resolve_ns_addr<'a>(
    ns: &'a Name,
    budget: &'a mut u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<IpAddr>>> + Send + 'a>> {
    Box::pin(async move {
        match resolve_once(ns, consts::rtype::A, budget).await {
            StepOutcome::Answer(recs) => {
                let ips: Vec<IpAddr> = recs.iter().filter_map(record_ip).collect();
                (!ips.is_empty()).then_some(ips)
            }
            _ => None,
        }
    })
}

fn record_ip(r: &Record) -> Option<IpAddr> {
    match &r.rdata {
        Rdata::A(a) => Some(IpAddr::V4(*a)),
        Rdata::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// Resolve `(qname, qtype)` iteratively (DO set) and return the final
/// authoritative message — answer or negative — for DNSSEC validation. Stops at
/// the first terminal response (it does not chase CNAMEs: the validator queries
/// explicit types). Uses the shared [`descend`] engine, so QNAME minimisation
/// (#231) applies here too; the terminal message always carries the real
/// `(qname, qtype)` question, unchanged for the validator.
pub async fn resolve_message(qname: &Name, qtype: u16) -> Option<wire::Message> {
    let mut budget = MAX_QUERIES;
    descend(qname, qtype, &mut budget).await
}

/// A [`Fetcher`](crate::dns::dnssec_chain::Fetcher) backed by this resolver's own
/// iterative DO descent — the production source of records for validation.
pub struct ResolverFetcher;

impl crate::dns::dnssec_chain::Fetcher for ResolverFetcher {
    async fn fetch(&self, name: &Name, qtype: u16) -> Option<wire::Message> {
        resolve_message(name, qtype).await
    }
}

/// A resolved-and-validated answer for the serving path.
pub struct Validated {
    /// Answer records (CNAME chain followed), without RRSIG/OPT.
    pub records: Vec<Record>,
    /// RRSIGs covering the served answer RRset(s) and every CNAME in the chain,
    /// in ANSWER-section order. Served only to DO=1 clients (RFC 4035 §3.2.1);
    /// empty for Insecure/unsigned answers. Kept separate from `records` so the
    /// RRSIG-free wire answer stays cacheable and servable to DO=0 clients (the
    /// fast path), while DO=1 clients get the signatures reattached.
    pub answer_rrsigs: Vec<Record>,
    /// VALIDATED authority for a negative answer (RFC 2308 §3): the RRSIG-checked,
    /// in-bailiwick SOA plus the DNSSEC denial proof (NSEC/NSEC3 + RRSIGs). Empty for
    /// a positive answer. A forged/unsigned SOA is never carried here.
    pub authority: Vec<Record>,
    /// Response code (NOERROR / NXDOMAIN).
    pub rcode: u16,
    /// DNSSEC verdict — the caller serves SERVFAIL on `Bogus`.
    pub verdict: crate::dns::dnssec_chain::Verdict,
}

/// Push, into `out`, the RRSIG records from `answers` whose owner is `owner` and
/// whose type-covered field is `covered`. RFC 4034 §3.1: the covered type is the
/// first two RDATA octets; RRSIG rdata is carried opaquely as `Rdata::Unknown`
/// (RFC 3597). These are exactly the signatures a DO=1 client needs to validate
/// the RRset we serve for `owner`.
fn collect_covering_rrsigs(answers: &[Record], owner: &Name, covered: u16, out: &mut Vec<Record>) {
    for r in answers {
        if r.rtype != consts::rtype::RRSIG || !r.name.eq_ignore_ascii_case(owner) {
            continue;
        }
        if let Rdata::Unknown { data, .. } = &r.rdata {
            if data.len() >= 2 && u16::from_be_bytes([data[0], data[1]]) == covered {
                out.push(r.clone());
            }
        }
    }
}

/// Resolve `(qname, qtype)` from the root and DNSSEC-validate the reply. The
/// serving records follow CNAMEs (via [`resolve`]); the verdict comes from the
/// authoritative reply for `qname`. `None` only on a hard resolution failure.
pub async fn resolve_validated(qname: &Name, qtype: u16, now: u32) -> Option<Validated> {
    use crate::dns::dnssec_chain::Verdict;
    let mut target = qname.clone();
    let mut cname_left = MAX_CNAME;
    let mut records: Vec<Record> = Vec::new();
    // RRSIGs covering the served RRsets, collected in ANSWER order alongside
    // `records`, to reattach for DO=1 clients (RFC 4035 §3.2.1).
    let mut rrsigs: Vec<Record> = Vec::new();
    let mut verdict = Verdict::Secure; // worst-of across every served hop

    loop {
        // The verdict AND the served records both come from THIS authoritative
        // message — never a divergent second descent. Following a CNAME re-queries
        // its target so that hop's RRset is validated under ITS own zone keys, so
        // every record we serve is covered by the verdict we report.
        let msg = resolve_message(&target, qtype).await?;
        let rcode = msg.header.rcode_low();
        // validate_full also returns the VALIDATED authority to serve with a negative
        // answer (SOA RRSIG-checked + in-bailiwick + denial proof) — never the raw
        // upstream authority, so a forged SOA can't ride out under AD=1.
        let (hop_verdict, hop_authority) =
            crate::dns::dnssec_chain::validate_full(&ResolverFetcher, &target, qtype, &msg, now)
                .await;
        verdict = worst_verdict(verdict, hop_verdict);

        // CNAME owned by this hop → serve it and follow; otherwise terminal.
        let cname = msg.answers.iter().find_map(|r| {
            if r.rtype == consts::rtype::CNAME && r.name.eq_ignore_ascii_case(&target) {
                if let Rdata::Cname(next) = &r.rdata {
                    return Some((r.clone(), next.clone()));
                }
            }
            None
        });

        if let Some((cn_rec, next)) = cname {
            records.push(cn_rec);
            // Signature(s) over this CNAME (owner = current target) — DO=1 clients.
            collect_covering_rrsigs(&msg.answers, &target, consts::rtype::CNAME, &mut rrsigs);
            if cname_left == 0 {
                // Refuse to serve a too-long / looping chain.
                return Some(Validated {
                    records,
                    answer_rrsigs: Vec::new(),
                    authority: Vec::new(),
                    rcode,
                    verdict: Verdict::Bogus,
                });
            }
            cname_left -= 1;
            target = next;
            continue;
        }

        // Terminal: serve exactly the qtype RRset at `target` — the records
        // `validate(&target, qtype, …)` just covered (RRSIG/OPT excluded).
        records.extend(
            msg.answers
                .iter()
                .filter(|r| r.rtype == qtype && r.name.eq_ignore_ascii_case(&target))
                .cloned(),
        );
        // Signature(s) over the terminal RRset — reattached for DO=1 clients (RFC 4035 §3.2.1).
        collect_covering_rrsigs(&msg.answers, &target, qtype, &mut rrsigs);
        // Serve only the VALIDATED authority from this terminal hop (RFC 2308 §3 SOA,
        // RRSIG-checked & in-bailiwick) — empty for a positive answer.
        // #232 / RFC 9824: a compact denial of existence (e.g. Cloudflare "black lies")
        // arrives as NOERROR + a validated NSEC that matches the name and carries the
        // NXNAME pseudo-type. Present it to the client as the NXDOMAIN it really is —
        // fail-closed: only when the denial validated Secure and the answer is empty.
        let rcode = if verdict == Verdict::Secure
            && rcode == consts::rcode::NOERROR
            && records.is_empty()
            && is_compact_nxdomain(&hop_authority, &target)
        {
            consts::rcode::NXDOMAIN
        } else {
            rcode
        };
        return Some(Validated { records, answer_rrsigs: rrsigs, authority: hop_authority, rcode, verdict });
    }
}

/// RFC 9824 compact denial of existence (#232): is this validated denial authority
/// really an NXDOMAIN? True when a validated NSEC in `authority` MATCHES `qname`
/// (owner == qname) and its type bitmap carries the NXNAME pseudo-type (128). Callers
/// invoke this only on a Secure verdict, so `authority` is the RRSIG-validated proof;
/// this is pure inspection of that proof.
fn is_compact_nxdomain(authority: &[Record], qname: &Name) -> bool {
    authority.iter().any(|r| {
        r.rtype == consts::rtype::NSEC
            && r.name.eq_ignore_ascii_case(qname)
            && matches!(&r.rdata, Rdata::Unknown { data, .. }
                if crate::dns::dnssec_denial::nsec_bitmap_has_nxname(data))
    })
}

/// Combine two hop verdicts into the verdict for the whole served chain: any
/// `Bogus` → `Bogus` (SERVFAIL); else any `Insecure` → `Insecure` (no AD); else
/// `Secure`. A chain is only as trustworthy as its weakest validated link.
fn worst_verdict(
    a: crate::dns::dnssec_chain::Verdict,
    b: crate::dns::dnssec_chain::Verdict,
) -> crate::dns::dnssec_chain::Verdict {
    use crate::dns::dnssec_chain::Verdict::*;
    match (a, b) {
        (Bogus, _) | (_, Bogus) => Bogus,
        (Insecure, _) | (_, Insecure) => Insecure,
        _ => Secure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ip_filter_rejects_private_and_special() {
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("198.41.0.4".parse().unwrap())); // a.root-servers
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("fe80::1".parse().unwrap()));
        assert!(!is_public_ip("fc00::1".parse().unwrap()));
        assert!(is_public_ip("2001:4860:4860::8888".parse().unwrap())); // public v6
        // DV-06: IPv4-mapped IPv6 must be re-evaluated against the embedded v4 —
        // on a dual-stack host the kernel routes ::ffff:a.b.c.d to that v4.
        assert!(!is_public_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("::ffff:169.254.0.1".parse().unwrap()));
        assert!(is_public_ip("::ffff:8.8.8.8".parse().unwrap())); // mapped public v4
        assert!(!is_public_ip("64:ff9b::8.8.8.8".parse().unwrap())); // NAT64 → v4
        assert!(!is_public_ip("2001:db8::1".parse().unwrap())); // documentation
        assert!(!is_public_ip("::1.2.3.4".parse().unwrap())); // IPv4-compatible (::/96)
    }

    // #231: QNAME-minimisation label arithmetic (pure, no network).
    #[test]
    fn minimised_probes_one_label_below_the_cut() {
        let q = Name::from_ascii("www.a.b.example.com.").unwrap();
        let n = |s: &str| Name::from_ascii(s).unwrap();
        let eq = |got: Name, want: &str| assert!(
            got.eq_ignore_ascii_case(&n(want)),
            "got {} want {want}",
            got.to_ascii()
        );
        // From the root: the first probe is the TLD only — the root never sees more.
        eq(minimised(&q, &Name::root(), 0), "com.");
        let com = n("com.");
        // One label past the `com` cut.
        eq(minimised(&q, &com, 0), "example.com.");
        // Lengthening under the same cut (empty non-terminals).
        eq(minimised(&q, &com, 1), "b.example.com.");
        eq(minimised(&q, &com, 2), "a.b.example.com.");
        // Reaching the target hands back qname itself (caller then asks the real Q).
        eq(minimised(&q, &com, 3), "www.a.b.example.com.");
        // Past the cap → full qname (anti-amplification on flat deep names).
        eq(minimised(&q, &com, MAX_MINIMISE), "www.a.b.example.com.");
    }

    #[test]
    fn minimised_is_noop_when_the_cut_is_the_direct_parent() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        // A name one label under its cut is already the target: the "probe" equals
        // qname, so the caller sends the real question (this is also the DS-at-parent
        // shape, which must not be minimised).
        assert!(minimised(&n("example.com."), &n("com."), 0).eq_ignore_ascii_case(&n("example.com.")));
        // A single-label name from the root never minimises.
        assert!(minimised(&n("com."), &Name::root(), 0).eq_ignore_ascii_case(&n("com.")));
    }

    // Live test (needs outbound UDP/53 to the internet). Run with:
    //   cargo test -- --ignored recursor_wire
    #[tokio::test]
    #[ignore]
    async fn live_resolve_a() {
        for fqdn in ["example.com.", "www.iana.org.", "one.one.one.one."] {
            let name = Name::from_ascii(fqdn).unwrap();
            match resolve(&name, consts::rtype::A).await {
                Outcome::Answer(recs) => {
                    let ips: Vec<String> = recs
                        .iter()
                        .filter_map(|r| match &r.rdata {
                            Rdata::A(a) => Some(a.to_string()),
                            _ => None,
                        })
                        .collect();
                    eprintln!("LIVE {fqdn} -> {ips:?} ({} records)", recs.len());
                    assert!(
                        recs.iter().any(|r| r.rtype == consts::rtype::A),
                        "{fqdn}: no A record in answer"
                    );
                }
                other => panic!("{fqdn}: expected A answer, got {other:?}"),
            }
        }
        // Negative: a name that does not exist must come back NXDOMAIN.
        // The zone must NOT use compact denial of existence ("black lies", Cloudflare):
        // with DO=1 those servers answer NOERROR + an NSEC proving non-existence rather
        // than NXDOMAIN, which the non-validating `resolve()` reads as NODATA (only the
        // validating path interprets the NSEC). `iana.org` returns a classic NXDOMAIN,
        // and being multi-label it also exercises QNAME minimisation on the negative path.
        let bad = Name::from_ascii("nx-zzz-does-not-exist-9821.iana.org.").unwrap();
        match resolve(&bad, consts::rtype::A).await {
            Outcome::Negative { rcode } => {
                eprintln!("LIVE NXDOMAIN rcode={rcode}");
                assert_eq!(rcode, consts::rcode::NXDOMAIN);
            }
            other => panic!("expected NXDOMAIN, got {other:?}"),
        }
    }

    // End-to-end production path: records fetched by OUR OWN iterative DO resolver
    // (ResolverFetcher / resolve_message), then DNSSEC-validated. Proves the real
    // chain works without any third-party resolver.
    //   cargo test -- --ignored live_validate_via_own_resolver
    #[tokio::test]
    #[ignore]
    async fn live_validate_via_own_resolver() {
        use crate::dns::dnssec_chain::{validate, Verdict};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let f = ResolverFetcher;

        let cases: [(&str, Verdict); 3] = [
            ("cloudflare.com.", Verdict::Secure),
            ("dnssec-failed.org.", Verdict::Bogus),
            ("google.com.", Verdict::Insecure),
        ];
        for (fqdn, want) in cases {
            let name = Name::from_ascii(fqdn).unwrap();
            let msg = resolve_message(&name, consts::rtype::A)
                .await
                .unwrap_or_else(|| panic!("{fqdn}: own resolver returned no message"));
            let got = validate(&f, &name, consts::rtype::A, &msg, now).await;
            eprintln!("OWN-RESOLVER {fqdn} -> {got:?}");
            assert_eq!(got, want, "{fqdn}: wrong verdict");
        }
        // Additional signed zones — RSA-1024 (Verisign/IANA/ISC) and ECDSA.
        for fqdn in ["iana.org.", "verisign.com.", "isc.org.", "nic.cz."] {
            let name = Name::from_ascii(fqdn).unwrap();
            if let Some(msg) = resolve_message(&name, consts::rtype::A).await {
                let got = validate(&f, &name, consts::rtype::A, &msg, now).await;
                eprintln!("OWN-RESOLVER {fqdn} -> {got:?}");
                assert_eq!(got, Verdict::Secure, "{fqdn}: expected Secure");
            }
        }
    }

    // #232 / RFC 9824: a compact denial of existence (Cloudflare "black lies") must be
    // presented to the client as NXDOMAIN, while a genuine NODATA stays NOERROR.
    // Needs outbound UDP+TCP/53. Run with:
    //   cargo test --release -- --ignored --nocapture live_compact_denial_nxdomain
    #[tokio::test]
    #[ignore]
    async fn live_compact_denial_nxdomain() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        // example.com is Cloudflare-hosted -> compact denial for a non-existent name.
        let bad = Name::from_ascii("nx-zzz-rb232-does-not-exist.example.com.").unwrap();
        let v = resolve_validated(&bad, consts::rtype::A, now)
            .await
            .expect("resolver returned nothing");
        eprintln!("compact-denial: rcode={} verdict={:?}", v.rcode, v.verdict);
        assert_eq!(v.rcode, consts::rcode::NXDOMAIN, "compact denial must become NXDOMAIN");
        // A genuine NODATA (name exists, type absent) must stay NOERROR: example.com
        // exists but has no HINFO (13) RRset, and that NSEC carries no NXNAME.
        let nd = Name::from_ascii("example.com.").unwrap();
        let v2 = resolve_validated(&nd, consts::rtype::HINFO, now)
            .await
            .expect("resolver returned nothing");
        eprintln!("genuine-nodata: rcode={} records={}", v2.rcode, v2.records.len());
        assert_eq!(v2.rcode, consts::rcode::NOERROR, "genuine NODATA must stay NOERROR");
        assert!(v2.records.is_empty(), "NODATA has no answer records");
    }

    // #230 regression: the infrastructure cache must make repeated misses under
    // the same parent materially faster. The FIRST miss walks from the root and
    // builds the whole DNSSEC chain; the next misses must reuse the cached zone
    // cut + validated DNSKEY chain and collapse to roughly one authoritative RTT.
    // Needs outbound UDP+TCP/53. Run alone for a clean cold/warm split:
    //   cargo test --release -- --ignored --nocapture cache_speeds_up_repeated_misses
    #[tokio::test]
    #[ignore]
    async fn cache_speeds_up_repeated_misses() {
        use std::time::{Instant, SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut ms = [0u128; 3];
        for (i, slot) in ms.iter_mut().enumerate() {
            // Distinct random NXDOMAIN under the same signed parent (clubic.com).
            let name = Name::from_ascii(&format!("zz-{i}-rb230probe.clubic.com.")).unwrap();
            let t = Instant::now();
            let _ = resolve_validated(&name, consts::rtype::A, now).await;
            *slot = t.elapsed().as_millis();
            eprintln!("miss {i} (validated) -> {} ms", *slot);
        }
        let warm = ms[1].min(ms[2]);
        assert!(
            warm * 2 <= ms[0].max(1),
            "warm misses ({warm} ms) must be at least 2x faster than the cold one ({} ms) — \
             the infrastructure cache is not being reused",
            ms[0]
        );
    }
}
