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

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Total upstream queries allowed for one user query (anti-DoS budget).
const MAX_QUERIES: u32 = 80;
/// Maximum delegation depth (root → TLD → … ) before giving up.
const MAX_DEPTH: u8 = 24;
/// Maximum CNAME indirections followed for one user query.
const MAX_CNAME: u8 = 12;

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
    let resp = timeout(QUERY_TIMEOUT, udp_exchange(addr, &q)).await.ok()??;
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

async fn udp_exchange(addr: SocketAddr, q: &[u8]) -> Option<Vec<u8>> {
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(addr).await.ok()?;
    sock.send(q).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).await.ok()?;
    buf.truncate(n);
    Some(buf)
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

/// One full descent from the root for a single (name, type), following
/// referrals until an answer / negative / failure. Does not follow CNAMEs
/// across the tree — that is the caller's loop.
async fn resolve_once(qname: &Name, qtype: u16, budget: &mut u32) -> StepOutcome {
    // #230: start at the deepest cached enclosing zone cut instead of always the
    // root. A stale/dead cached cut (its first query fails) is forgotten and we
    // restart from the root, so the cache can only speed resolution up, never
    // break it. Every answer is still DNSSEC-validated by the caller.
    let (mut zone, mut ns_ips, mut from_cache) = match cached_start(qname, qtype) {
        Some((z, ips)) => (z, ips, true),
        None => (Name::root(), root_hints(), false),
    };

    for _depth in 0..MAX_DEPTH {
        let Some(msg) = query_ns_set(&ns_ips, qname, qtype, budget).await else {
            if from_cache {
                infra_cache::zone_cut_forget(&zone);
                zone = Name::root();
                ns_ips = root_hints();
                from_cache = false;
                continue;
            }
            return StepOutcome::Failure;
        };
        from_cache = false;
        let rcode = msg.header.rcode_low();

        // CNAME for our exact name (even when the type differs) → hand back to caller.
        if let Some(cn) = msg.answers.iter().find(|r| {
            r.rtype == consts::rtype::CNAME && r.name.eq_ignore_ascii_case(qname)
        }) {
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

        // Referral? Collect NS records in AUTHORITY for a zone strictly below the
        // current one and at-or-above qname (otherwise it is a loop / lame).
        let referral_zone = msg
            .authority
            .iter()
            .filter(|r| r.rtype == consts::rtype::NS)
            .map(|r| &r.name)
            .find(|n| qname.is_in_zone(n) && n.is_in_zone(&zone) && !n.eq_ignore_ascii_case(&zone))
            .cloned();

        let Some(next_zone) = referral_zone else {
            // No answer, no usable referral: NODATA (SOA present) or lame.
            return StepOutcome::Negative { rcode: consts::rcode::NOERROR };
        };

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
                    return StepOutcome::Failure;
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
            return StepOutcome::Failure;
        }
        // #230: remember this cut so the next miss under it skips the root walk.
        infra_cache::zone_cut_learn(&next_zone, &next_ips, cut_ttl(&msg, &next_zone, &ns_names));
        ns_ips = next_ips;
        zone = next_zone;
    }
    StepOutcome::Failure
}

/// Try each nameserver IP (in turn) until one answers; bounded by `budget`.
async fn query_ns_set(
    ns_ips: &[IpAddr],
    qname: &Name,
    qtype: u16,
    budget: &mut u32,
) -> Option<wire::Message> {
    for ip in ns_ips {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let addr = SocketAddr::new(*ip, 53);
        if let Some(msg) = query_server(addr, qname, qtype).await {
            return Some(msg);
        }
    }
    None
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
/// authoritative message — answer or negative — for DNSSEC validation. Follows
/// referrals like `resolve_once` but stops at the first terminal response (it
/// does not chase CNAMEs: the validator queries explicit types).
pub async fn resolve_message(qname: &Name, qtype: u16) -> Option<wire::Message> {
    let mut budget = MAX_QUERIES;
    // #230: start from the deepest cached cut, with a root fallback if it is stale.
    let (mut zone, mut ns_ips, mut from_cache) = match cached_start(qname, qtype) {
        Some((z, ips)) => (z, ips, true),
        None => (Name::root(), root_hints(), false),
    };

    for _ in 0..MAX_DEPTH {
        let msg = match query_ns_set(&ns_ips, qname, qtype, &mut budget).await {
            Some(m) => m,
            None => {
                if from_cache {
                    infra_cache::zone_cut_forget(&zone);
                    zone = Name::root();
                    ns_ips = root_hints();
                    from_cache = false;
                    continue;
                }
                return None;
            }
        };
        from_cache = false;
        let rcode = msg.header.rcode_low();

        // Terminal: an answer for our name (qtype or CNAME), or NXDOMAIN.
        let has_answer = msg.answers.iter().any(|r| {
            (r.rtype == qtype || r.rtype == consts::rtype::CNAME) && r.name.eq_ignore_ascii_case(qname)
        });
        if has_answer || rcode == consts::rcode::NXDOMAIN {
            return Some(msg);
        }

        // Referral down the tree?
        let referral_zone = msg
            .authority
            .iter()
            .filter(|r| r.rtype == consts::rtype::NS)
            .map(|r| &r.name)
            .find(|nm| qname.is_in_zone(nm) && nm.is_in_zone(&zone) && !nm.eq_ignore_ascii_case(&zone))
            .cloned();
        let Some(next_zone) = referral_zone else {
            // No answer, no referral → NODATA (the message carries SOA/NSEC*).
            return Some(msg);
        };

        let ns_names: Vec<Name> = msg
            .authority
            .iter()
            .filter(|r| r.rtype == consts::rtype::NS && r.name.eq_ignore_ascii_case(&next_zone))
            .filter_map(|r| match &r.rdata {
                Rdata::Ns(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        let mut next_ips: Vec<IpAddr> = msg
            .additional
            .iter()
            .filter(|r| ns_names.iter().any(|ns| ns.eq_ignore_ascii_case(&r.name)))
            .filter_map(record_ip)
            .filter(|ip| is_public_ip(*ip))
            .collect();
        if next_ips.is_empty() {
            for ns in &ns_names {
                if budget == 0 {
                    return None;
                }
                if let Some(ips) = resolve_ns_addr(ns, &mut budget).await {
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
    }
    None
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
        return Some(Validated { records, answer_rrsigs: rrsigs, authority: hop_authority, rcode, verdict });
    }
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
        let bad = Name::from_ascii("nx-zzz-does-not-exist-9821.example.com.").unwrap();
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
