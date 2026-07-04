// SPDX-License-Identifier: AGPL-3.0-or-later
// Transport-agnostic DNS wire builder (#156, extended for kernel fast path).
//
// Originally written for the XDP fast path; now shared between:
//   - src/dns/xdp/worker.rs  (AF_XDP zero-copy path)
//   - src/dns/kernel_loop.rs (kernel UDP fast path, no AF_XDP dependency)
//
// Replaces hickory Message::from_bytes + BinEncoder::emit for the most common
// query types (A, AAAA) answered by local zones.  Zero allocations on the hot
// path; reads/writes directly into caller-supplied &[u8] / &mut [u8] buffers.
//
// EDNS (RFC 6891): if the query carries an OPT RR (arcount > 0), the response
// echoes a minimal OPT RR (DO=0, rdlen=0) for non-DNSSEC queries.  DO=1 →
// fall back to the wire serving core (signed local zones are signed there).

// Only the legacy hickory-typed build_answer_a_aaaa (below) needs this; the hot
// path uses build_answer_a_aaaa_wire. Absent from the default release build.
#[cfg(test)]
use hickory_proto::rr::RData;
use smallvec::SmallVec;

// LocalZoneSet/ZoneAction used in worker.rs (wire_qname_to_lower_name caller), not in this module.
use crate::dns::simd;
use crate::dns::local::WireRdata;

// ── Wire constants ────────────────────────────────────────────────────────────

/// Minimum DNS wire message size: 12-byte header + 1-byte qname + 4 bytes qtype/class.
const DNS_HDR: usize = 12;

/// QR=1 AA=1 Opcode=0 TC=0 RD=1 RA=1 Z=0 RCODE=0  (authoritative answer)
const FLAGS_AA_NOERROR: u16 = 0x8580;

/// RR name-compression pointer to offset 12 (start of question section).
#[allow(dead_code)]
const COMPRESSION_PTR: [u8; 2] = [0xC0, 0x0C];

/// DNS qtype A
#[allow(dead_code)]
const QTYPE_A: u16 = 1;
/// DNS qtype AAAA
#[allow(dead_code)]
const QTYPE_AAAA: u16 = 28;
/// DNS qtype OPT (EDNS)
const QTYPE_OPT: u16 = 41;
/// Class IN
#[allow(dead_code)]
const CLASS_IN: u16 = 1;

// ── Parsed query (stack-only) ─────────────────────────────────────────────────

/// EDNS0 OPT RR info extracted from the query's additional section.
///
/// Only populated when arcount>0 and an OPT RR (type=41) is found.
/// `do_bit=true` means the client requests DNSSEC → caller must fall back to the wire serving core.
#[derive(Clone, Copy, Debug)]
pub struct EdnsInfo {
    /// UDP payload size (class field of OPT RR) — echo in response.
    pub udp_payload: u16,
    /// DNSSEC OK bit (bit 15 of OPT TTL extended field).
    /// If true → caller MUST fall back to the wire serving core (DNSSEC not handled in this builder).
    pub do_bit: bool,
}

/// Minimal parsed DNS query — no heap allocation.
pub struct WireQuery<'a> {
    /// Transaction ID (2 bytes, big-endian from wire).
    pub id: u16,
    /// Raw wire QNAME (length-prefixed labels, ends with \0).
    /// Slice into the original query buffer — zero copy.
    pub qname_wire: &'a [u8],
    /// Parsed qtype value (e.g. A=1, AAAA=28) from the query wire.
    pub qtype: u16,
    /// Query class (should be IN=1 for normal queries).
    pub qclass: u16,
    /// EDNS0 info if the query carries an OPT RR (arcount > 0).
    /// None = no EDNS (dnsmark, legacy clients).
    /// Some(e) with do_bit=true → DNSSEC requested → fall back to the wire serving core.
    pub edns: Option<EdnsInfo>,
}

// ── Parse ─────────────────────────────────────────────────────────────────────

/// Parse the DNS wire query into a `WireQuery`.
///
/// Returns `None` if the packet is malformed or unsupported
/// (qdcount != 1, packet too short, QNAME not terminated, etc.).
///
/// # Hot-path constraints
/// - No allocation (SmallVec is stack-local, not returned).
/// - `simd::find_zero` dispatches to SSE2 at runtime (Xeon E5 v2 baseline).
#[inline]
pub fn parse_query(buf: &[u8]) -> Option<WireQuery<'_>> {
    // Need at least a 12-byte DNS header.
    if buf.len() < DNS_HDR + 5 {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);

    // QR bit must be 0 (this is a query, not a response).
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);

    // We only handle standard single-question queries.
    if qdcount != 1 {
        return None;
    }

    // QNAME starts at byte 12. Find the terminating \0 via SIMD.
    let qname_start = DNS_HDR;
    let qname_zero = simd::find_zero(&buf[qname_start..])?;
    // qname_wire includes the terminating \0.
    let qname_end = qname_start + qname_zero + 1;

    // After QNAME: qtype (2) + qclass (2) — need 4 more bytes.
    if buf.len() < qname_end + 4 {
        return None;
    }

    let qtype  = u16::from_be_bytes([buf[qname_end],     buf[qname_end + 1]]);
    let qclass = u16::from_be_bytes([buf[qname_end + 2], buf[qname_end + 3]]);

    // Parse EDNS OPT RR if present (arcount > 0).
    // Extracts udp_payload + do_bit for OPT echo in the response.
    let edns = parse_opt_rr(buf, qname_end + 4, arcount);

    Some(WireQuery {
        id,
        qname_wire: &buf[qname_start..qname_end],
        qtype,
        qclass,
        edns,
    })
}

/// Parse the additional section for an OPT RR (type=41, RFC 6891).
///
/// Fast path: arcount=0 → returns None immediately (no scan).
/// Returns Some(EdnsInfo) if an OPT RR is found and parseable.
/// Returns None if no OPT is found or the buffer is truncated.
///
/// # Security
/// All buffer accesses are bounds-checked. A truncated or malformed
/// additional section yields None without panicking (#156 security review).
#[inline]
pub(crate) fn parse_opt_rr(buf: &[u8], mut pos: usize, arcount: u16) -> Option<EdnsInfo> {
    if arcount == 0 {
        return None;
    }
    // Scan arcount additional RRs for OPT (ancount=nscount=0 in a query).
    for _ in 0..arcount {
        if pos >= buf.len() {
            break;
        }
        // Name field: root label (\0, 1B) or compression ptr (0xC0xx, 2B).
        // OPT MUST use root label per RFC 6891 §6.1.2.
        let name_len = if buf[pos] == 0x00 {
            1usize
        } else if buf[pos] & 0xC0 == 0xC0 {
            2usize
        } else {
            // Full-label name — OPT never has this; bail conservatively.
            return None;
        };
        pos += name_len;
        // Need at least type(2)+class(2) to identify the RR.
        if pos + 4 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        if rtype == QTYPE_OPT {
            // OPT RR found. Need pos+10 to read class(2)+ttl(4)+rdlen(2).
            // Guard: pos+10 <= buf.len() (same bound as the security fix).
            if pos + 10 > buf.len() {
                // Truncated OPT — treat as no EDNS (conservative).
                return None;
            }
            // class field = requestor's UDP payload size.
            let udp_payload = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            // TTL field (4B): bits [31:16]=ext-rcode+version, bit 15=DO.
            // buf[pos+4] = high byte of TTL = ext-rcode (8b); buf[pos+5] = version (8b).
            // buf[pos+6] = high byte of flags: bit 7 = DO.
            let do_bit = buf[pos + 6] & 0x80 != 0;
            return Some(EdnsInfo { udp_payload, do_bit });
        }
        // Not OPT — skip this RR. Need pos+10 to read rdlen at pos+8/pos+9.
        if pos + 10 > buf.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
    None
}

// ── LowerName from wire QNAME ─────────────────────────────────────────────────

// (removed) wire_qname_to_lower_name — built a hickory LowerName for the old
// LocalZoneSet key. Its own follow-up #156 (wire-QNAME / CRC32 keys) is now
// done: the serving path looks records up by lowercased wire QNAME via
// find_wire / local_records_wire (src/dns/local.rs), so this last fast-path
// hickory allocation is gone.

/// Normalise a raw wire-format QNAME from a DNS query into a lowercase
/// `SmallVec<[u8;64]>` suitable for hashing with `hash_wire_qname`.
///
/// # Shared normalisation contract (#156 item 3, Livraison C)
/// This is the SINGLE normalisation routine used by:
///   - `answer_dns_wire()` hot path (worker.rs)
///   - The `wire_qname_roundtrip` test in `hasher.rs`
/// Both call this function, never an inline copy, so the round-trip test
/// covers the real production path (the no-op-killer guard).
///
/// Safety: `copy_lowercase_label` only touches 0x41-0x5A bytes ('A'-'Z').
/// Wire length bytes are 0x00-0x3F, never in that range -> safe to process
/// the entire buffer (including length prefixes) in a single pass.
#[inline]
pub fn normalize_query_qname(wire: &[u8]) -> SmallVec<[u8; 64]> {
    let mut buf: SmallVec<[u8; 64]> = SmallVec::new();
    simd::copy_lowercase_label(&mut buf, wire);
    buf
}

// ── Write helpers ─────────────────────────────────────────────────────────────

/// Write a big-endian u16 into `buf[pos..pos+2]`. Returns pos+2.
#[inline(always)]
fn put_u16(buf: &mut [u8], pos: usize, val: u16) -> usize {
    buf[pos..pos + 2].copy_from_slice(&val.to_be_bytes());
    pos + 2
}

/// Write a big-endian u32 into `buf[pos..pos+4]`. Returns pos+4.
#[inline(always)]
fn put_u32(buf: &mut [u8], pos: usize, val: u32) -> usize {
    buf[pos..pos + 4].copy_from_slice(&val.to_be_bytes());
    pos + 4
}

/// Write a minimal OPT RR (RFC 6891) into `buf[pos..]`. Returns pos+11.
///
/// Wire layout (11 bytes, rdlen=0):
/// ```text
/// \0            (1B  root label — OPT owner name, RFC 6891 §6.1.2)
/// 0x00 0x29     (2B  type = OPT = 41)
/// payload(2B)   (2B  class = requestor UDP payload size, echoed)
/// 0x00 0x00     (2B  ext-rcode=0, EDNS version=0)
/// 0x00 0x00     (2B  Z flags: DO=0 — this builder never sets DNSSEC-OK; signing is on the serving path)
/// 0x00 0x00     (2B  rdlen=0 — no RDATA options)
/// ```
/// Total: 1+2+2+4+2 = 11 bytes.
///
/// # Precondition
/// Caller must ensure `buf[pos..]` has at least 11 bytes (pre-checked via total size).
#[inline(always)]
fn write_opt_rr(buf: &mut [u8], pos: usize, udp_payload: u16) -> usize {
    buf[pos] = 0x00;                              // root label (\0)
    let pos = put_u16(buf, pos + 1, 41);          // type = OPT
    let pos = put_u16(buf, pos, udp_payload);     // class = UDP payload size (echoed)
    let pos = put_u32(buf, pos, 0x0000_0000);     // TTL: ext-rcode=0, version=0, DO=0, Z=0
    put_u16(buf, pos, 0)                          // rdlen = 0
}

// ── Build A / AAAA response ───────────────────────────────────────────────────

/// Build an authoritative A or AAAA response directly into `out`.
///
/// Covers: `ZoneAction::Static` and `ZoneAction::Redirect` with A/AAAA records.
/// Returns `Some(len)` on success, `None` if the case is unsupported or `out`
/// is too small (caller falls back to the wire serving core).
///
/// # Wire layout
/// ```text
/// [Header 12B][Question: qname + qtype + qclass][Answer RRs: 0xC00C + type + class + TTL + rdlen + rdata]*
/// ```
///
/// # EDNS
/// Does NOT echo OPT RR. Caller must check `wq.has_edns` and fall back to
/// the wire serving core if EDNS echo is required (until EDNS echo is
/// implemented in a subsequent delivery).
/// Build a DNS A/AAAA answer directly from pre-fetched records.
///
/// # #156 perf — single lookup
/// The caller (`answer_dns_wire` in worker.rs) has already done the zone lookup
/// and `local_records()` call.  Receiving `records: &[&Record]` directly avoids
/// the double HashMap lookup that the old `zones: &LocalZoneSet` signature caused
/// on every hot-path packet.
///
/// Caller responsibilities:
///   - records is non-empty (caller checks and dispatches to build_nodata/build_nxdomain)
///   - wq.qtype is A (1) or AAAA (28) (caller pre-checks before calling)
///   - wq.qclass is IN (caller pre-checks)
#[cfg(test)]
#[allow(dead_code)]
pub fn build_answer_a_aaaa(
    wq: &WireQuery<'_>,
    out: &mut [u8],
    records: &[&hickory_proto::rr::Record],
    edns: Option<&EdnsInfo>,
) -> Option<usize> {
    // Caller is responsible for non-empty records and correct qtype/qclass.
    debug_assert!(!records.is_empty(), "build_answer_a_aaaa: empty records");
    debug_assert!(
        wq.qtype == QTYPE_A || wq.qtype == QTYPE_AAAA,
        "build_answer_a_aaaa: unexpected qtype {}",
        wq.qtype
    );

    let ancount  = records.len();
    let qname_len = wq.qname_wire.len(); // includes terminating \0
    let opt_size  = if edns.is_some() { 11 } else { 0 }; // OPT RR

    // Compute required output size.
    // Header(12) + Question(qname + 4) + ancount * (ptr+type+class+ttl+rdlen+rdata) + OPT?
    let rdata_len: usize = if wq.qtype == QTYPE_A { 4 } else { 16 };
    let rr_size = 2 + 2 + 2 + 4 + 2 + rdata_len; // ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata
    let total = DNS_HDR + qname_len + 4 + ancount * rr_size + opt_size;
    if out.len() < total {
        return None; // buffer too small — should not happen (FRAME_SIZE >> DNS max)
    }

    let arcount: u16 = if edns.is_some() { 1 } else { 0 };

    // ── Header (12 bytes) ──────────────────────────────────────────────────
    let mut pos = 0;
    pos = put_u16(out, pos, wq.id);                    // ID
    pos = put_u16(out, pos, FLAGS_AA_NOERROR);         // Flags: QR AA RD RA NOERROR
    pos = put_u16(out, pos, 1);                        // QDCOUNT = 1
    pos = put_u16(out, pos, ancount as u16);           // ANCOUNT
    pos = put_u16(out, pos, 0);                        // NSCOUNT = 0
    pos = put_u16(out, pos, arcount);                  // ARCOUNT (1 if OPT echo)

    // ── Question section (echo wire) ───────────────────────────────────────
    out[pos..pos + qname_len].copy_from_slice(wq.qname_wire);
    pos += qname_len;
    pos = put_u16(out, pos, wq.qtype);                 // QTYPE
    pos = put_u16(out, pos, wq.qclass);                // QCLASS

    // ── Answer RRs ────────────────────────────────────────────────────────
    for r in records.iter() {
        let ttl = (*r).ttl;

        let ip_bytes: SmallVec<[u8; 16]> = match (*r).data {
            RData::A(a)    => SmallVec::from_slice(&a.octets()),
            RData::AAAA(a) => SmallVec::from_slice(&a.octets()),
            _              => return None, // unexpected rdata type — fallback
        };

        // Sanity: rdata length must match expected (no truncation).
        if ip_bytes.len() != rdata_len {
            return None;
        }

        // Name: compression pointer → question QNAME at offset 12.
        out[pos..pos + 2].copy_from_slice(&COMPRESSION_PTR);
        pos += 2;
        pos = put_u16(out, pos, wq.qtype);             // TYPE (A=1 or AAAA=28)
        pos = put_u16(out, pos, CLASS_IN);             // CLASS IN
        pos = put_u32(out, pos, ttl);                  // TTL
        pos = put_u16(out, pos, rdata_len as u16);     // RDLENGTH
        out[pos..pos + rdata_len].copy_from_slice(&ip_bytes);
        pos += rdata_len;
    }

    // ── Additional: OPT RR echo (RFC 6891 §7) ─────────────────────────────
    if let Some(e) = edns {
        pos = write_opt_rr(out, pos, e.udp_payload);
    }

    Some(pos)
}


// ── Build negative / error responses ─────────────────────────────────────────

/// Internal: write DNS header + echo question section into `out`.
/// Returns the position after the question section, or None if out is too small.
///
/// Shared by build_nxdomain / build_nodata / build_refused.
#[inline(always)]
fn write_header_and_question(
    out:      &mut [u8],
    id:       u16,
    flags:    u16,
    ancount:  u16,
    qname:    &[u8],
    qtype:    u16,
    qclass:   u16,
    edns:     Option<&EdnsInfo>,
) -> Option<usize> {
    let qname_len  = qname.len();
    let opt_size   = if edns.is_some() { 11 } else { 0 }; // OPT RR = 11 bytes
    let total      = DNS_HDR + qname_len + 4 + opt_size;
    if out.len() < total {
        return None;
    }
    let arcount: u16 = if edns.is_some() { 1 } else { 0 };
    let mut pos = 0;
    pos = put_u16(out, pos, id);        // ID
    pos = put_u16(out, pos, flags);     // Flags
    pos = put_u16(out, pos, 1);         // QDCOUNT = 1
    pos = put_u16(out, pos, ancount);   // ANCOUNT
    pos = put_u16(out, pos, 0);         // NSCOUNT = 0
    pos = put_u16(out, pos, arcount);   // ARCOUNT (1 if OPT echo, 0 otherwise)
    out[pos..pos + qname_len].copy_from_slice(qname);
    pos += qname_len;
    pos = put_u16(out, pos, qtype);     // QTYPE  (echo)
    pos = put_u16(out, pos, qclass);    // QCLASS (echo)
    // Additional section: minimal OPT RR echo (RFC 6891 §7)
    if let Some(e) = edns {
        pos = write_opt_rr(out, pos, e.udp_payload);
    }
    Some(pos)
}

/// QR=1 AA=1 RD=1 RA=1 RCODE=3 (NXDOMAIN)
#[allow(dead_code)]
const FLAGS_AA_NXDOMAIN: u16 = 0x8583;

/// QR=1 AA=0 RD=1 RA=1 RCODE=5 (REFUSED)
const FLAGS_REFUSED: u16 = 0x8585;

/// Build an NXDOMAIN response directly into `out`.
///
/// Wire: Header(12, RCODE=3, ancount=0) + echo Question.
/// No SOA in authority (RFC-minimal; no negative-answer cache exists on the fast
/// path, or anywhere else in the codebase — see #210). dig reports `status:
/// NXDOMAIN` correctly regardless.
///
/// Returns `Some(len)` on success, `None` if `out` is too small.
/// Build an A/AAAA answer from pre-serialised `WireRdata` entries (from `WireRecordIndex`).
///
/// Unlike `build_answer_a_aaaa()` which takes `&[&Record]` and calls hickory RData,
/// this function works entirely from pre-serialised bytes (`WireRdata.rdata`) --
/// zero hickory in the hot path. (#156 item 3, Livraison C)
///
/// `recs` must be non-empty (caller's responsibility, filtered by qtype in `answer_dns_wire`).
/// Returns `None` if `out` is too small (caller falls back to the wire serving core).
pub fn build_answer_a_aaaa_wire(
    wq: &WireQuery<'_>,
    out: &mut [u8],
    recs: &[WireRdata],
    edns: Option<&EdnsInfo>,
) -> Option<usize> {
    debug_assert!(!recs.is_empty(), "build_answer_a_aaaa_wire: empty records");

    let qname_len    = wq.qname_wire.len();
    let question_len = qname_len + 4;          // qname + qtype(2) + qclass(2)
    let rr_fixed     = 2 + 2 + 2 + 4 + 2;     // ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)
    let ancount      = recs.len();
    let rdata_total: usize = recs.iter().map(|r| r.rdata.len()).sum();
    let opt_size     = if edns.is_some() { 11 } else { 0 }; // OPT RR
    let total = DNS_HDR + question_len + rr_fixed * ancount + rdata_total + opt_size;

    if out.len() < total {
        return None;
    }

    // Header (12 bytes)
    let flags_aa: u16 = 0x8580; // QR=1 AA=1 RD=1 RA=1 RCODE=0
    let arcount: u16  = if edns.is_some() { 1 } else { 0 };
    let mut p = 0;
    p = put_u16(out, p, wq.id);
    p = put_u16(out, p, flags_aa);
    p = put_u16(out, p, 1);               // qdcount
    p = put_u16(out, p, ancount as u16);  // ancount
    p = put_u16(out, p, 0);               // nscount
    p = put_u16(out, p, arcount);         // arcount

    // Question (echo)
    out[p..p + qname_len].copy_from_slice(wq.qname_wire);
    p += qname_len;
    p = put_u16(out, p, wq.qtype);
    p = put_u16(out, p, wq.qclass);

    // Answer RRs (from pre-serialised WireRdata)
    for rec in recs {
        p = put_u16(out, p, 0xC00C);                      // compression ptr -> offset 12
        p = put_u16(out, p, wq.qtype);                    // type A or AAAA
        p = put_u16(out, p, 1);                           // class IN
        p = put_u32(out, p, rec.ttl);                     // TTL
        p = put_u16(out, p, rec.rdata.len() as u16);      // rdlength
        out[p..p + rec.rdata.len()].copy_from_slice(&rec.rdata);
        p += rec.rdata.len();
    }

    // OPT RR (EDNS echo, 11 bytes)
    if let Some(ei) = edns {
        p = write_opt_rr(out, p, ei.udp_payload);
    }

    Some(p)
}

#[allow(dead_code)]
pub fn build_nxdomain(wq: &WireQuery<'_>, out: &mut [u8], edns: Option<&EdnsInfo>) -> Option<usize> {
    write_header_and_question(out, wq.id, FLAGS_AA_NXDOMAIN, 0, wq.qname_wire, wq.qtype, wq.qclass, edns)
}

/// Build a NODATA response (NOERROR, ancount=0) directly into `out`.
///
/// Used when the zone exists but has no records of the requested type.
/// Wire: Header(12, RCODE=0, ancount=0) + echo Question.
/// AA=1 (we are authoritative for the zone).
///
/// Returns `Some(len)` on success, `None` if `out` is too small.
///
/// Reserved for a future wildcard-aware fast path (#156): the wire path
/// currently falls back to the wire serving core for empty-exact-match cases
/// (which may be wildcards), so this is not yet wired into `answer_dns_wire`. Kept + unit-tested.
#[allow(dead_code)]
pub fn build_nodata(wq: &WireQuery<'_>, out: &mut [u8], edns: Option<&EdnsInfo>) -> Option<usize> {
    // FLAGS_AA_NOERROR = 0x8580 (QR=1 AA=1 RD=1 RA=1 RCODE=0)
    write_header_and_question(out, wq.id, FLAGS_AA_NOERROR, 0, wq.qname_wire, wq.qtype, wq.qclass, edns)
}

/// Build a REFUSED response directly into `out`.
///
/// Used when ACL action is Refuse.
/// Wire: Header(12, RCODE=5, ancount=0) + echo Question.
/// AA=0 (not authoritative — we refused to process).
///
/// Returns `Some(len)` on success, `None` if `out` is too small.
pub fn build_refused(wq: &WireQuery<'_>, out: &mut [u8], edns: Option<&EdnsInfo>) -> Option<usize> {
    write_header_and_question(out, wq.id, FLAGS_REFUSED, 0, wq.qname_wire, wq.qtype, wq.qclass, edns)
}


// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_edns ──────────────────────────────────────────────────────────

    /// Happy path: arcount=0 → false immediately (no scan).
    #[test]
    fn parse_opt_rr_no_additional() {
        // Buffer content doesn't matter when arcount=0.
        assert!(parse_opt_rr(&[0u8; 40], 20, 0).is_none());
    }

    /// Security regression test (#156): truncated non-OPT RR (TSIG, type=250).
    ///
    /// Before the fix, `detect_edns` read `buf[pos+8]` and `buf[pos+9]` to parse rdlen
    /// after checking only `pos+8 > buf.len()` — allowing `pos+8 == buf.len()` to panic.
    /// Fix: guard is `pos+10 > buf.len()`.
    ///
    /// Layout:  \0(1B) + type=TSIG(2B) + class(2B) = 5 bytes at pos=0.
    /// Reading rdlen needs buf[pos+8..pos+9] = buf[8..9] — buf.len()=5 → OOB pre-fix.
    /// Post-fix: `pos+10=10 > 5` → break → returns false without panicking.
    #[test]
    fn parse_opt_rr_truncated_no_panic() {
        // Non-OPT RR truncated: name(\0) + type(TSIG=250) + class(IN) only — no TTL/rdlen.
        // The function sees rtype=250 ≠ OPT, then tries to read rdlen at pos+8/pos+9.
        // With the fix (pos+10 > len guard), it breaks cleanly and returns false.
        let truncated: &[u8] = &[
            0x00,       // root label (name = \0, name_len = 1) → pos becomes 1
            0x00, 0xFA, // type = TSIG (250) — NOT OPT, so we proceed to rdlen read
            0x00, 0x01, // class IN — pos is now at 1, pos+4=5 ≤ 5 ✓ (passes first guard)
            // ttl and rdlen intentionally absent (buf.len()=5, need pos+10=11 for rdlen)
        ];
        // Pre-fix: would panic at buf[pos+8] (index 9, len=5).
        // Post-fix: pos+10 (=11) > 5 → break → false.
        let result = parse_opt_rr(truncated, 0, 1);
        assert!(result.is_none(), "truncated non-OPT RR must yield None without panicking");
    }

    /// OPT RR present and well-formed → true.
    #[test]
    fn parse_opt_rr_opt_present() {
        // Minimal well-formed additional RR with type=OPT.
        // \0 (root) + type=41 (0x00,0x29) + class=1232 (0x04,0xD0) +
        // ttl=0 (4B) + rdlen=0 (2B) → total 11 bytes.
        let opt_rr: &[u8] = &[
            0x00,               // root label
            0x00, 0x29,         // type = OPT (41)
            0x04, 0xD0,         // class (EDNS UDP payload = 1232)
            0x00, 0x00, 0x00, 0x00, // ttl (extended RCODE + flags)
            0x00, 0x00,         // rdlen = 0 (no options)
        ];
        assert!(parse_opt_rr(opt_rr, 0, 1).is_some());
    }

    /// Non-OPT additional RR (e.g. TSIG type=250) → false.
    #[test]
    fn parse_opt_rr_non_opt_rr() {
        // \0 + type=250 (TSIG) + class + ttl + rdlen=0
        let tsig_rr: &[u8] = &[
            0x00,               // root label
            0x00, 0xFA,         // type = TSIG (250) — not OPT
            0x00, 0x01,         // class IN
            0x00, 0x00, 0x00, 0x00, // ttl
            0x00, 0x00,         // rdlen = 0
        ];
        assert!(parse_opt_rr(tsig_rr, 0, 1).is_none());
    }

    /// Two additional RRs: non-OPT first, OPT second → true.
    #[test]
    fn parse_opt_rr_opt_second_rr() {
        let mut buf = Vec::new();
        // RR 1: TSIG, rdlen=0
        buf.extend_from_slice(&[0x00, 0x00, 0xFA, 0x00, 0x01, 0x00,0x00,0x00,0x00, 0x00,0x00]);
        // RR 2: OPT, rdlen=0
        buf.extend_from_slice(&[0x00, 0x00, 0x29, 0x04, 0xD0, 0x00,0x00,0x00,0x00, 0x00,0x00]);
        assert!(parse_opt_rr(&buf, 0, 2).is_some());
    }

    // ── parse_query ──────────────────────────────────────────────────────────

    /// Too-short buffer → None (no panic).
    #[test]
    fn parse_query_too_short() {
        assert!(parse_query(&[0u8; 10]).is_none());
    }

    /// QR bit set (response, not query) → None.
    #[test]
    fn parse_query_rejects_response() {
        let mut buf = [0u8; 25];
        buf[2] = 0x80; // QR=1
        buf[4] = 0; buf[5] = 1; // qdcount=1
        buf[12] = 0x05; // qname label len=5 (won't find \0 properly but QR check is first)
        assert!(parse_query(&buf).is_none());
    }
    // ── build_nxdomain / build_nodata / build_refused ────────────────────────

    /// Helper: build a minimal wire query for tests.
    /// Returns (buf, WireQuery) for a standard A query of "a.test." (7 wire bytes).
    #[allow(dead_code, unused_mut)]
    fn make_wire_query_a() -> ([u8; 512], Vec<u8>) {
        // Wire QNAME for "a.test.": \x01 a \x04 test \x00
        let qname: Vec<u8> = vec![0x01, b'a', 0x04, b't', b'e', b's', b't', 0x00];
        let mut buf = vec![0u8; 512];
        // Construct a fake WireQuery manually using the struct fields
        // (we bypass parse_query to avoid building a full DNS packet)
        let _ = &buf; // silence unused
        (
            [0u8; 512],
            qname,
        )
    }

    /// NXDOMAIN: wire-correct header (flags=0x8583, ancount=0) + echo question.
    #[test]
    fn build_nxdomain_wire_correct() {
        let qname: &[u8] = &[0x01, b'a', 0x04, b't', b'e', b's', b't', 0x00]; // "a.test."
        let wq = WireQuery { id: 0xABCD, qname_wire: qname, qtype: 1, qclass: 1, edns: None };
        let mut out = [0u8; 512];
        let len = build_nxdomain(&wq, &mut out, None).expect("build_nxdomain failed");

        // Header: ID=0xABCD, flags=0x8583, qdcount=1, ancount=0, nscount=0, arcount=0
        assert_eq!(&out[0..2],   &[0xAB, 0xCD], "ID mismatch");
        assert_eq!(&out[2..4],   &[0x85, 0x83], "flags must be 0x8583 (AA NXDOMAIN)");
        assert_eq!(&out[4..6],   &[0x00, 0x01], "qdcount=1");
        assert_eq!(&out[6..8],   &[0x00, 0x00], "ancount=0");
        assert_eq!(&out[8..10],  &[0x00, 0x00], "nscount=0");
        assert_eq!(&out[10..12], &[0x00, 0x00], "arcount=0");

        // Question: echo qname + qtype + qclass
        assert_eq!(&out[12..12 + qname.len()], qname, "QNAME echo mismatch");
        let qtype_off = 12 + qname.len();
        assert_eq!(&out[qtype_off..qtype_off+2], &[0x00, 0x01], "QTYPE A=1");
        assert_eq!(&out[qtype_off+2..qtype_off+4], &[0x00, 0x01], "QCLASS IN=1");

        assert_eq!(len, 12 + qname.len() + 4);
    }

    /// NODATA: flags=0x8580 (NOERROR AA), ancount=0.
    #[test]
    fn build_nodata_wire_correct() {
        let qname: &[u8] = &[0x01, b'b', 0x04, b't', b'e', b's', b't', 0x00];
        let wq = WireQuery { id: 0x1234, qname_wire: qname, qtype: 28, qclass: 1, edns: None };
        let mut out = [0u8; 512];
        let len = build_nodata(&wq, &mut out, None).expect("build_nodata failed");

        assert_eq!(&out[0..2], &[0x12, 0x34], "ID");
        assert_eq!(&out[2..4], &[0x85, 0x80], "flags must be 0x8580 (AA NOERROR)");
        assert_eq!(&out[4..6], &[0x00, 0x01], "qdcount=1");
        assert_eq!(&out[6..8], &[0x00, 0x00], "ancount=0");
        assert_eq!(len, 12 + qname.len() + 4);
    }

    /// REFUSED: flags=0x8585 (REFUSED), ancount=0, AA=0.
    #[test]
    fn build_refused_wire_correct() {
        let qname: &[u8] = &[0x04, b't', b'e', b's', b't', 0x00];
        let wq = WireQuery { id: 0xFFFF, qname_wire: qname, qtype: 1, qclass: 1, edns: None };
        let mut out = [0u8; 512];
        let len = build_refused(&wq, &mut out, None).expect("build_refused failed");

        assert_eq!(&out[0..2], &[0xFF, 0xFF], "ID");
        assert_eq!(&out[2..4], &[0x85, 0x85], "flags must be 0x8585 (REFUSED)");
        assert_eq!(&out[6..8], &[0x00, 0x00], "ancount=0");
        assert_eq!(len, 12 + qname.len() + 4);
    }

    /// Buffer too small → None (no panic, no partial write).
    #[test]
    fn build_nxdomain_buf_too_small() {
        let qname: &[u8] = &[0x01, b'a', 0x04, b't', b'e', b's', b't', 0x00];
        let wq = WireQuery { id: 0x0001, qname_wire: qname, qtype: 1, qclass: 1, edns: None };
        let mut out = [0u8; 10]; // too small (need 12+8+4=24)
        assert!(build_nxdomain(&wq, &mut out, None).is_none());
    }

    /// All three share the same question echo — cross-check qtype=AAAA.
    #[test]
    fn build_negative_echo_qtype_aaaa() {
        let qname: &[u8] = &[0x03, b'f', b'o', b'o', 0x00];
        let wq = WireQuery { id: 0x0042, qname_wire: qname, qtype: 28, qclass: 1, edns: None };
        let mut out = [0u8; 512];
        let len = build_nxdomain(&wq, &mut out, None).unwrap();
        let qtype_off = 12 + qname.len();
        assert_eq!(&out[qtype_off..qtype_off+2], &[0x00, 0x1C], "QTYPE AAAA=28");
        assert_eq!(len, 12 + qname.len() + 4);
    }


    // ── EDNS / OPT echo ──────────────────────────────────────────────────────

    /// parse_opt_rr returns correct EdnsInfo for a well-formed OPT RR.
    #[test]
    fn parse_opt_rr_returns_edns_info() {
        // OPT RR: \0 + type=41 + class=1232 (0x04D0) + ttl(DO=0)=0 + rdlen=0
        let opt: &[u8] = &[
            0x00,               // root label
            0x00, 0x29,         // type OPT = 41
            0x04, 0xD0,         // class = 1232 (dig default payload)
            0x00, 0x00, 0x00, 0x00, // TTL: ext-rcode=0, version=0, DO=0
            0x00, 0x00,         // rdlen = 0
        ];
        let info = parse_opt_rr(opt, 0, 1).expect("should detect OPT");
        assert_eq!(info.udp_payload, 1232);
        assert!(!info.do_bit, "DO=0 expected");
    }

    /// parse_opt_rr correctly detects DO=1 bit.
    #[test]
    fn parse_opt_rr_do_bit_set() {
        // TTL high bytes: ext-rcode=0, version=0, flags high=0x80 (DO=1)
        let opt: &[u8] = &[
            0x00,               // root label
            0x00, 0x29,         // type OPT
            0x04, 0xD0,         // class = 1232
            0x00, 0x00, 0x80, 0x00, // TTL: buf[pos+6] = 0x80 → DO=1
            0x00, 0x00,         // rdlen = 0
        ];
        let info = parse_opt_rr(opt, 0, 1).expect("should detect OPT");
        assert!(info.do_bit, "DO=1 expected");
    }

    /// build_nxdomain with EDNS echoes OPT RR: arcount=1, 11 extra bytes.
    #[test]
    fn build_nxdomain_with_edns_opt_echo() {
        let qname: &[u8] = &[5, b'h', b'e', b'l', b'l', b'o', 0]; // "hello."
        let wq = WireQuery { id: 0x1111, qname_wire: qname, qtype: 1, qclass: 1, edns: None };
        let edns = EdnsInfo { udp_payload: 1232, do_bit: false };

        let mut out_plain = [0u8; 256];
        let mut out_edns  = [0u8; 256];
        let len_plain = build_nxdomain(&wq, &mut out_plain, None).unwrap();
        let len_edns  = build_nxdomain(&wq, &mut out_edns, Some(&edns)).unwrap();

        // EDNS response must be 11 bytes longer (OPT RR)
        assert_eq!(len_edns, len_plain + 11, "OPT RR adds 11 bytes");

        // arcount must be 1 in EDNS response, 0 in plain
        assert_eq!(u16::from_be_bytes([out_plain[10], out_plain[11]]), 0, "plain arcount=0");
        assert_eq!(u16::from_be_bytes([out_edns[10],  out_edns[11]]),  1, "edns arcount=1");

        // OPT RR starts at len_plain: verify root label + type=41 + payload=1232
        let opt_start = len_plain;
        assert_eq!(out_edns[opt_start], 0x00, "OPT root label");
        assert_eq!(u16::from_be_bytes([out_edns[opt_start+1], out_edns[opt_start+2]]), 41, "OPT type=41");
        assert_eq!(u16::from_be_bytes([out_edns[opt_start+3], out_edns[opt_start+4]]), 1232, "OPT payload=1232");
        // DO bit must be 0 (we set DO=0 in all wire responses)
        assert_eq!(out_edns[opt_start+7] & 0x80, 0, "DO=0 in response");
        // rdlen must be 0
        assert_eq!(u16::from_be_bytes([out_edns[opt_start+9], out_edns[opt_start+10]]), 0, "rdlen=0");
    }

    /// build_nxdomain NXDOMAIN flags unchanged when EDNS present.
    #[test]
    fn build_nxdomain_flags_unchanged_with_edns() {
        let qname: &[u8] = &[3, b'a', b'b', b'c', 0];
        let wq   = WireQuery { id: 0xBEEF, qname_wire: qname, qtype: 1, qclass: 1, edns: None };
        let edns = EdnsInfo { udp_payload: 512, do_bit: false };
        let mut out = [0u8; 256];
        let _len = build_nxdomain(&wq, &mut out, Some(&edns)).unwrap();
        // Flags: 0x8583 = QR=1 AA=1 RCODE=3 (NXDOMAIN)
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 0x8583, "NXDOMAIN flags");
        // ancount must be 0 (negative response)
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 0, "ancount=0");
    }

}
