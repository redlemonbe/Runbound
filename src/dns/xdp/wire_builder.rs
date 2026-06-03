// SPDX-License-Identifier: AGPL-3.0-or-later
// Wire-format DNS builder for the XDP hot path (#156).
//
// Replaces hickory Message::from_bytes + BinEncoder::emit in the fast path
// for the most common query types (A, AAAA) answered by local zones.
// All allocations eliminated except one unavoidable LowerName::from_bytes
// needed for LocalZoneSet::find() / local_records() key lookups.
//
// EDNS (RFC 6891): if the query carries an OPT RR (arcount > 0, has_edns=true),
// the caller must either echo a minimal OPT RR in the response or fall back to
// hickory. This module exposes has_edns so the caller can decide.
//
// Correctness contract:
//   - Writes directly into `out: &mut [u8]` (TX UMEM slice) — zero extra copy.
//   - Returns Some(len) on success, None on parse error or unsupported case
//     (caller falls back to hickory answer_dns()).
//   - Only handles qtype A (1) and AAAA (28) records.
//   - NXDOMAIN, NODATA, REFUSED, EDNS echo: next deliveries.

use hickory_proto::rr::{RData, RecordType, LowerName, Name};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use smallvec::SmallVec;

use crate::dns::local::{LocalZoneSet, ZoneAction};
use crate::dns::simd;

// ── Wire constants ────────────────────────────────────────────────────────────

/// Minimum DNS wire message size: 12-byte header + 1-byte qname + 4 bytes qtype/class.
const DNS_HDR: usize = 12;

/// QR=1 AA=1 Opcode=0 TC=0 RD=1 RA=1 Z=0 RCODE=0  (authoritative answer)
const FLAGS_AA_NOERROR: u16 = 0x8580;

/// RR name-compression pointer to offset 12 (start of question section).
const COMPRESSION_PTR: [u8; 2] = [0xC0, 0x0C];

/// DNS qtype A
const QTYPE_A: u16 = 1;
/// DNS qtype AAAA
const QTYPE_AAAA: u16 = 28;
/// DNS qtype OPT (EDNS)
const QTYPE_OPT: u16 = 41;
/// Class IN
const CLASS_IN: u16 = 1;

// ── Parsed query (stack-only) ─────────────────────────────────────────────────

/// Minimal parsed DNS query — no heap allocation.
pub struct WireQuery<'a> {
    /// Transaction ID (2 bytes, big-endian from wire).
    pub id: u16,
    /// Raw wire QNAME (length-prefixed labels, ends with \0).
    /// Slice into the original query buffer — zero copy.
    pub qname_wire: &'a [u8],
    /// Byte offset of qtype in the original query buffer.
    pub qtype: u16,
    /// Query class (should be IN=1 for normal queries).
    pub qclass: u16,
    /// True if the query has an OPT RR (EDNS0, arcount > 0).
    pub has_edns: bool,
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

    // Detect EDNS: scan additional records for an OPT RR (type 41).
    // We don't parse OPT fully here — just set has_edns for the caller.
    let has_edns = detect_edns(buf, qname_end + 4, arcount);

    Some(WireQuery {
        id,
        qname_wire: &buf[qname_start..qname_end],
        qtype,
        qclass,
        has_edns,
    })
}

/// Scan the additional section for an OPT RR (qtype=41).
/// Fast path: most queries have arcount=0 → returns immediately.
#[inline]
fn detect_edns(buf: &[u8], mut pos: usize, arcount: u16) -> bool {
    if arcount == 0 {
        return false;
    }
    // Skip answer + authority sections (ancount=nscount=0 in a query).
    // Scan arcount RRs looking for OPT.
    for _ in 0..arcount {
        // Each RR starts with a name (possibly compressed or root \0).
        if pos >= buf.len() {
            break;
        }
        // Root label (\0) = 1 byte name. Compressed ptr = 2 bytes (0xC0xx).
        let name_len = if buf[pos] == 0x00 {
            1usize
        } else if buf[pos] & 0xC0 == 0xC0 {
            2usize
        } else {
            // Full label scan — rare in queries, bail out conservatively.
            return false;
        };
        pos += name_len;
        if pos + 4 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        if rtype == QTYPE_OPT {
            return true;
        }
        // Skip remainder of this RR: type(2) + class(2) + ttl(4) + rdlen(2) + rdata.
        if pos + 8 > buf.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
    false
}

// ── LowerName from wire QNAME ─────────────────────────────────────────────────

/// Build a `LowerName` from a wire-format QNAME for LocalZoneSet lookups.
///
/// This is the **only remaining hickory allocation** in the fast path.
/// Necessary because `LocalZoneSet::find()` and `local_records()` require
/// a `&LowerName` key. Follow-up #156: replace LocalZoneSet key with
/// wire-QNAME/CRC32 to eliminate this last alloc.
///
/// # Topology note
/// On non-contiguous CPU numbering (NUMA exotic), the CPUMAP index/cpu_id
/// mapping has a known limitation (see FINDINGS.md #155 follow-up).
/// This function has no such constraint — it is topology-agnostic.
#[inline]
pub fn wire_qname_to_lower_name(qname_wire: &[u8]) -> Option<LowerName> {
    let mut decoder = BinDecoder::new(qname_wire);
    let name = Name::read(&mut decoder).ok()?;
    Some(LowerName::from(name))
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

// ── Build A / AAAA response ───────────────────────────────────────────────────

/// Build an authoritative A or AAAA response directly into `out`.
///
/// Covers: `ZoneAction::Static` and `ZoneAction::Redirect` with A/AAAA records.
/// Returns `Some(len)` on success, `None` if the case is unsupported or `out`
/// is too small (caller falls back to hickory).
///
/// # Wire layout
/// ```text
/// [Header 12B][Question: qname + qtype + qclass][Answer RRs: 0xC00C + type + class + TTL + rdlen + rdata]*
/// ```
///
/// # EDNS
/// Does NOT echo OPT RR. Caller must check `wq.has_edns` and fall back to
/// hickory if EDNS echo is required (until EDNS echo is implemented in
/// a subsequent delivery).
pub fn build_answer_a_aaaa<'z>(
    wq: &WireQuery<'_>,
    out: &mut [u8],
    zones: &'z LocalZoneSet,
) -> Option<usize> {
    // Only handle IN class queries.
    if wq.qclass != CLASS_IN {
        return None;
    }
    // Only A and AAAA in this delivery.
    if wq.qtype != QTYPE_A && wq.qtype != QTYPE_AAAA {
        return None;
    }

    // Build LowerName for zone lookup (one hickory alloc — unavoidable here).
    let lower = wire_qname_to_lower_name(wq.qname_wire)?;

    // Zone lookup: only Static/Redirect zones are authoritative for A/AAAA.
    let zone_action = zones.find(&lower)?;
    match zone_action {
        ZoneAction::Static | ZoneAction::Redirect => {}
        _ => return None, // NxDomain, BlockPage, Refuse → handled in next delivery
    }

    // Fetch matching records (A or AAAA depending on qtype).
    let rtype = if wq.qtype == QTYPE_A {
        RecordType::A
    } else {
        RecordType::AAAA
    };
    let records = zones.local_records(&lower, rtype);

    // Determine ancount: 0 records = NODATA (NOERROR, ancount=0) — handled by
    // next delivery. Return None for now to fall back to hickory.
    if records.is_empty() {
        return None;
    }

    let ancount = records.len();
    let qname_len = wq.qname_wire.len(); // includes terminating \0

    // Compute required output size.
    // Header(12) + Question(qname + 4) + ancount * (2+2+2+4+2+rdlen)
    let rdata_len: usize = if wq.qtype == QTYPE_A { 4 } else { 16 };
    let rr_size = 2 + 2 + 2 + 4 + 2 + rdata_len; // ptr + type + class + ttl + rdlen + rdata
    let total = DNS_HDR + qname_len + 4 + ancount * rr_size;
    if out.len() < total {
        return None; // buffer too small — should not happen (FRAME_SIZE >> DNS max)
    }

    // ── Header (12 bytes) ──────────────────────────────────────────────────
    let mut pos = 0;
    pos = put_u16(out, pos, wq.id);                    // ID
    pos = put_u16(out, pos, FLAGS_AA_NOERROR);         // Flags: QR AA RD RA NOERROR
    pos = put_u16(out, pos, 1);                        // QDCOUNT = 1
    pos = put_u16(out, pos, ancount as u16);           // ANCOUNT
    pos = put_u16(out, pos, 0);                        // NSCOUNT = 0
    pos = put_u16(out, pos, 0);                        // ARCOUNT = 0

    // ── Question section (echo wire) ───────────────────────────────────────
    out[pos..pos + qname_len].copy_from_slice(wq.qname_wire);
    pos += qname_len;
    pos = put_u16(out, pos, wq.qtype);                 // QTYPE
    pos = put_u16(out, pos, wq.qclass);                // QCLASS

    // ── Answer RRs ────────────────────────────────────────────────────────
    for r in &records {
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

    Some(pos)
}
