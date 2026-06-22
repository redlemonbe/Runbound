// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! RFC 8945 TSIG verification for inbound DNS UPDATE — hickory-free.
//!
//! Authenticates a signed request by recomputing the MAC over the message and
//! the TSIG variables (RFC 8945 §4.3.3) and comparing it, in constant time, to
//! the MAC carried in the request's TSIG RR. The HMAC primitives come from
//! `ring` (SHA-1/256/384/512); this module owns only the DNS wire layout, the
//! same division of labour as `dnssec_sign`.
//!
//! Only verification of a first request is implemented (no multi-message TSIG
//! streams): that is all DNS UPDATE needs. Signing exists solely as a test
//! helper, kept behind `#[cfg(test)]`.

use ring::hmac;

use crate::dns::wire::consts::rtype;
use crate::dns::wire::{Decoder, Encoder, Name};

/// TSIG HMAC algorithm. De-hickory replacement for `hickory_proto`'s
/// `TsigAlgorithm`, carrying only the SHA variants Runbound's config accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsigAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl TsigAlg {
    /// Parse a config algorithm token (case-insensitive). `None` for anything
    /// unsupported — the caller must refuse to load such a key.
    pub fn parse(s: &str) -> Option<TsigAlg> {
        match s.to_ascii_lowercase().as_str() {
            "hmac-sha1" => Some(TsigAlg::Sha1),
            "hmac-sha256" => Some(TsigAlg::Sha256),
            "hmac-sha384" => Some(TsigAlg::Sha384),
            "hmac-sha512" => Some(TsigAlg::Sha512),
            _ => None,
        }
    }

    /// The TSIG algorithm domain-name (RFC 8945 §6), trailing dot included.
    fn wire_name(self) -> &'static str {
        match self {
            TsigAlg::Sha1 => "hmac-sha1.",
            TsigAlg::Sha256 => "hmac-sha256.",
            TsigAlg::Sha384 => "hmac-sha384.",
            TsigAlg::Sha512 => "hmac-sha512.",
        }
    }

    fn ring_alg(self) -> hmac::Algorithm {
        match self {
            TsigAlg::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TsigAlg::Sha256 => hmac::HMAC_SHA256,
            TsigAlg::Sha384 => hmac::HMAC_SHA384,
            TsigAlg::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// Why a TSIG-signed request was rejected. Each maps to a DNS RCODE at the call
/// site (REFUSED for auth failures, FORMERR/SERVFAIL for malformed input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsigError {
    /// No TSIG RR present (or ARCOUNT == 0).
    Missing,
    /// Malformed message or TSIG RDATA.
    FormErr,
    /// Key name not in the configured set.
    UnknownKey,
    /// TSIG algorithm does not match the configured key's algorithm.
    AlgMismatch,
    /// Time signed outside the accepted window.
    BadTime,
    /// MAC verification failed.
    BadSig,
}

/// A parsed TSIG resource record (RFC 8945 §4.2).
#[derive(Clone, Debug)]
struct TsigRr {
    key_name: Name,
    algorithm: Name,
    time_signed: u64, // 48-bit
    fudge: u16,
    mac: Vec<u8>,
    #[allow(dead_code)]
    original_id: u16,
    error: u16,
    other: Vec<u8>,
}

/// Advance `d` past one resource record (owner name + fixed fields + RDATA).
fn skip_record(d: &mut Decoder) -> Option<()> {
    Name::parse(d).ok()?; // owner (may be compressed)
    d.u16().ok()?; // type
    d.u16().ok()?; // class
    d.u32().ok()?; // ttl
    let rdlen = d.u16().ok()? as usize;
    d.slice(rdlen).ok()?; // rdata
    Some(())
}

/// Locate and parse the TSIG RR (always the last record, RFC 8945 §5.1),
/// returning it plus the byte offset where its owner name begins and the
/// message's original ARCOUNT. Walks the message with our own decoder so the
/// offset is exact, which the MAC reconstruction needs.
fn parse_for_tsig(raw: &[u8]) -> Result<(TsigRr, usize, u16), TsigError> {
    let mut d = Decoder::new(raw);
    // Header (RFC 1035 §4.1.1): id, flags, then the four section counts.
    d.u16().map_err(|_| TsigError::FormErr)?; // id
    d.u16().map_err(|_| TsigError::FormErr)?; // flags
    let qd = d.u16().map_err(|_| TsigError::FormErr)?;
    let an = d.u16().map_err(|_| TsigError::FormErr)?;
    let ns = d.u16().map_err(|_| TsigError::FormErr)?;
    let ar = d.u16().map_err(|_| TsigError::FormErr)?;
    if ar == 0 {
        return Err(TsigError::Missing);
    }

    for _ in 0..qd {
        Name::parse(&mut d).map_err(|_| TsigError::FormErr)?; // qname
        d.u16().map_err(|_| TsigError::FormErr)?; // qtype
        d.u16().map_err(|_| TsigError::FormErr)?; // qclass
    }
    for _ in 0..(an as u32 + ns as u32) {
        skip_record(&mut d).ok_or(TsigError::FormErr)?;
    }
    for _ in 0..(ar - 1) {
        skip_record(&mut d).ok_or(TsigError::FormErr)?;
    }

    let tsig_start = d.pos();
    let key_name = Name::parse(&mut d).map_err(|_| TsigError::FormErr)?;
    let rtype_n = d.u16().map_err(|_| TsigError::FormErr)?;
    d.u16().map_err(|_| TsigError::FormErr)?; // class (ANY)
    d.u32().map_err(|_| TsigError::FormErr)?; // ttl (0)
    let rdlen = d.u16().map_err(|_| TsigError::FormErr)? as usize;
    if rtype_n != rtype::TSIG {
        return Err(TsigError::Missing);
    }
    let rdata_end = d.pos() + rdlen;

    let algorithm = Name::parse(&mut d).map_err(|_| TsigError::FormErr)?;
    let time_hi = d.u16().map_err(|_| TsigError::FormErr)? as u64;
    let time_lo = d.u32().map_err(|_| TsigError::FormErr)? as u64;
    let time_signed = (time_hi << 32) | time_lo;
    let fudge = d.u16().map_err(|_| TsigError::FormErr)?;
    let mac_size = d.u16().map_err(|_| TsigError::FormErr)? as usize;
    let mac = d.slice(mac_size).map_err(|_| TsigError::FormErr)?.to_vec();
    let original_id = d.u16().map_err(|_| TsigError::FormErr)?;
    let error = d.u16().map_err(|_| TsigError::FormErr)?;
    let other_len = d.u16().map_err(|_| TsigError::FormErr)? as usize;
    let other = d.slice(other_len).map_err(|_| TsigError::FormErr)?.to_vec();

    if d.pos() != rdata_end {
        return Err(TsigError::FormErr); // RDLENGTH disagrees with contents
    }

    Ok((
        TsigRr {
            key_name,
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        },
        tsig_start,
        ar,
    ))
}

/// Reconstruct the data the request MAC is computed over (RFC 8945 §4.3.3 for a
/// first request, no prior digest): the DNS message with the TSIG RR removed and
/// ARCOUNT decremented, followed by the canonical TSIG variables.
fn request_digest_data(raw: &[u8], tsig_start: usize, arcount: u16, tsig: &TsigRr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tsig_start + 96);
    // Message portion = the verbatim received bytes up to the TSIG RR, with the
    // header's ARCOUNT lowered by one (the TSIG is not part of the signed copy).
    buf.extend_from_slice(&raw[..tsig_start]);
    let new_ar = arcount - 1;
    buf[10] = (new_ar >> 8) as u8;
    buf[11] = (new_ar & 0xff) as u8;

    // TSIG variables, in order (RFC 8945 §4.3.3).
    let mut e = Encoder::uncompressed();
    tsig.key_name.emit_canonical(&mut e); // NAME (lowercased, uncompressed)
    e.u16(crate::dns::wire::consts::class::ANY); // CLASS
    e.u32(0); // TTL
    tsig.algorithm.emit_canonical(&mut e); // Algorithm Name
    e.u16((tsig.time_signed >> 32) as u16); // Time Signed (48-bit)
    e.u32(tsig.time_signed as u32);
    e.u16(tsig.fudge); // Fudge
    e.u16(tsig.error); // Error
    e.u16(tsig.other.len() as u16); // Other Len
    e.bytes(&tsig.other); // Other Data
    buf.extend_from_slice(e.as_slice());
    buf
}

/// Verify a TSIG-signed DNS request against the configured keys.
///
/// On success returns the matched key name (lowercased, no trailing dot) for
/// logging. The MAC comparison is constant-time (`ring::hmac::verify`). The
/// accepted clock skew is ±`window_secs` around `now_secs` (RFC 8945 §5.2.3
/// recommends the fudge; Runbound keeps a fixed window for parity with the prior
/// handler).
pub fn verify_request(
    raw: &[u8],
    keys: &[(String, TsigAlg, Vec<u8>)],
    now_secs: u64,
    window_secs: u64,
) -> Result<String, TsigError> {
    let (tsig, tsig_start, arcount) = parse_for_tsig(raw)?;

    let key_name = tsig.key_name.to_ascii().to_ascii_lowercase();
    let key_name = key_name.trim_end_matches('.').to_string();
    let Some((_, alg, secret)) = keys.iter().find(|(n, _, _)| *n == key_name) else {
        return Err(TsigError::UnknownKey);
    };

    let recv_alg = tsig.algorithm.to_ascii().to_ascii_lowercase();
    if recv_alg.trim_end_matches('.') != alg.wire_name().trim_end_matches('.') {
        return Err(TsigError::AlgMismatch);
    }

    if now_secs.abs_diff(tsig.time_signed) > window_secs {
        return Err(TsigError::BadTime);
    }

    let tbs = request_digest_data(raw, tsig_start, arcount, &tsig);
    let key = hmac::Key::new(alg.ring_alg(), secret);
    hmac::verify(&key, &tbs, &tsig.mac).map_err(|_| TsigError::BadSig)?;
    Ok(key_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::consts::{class, opcode, rtype};
    use crate::dns::wire::{Header, Message, Question};

    /// Build an unsigned UPDATE message (header + a question/zone), encoded.
    fn unsigned_update() -> Vec<u8> {
        let mut h = Header::default();
        h.id = 0x1234;
        h.set_opcode(opcode::UPDATE);
        let mut m = Message {
            header: h,
            ..Default::default()
        };
        m.questions
            .push(Question::new(Name::from_ascii("example.test.").unwrap(), rtype::SOA));
        m.encode()
    }

    /// Append a TSIG RR signing `msg_unsigned` with `key` under `alg` at
    /// `time_signed`, returning the full signed wire bytes. Mirrors the verify
    /// path's reconstruction so the two are exercised together; hickory provides
    /// the *independent* correctness oracle below.
    fn sign(msg_unsigned: &[u8], key_name: &str, alg: TsigAlg, secret: &[u8], time_signed: u64) -> Vec<u8> {
        let kname = Name::from_ascii(key_name).unwrap();
        let aname = Name::from_ascii(alg.wire_name()).unwrap();
        // Variables digest = message (arcount unchanged, = 0 additionals) || vars.
        let tsig_for_vars = TsigRr {
            key_name: kname.clone(),
            algorithm: aname.clone(),
            time_signed,
            fudge: 300,
            mac: Vec::new(),
            original_id: 0x1234,
            error: 0,
            other: Vec::new(),
        };
        // tsig_start for an unsigned message == its full length (TSIG appended at end),
        // and arcount there is (current additionals + 1) so the −1 restores the original.
        // Build the to-be-signed buffer directly: msg bytes (arcount already final-1) || vars.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(msg_unsigned); // arcount = 0 here, which is final(1)-1
        let mut e = Encoder::uncompressed();
        tsig_for_vars.key_name.emit_canonical(&mut e);
        e.u16(class::ANY);
        e.u32(0);
        tsig_for_vars.algorithm.emit_canonical(&mut e);
        e.u16((time_signed >> 32) as u16);
        e.u32(time_signed as u32);
        e.u16(tsig_for_vars.fudge);
        e.u16(0); // error
        e.u16(0); // other len
        tbs.extend_from_slice(e.as_slice());

        let key = hmac::Key::new(alg.ring_alg(), secret);
        let mac = hmac::sign(&key, &tbs).as_ref().to_vec();

        // Now assemble the signed message: bump ARCOUNT to 1, append TSIG RR.
        let mut signed = msg_unsigned.to_vec();
        let ar = u16::from_be_bytes([signed[10], signed[11]]) + 1;
        signed[10] = (ar >> 8) as u8;
        signed[11] = (ar & 0xff) as u8;

        let mut rr = Encoder::uncompressed();
        kname.emit_raw(&mut rr);
        rr.u16(rtype::TSIG);
        rr.u16(class::ANY);
        rr.u32(0);
        let at = rr.reserve_u16();
        aname.emit_raw(&mut rr);
        rr.u16((time_signed >> 32) as u16);
        rr.u32(time_signed as u32);
        rr.u16(300); // fudge
        rr.u16(mac.len() as u16);
        rr.bytes(&mac);
        rr.u16(0x1234); // original id
        rr.u16(0); // error
        rr.u16(0); // other len
        rr.patch_u16_len(at);
        signed.extend_from_slice(rr.as_slice());
        signed
    }

    fn keys() -> Vec<(String, TsigAlg, Vec<u8>)> {
        vec![("ddns-key".into(), TsigAlg::Sha256, b"super-secret-key-material".to_vec())]
    }

    #[test]
    fn verifies_valid_signature() {
        let now = 1_700_000_000u64;
        let signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, b"super-secret-key-material", now);
        let got = verify_request(&signed, &keys(), now, 300).expect("valid TSIG");
        assert_eq!(got, "ddns-key");
    }

    #[test]
    fn rejects_tampered_message() {
        let now = 1_700_000_000u64;
        let mut signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, b"super-secret-key-material", now);
        // Flip a byte in the question section (after the 12-byte header).
        signed[15] ^= 0x01;
        assert_eq!(verify_request(&signed, &keys(), now, 300), Err(TsigError::BadSig));
    }

    #[test]
    fn rejects_wrong_key_secret() {
        let now = 1_700_000_000u64;
        let signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, b"WRONG-secret", now);
        assert_eq!(verify_request(&signed, &keys(), now, 300), Err(TsigError::BadSig));
    }

    #[test]
    fn rejects_unknown_key_name() {
        let now = 1_700_000_000u64;
        let signed = sign(&unsigned_update(), "other-key.", TsigAlg::Sha256, b"super-secret-key-material", now);
        assert_eq!(verify_request(&signed, &keys(), now, 300), Err(TsigError::UnknownKey));
    }

    #[test]
    fn rejects_expired_timestamp() {
        let now = 1_700_000_000u64;
        let signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, b"super-secret-key-material", now - 1000);
        assert_eq!(verify_request(&signed, &keys(), now, 300), Err(TsigError::BadTime));
    }

    #[test]
    fn missing_tsig_is_detected() {
        let now = 1_700_000_000u64;
        let unsigned = unsigned_update();
        assert_eq!(verify_request(&unsigned, &keys(), now, 300), Err(TsigError::Missing));
    }

    /// Oracle: hickory must reconstruct the *same* to-be-signed buffer from our
    /// signed message, and accept our ring-computed MAC over it. This proves our
    /// RFC 8945 §4.3.3 variable layout and HMAC are byte-identical to hickory's —
    /// the security-critical invariant of the verifier.
    #[test]
    fn digest_buffer_matches_hickory() {
        use hickory_proto::rr::rdata::tsig::signed_bitmessage_to_buf;
        let now = 1_700_000_000u64;
        let secret = b"super-secret-key-material";
        let signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, secret, now);

        // Our reconstruction.
        let (tsig, tsig_start, ar) = parse_for_tsig(&signed).expect("parse");
        let ours = request_digest_data(&signed, tsig_start, ar, &tsig);

        // hickory's reconstruction of the same signed message.
        let (theirs, _) = signed_bitmessage_to_buf(&signed, None, true).expect("hickory buf");
        assert_eq!(ours, theirs, "TBS must be byte-identical to hickory");

        // And hickory's own verifier accepts our MAC over its buffer.
        use hickory_proto::op::Message as HMessage;
        let hmsg = HMessage::from_vec(&signed).expect("hickory parses signed");
        let hsig = hmsg.signature().expect("hickory finds TSIG");
        let htsig = &hsig.data;
        assert!(
            htsig.algorithm.verify_mac(secret, &theirs, &htsig.mac).is_ok(),
            "hickory verify_mac accepts our ring MAC"
        );
    }
}
