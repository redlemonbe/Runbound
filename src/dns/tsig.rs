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
use subtle::ConstantTimeEq;

use crate::dns::wire::consts::rtype;
use crate::dns::wire::{Decoder, Encoder, Name};

/// TSIG HMAC algorithm. In-house replacement for `hickory_proto`'s
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
            // SEC-2026-07-F: SHA-1 is deprecated; reject by default to match the DNSSEC
            // path (which rejects SHA-1), opt-in only via RUNBOUND_TSIG_ALLOW_SHA1=1.
            "hmac-sha1" => {
                if std::env::var("RUNBOUND_TSIG_ALLOW_SHA1").ok().as_deref() == Some("1") {
                    tracing::warn!("TSIG hmac-sha1 key accepted via RUNBOUND_TSIG_ALLOW_SHA1 — SHA-1 is deprecated, migrate to hmac-sha256+.");
                    Some(TsigAlg::Sha1)
                } else {
                    tracing::warn!("TSIG hmac-sha1 key rejected (deprecated). Set RUNBOUND_TSIG_ALLOW_SHA1=1 to allow, or migrate to hmac-sha256+.");
                    None
                }
            }
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

/// A successfully verified request. `request_mac` is needed to sign the response
/// (RFC 8945 §5.4.1 prepends the request MAC to the response digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Matched key name, lowercased, no trailing dot.
    pub key_name: String,
    /// The MAC carried in the request's TSIG RR.
    pub request_mac: Vec<u8>,
}

/// Verify a TSIG-signed DNS request against the configured keys.
///
/// On success returns the matched key and the request MAC. The MAC comparison is
/// constant-time (`ring::hmac::verify`). The accepted clock skew is ±`window_secs`
/// around `now_secs` (RFC 8945 §5.2.3 recommends the fudge; Runbound keeps a
/// fixed window for parity with the prior handler).
pub fn verify_request(
    raw: &[u8],
    keys: &[(String, TsigAlg, Vec<u8>)],
    now_secs: u64,
    window_secs: u64,
) -> Result<Verified, TsigError> {
    let (tsig, tsig_start, arcount) = parse_for_tsig(raw)?;

    let key_name = tsig.key_name.to_ascii().to_ascii_lowercase();
    let key_name = key_name.trim_end_matches('.').to_string();
    // PENT-5: look the key up without an early-exit, so the lookup time does not
    // reveal which (or how many) configured key names were compared before a match
    // — i.e. no timing oracle for key-name enumeration. The name length is not
    // sensitive (it is sent in clear in the TSIG RR); the key *secret* is verified
    // separately in constant time by `ring::hmac::verify`.
    let mut matched: Option<(&TsigAlg, &Vec<u8>)> = None;
    for (n, alg, secret) in keys.iter() {
        let eq = n.len() == key_name.len()
            && bool::from(n.as_bytes().ct_eq(key_name.as_bytes()));
        if eq {
            matched = Some((alg, secret));
        }
    }
    let Some((alg, secret)) = matched else {
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
    Ok(Verified {
        key_name,
        request_mac: tsig.mac,
    })
}

/// Append a TSIG RR to a message: bump ARCOUNT and write the RR at the end.
/// Shared by response signing and the test signer.
fn append_tsig_rr(
    msg: &mut Vec<u8>,
    key_name: &Name,
    alg_name: &Name,
    time_signed: u64,
    fudge: u16,
    mac: &[u8],
    original_id: u16,
) {
    let ar = u16::from_be_bytes([msg[10], msg[11]]).wrapping_add(1);
    msg[10] = (ar >> 8) as u8;
    msg[11] = (ar & 0xff) as u8;

    let mut rr = Encoder::uncompressed();
    key_name.emit_raw(&mut rr);
    rr.u16(rtype::TSIG);
    rr.u16(crate::dns::wire::consts::class::ANY);
    rr.u32(0);
    let at = rr.reserve_u16();
    alg_name.emit_raw(&mut rr);
    rr.u16((time_signed >> 32) as u16);
    rr.u32(time_signed as u32);
    rr.u16(fudge);
    rr.u16(mac.len() as u16);
    rr.bytes(mac);
    rr.u16(original_id);
    rr.u16(0); // error
    rr.u16(0); // other len
    rr.patch_u16_len(at);
    msg.extend_from_slice(rr.as_slice());
}

/// Sign a response to a TSIG-authenticated request (RFC 8945 §5.4.1): the digest
/// covers the request MAC (length-prefixed), the response message, and the
/// response TSIG variables. Returns the response with a signed TSIG RR appended.
///
/// `response` must be the full unsigned response wire (ARCOUNT not yet counting
/// the TSIG). `key_name` is the verified key name (trailing dot optional).
pub fn sign_response(
    response: &[u8],
    request_mac: &[u8],
    key_name: &str,
    alg: TsigAlg,
    secret: &[u8],
    time_signed: u64,
    fudge: u16,
) -> Vec<u8> {
    let kname = match Name::from_ascii(key_name) {
        Ok(n) => n,
        Err(_) => return response.to_vec(), // unsignable name → return unsigned
    };
    let aname = Name::from_ascii(alg.wire_name()).expect("static alg name parses");

    // TBS = u16(len(request_mac)) || request_mac || response || response variables.
    let mut tbs = Vec::with_capacity(2 + request_mac.len() + response.len() + 32);
    tbs.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    tbs.extend_from_slice(request_mac);
    tbs.extend_from_slice(response);
    let mut e = Encoder::uncompressed();
    kname.emit_canonical(&mut e);
    e.u16(crate::dns::wire::consts::class::ANY);
    e.u32(0);
    aname.emit_canonical(&mut e);
    e.u16((time_signed >> 32) as u16);
    e.u32(time_signed as u32);
    e.u16(fudge);
    e.u16(0); // error
    e.u16(0); // other len
    tbs.extend_from_slice(e.as_slice());

    let key = hmac::Key::new(alg.ring_alg(), secret);
    let mac = hmac::sign(&key, &tbs).as_ref().to_vec();

    let original_id = u16::from_be_bytes([response[0], response[1]]);
    let mut out = response.to_vec();
    append_tsig_rr(&mut out, &kname, &aname, time_signed, fudge, &mac, original_id);
    out
}

/// Test-only TSIG signing, shared with the DDNS handler's tests. Mirrors the
/// verify path's TBS reconstruction; hickory provides the independent oracle in
/// `digest_buffer_matches_hickory`.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::dns::wire::consts::class;

    /// Append a TSIG RR signing `msg_unsigned` with `secret` under `alg` at
    /// `time_signed`, returning the full signed wire bytes.
    pub fn sign(
        msg_unsigned: &[u8],
        key_name: &str,
        alg: TsigAlg,
        secret: &[u8],
        time_signed: u64,
    ) -> Vec<u8> {
        let kname = Name::from_ascii(key_name).unwrap();
        let aname = Name::from_ascii(alg.wire_name()).unwrap();

        // To-be-signed = message (ARCOUNT as-is == final − 1) || TSIG variables.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(msg_unsigned);
        let mut e = Encoder::uncompressed();
        kname.emit_canonical(&mut e);
        e.u16(class::ANY);
        e.u32(0);
        aname.emit_canonical(&mut e);
        e.u16((time_signed >> 32) as u16);
        e.u32(time_signed as u32);
        e.u16(300); // fudge
        e.u16(0); // error
        e.u16(0); // other len
        tbs.extend_from_slice(e.as_slice());

        let key = hmac::Key::new(alg.ring_alg(), secret);
        let mac = hmac::sign(&key, &tbs).as_ref().to_vec();

        let orig_id = u16::from_be_bytes([msg_unsigned[0], msg_unsigned[1]]);
        let mut signed = msg_unsigned.to_vec();
        super::append_tsig_rr(&mut signed, &kname, &aname, time_signed, 300, &mac, orig_id);
        signed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::consts::{opcode, rtype};
    use crate::dns::wire::{Header, Message, Question};

    /// Build an unsigned UPDATE message (header + a question/zone), encoded.
    fn unsigned_update() -> Vec<u8> {
        let mut h = Header {
            id: 0x1234,
            ..Default::default()
        };
        h.set_opcode(opcode::UPDATE);
        let mut m = Message {
            header: h,
            ..Default::default()
        };
        m.questions
            .push(Question::new(Name::from_ascii("example.test.").unwrap(), rtype::SOA));
        m.encode()
    }

    use super::test_support::sign;

    fn keys() -> Vec<(String, TsigAlg, Vec<u8>)> {
        vec![("ddns-key".into(), TsigAlg::Sha256, b"super-secret-key-material".to_vec())]
    }

    #[test]
    fn verifies_valid_signature() {
        let now = 1_700_000_000u64;
        let signed = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, b"super-secret-key-material", now);
        let got = verify_request(&signed, &keys(), now, 300).expect("valid TSIG");
        assert_eq!(got.key_name, "ddns-key");
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
    fn config_key_name_trailing_dot_is_normalized() {
        // Regression: `verify_request` looks up the request key name with the trailing
        // dot stripped, so the handler must store config TSIG key names dot-stripped
        // too. A config written `tsig-key: "test-key." ...` previously stored "test-key."
        // (dot kept) while the verifier looked up "test-key" -> UnknownKey, so DDNS with
        // a dotted key name silently failed. RunboundHandler::new now normalizes with
        // `trim_end_matches('.').to_ascii_lowercase()`; lock that contract in here.
        let now = 1_700_000_000u64;
        let secret = b"super-secret-key-material";
        let signed = sign(&unsigned_update(), "test-key.", TsigAlg::Sha256, secret, now);

        // Handler-normalized storage (the fix) verifies a dotted-name request.
        let stored_fixed = vec![(
            "test-key.".trim_end_matches('.').to_ascii_lowercase(),
            TsigAlg::Sha256,
            secret.to_vec(),
        )];
        let got = verify_request(&signed, &stored_fixed, now, 300).expect("dotted config key must verify");
        assert_eq!(got.key_name, "test-key");

        // Pre-fix storage (trailing dot kept) reproduces the bug: UnknownKey.
        let stored_buggy = vec![("test-key.".to_string(), TsigAlg::Sha256, secret.to_vec())];
        assert_eq!(verify_request(&signed, &stored_buggy, now, 300), Err(TsigError::UnknownKey));
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

    /// Oracle: a response we sign (RFC 8945 §5.4.1, request MAC prepended) must
    /// verify under hickory's response verifier — proving the response-side
    /// digest layout and HMAC interoperate. This is what makes `nsupdate`
    /// accept the UPDATE reply.
    #[test]
    fn response_signature_accepted_by_hickory() {
        use hickory_proto::rr::rdata::tsig::signed_bitmessage_to_buf;
        let now = 1_700_000_000u64;
        let secret = b"super-secret-key-material";

        // Sign a request, verify it, take the request MAC.
        let req = sign(&unsigned_update(), "ddns-key.", TsigAlg::Sha256, secret, now);
        let v = verify_request(&req, &keys(), now, 300).expect("request verifies");

        // Build and sign a response.
        let mut h = Header {
            id: 0x1234,
            ..Default::default()
        };
        h.set_opcode(opcode::UPDATE);
        h.set_qr(true);
        let mut resp = Message { header: h, ..Default::default() };
        resp.questions
            .push(Question::new(Name::from_ascii("example.test.").unwrap(), rtype::SOA));
        let resp_bytes = resp.encode();
        let signed = sign_response(&resp_bytes, &v.request_mac, "ddns-key.", TsigAlg::Sha256, secret, now, 300);

        // hickory verifies the response against the request MAC context. A
        // request/response pair signs the response as a "first message" (full
        // TSIG variables) with the request MAC prepended (RFC 8945 §5.4.1).
        let (htbs, htsig_rec) = signed_bitmessage_to_buf(&signed, Some(&v.request_mac), true)
            .expect("hickory response buf");
        assert!(
            htsig_rec.data.algorithm.verify_mac(secret, &htbs, &htsig_rec.data.mac).is_ok(),
            "hickory accepts our response TSIG"
        );
    }
}
