// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Hickory-free DNSSEC validation: the chain walk.
//
// Walks the delegation chain from the hardcoded root anchor down to a zone,
// validating each DNSKEY against the parent's DS (incr. 1 + 2), and classifies
// the result Secure / Insecure / Bogus. An absent-but-PROVEN DS (NSEC/NSEC3
// denial, incr. 3) marks the subtree Insecure; a broken link is Bogus. Records
// are obtained through a `Fetcher`, so the same logic serves the live resolver
// (its own DO descent) and the tests (a DO resolver).
//
// Fail-closed: any parse/validation failure is Bogus, and only a fully-validated
// answer under the zone's trusted keys is Secure.

#![allow(dead_code)]

use crate::dns::dnssec_denial as denial;
use crate::dns::dnssec_verify as verify;
use crate::dns::wire::{self, consts, Name, Rdata};

/// DNSSEC validation outcome (RFC 4035 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Chain of trust complete and the data validated.
    Secure,
    /// A proven-unsigned delegation: no DNSSEC below, treat as plain DNS.
    Insecure,
    /// Validation failed — the answer MUST NOT be served (→ SERVFAIL).
    Bogus,
}

/// Source of DNSSEC records (DNSKEY/DS/answer/denial), DO-enabled.
pub trait Fetcher {
    /// Fetch `(name, qtype)` and return the parsed message, or `None` on I/O error.
    fn fetch(
        &self,
        name: &Name,
        qtype: u16,
    ) -> impl std::future::Future<Output = Option<wire::Message>> + Send;
}

/// Owned RDATA of `rtype` in `section`, plus the RRSIG rdatas covering `rtype`.
fn split(section: &[wire::Record], rtype: u16) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let rdatas = section
        .iter()
        .filter(|r| r.rtype == rtype)
        .map(|r| {
            let mut e = wire::Encoder::uncompressed();
            r.rdata.emit(&mut e);
            e.into_vec()
        })
        .collect();
    let sigs = section
        .iter()
        .filter(|r| r.rtype == consts::rtype::RRSIG)
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => Some(data.clone()),
            _ => None,
        })
        .filter(|d| d.len() >= 2 && u16::from_be_bytes([d[0], d[1]]) == rtype)
        .collect();
    (rdatas, sigs)
}

/// Min TTL of the DNSKEY records in `section` (the RRset's cache lifetime), with
/// a conservative floor if none are present — the lifetime for the #230 cache.
fn dnskey_ttl(section: &[wire::Record]) -> u32 {
    section
        .iter()
        .filter(|r| r.rtype == consts::rtype::DNSKEY)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(3600)
}

/// The earliest RRSIG signature-expiration across `sigs` (RFC 4034 §3.1.5: an
/// absolute unix timestamp at RRSIG rdata offset 8..12), or `None` if none parse.
fn min_rrsig_expiration(sigs: &[Vec<u8>]) -> Option<u32> {
    sigs.iter()
        .filter_map(|d| d.get(8..12).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
        .min()
}

/// Lifetime to cache a validated DNSKEY set under: the RRset TTL, further bounded
/// by how long its signatures stay valid — so a revoked/rolled key is never reused
/// past the point its RRSIG expired, not merely until the RRset TTL lapses (#230
/// audit F-1). `sigs` are the RRSIG rdatas covering the DNSKEY RRset.
fn dnskey_cache_ttl(rrset_ttl: u32, sigs: &[Vec<u8>], now: u32) -> u32 {
    match min_rrsig_expiration(sigs) {
        Some(exp) => rrset_ttl.min(exp.saturating_sub(now)),
        None => rrset_ttl,
    }
}

fn as_unknown(rdatas: &[Vec<u8>], rtype: u16) -> Vec<Rdata> {
    rdatas
        .iter()
        .map(|d| Rdata::Unknown { rtype, data: d.clone() })
        .collect()
}

/// The ancestor chain root→zone (exclusive of root): e.g. cloudflare.com →
/// [com., cloudflare.com.]. Each entry is a zone cut to cross.
fn delegation_path(zone: &Name) -> Vec<Name> {
    let mut up = Vec::new();
    let mut cur = zone.clone();
    while !cur.is_root() {
        up.push(cur.clone());
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }
    up.reverse(); // shortest (just below root) first
    up
}

/// Validate the chain of trust down to `zone` and return its trusted DNSKEY
/// rdatas (Secure), or a non-Secure verdict.
pub async fn trusted_keys_for<F: Fetcher>(
    fetcher: &F,
    zone: &Name,
    now: u32,
) -> (Verdict, Vec<Vec<u8>>) {
    use crate::dns::infra_cache;

    // #230: a fully-validated key set for the exact target zone → done, no fetch.
    // Only Secure zones are ever cached, so a hit is always Secure.
    if let Some(keys) = infra_cache::dnskey_get(zone) {
        return (Verdict::Secure, keys);
    }

    // 1. Root DNSKEY: reuse the cached validated set if fresh, else fetch it,
    //    validate against the hardcoded anchor, and cache it (~once / 48 h).
    let mut current = Name::root();
    let mut keys: Vec<Vec<u8>> = if let Some(rk) = infra_cache::dnskey_get(&Name::root()) {
        rk
    } else {
        let Some(root_msg) = fetcher.fetch(&Name::root(), consts::rtype::DNSKEY).await else {
            return (Verdict::Bogus, vec![]);
        };
        let (rk, rs) = split(&root_msg.answers, consts::rtype::DNSKEY);
        let rk_refs: Vec<&[u8]> = rk.iter().map(|v| v.as_slice()).collect();
        let rs_refs: Vec<&[u8]> = rs.iter().map(|v| v.as_slice()).collect();
        let Some(root_keys) = verify::validate_dnskey_rrset(
            &Name::root(),
            &rk_refs,
            &rs_refs,
            verify::ROOT_ANCHORS,
            now,
        ) else {
            return (Verdict::Bogus, vec![]);
        };
        let owned: Vec<Vec<u8>> = root_keys.iter().map(|s| s.to_vec()).collect();
        let ttl = dnskey_cache_ttl(dnskey_ttl(&root_msg.answers), &rs, now);
        infra_cache::dnskey_learn(&Name::root(), &owned, ttl);
        owned
    };

    // 2. Descend each zone cut, validating DS (in the parent) then the child DNSKEY.
    for child in delegation_path(zone) {
        if child.eq_ignore_ascii_case(&current) {
            continue;
        }
        // #230: a cut we already validated (and cached) → adopt its keys directly,
        // skipping the DS + DNSKEY fetch for it.
        if let Some(ck) = infra_cache::dnskey_get(&child) {
            keys = ck;
            current = child;
            continue;
        }
        let key_refs: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();

        let Some(ds_msg) = fetcher.fetch(&child, consts::rtype::DS).await else {
            return (Verdict::Bogus, vec![]);
        };
        let (ds_rd, ds_sig) = split(&ds_msg.answers, consts::rtype::DS);

        if ds_rd.is_empty() {
            // `delegation_path` synthesizes every label boundary between the root
            // and `zone`, not just the ones that are REAL delegations — reverse
            // (in-addr.arpa) trees routinely skip levels (RFC 2317-style: e.g.
            // 1.1.in-addr.arpa. has no NS of its own; the real next cut is
            // 1.1.1.in-addr.arpa., delegated straight from 1.in-addr.arpa. by
            // APNIC/ARIN to Cloudflare — confirmed live via `dig +trace -x 1.1.1.1`).
            // A DS query at exactly a delegation point is answered authoritatively
            // by the PARENT either way (RFC 4035 §3.1.4.1), so an empty DS answer
            // looks IDENTICAL whether `child` is a real (if unsigned) cut or just a
            // synthetic non-existent label — the response shape alone (SOA owner,
            // lack of a referral) cannot tell them apart. What DOES distinguish them
            // uniformly, whether `fetcher` walks iteratively or delegates to an
            // upstream full resolver: a genuinely delegated name has its OWN NS
            // RRset resolvable in the answer section (confirmed live: `dig
            // google.com NS` → ANSWER 4; `dig 1.1.in-addr.arpa NS` → ANSWER 0, only
            // a NODATA SOA; `dig 1.1.1.in-addr.arpa NS` → ANSWER 2). Only treat an
            // empty DS as an insecure-delegation candidate when `child` clears that
            // bar; otherwise it's not a real cut, so skip it and keep validating
            // deeper against the SAME (already-trusted) parent keys.
            let is_real_cut = fetcher
                .fetch(&child, consts::rtype::NS)
                .await
                .is_some_and(|ns_msg| {
                    ns_msg
                        .answers
                        .iter()
                        .any(|r| r.rtype == consts::rtype::NS && r.name.eq_ignore_ascii_case(&child))
                });
            if !is_real_cut {
                continue;
            }
            // No DS: must be a PROVEN insecure delegation (NSEC/NSEC3 in authority,
            // validated under the parent's keys). Otherwise Bogus.
            return if denial_secure(&ds_msg, &child, &key_refs, now) {
                (Verdict::Insecure, vec![])
            } else {
                (Verdict::Bogus, vec![])
            };
        }

        // DS RRset must be signed by the parent.
        let ds_un = as_unknown(&ds_rd, consts::rtype::DS);
        let ds_refs: Vec<&Rdata> = ds_un.iter().collect();
        let dssig_refs: Vec<&[u8]> = ds_sig.iter().map(|v| v.as_slice()).collect();
        if !verify::validate_rrset(
            &child,
            consts::class::IN,
            consts::rtype::DS,
            &ds_refs,
            &dssig_refs,
            &key_refs,
            now,
        ) {
            return (Verdict::Bogus, vec![]);
        }

        // Child DNSKEY validated against the now-trusted DS.
        let ds_list: Vec<verify::Ds> = ds_rd.iter().filter_map(|r| verify::parse_ds(r)).collect();
        let Some(km) = fetcher.fetch(&child, consts::rtype::DNSKEY).await else {
            return (Verdict::Bogus, vec![]);
        };
        let (ck, cs) = split(&km.answers, consts::rtype::DNSKEY);
        let ck_refs: Vec<&[u8]> = ck.iter().map(|v| v.as_slice()).collect();
        let cs_refs: Vec<&[u8]> = cs.iter().map(|v| v.as_slice()).collect();
        let Some(child_keys) =
            verify::validate_dnskey_rrset(&child, &ck_refs, &cs_refs, &ds_list, now)
        else {
            return (Verdict::Bogus, vec![]);
        };
        keys = child_keys.iter().map(|s| s.to_vec()).collect();
        // #230: cache this now-validated cut (Secure) so later chains reuse it,
        // bounded by the DNSKEY RRSIG validity (audit F-1).
        let ttl = dnskey_cache_ttl(dnskey_ttl(&km.answers), &cs, now);
        infra_cache::dnskey_learn(&child, &keys, ttl);
        current = child;
    }
    (Verdict::Secure, keys)
}

/// Are the denial records in `msg`'s authority a VALID, signed proof that `name`
/// has no DS (an insecure delegation)? Only NSEC/NSEC3 RRsets that themselves
/// validate under `keys` are considered — forged records mixed in are ignored.
fn denial_secure(msg: &wire::Message, name: &Name, keys: &[&[u8]], now: u32) -> bool {
    let nsecs = collect_validated_nsec(msg, keys, now);
    if !nsecs.is_empty() {
        return denial::nsec_proves_no_ds(&nsecs, name);
    }
    let nsec3s = collect_validated_nsec3(msg, keys, now);
    !nsec3s.is_empty() && denial::nsec3_proves_no_ds(&nsec3s, name)
}

/// Validate the RRset of `rtype` owned by `owner` within `msg`'s authority under `keys`.
fn rrset_validated(msg: &wire::Message, owner: &Name, rtype: u16, keys: &[&[u8]], now: u32) -> bool {
    let rdatas: Vec<Rdata> = msg
        .authority
        .iter()
        .filter(|r| r.rtype == rtype && r.name.eq_ignore_ascii_case(owner))
        .map(|r| {
            if let Rdata::Unknown { data, .. } = &r.rdata {
                Rdata::Unknown { rtype, data: data.clone() }
            } else {
                r.rdata.clone()
            }
        })
        .collect();
    let refs: Vec<&Rdata> = rdatas.iter().collect();
    let sigs: Vec<Vec<u8>> = msg
        .authority
        .iter()
        .filter(|r| r.rtype == consts::rtype::RRSIG && r.name.eq_ignore_ascii_case(owner))
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => Some(data.clone()),
            _ => None,
        })
        .filter(|d| d.len() >= 2 && u16::from_be_bytes([d[0], d[1]]) == rtype)
        .collect();
    let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
    verify::validate_rrset(owner, consts::class::IN, rtype, &refs, &sig_refs, keys, now)
}

/// NSEC records whose RRset validated under `keys` (only these may back a proof).
fn collect_validated_nsec<'a>(msg: &'a wire::Message, keys: &[&[u8]], now: u32) -> Vec<denial::Nsec<'a>> {
    msg.authority
        .iter()
        .filter(|r| {
            r.rtype == consts::rtype::NSEC
                && rrset_validated(msg, &r.name, consts::rtype::NSEC, keys, now)
        })
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => denial::Nsec::parse(r.name.clone(), data),
            _ => None,
        })
        .collect()
}

/// NSEC3 records whose RRset validated under `keys` (only these may back a proof).
fn collect_validated_nsec3<'a>(msg: &'a wire::Message, keys: &[&[u8]], now: u32) -> Vec<denial::Nsec3<'a>> {
    msg.authority
        .iter()
        .filter(|r| {
            r.rtype == consts::rtype::NSEC3
                && rrset_validated(msg, &r.name, consts::rtype::NSEC3, keys, now)
        })
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => denial::Nsec3::parse(&r.name, data),
            _ => None,
        })
        .collect()
}

/// The zone apex for a message: the signer of any RRSIG it carries.
fn zone_apex(msg: &wire::Message) -> Option<Name> {
    msg.answers
        .iter()
        .chain(msg.authority.iter())
        .filter(|r| r.rtype == consts::rtype::RRSIG)
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => verify::rrsig_signer(data),
            _ => None,
        })
        .next()
}

/// The signing zone taken from the RRSIG that actually covers qname's OWN answer
/// RRset (owner == qname), in-bailiwick. Preferred over [`zone_apex`] for a positive
/// answer so it validates under the zone that signed IT — not the first (possibly
/// unrelated, merely-enclosing) RRSIG that happens to appear first in the message.
fn answer_zone(msg: &wire::Message, qname: &Name) -> Option<Name> {
    msg.answers
        .iter()
        .filter(|r| r.rtype == consts::rtype::RRSIG && r.name.eq_ignore_ascii_case(qname))
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => verify::rrsig_signer(data),
            _ => None,
        })
        .find(|z| qname.is_in_zone(z))
}

/// The SOA owner (zone apex) in the authority section, if any.
fn soa_owner(msg: &wire::Message) -> Option<Name> {
    msg.authority
        .iter()
        .find(|r| r.rtype == consts::rtype::SOA)
        .map(|r| r.name.clone())
}

/// Does `msg` carry a validated NSEC/NSEC3 proving `qname` has no exact match?
/// Required to accept a wildcard-expanded positive answer as Secure (RFC 4035
/// §5.3.4): a name that actually exists cannot be proven non-existent, so this
/// defeats replay of a wildcard signature onto a real name. Only RRSIG-validated
/// denial records are considered. Fail-closed (no proof → false → Bogus).
fn proves_no_exact_match(
    msg: &wire::Message,
    qname: &Name,
    zone: &Name,
    keys: &[&[u8]],
    now: u32,
) -> bool {
    let nsecs = collect_validated_nsec(msg, keys, now);
    if denial::nsec_proves_nonexistence(&nsecs, qname) {
        return true;
    }
    let nsec3s = collect_validated_nsec3(msg, keys, now);
    denial::nsec3_proves_name_nonexistent(&nsec3s, qname, zone)
}

/// Validate the denial of existence in `msg` for `qname`/`qtype` under `zone`'s
/// `keys` (NXDOMAIN or NODATA). Only validated NSEC/NSEC3 records are trusted.
fn validate_denial(
    msg: &wire::Message,
    qname: &Name,
    qtype: u16,
    zone: &Name,
    keys: &[&[u8]],
    now: u32,
) -> bool {
    let nsecs = collect_validated_nsec(msg, keys, now);
    let nsec3s = collect_validated_nsec3(msg, keys, now);
    if nsecs.is_empty() && nsec3s.is_empty() {
        return false;
    }
    if msg.header.rcode_low() == consts::rcode::NXDOMAIN {
        denial::nsec_proves_nxdomain(&nsecs, qname, zone)
            || denial::nsec3_proves_nxdomain(&nsec3s, qname, zone)
    } else {
        // NODATA: the name exists, the type does not.
        nsecs
            .iter()
            .any(|nz| denial::nsec_proves_nodata(&nz.owner, nz.bitmap, qname, qtype))
            || denial::nsec3_proves_nodata(&nsec3s, qname, qtype)
    }
}

/// Full DNSSEC verdict for a resolved message (positive answer or negative).
/// Fetches DNSKEY/DS through `fetcher` (the resolver's own DO descent) to build
/// the chain of trust, then validates the data. Fail-closed: a signed zone whose
/// data carries no usable signature/proof is Bogus.
pub async fn validate<F: Fetcher>(
    fetcher: &F,
    qname: &Name,
    qtype: u16,
    msg: &wire::Message,
    now: u32,
) -> Verdict {
    validate_full(fetcher, qname, qtype, msg, now).await.0
}

/// Like [`validate`] but also returns the authority records to serve with a NEGATIVE
/// answer (RFC 2308 §3). For a Secure denial these are ONLY the SOA RRset at the zone
/// apex that itself RRSIG-validates under the zone keys (a forged/unsigned/out-of-
/// bailiwick SOA is dropped, so it can never ride out under AD=1 — audit Finding 1),
/// plus the in-bailiwick NSEC/NSEC3 denial records and RRSIGs. For an Insecure
/// (proven-unsigned) zone, the in-bailiwick SOA served WITHOUT AD. Empty for positive
/// answers and for Bogus.
pub async fn validate_full<F: Fetcher>(
    fetcher: &F,
    qname: &Name,
    qtype: u16,
    msg: &wire::Message,
    now: u32,
) -> (Verdict, Vec<wire::Record>) {
    // Determine the signing zone from an RRSIG; absent any RRSIG the data is
    // unsigned — only call that Insecure if the enclosing zone is PROVEN unsigned.
    // The signing zone of a legitimate answer is always at or above qname. An
    // attacker can attach a junk RRSIG (or forge the SOA owner) whose name points
    // at an unrelated, genuinely-insecure zone to coerce an `Insecure` verdict on
    // a signed name (DNSSEC downgrade — the forged answer would then be served
    // without SERVFAIL). Bind the zone to qname: any signer / SOA owner that does
    // not enclose qname is ignored, and such data falls through to Bogus.
    let Some(zone) = answer_zone(msg, qname).or_else(|| zone_apex(msg).filter(|z| qname.is_in_zone(z)))
    else {
        let z = soa_owner(msg)
            .filter(|z| qname.is_in_zone(z))
            .unwrap_or_else(|| qname.clone());
        return match trusted_keys_for(fetcher, &z, now).await.0 {
            Verdict::Insecure => (Verdict::Insecure, inbailiwick_soa(msg, qname)),
            _ => (Verdict::Bogus, Vec::new()),
        };
    };

    let (chain, keys) = trusted_keys_for(fetcher, &zone, now).await;
    match chain {
        Verdict::Bogus => return (Verdict::Bogus, Vec::new()),
        Verdict::Insecure => return (Verdict::Insecure, inbailiwick_soa(msg, qname)),
        Verdict::Secure => {}
    }
    let key_refs: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();

    // Positive answer for the queried type, or a CNAME for the name.
    let ans_type = if msg
        .answers
        .iter()
        .any(|r| r.rtype == qtype && r.name.eq_ignore_ascii_case(qname))
    {
        Some(qtype)
    } else if msg
        .answers
        .iter()
        .any(|r| r.rtype == consts::rtype::CNAME && r.name.eq_ignore_ascii_case(qname))
    {
        Some(consts::rtype::CNAME)
    } else {
        None
    };

    if let Some(t) = ans_type {
        let rdatas: Vec<&Rdata> = msg
            .answers
            .iter()
            .filter(|r| r.rtype == t && r.name.eq_ignore_ascii_case(qname))
            .map(|r| &r.rdata)
            .collect();
        let (_rd, sigs) = split(&msg.answers, t);
        let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
        let verdict = match verify::validate_rrset_wc(
            qname,
            consts::class::IN,
            t,
            &rdatas,
            &sig_refs,
            &key_refs,
            now,
        ) {
            None => Verdict::Bogus,
            Some(false) => Verdict::Secure,
            // RFC 4035 §5.3.4: a wildcard-expanded answer is Secure only if the
            // response also proves qname has no exact match (a validated NSEC/NSEC3
            // covering it). Without that, a wildcard RRSIG could be replayed onto an
            // existing name. Fail-closed: no proof → Bogus.
            Some(true) => {
                if proves_no_exact_match(msg, qname, &zone, &key_refs, now) {
                    Verdict::Secure
                } else {
                    Verdict::Bogus
                }
            }
        };
        return (verdict, Vec::new()); // positive answer: no authority served
    }

    // Negative answer: the denial proof must validate under the zone keys.
    if validate_denial(msg, qname, qtype, &zone, &key_refs, now) {
        (
            Verdict::Secure,
            validated_negative_authority(msg, &zone, &key_refs, now),
        )
    } else {
        (Verdict::Bogus, Vec::new())
    }
}

/// In-bailiwick SOA records (owner encloses qname) — for an Insecure (proven-unsigned)
/// negative answer, where the SOA is served WITHOUT AD (there is no signature to check).
fn inbailiwick_soa(msg: &wire::Message, qname: &Name) -> Vec<wire::Record> {
    msg.authority
        .iter()
        .filter(|r| r.rtype == consts::rtype::SOA && qname.is_in_zone(&r.name))
        .cloned()
        .collect()
}

/// Validated authority for a SECURE negative answer: the SOA RRset at the zone apex,
/// included ONLY if it RRSIG-validates under the zone keys (a forged/unsigned SOA is
/// dropped so it can never be served under AD=1 — audit Finding 1), plus the
/// in-bailiwick NSEC/NSEC3 denial records and RRSIGs. DO-gating is applied by the
/// serving layer (`wire_negative`).
fn validated_negative_authority(
    msg: &wire::Message,
    zone: &Name,
    keys: &[&[u8]],
    now: u32,
) -> Vec<wire::Record> {
    let mut out: Vec<wire::Record> = Vec::new();
    // SOA at the zone apex — only when its RRset RRSIG-validates.
    let soa_rdatas: Vec<&Rdata> = msg
        .authority
        .iter()
        .filter(|r| r.rtype == consts::rtype::SOA && r.name.eq_ignore_ascii_case(zone))
        .map(|r| &r.rdata)
        .collect();
    let (_rd, soa_sigs) = split(&msg.authority, consts::rtype::SOA);
    let soa_sig_refs: Vec<&[u8]> = soa_sigs.iter().map(|v| v.as_slice()).collect();
    if !soa_rdatas.is_empty()
        && verify::validate_rrset(
            zone,
            consts::class::IN,
            consts::rtype::SOA,
            &soa_rdatas,
            &soa_sig_refs,
            keys,
            now,
        )
    {
        out.extend(
            msg.authority
                .iter()
                .filter(|r| r.rtype == consts::rtype::SOA && r.name.eq_ignore_ascii_case(zone))
                .cloned(),
        );
    }
    // Denial proof (NSEC/NSEC3) + signatures, restricted to records within the zone.
    out.extend(
        msg.authority
            .iter()
            .filter(|r| {
                (matches!(r.rtype, consts::rtype::NSEC | consts::rtype::NSEC3)
                    || r.rtype == consts::rtype::RRSIG)
                    && r.name.is_in_zone(zone)
            })
            .cloned(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_path_orders_root_down() {
        let p = delegation_path(&Name::from_ascii("cloudflare.com.").unwrap());
        let labels: Vec<String> = p.iter().map(|n| n.to_ascii()).collect();
        assert_eq!(labels, vec!["com.".to_string(), "cloudflare.com.".to_string()]);
        assert!(delegation_path(&Name::root()).is_empty());
    }

    #[test]
    fn dnskey_cache_ttl_bounded_by_rrsig_expiration() {
        // RRSIG rdata layout: type_covered(2) algo(1) labels(1) orig_ttl(4)
        // sig_expiration(4) ... — put the expiration (=1000) at offset 8..12.
        let mut sig = vec![0u8; 18];
        sig[8..12].copy_from_slice(&1000u32.to_be_bytes());
        let one = std::slice::from_ref(&sig);
        // RRset TTL 5000 but the signature expires at t=1000 → from now=600, cap 400.
        assert_eq!(dnskey_cache_ttl(5000, one, 600), 400);
        // RRset TTL 100 is shorter than the remaining signature validity → TTL wins.
        assert_eq!(dnskey_cache_ttl(100, one, 600), 100);
        // No signatures supplied → fall back to the RRset TTL.
        assert_eq!(dnskey_cache_ttl(300, &[], 600), 300);
        // Signature already expired → 0 (the cache's TTL_FLOOR clamps the min age).
        assert_eq!(dnskey_cache_ttl(5000, one, 2000), 0);
    }

    // A DO-over-TCP fetcher against a public resolver, CD=1 (raw records).
    struct DoFetcher;
    impl Fetcher for DoFetcher {
        async fn fetch(&self, name: &Name, qtype: u16) -> Option<wire::Message> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut idb = [0u8; 2];
            let _ = getrandom::fill(&mut idb);
            let mut enc = wire::Encoder::uncompressed();
            wire::Header { id: u16::from_be_bytes(idb), flags: 0x0110, qdcount: 1, ancount: 0, nscount: 0, arcount: 1 }.emit(&mut enc);
            wire::Question::new(name.clone(), qtype).emit(&mut enc);
            enc.u8(0);
            enc.u16(consts::rtype::OPT);
            enc.u16(1232);
            enc.u32(0x0000_8000);
            enc.u16(0);
            let q = enc.into_vec();
            let mut s = tokio::net::TcpStream::connect("8.8.8.8:53").await.ok()?;
            s.write_all(&(q.len() as u16).to_be_bytes()).await.ok()?;
            s.write_all(&q).await.ok()?;
            let mut lb = [0u8; 2];
            s.read_exact(&mut lb).await.ok()?;
            let mut resp = vec![0u8; u16::from_be_bytes(lb) as usize];
            s.read_exact(&mut resp).await.ok()?;
            wire::Message::parse(&resp).ok()
        }
    }

    fn now() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
    }

    // Live: a signed zone is Secure, a bogus zone is Bogus, an unsigned zone is
    // Insecure.  cargo test -- --ignored verdicts_live
    #[tokio::test]
    #[ignore]
    async fn verdicts_live() {
        let f = DoFetcher;
        let now = now();

        let cf = Name::from_ascii("cloudflare.com.").unwrap();
        let am = f.fetch(&cf, consts::rtype::A).await.unwrap();
        let v = validate(&f, &cf, consts::rtype::A, &am, now).await;
        eprintln!("cloudflare.com A -> {v:?}");
        assert_eq!(v, Verdict::Secure);

        let bad = Name::from_ascii("dnssec-failed.org.").unwrap();
        let bm = f.fetch(&bad, consts::rtype::A).await.unwrap();
        let vb = validate(&f, &bad, consts::rtype::A, &bm, now).await;
        eprintln!("dnssec-failed.org A -> {vb:?}");
        assert_eq!(vb, Verdict::Bogus);

        // google.com is delegated unsigned (no DS) under the signed .com → Insecure,
        // and that must be PROVEN by validated NSEC3 NODATA, not just assumed.
        let un = Name::from_ascii("google.com.").unwrap();
        let (chain, _) = trusted_keys_for(&f, &un, now).await;
        eprintln!("google.com chain -> {chain:?}");
        assert_eq!(chain, Verdict::Insecure);

        // Regression: reverse-DNS trees routinely skip delegation levels (RFC
        // 2317-style — confirmed live via `dig +trace -x 1.1.1.1`: the real chain
        // is in-addr.arpa. -> 1.in-addr.arpa. (APNIC/ARIN) -> 1.1.1.in-addr.arpa.
        // (Cloudflare), with NO separate delegation at 1.1.in-addr.arpa. — that
        // label has no NS of its own). Before the fix, `delegation_path`'s
        // synthesized (non-cut) boundary at 1.1.in-addr.arpa. had an empty DS
        // answer misread as "insecure delegation ends here", short-circuiting the
        // walk into Bogus/SERVFAIL before it ever reached the real cut. The real
        // cut (1.1.1.in-addr.arpa., confirmed live: `dig 1.1.1.in-addr.arpa DS` →
        // NODATA + valid NSEC) is itself genuinely unsigned — Quad9 and
        // Cloudflare's own resolver both answer this exact query without the AD
        // bit too — so the correct verdict is Insecure, not Bogus: the fix must
        // reach and correctly validate the REAL cut, not fabricate security that
        // was never there.
        let ptr = Name::from_ascii("1.1.1.1.in-addr.arpa.").unwrap();
        let (ptr_chain, _) = trusted_keys_for(&f, &ptr, now).await;
        eprintln!("1.1.1.1.in-addr.arpa. chain -> {ptr_chain:?}");
        assert_eq!(ptr_chain, Verdict::Insecure);
    }
}
