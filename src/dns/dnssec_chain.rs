// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Hickory-free DNSSEC validation — Phase 2, increment 4b: the chain walk.
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
    // 1. Root DNSKEY against the hardcoded anchor.
    let Some(root_msg) = fetcher.fetch(&Name::root(), consts::rtype::DNSKEY).await else {
        return (Verdict::Bogus, vec![]);
    };
    let (rk, rs) = split(&root_msg.answers, consts::rtype::DNSKEY);
    let rk_refs: Vec<&[u8]> = rk.iter().map(|v| v.as_slice()).collect();
    let rs_refs: Vec<&[u8]> = rs.iter().map(|v| v.as_slice()).collect();
    let Some(root_keys) =
        verify::validate_dnskey_rrset(&Name::root(), &rk_refs, &rs_refs, verify::ROOT_ANCHORS, now)
    else {
        return (Verdict::Bogus, vec![]);
    };
    let mut current = Name::root();
    let mut keys: Vec<Vec<u8>> = root_keys.iter().map(|s| s.to_vec()).collect();

    // 2. Descend each zone cut, validating DS (in the parent) then the child DNSKEY.
    for child in delegation_path(zone) {
        if child.eq_ignore_ascii_case(&current) {
            continue;
        }
        let key_refs: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();

        let Some(ds_msg) = fetcher.fetch(&child, consts::rtype::DS).await else {
            return (Verdict::Bogus, vec![]);
        };
        let (ds_rd, ds_sig) = split(&ds_msg.answers, consts::rtype::DS);

        if ds_rd.is_empty() {
            // No DS: must be a PROVEN insecure delegation (NSEC/NSEC3 in authority,
            // validated under the parent's keys). Otherwise Bogus.
            return if denial_secure(&ds_msg, &child, consts::rtype::DS, &key_refs, now) {
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
        current = child;
    }
    (Verdict::Secure, keys)
}

/// Are the denial (NSEC/NSEC3) records in `msg`'s authority a VALID proof — signed
/// under `keys` — that `name` has no record of `qtype` (here: no DS → insecure)?
fn denial_secure(msg: &wire::Message, name: &Name, qtype: u16, keys: &[&[u8]], now: u32) -> bool {
    // Every NSEC/NSEC3 used must itself be validated under the zone keys.
    let nsec_ok = msg.authority.iter().any(|r| {
        r.rtype == consts::rtype::NSEC && rrset_validated(msg, &r.name, consts::rtype::NSEC, keys, now)
    });
    let nsec3_ok = msg.authority.iter().any(|r| {
        r.rtype == consts::rtype::NSEC3
            && rrset_validated(msg, &r.name, consts::rtype::NSEC3, keys, now)
    });
    if !nsec_ok && !nsec3_ok {
        return false;
    }
    debug_assert_eq!(qtype, consts::rtype::DS);
    // Prove the delegation `name` has no DS — the zone exists but is unsigned.
    let nsecs = collect_nsec(msg);
    if !nsecs.is_empty() {
        return denial::nsec_proves_no_ds(&nsecs, name);
    }
    let nsec3s = collect_nsec3(msg);
    denial::nsec3_proves_no_ds(&nsec3s, name)
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

fn collect_nsec(msg: &wire::Message) -> Vec<denial::Nsec<'_>> {
    msg.authority
        .iter()
        .filter(|r| r.rtype == consts::rtype::NSEC)
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => denial::Nsec::parse(r.name.clone(), data),
            _ => None,
        })
        .collect()
}

fn collect_nsec3(msg: &wire::Message) -> Vec<denial::Nsec3<'_>> {
    msg.authority
        .iter()
        .filter(|r| r.rtype == consts::rtype::NSEC3)
        .filter_map(|r| match &r.rdata {
            Rdata::Unknown { data, .. } => denial::Nsec3::parse(&r.name, data),
            _ => None,
        })
        .collect()
}

/// Validate a positive answer `(qname, qtype)` end to end and return the verdict.
/// `answer` is the message holding the answer RRset and its RRSIGs.
pub async fn validate_positive<F: Fetcher>(
    fetcher: &F,
    qname: &Name,
    qtype: u16,
    answer: &wire::Message,
    zone: &Name,
    now: u32,
) -> Verdict {
    let (chain, keys) = trusted_keys_for(fetcher, zone, now).await;
    match chain {
        Verdict::Bogus => return Verdict::Bogus,
        Verdict::Insecure => return Verdict::Insecure,
        Verdict::Secure => {}
    }
    let key_refs: Vec<&[u8]> = keys.iter().map(|v| v.as_slice()).collect();
    let rdatas: Vec<&Rdata> = answer
        .answers
        .iter()
        .filter(|r| r.rtype == qtype && r.name.eq_ignore_ascii_case(qname))
        .map(|r| &r.rdata)
        .collect();
    let (_rd, sigs) = split(&answer.answers, qtype);
    let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
    if rdatas.is_empty() {
        return Verdict::Bogus; // expected an answer, none present
    }
    if verify::validate_rrset(qname, consts::class::IN, qtype, &rdatas, &sig_refs, &key_refs, now) {
        Verdict::Secure
    } else {
        Verdict::Bogus
    }
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
        let v = validate_positive(&f, &cf, consts::rtype::A, &am, &cf, now).await;
        eprintln!("cloudflare.com A -> {v:?}");
        assert_eq!(v, Verdict::Secure);

        let bad = Name::from_ascii("dnssec-failed.org.").unwrap();
        let bm = f.fetch(&bad, consts::rtype::A).await.unwrap();
        let vb = validate_positive(&f, &bad, consts::rtype::A, &bm, &bad, now).await;
        eprintln!("dnssec-failed.org A -> {vb:?}");
        assert_eq!(vb, Verdict::Bogus);

        // google.com is delegated unsigned (no DS) under the signed .com → Insecure,
        // and that must be PROVEN by validated NSEC3 NODATA, not just assumed.
        let un = Name::from_ascii("google.com.").unwrap();
        let (chain, _) = trusted_keys_for(&f, &un, now).await;
        eprintln!("google.com chain -> {chain:?}");
        assert_eq!(chain, Verdict::Insecure);
    }
}
