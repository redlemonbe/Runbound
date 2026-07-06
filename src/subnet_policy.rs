// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//
// Per-subnet / per-VLAN filtering policies (#8).
//
// Each policy adds extra-blacklisted domains for one source CIDR (additive to the
// global filter). The slow path checks `blocks()` in `serve_wire`; the resulting
// REFUSED is never cached, so it can't leak to other subnets.
//
// The fast-path cache ALSO consults this (via `has_policies()` + `blocks()` in
// `answer_from_cache`): an extra-blacklisted domain that also resolves normally can
// be positively cached, and a cache hit would otherwise be served without the
// per-subnet check — bypassing the policy for cached names. When a policy blocks a
// cached (src_ip, qname), the fast path falls back to `serve_wire`, which applies
// the block. `has_policies()` gates this on a single relaxed load, so the check is
// free when no policy is configured (the default). Per-subnet feed-override
// (un-blocking a globally-blocked domain) and per-subnet rate-limit are still NOT
// implemented — they would need deeper fast-path changes.

use crate::dns::acl::CidrBlock;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Fast no-policy gate: when no policy is configured (the default), the slow-path
/// `blocks()` check returns on a single relaxed load, skipping the `ArcSwap` load
/// (and its refcount bump) entirely — the feature costs nothing when unused.
static HAS_POLICIES: AtomicBool = AtomicBool::new(false);

/// A subnet policy as edited via the API and persisted to JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SubnetPolicy {
    /// Policy name. Optional in a request body: `PUT /api/policies/:name` takes the
    /// name from the path (the handler overrides this field), and a `POST` without a
    /// name is rejected by `upsert_policy_resp` with a clear 400 "name is required"
    /// instead of a cryptic 422 deserialization error when `name` is a hard field.
    #[serde(default)]
    pub name: String,
    /// Source CIDR this policy applies to, e.g. `"192.168.10.0/24"`.
    pub subnet: String,
    /// Domains blocked ONLY for clients in `subnet` (additive to the global filter).
    /// A listed domain blocks itself and all of its subdomains.
    #[serde(default)]
    pub blacklist_extra: Vec<String>,
}

struct Compiled {
    name: String,
    cidr: CidrBlock,
    domains: HashSet<String>,
    blocked: AtomicU64,
}

#[derive(Default)]
pub struct CompiledPolicies(Vec<Compiled>);

impl CompiledPolicies {
    /// Does a policy matching `ip` extra-blacklist `qname_lc` (or a parent of it)?
    /// `qname_lc` is the lowercased, optionally trailing-dotted query name.
    pub fn blocks(&self, ip: IpAddr, qname_lc: &str) -> bool {
        let name = qname_lc.trim_end_matches('.');
        for p in &self.0 {
            if p.cidr.contains(ip) && name_or_parent_in(&p.domains, name) {
                p.blocked.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
}

/// True if `name` or any of its parent domains is in `set`.
fn name_or_parent_in(set: &HashSet<String>, name: &str) -> bool {
    if set.contains(name) {
        return true;
    }
    let mut rest = name;
    while let Some(pos) = rest.find('.') {
        rest = &rest[pos + 1..];
        if !rest.is_empty() && set.contains(rest) {
            return true;
        }
    }
    false
}

fn store_path() -> PathBuf {
    crate::runtime::base_dir().join("subnet-policies.json")
}

/// Persisted policies (empty if the file is absent). A CORRUPT file is logged and
/// treated as empty rather than crashing — but the warning makes the resulting
/// fail-open (0 policies active) visible instead of silent.
pub fn load() -> Vec<SubnetPolicy> {
    match std::fs::read(store_path()) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "subnet-policies.json is corrupt — ignoring it (0 subnet policies active)");
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Persist the policies to JSON (write-then-rename).
pub fn save(policies: &[SubnetPolicy]) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(policies)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let path = store_path();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)
}

/// Compile the policies, carrying each unchanged-by-name policy's `blocked` counter
/// over from `prev` so the dashboard stat survives an edit to a *different* policy.
fn compile_with(policies: &[SubnetPolicy], prev: Option<&CompiledPolicies>) -> CompiledPolicies {
    let mut out = Vec::new();
    for p in policies {
        let Some(cidr) = CidrBlock::parse(&p.subnet) else {
            continue; // skip malformed CIDR (the API validates on write)
        };
        let domains = p
            .blacklist_extra
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        let prior = prev
            .and_then(|c| c.0.iter().find(|c| c.name == p.name))
            .map(|c| c.blocked.load(Ordering::Relaxed))
            .unwrap_or(0);
        out.push(Compiled {
            name: p.name.clone(),
            cidr,
            domains,
            blocked: AtomicU64::new(prior),
        });
    }
    CompiledPolicies(out)
}

/// Live, query-time policies — read on the slow serving path, swapped on API CRUD.
static LIVE: OnceLock<ArcSwap<CompiledPolicies>> = OnceLock::new();

/// Initialise the live policies from the persisted file (call once at startup).
pub fn init() {
    let compiled = compile_with(&load(), None);
    HAS_POLICIES.store(!compiled.0.is_empty(), Ordering::Relaxed);
    let _ = LIVE.set(ArcSwap::from_pointee(compiled));
}

/// Recompile and hot-swap the live policies after an API edit (carrying counters).
pub fn apply(policies: &[SubnetPolicy]) {
    let compiled = match LIVE.get() {
        Some(live) => compile_with(policies, Some(&live.load())),
        None => compile_with(policies, None),
    };
    HAS_POLICIES.store(!compiled.0.is_empty(), Ordering::Relaxed);
    match LIVE.get() {
        Some(live) => live.store(Arc::new(compiled)),
        None => {
            let _ = LIVE.set(ArcSwap::from_pointee(compiled));
        }
    }
}

/// Slow-path query check: is `qname_lc` extra-blacklisted for `ip` by some policy?
/// Returns on a single relaxed load when no policy is configured (the default).
#[inline]
pub fn blocks(ip: IpAddr, qname_lc: &str) -> bool {
    HAS_POLICIES.load(Ordering::Relaxed)
        && LIVE.get().is_some_and(|l| l.load().blocks(ip, qname_lc))
}

/// Fast-path gate: `true` iff at least one policy is configured. Single relaxed
/// load, so the fast path can skip the (allocating) wire→presentation qname
/// conversion entirely when no policy exists (the default).
#[inline]
pub fn has_policies() -> bool {
    HAS_POLICIES.load(Ordering::Relaxed)
}

/// Per-policy blocked counters (since the last edit) for the API / dashboard.
pub fn blocked_counts() -> Vec<(String, u64)> {
    LIVE.get()
        .map(|l| {
            l.load()
                .0
                .iter()
                .map(|c| (c.name.clone(), c.blocked.load(Ordering::Relaxed)))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(name: &str, subnet: &str, domains: &[&str]) -> SubnetPolicy {
        SubnetPolicy {
            name: name.into(),
            subnet: subnet.into(),
            blacklist_extra: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn matches_subnet_and_domain_with_subdomains() {
        let c = compile_with(&[pol("kids", "192.168.10.0/24", &["social.example.com"])], None);
        let in_subnet: IpAddr = "192.168.10.42".parse().unwrap();
        let other: IpAddr = "192.168.20.5".parse().unwrap();
        // exact + subdomain blocked inside the subnet
        assert!(c.blocks(in_subnet, "social.example.com."));
        assert!(c.blocks(in_subnet, "www.social.example.com"));
        // unrelated domain not blocked
        assert!(!c.blocks(in_subnet, "example.com"));
        // same domain, different subnet → not blocked
        assert!(!c.blocks(other, "social.example.com."));
    }
}
