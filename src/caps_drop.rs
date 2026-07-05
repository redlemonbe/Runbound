// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//! Post-startup capability drop (pentest hardening).
//!
//! The XDP fast path needs `CAP_BPF` (BPF_MAP_CREATE / BPF_PROG_LOAD) and
//! `CAP_PERFMON` (verifier requirement for the XDP program type) — but only at
//! *load time*. Every runtime BPF operation after that (icmp ban/unban,
//! blacklist reload, domain-routing gate, XSKMAP registration) updates a map
//! through an fd the process already holds; the kernel checks those against
//! the fd's open mode (`map_get_sys_perms`), not against the caller's
//! capabilities again — so CAP_BPF is never re-checked after the map/program
//! was created. See `bpf(2)`: the capability gate is on `BPF_MAP_CREATE` /
//! `BPF_PROG_LOAD`, not on `BPF_MAP_UPDATE_ELEM` et al.
//!
//! Threat model: `AmbientCapabilities=` (systemd) is what lets a non-root,
//! non-file-capability process's capabilities survive `execve()`. If the DNS
//! server were ever remote-code-executed, that RCE — or any child process it
//! spawns — would inherit CAP_BPF/CAP_PERFMON for the rest of the process
//! lifetime, and CAP_BPF alone is sufficient to load an arbitrary eBPF
//! program (kernel r/w primitive → root). Dropping these two capabilities
//! from Effective/Permitted/Inheritable/Ambient right after the one-time XDP
//! load/attach sequence closes that window for the remaining (multi-day)
//! process lifetime, with zero cost on the query path: this runs once, at
//! boot, after the sockets are already bound and before the server starts
//! answering queries — it is not in any per-query or per-packet code path.
//!
//! `CapabilityBoundingSet=` cannot be shrunk here (that needs `CAP_SETPCAP`,
//! which the unit does not grant — intentionally, to keep the bounding-set
//! attack surface minimal too). That is not a gap: the bounding set alone
//! never grants a capability, it only caps what a *future* privileged re-exec
//! (e.g. a setuid/file-capability binary) could gain. Once Effective +
//! Permitted are cleared, in-process code and every child process this
//! process spawns get `CAP_BPF`/`CAP_PERFMON` = absent, which is what
//! actually matters for both the in-process-exploit and the
//! spawn-a-shell RCE scenarios.

use caps::{CapSet, Capability};

/// Capabilities that are only needed for the one-time XDP load/attach
/// sequence, never for any operation after it.
const LOAD_TIME_ONLY: &[Capability] = &[Capability::CAP_BPF, Capability::CAP_PERFMON];

/// Drop `LOAD_TIME_ONLY` from Effective, Permitted, Inheritable and Ambient.
///
/// Best-effort: a failure here (e.g. the capability was never granted in the
/// first place — plain `xdp: no` deployments, or running as full root in a
/// dev/test environment) is logged and otherwise ignored. This is a
/// defence-in-depth hardening step, not a functional requirement — it must
/// never take the DNS server down.
///
/// Call exactly once, after the XDP program is loaded/attached and all
/// startup-time BPF map initialisation (ICMP config push, CPUMAP, XSKMAP
/// registration) has completed. Safe to call unconditionally even when XDP
/// is disabled or the `xdp` feature is not compiled in — dropping a
/// capability the process never held is a no-op.
pub fn drop_bpf_load_time_capabilities() {
    for &set in &[
        CapSet::Ambient,
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
    ] {
        for &cap in LOAD_TIME_ONLY {
            // caps::has_cap can itself fail (e.g. sandboxed/odd environments);
            // treat that the same as "already absent" rather than panic.
            if !caps::has_cap(None, set, cap).unwrap_or(false) {
                continue;
            }
            if let Err(e) = caps::drop(None, set, cap) {
                tracing::warn!(
                    capability = ?cap,
                    set = ?set,
                    err = %e,
                    "post-startup capability drop failed — continuing with the \
                     capability still held (hardening best-effort, not fatal)"
                );
            }
        }
    }

    let remaining: Vec<Capability> = LOAD_TIME_ONLY
        .iter()
        .copied()
        .filter(|&cap| {
            [CapSet::Ambient, CapSet::Effective, CapSet::Permitted, CapSet::Inheritable]
                .iter()
                .any(|&set| caps::has_cap(None, set, cap).unwrap_or(false))
        })
        .collect();

    if remaining.is_empty() {
        tracing::info!(
            "CAP_BPF/CAP_PERFMON dropped post-XDP-setup — no longer available to this \
             process or any child it spawns for the rest of its lifetime"
        );
    } else {
        tracing::warn!(
            ?remaining,
            "some load-time capabilities are still held after the drop attempt"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The function must never panic, on any system (with or without the
    /// capabilities, running as root or not, inside a container or not) —
    /// it is a best-effort hardening step called unconditionally at boot.
    #[test]
    fn drop_never_panics() {
        drop_bpf_load_time_capabilities();
        drop_bpf_load_time_capabilities(); // idempotent: dropping twice is fine
    }
}
