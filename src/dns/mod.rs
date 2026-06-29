pub mod forward;
pub mod simd;
pub mod ddns;
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
pub mod acl;
pub mod cache_snapshot;
pub mod hasher;
pub mod wire_builder;
pub mod kernel_loop;
pub mod local;
pub mod axfr;
pub mod tsig;
pub mod prefetch;
pub mod ratelimit;
pub mod server;
// In-house iterative recursive resolver + DNSSEC validation (hickory-free).
// The default serving path uses these for `resolution: full-recursion`.
pub mod recursor_wire;
pub mod dnssec_verify;
pub mod dnssec_denial;
pub mod dnssec_chain;
pub mod zone_signer;
pub mod dnssec_sign;
pub mod plain_server;
pub mod wire;
// hickory <-> wire converter — only the recursor handler and the differential
// oracle tests still cross the boundary; gone from the default release build.
#[cfg(test)]
pub mod wire_bridge;
pub mod wire_serve;
pub mod xdp;

pub use acl::Acl;
pub use local::ZoneAction;
pub use ratelimit::RateLimiter;
pub use server::run_dns_server;

use serde::{Deserialize, Serialize};

/// How a blocked domain responds to DNS queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlacklistAction {
    /// Client receives REFUSED — domain exists but is blocked
    #[default]
    Refuse,
    /// Client receives NXDOMAIN — domain appears to not exist
    NxDomain,
    /// Redirect to block page HTTP server IP.
    BlockPage,
}

impl std::fmt::Display for BlacklistAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlacklistAction::Refuse => write!(f, "refuse"),
            BlacklistAction::NxDomain => write!(f, "nxdomain"),
            BlacklistAction::BlockPage => write!(f, "block_page"),
        }
    }
}

impl From<&BlacklistAction> for ZoneAction {
    fn from(b: &BlacklistAction) -> Self {
        match b {
            BlacklistAction::Refuse => ZoneAction::Refuse,
            BlacklistAction::NxDomain => ZoneAction::NxDomain,
            BlacklistAction::BlockPage => ZoneAction::BlockPage,
        }
    }
}

/// Resolution-mode control. Iterative resolution + DNSSEC validation live in
/// [`recursor_wire`] / [`dnssec_chain`] and run on the serving path; this module
/// only carries the hot-swappable mode flag and a (stateless) handle for the API
/// and relay plumbing.
pub mod recursor {
    use crate::config::parser::ResolutionMode;
    use std::sync::atomic::AtomicU8;
    use std::sync::Arc;

    /// Stateless handle kept for API/relay plumbing; the validating resolver
    /// holds no per-mode state of its own.
    #[derive(Clone)]
    pub struct SharedRecursor(());

    impl SharedRecursor {
        pub fn load_full(&self) -> Option<Arc<()>> {
            None
        }
    }

    /// 1 for full-recursion, 0 for forward — read on the serving hot path.
    pub fn mode_atomic(mode: ResolutionMode) -> Arc<AtomicU8> {
        Arc::new(AtomicU8::new(u8::from(mode == ResolutionMode::FullRecursion)))
    }

    pub fn shared_recursor(_mode: ResolutionMode, _dnssec: bool) -> SharedRecursor {
        SharedRecursor(())
    }
}
