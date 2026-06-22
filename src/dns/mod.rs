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
#[cfg(feature = "recursor")]
pub mod recursor;
pub mod zone_signer;
pub mod dnssec_sign;
pub mod plain_server;
pub mod wire;
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

/// Stub types and functions exported when the `recursor` feature is disabled.
/// Allows callers to use `dns::recursor::SharedRecursor`, `dns::recursor::mode_atomic()`,
/// and `dns::recursor::shared_recursor()` unconditionally — they produce no-ops.
#[cfg(not(feature = "recursor"))]
pub mod recursor {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU8;
    use crate::config::parser::ResolutionMode;

    /// Opaque no-op handle — forward mode only when recursor feature is off.
    #[derive(Clone)]
    pub struct SharedRecursor(());

    impl SharedRecursor {
        pub fn load_full(&self) -> Option<Arc<()>> { None }
    }

    /// Always returns forward mode (0).
    pub fn mode_atomic(_mode: ResolutionMode) -> Arc<AtomicU8> {
        Arc::new(AtomicU8::new(0))
    }

    /// Returns a no-op SharedRecursor handle.
    pub fn shared_recursor(_mode: ResolutionMode, _dnssec: bool) -> SharedRecursor {
        SharedRecursor(())
    }

    /// No-op — recursor feature is off, rebuild always returns an error.
    #[allow(dead_code)]
    pub fn rebuild_shared(
        _handle: &SharedRecursor,
        _mode: ResolutionMode,
        _dnssec: bool,
    ) -> Result<(), String> {
        Err("recursor feature not compiled in".into())
    }
}
