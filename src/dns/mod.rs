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
pub mod prefetch;
pub mod ratelimit;
pub mod server;
pub mod recursor;
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
