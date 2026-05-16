pub mod acl;
pub mod local;
pub mod ratelimit;
pub mod server;
pub mod xdp;

pub use acl::Acl;
pub use local::{ZoneAction};
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
}

impl std::fmt::Display for BlacklistAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlacklistAction::Refuse   => write!(f, "refuse"),
            BlacklistAction::NxDomain => write!(f, "nxdomain"),
        }
    }
}

impl From<&BlacklistAction> for ZoneAction {
    fn from(b: &BlacklistAction) -> Self {
        match b {
            BlacklistAction::Refuse   => ZoneAction::Refuse,
            BlacklistAction::NxDomain => ZoneAction::NxDomain,
        }
    }
}
