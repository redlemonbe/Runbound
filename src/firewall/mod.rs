// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Auto firewall management (#90).
//
// At startup: detect active firewall backend, open exactly the ports Runbound
// needs based on config. At shutdown: close only the rules this instance opened.
//
// Safety invariants:
//   - Never flush or reset existing rules — only add/delete specific rules.
//   - Rules tagged with `tag` (config `firewall.tag`, default "runbound").
//   - If open fails → warning in log, startup continues unchanged.
//   - CAP_NET_ADMIN / root required; if absent → skip with warning.
//   - `RUNBOUND_FIREWALL_DRY_RUN=1` → log only, no changes.
//   - `manage: no` in config → skip entirely.

pub mod backend;

pub use backend::FirewallManager;

use crate::config::parser::UnboundConfig;

/// Set of ports Runbound needs open, derived from active config.
pub struct PortSet {
    pub dns_port: u16,
    pub api_port: Option<u16>,
    pub sync_port: Option<u16>,
}

impl PortSet {
    pub fn from_config(cfg: &UnboundConfig) -> Self {
        Self {
            dns_port: cfg.port,
            api_port: cfg.api_port,
            sync_port: if cfg.is_master() { cfg.sync_port } else { None },
        }
    }
}
