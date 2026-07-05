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
    /// DoT / DoH / DoQ ports — `Some` only when encrypted DNS is configured
    /// (tls-service-pem + tls-service-key), so the firewall opens them too (#tls-fw).
    pub dot_port: Option<u16>,
    pub doh_port: Option<u16>,
    pub doq_port: Option<u16>,
}

impl PortSet {
    pub fn from_config(cfg: &UnboundConfig) -> Self {
        let tls_on = cfg.tls.cert_path.is_some() && cfg.tls.key_path.is_some();
        Self {
            dns_port: cfg.port,
            api_port: cfg.api_port,
            sync_port: if cfg.is_master() { cfg.sync_port } else { None },
            dot_port: tls_on.then(|| cfg.tls.dot_port.unwrap_or(853)),
            doh_port: tls_on.then(|| cfg.tls.doh_port.unwrap_or(443)),
            doq_port: tls_on.then(|| cfg.tls.doq_port.unwrap_or(853)),
        }
    }

    /// The (port, protocol) rules this set wants open. DoT/DoH are TCP, DoQ is UDP.
    pub fn rules(&self) -> Vec<(u16, &'static str)> {
        let mut r = vec![(self.dns_port, "udp"), (self.dns_port, "tcp")];
        if let Some(p) = self.api_port {
            r.push((p, "tcp"));
        }
        if let Some(p) = self.sync_port {
            r.push((p, "tcp"));
        }
        if let Some(p) = self.dot_port {
            r.push((p, "tcp"));
        }
        if let Some(p) = self.doh_port {
            r.push((p, "tcp"));
        }
        if let Some(p) = self.doq_port {
            r.push((p, "udp"));
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::UnboundConfig;

    #[test]
    fn rules_include_tls_ports_only_when_configured() {
        let mut cfg = UnboundConfig::defaults();
        cfg.port = 53;
        // no cert -> no TLS ports
        let r = PortSet::from_config(&cfg).rules();
        assert!(!r.iter().any(|(p, _)| *p == 853 || *p == 443), "TLS ports must be absent without a cert");
        // configure a cert -> DoT/DoH/DoQ rules appear
        cfg.tls.cert_path = Some("/x/cert.pem".into());
        cfg.tls.key_path = Some("/x/key.pem".into());
        let r = PortSet::from_config(&cfg).rules();
        assert!(r.contains(&(853, "tcp")), "DoT 853/tcp expected");
        assert!(r.contains(&(443, "tcp")), "DoH 443/tcp expected");
        assert!(r.contains(&(853, "udp")), "DoQ 853/udp expected");
    }
}
