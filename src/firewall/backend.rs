// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Firewall backend detection and rule lifecycle management (#90).

use std::process::Command;
use std::sync::Mutex;

use tracing::{info, warn};

use super::PortSet;

/// Detected firewall backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ufw,
    Nftables,
    Iptables,
    /// No supported firewall found — all operations are no-ops.
    None,
}

impl Backend {
    fn detect() -> Self {
        if cmd_exists("ufw") && ufw_active() {
            return Backend::Ufw;
        }
        if cmd_exists("nft") {
            return Backend::Nftables;
        }
        if cmd_exists("iptables") {
            return Backend::Iptables;
        }
        Backend::None
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Ufw => "ufw",
            Backend::Nftables => "nftables",
            Backend::Iptables => "iptables",
            Backend::None => "none",
        }
    }
}

fn cmd_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ufw_active() -> bool {
    Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
        .unwrap_or(false)
}

/// An opened firewall rule, tracked for cleanup on shutdown.
#[derive(Debug, Clone)]
struct Rule {
    port: u16,
    proto: &'static str,
    /// nftables only: handle number returned after `nft add rule` for deletion.
    nft_handle: Option<u64>,
}

/// Manages the lifecycle of firewall rules opened by this Runbound instance.
pub struct FirewallManager {
    backend: Backend,
    tag: String,
    dry_run: bool,
    /// Rules opened by this instance — tracked for shutdown cleanup.
    opened: Mutex<Vec<Rule>>,
}

impl FirewallManager {
    /// Detect the active firewall backend and create a manager.
    ///
    /// `manage: false` in config → returns a no-op manager (`Backend::None`).
    pub fn new(manage: bool, backend_override: Option<&str>, tag: &str) -> Self {
        let dry_run = std::env::var("RUNBOUND_FIREWALL_DRY_RUN").as_deref() == Ok("1");

        let backend = if !manage {
            Backend::None
        } else {
            match backend_override {
                Some("ufw") => Backend::Ufw,
                Some("nftables") => Backend::Nftables,
                Some("iptables") => Backend::Iptables,
                Some("none") | Some("no") => Backend::None,
                _ => Backend::detect(),
            }
        };

        if dry_run && backend != Backend::None {
            info!(
                backend = backend.as_str(),
                "firewall dry-run mode — no rules will be modified"
            );
        } else if backend != Backend::None {
            info!(backend = backend.as_str(), "firewall management active");
        } else {
            info!("firewall management disabled or no supported backend detected");
        }

        Self {
            backend,
            tag: tag.to_owned(),
            dry_run,
            opened: Mutex::new(Vec::new()),
        }
    }

    /// Open firewall rules for the ports in `ports`.
    /// Errors are logged as warnings; startup continues regardless.
    pub fn open(&self, ports: &PortSet) {
        if self.backend == Backend::None {
            return;
        }

        for (port, proto) in ports.rules() {
            match self.open_rule(port, proto) {
                Ok(handle) => {
                    let mut g = self.opened.lock().unwrap_or_else(|e| e.into_inner());
                    g.push(Rule {
                        port,
                        proto,
                        nft_handle: handle,
                    });
                }
                Err(e) => warn!(port, proto, err=%e, "firewall: failed to open port — continuing"),
            }
        }
    }

    /// Close all rules opened by this instance.
    pub fn close(&self) {
        if self.backend == Backend::None {
            return;
        }
        let rules: Vec<Rule> = {
            let mut g = self.opened.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *g)
        };
        for rule in &rules {
            if let Err(e) = self.close_rule(rule) {
                warn!(port=rule.port, proto=rule.proto, err=%e, "firewall: failed to close port");
            }
        }
    }

    /// Re-sync open rules to `new`: open ports newly desired, close ports no longer
    /// desired, leave unchanged ones in place. Used on live encrypted-DNS changes so
    /// the firewall tracks DoT/DoH/DoQ being enabled / disabled / re-ported (#tls-fw).
    pub fn resync(&self, new: &PortSet) {
        if self.backend == Backend::None {
            return;
        }
        let desired = new.rules();
        let mut opened = self.opened.lock().unwrap_or_else(|e| e.into_inner());
        let mut keep: Vec<Rule> = Vec::with_capacity(opened.len());
        for rule in std::mem::take(&mut *opened) {
            if desired.iter().any(|(p, pr)| *p == rule.port && *pr == rule.proto) {
                keep.push(rule);
            } else if let Err(e) = self.close_rule(&rule) {
                warn!(port = rule.port, proto = rule.proto, err = %e, "firewall: resync close failed");
            }
        }
        for (port, proto) in desired {
            if !keep.iter().any(|r| r.port == port && r.proto == proto) {
                match self.open_rule(port, proto) {
                    Ok(handle) => keep.push(Rule { port, proto, nft_handle: handle }),
                    Err(e) => warn!(port, proto, err = %e, "firewall: resync open failed"),
                }
            }
        }
        *opened = keep;
    }

    #[allow(dead_code)]
    /// Returns the backend name and the list of currently open rules (for the API).
    pub fn status(&self) -> (String, Vec<(u16, &'static str)>) {
        let g = self.opened.lock().unwrap_or_else(|e| e.into_inner());
        let rules = g.iter().map(|r| (r.port, r.proto)).collect();
        (self.backend.as_str().to_owned(), rules)
    }

    fn open_rule(&self, port: u16, proto: &'static str) -> Result<Option<u64>, String> {
        let tag = &self.tag;
        match self.backend {
            Backend::Ufw => {
                let rule = format!("{port}/{proto}");
                if self.dry_run {
                    info!(
                        cmd = format!("ufw allow {rule} comment {tag:?}"),
                        "firewall dry-run"
                    );
                    return Ok(None);
                }
                run("ufw", &["allow", &rule, "comment", tag]).map(|_| None)
            }
            Backend::Nftables => {
                let proto_clause = format!("{proto} dport {port}");
                let comment = format!("comment \\\"{}\\\"", tag);
                if self.dry_run {
                    info!(
                        cmd = format!(
                            "nft add rule inet filter input {proto_clause} accept {comment}"
                        ),
                        "firewall dry-run"
                    );
                    return Ok(None);
                }
                // nft needs proto / dport / port as separate tokens, not one string.
                let port_str = port.to_string();
                let out = run(
                    "nft",
                    &[
                        "add", "rule", "inet", "filter", "input",
                        proto, "dport", &port_str,
                        "accept", "comment", tag,
                    ],
                )?;
                // Parse handle from "# handle N" in output
                let handle = out.lines().find_map(|l| {
                    l.strip_prefix("# handle ")
                        .and_then(|s| s.trim().parse::<u64>().ok())
                });
                Ok(handle)
            }
            Backend::Iptables => {
                if self.dry_run {
                    info!(cmd=format!("iptables -A INPUT -p {proto} --dport {port} -m comment --comment {tag:?} -j ACCEPT"), "firewall dry-run");
                    return Ok(None);
                }
                run(
                    "iptables",
                    &[
                        "-A",
                        "INPUT",
                        "-p",
                        proto,
                        "--dport",
                        &port.to_string(),
                        "-m",
                        "comment",
                        "--comment",
                        tag,
                        "-j",
                        "ACCEPT",
                    ],
                )
                .map(|_| None)
            }
            Backend::None => Ok(None),
        }
    }

    fn close_rule(&self, rule: &Rule) -> Result<(), String> {
        let tag = &self.tag;
        let port = rule.port;
        let proto = rule.proto;
        match self.backend {
            Backend::Ufw => {
                let r = format!("{port}/{proto}");
                if self.dry_run {
                    info!(
                        cmd = format!("ufw delete allow {r}"),
                        "firewall dry-run close"
                    );
                    return Ok(());
                }
                // SEC-I15: delete the exact rule we created (port/proto + our comment),
                // so a same-port admin rule is never removed; fall back to the broad match
                // on ufw versions that ignore the comment in `delete`.
                if run("ufw", &["delete", "allow", &r, "comment", tag]).is_ok() {
                    Ok(())
                } else {
                    run("ufw", &["delete", "allow", &r]).map(|_| ())
                }
            }
            Backend::Nftables => match rule.nft_handle {
                Some(h) => {
                    if self.dry_run {
                        info!(handle = h, "firewall dry-run close nft rule");
                        return Ok(());
                    }
                    run(
                        "nft",
                        &[
                            "delete",
                            "rule",
                            "inet",
                            "filter",
                            "input",
                            "handle",
                            &h.to_string(),
                        ],
                    )
                    .map(|_| ())
                }
                None => {
                    warn!(
                        port,
                        proto, "nftables: no handle stored — cannot remove rule"
                    );
                    Ok(())
                }
            },
            Backend::Iptables => {
                if self.dry_run {
                    info!(cmd=format!("iptables -D INPUT -p {proto} --dport {port} -m comment --comment {tag:?} -j ACCEPT"), "firewall dry-run close");
                    return Ok(());
                }
                run(
                    "iptables",
                    &[
                        "-D",
                        "INPUT",
                        "-p",
                        proto,
                        "--dport",
                        &port.to_string(),
                        "-m",
                        "comment",
                        "--comment",
                        tag,
                        "-j",
                        "ACCEPT",
                    ],
                )
                .map(|_| ())
            }
            Backend::None => Ok(()),
        }
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
