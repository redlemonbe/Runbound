// SPDX-License-Identifier: AGPL-3.0-or-later
// ICMP echo responder — config types, stats, BPF map accessors, flood ban (#89).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use dashmap::DashMap;

/// In-memory config mirroring the BPF `icmp_cfg_entry` map entry.
#[derive(Clone, Debug)]
pub struct IcmpConfig {
    pub enabled: bool,
    pub rate_pps: u32,
    pub burst: u32,
    /// Rate-limited packets from same IP within one poll cycle to trigger a ban.
    pub ban_threshold: u32,
}

impl Default for IcmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rate_pps: 10,
            burst: 5,
            ban_threshold: 100,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum BanSource {
    IcmpFlood,
    Manual,
    Relay,
}

#[derive(Clone, Debug)]
pub struct BanEntry {
    pub ts: Instant,
    pub src: BanSource,
    /// Permanent ("blacklisted") ban — never auto-expires in cleanup.
    pub permanent: bool,
}

/// Command sent to the XDP poll task to apply/remove a kernel-level ban.
///
/// #228: v6 variants added so IPv6 bans reach the XDP fast path too (the poll
/// task pushes them into the `icmp_banned_v6` BPF map). The v4 variants are
/// unchanged — the proven IPv4 path is left byte-for-byte identical.
pub enum IcmpBanCmd {
    Ban(Ipv4Addr),
    Unban(Ipv4Addr),
    BanV6(Ipv6Addr),
    UnbanV6(Ipv6Addr),
}

/// Rust-side counters + ban tracking + channels for propagation.
///
/// # Channel design
/// `ban_cmd_tx/rx`: created at construction time in `new()`.
/// - NodeRelay and AppState clone `ban_cmd_tx` to forward ban commands.
/// - The XDP poll task calls `ban_cmd_rx.lock().take()` once to own the receiver.
///
/// `ban_propagate_tx`: set once by `build_and_launch` (where sync_journal is
/// available) to propagate new bans to slaves via relay.
pub struct IcmpStats {
    pub handled: AtomicU64,
    pub replied: AtomicU64,
    pub dropped: AtomicU64,  // = banned_drop (BPF stat index 2)
    pub rate_limited: AtomicU64,
    /// IPs currently banned by flood detection or manual API call.
    pub banned: DashMap<IpAddr, BanEntry, ahash::RandomState>,
    /// Sender cloned by NodeRelay/AppState to forward ban commands to the poll task.
    pub ban_cmd_tx: tokio::sync::mpsc::UnboundedSender<IcmpBanCmd>,
    /// Consumed once by the XDP poll task; None after that.
    pub ban_cmd_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<IcmpBanCmd>>>,
    /// Set once by build_and_launch to propagate new bans to slaves via relay.
    pub ban_propagate_tx: OnceLock<tokio::sync::mpsc::UnboundedSender<IpAddr>>,
    /// Cheap presence flag so the per-packet data-path check is ~free when no IP
    /// is banned (the common case): a single relaxed load, no DashMap hashing.
    pub banned_present: std::sync::atomic::AtomicBool,
}

impl IcmpStats {
    pub fn new() -> Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            handled: AtomicU64::new(0),
            replied: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            banned: DashMap::with_hasher(ahash::RandomState::default()),
            ban_cmd_tx: tx,
            ban_cmd_rx: Mutex::new(Some(rx)),
            ban_propagate_tx: OnceLock::new(),
            banned_present: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn ban(&self, ip: IpAddr, src: BanSource) {
        self.banned.insert(ip, BanEntry { ts: Instant::now(), src, permanent: false });
        self.banned_present.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Permanent ban ("blacklist") — survives expiry cleanup. Used by the API
    /// blacklist action; still propagated to slaves like any other ban.
    pub fn ban_permanent(&self, ip: IpAddr) {
        self.banned.insert(ip, BanEntry { ts: Instant::now(), src: BanSource::Manual, permanent: true });
        self.banned_present.store(true, std::sync::atomic::Ordering::Relaxed);
        self.persist_blacklist();
    }

    /// Per-packet data-path check (XDP enforces via the BPF `icmp_banned` map;
    /// the kernel slow path calls this so bans also drop in `xdp: no`).
    #[inline]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned_present.load(std::sync::atomic::Ordering::Relaxed) && self.banned.contains_key(&ip)
    }

    pub fn unban(&self, ip: IpAddr) {
        self.banned.remove(&ip);
        self.banned_present.store(!self.banned.is_empty(), std::sync::atomic::Ordering::Relaxed);
        self.persist_blacklist();
    }

    /// Remove ban entries older than  and unban from XDP fast path.
    /// Called periodically by a background task (default: every hour, 24h TTL).
    pub fn cleanup_expired_bans(&self, ttl_secs: u64) {
        let now = std::time::Instant::now();
        let mut to_unban: Vec<IpAddr> = Vec::new();
        self.banned.retain(|ip, entry| {
            if entry.permanent || now.duration_since(entry.ts).as_secs() < ttl_secs {
                true
            } else {
                to_unban.push(*ip);
                false
            }
        });
        self.banned_present.store(!self.banned.is_empty(), std::sync::atomic::Ordering::Relaxed);
        for ip in to_unban {
            match ip {
                IpAddr::V4(ipv4) => {
                    let _ = self.ban_cmd_tx.send(IcmpBanCmd::Unban(ipv4));
                }
                IpAddr::V6(ipv6) => {
                    let _ = self.ban_cmd_tx.send(IcmpBanCmd::UnbanV6(ipv6));
                }
            }
        }
    }

    /// Path of the persisted permanent-ban ("blacklist") list.
    fn blacklist_path() -> std::path::PathBuf {
        crate::runtime::base_dir().join("ip-blacklist.json")
    }

    /// Persist the permanent ("blacklisted") IPs to disk so they survive a restart.
    pub fn persist_blacklist(&self) {
        // Cap persisted entries (anti unbounded growth) and write 0600 (the ban list
        // is not world-readable). #SEC-H9.
        const MAX_PERSISTED_BLACKLIST: usize = 100_000;
        let ips: Vec<String> = self
            .banned
            .iter()
            .filter(|e| e.value().permanent)
            .map(|e| e.key().to_string())
            .take(MAX_PERSISTED_BLACKLIST)
            .collect();
        let path = Self::blacklist_path();
        if let Ok(j) = serde_json::to_string(&ips) {
            if std::fs::write(&path, j).is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    /// Load persisted permanent bans at startup and re-apply them (store + XDP map).
    pub fn load_blacklist(&self) {
        let data = match std::fs::read_to_string(Self::blacklist_path()) {
            Ok(d) => d,
            Err(_) => return,
        };
        let ips: Vec<String> = serde_json::from_str(&data).unwrap_or_default();
        let mut n = 0u32;
        // #SEC-H(Qwen-Q2): cap entries applied on load too (defense-in-depth vs a
        // tampered/oversized file), mirroring persist_blacklist.
        for ip_s in ips.into_iter().take(100_000) {
            if let Ok(ip) = ip_s.parse::<IpAddr>() {
                self.banned.insert(ip, BanEntry { ts: Instant::now(), src: BanSource::Manual, permanent: true });
                match ip {
                    IpAddr::V4(v4) => {
                        let _ = self.ban_cmd_tx.send(IcmpBanCmd::Ban(v4));
                    }
                    IpAddr::V6(v6) => {
                        let _ = self.ban_cmd_tx.send(IcmpBanCmd::BanV6(v6));
                    }
                }
                n += 1;
            }
        }
        if n > 0 {
            self.banned_present.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(count = n, "loaded persisted IP blacklist");
        }
    }

    pub fn banned_snapshot(&self) -> Vec<serde_json::Value> {
        let now = Instant::now();
        self.banned.iter().map(|e| {
            let ip = *e.key();
            let entry = e.value();
            serde_json::json!({
                "ip": ip.to_string(),
                "source": format!("{:?}", entry.src),
                "banned_ago_s": now.duration_since(entry.ts).as_secs(),
                "permanent": entry.permanent,
            })
        }).collect()
    }
}
