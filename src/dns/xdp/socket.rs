// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// AF_XDP socket creation, ring setup, and NIC binding.
//
// One XskSocket per NIC queue. Each socket has its own UMEM (simplest model;
// shared UMEM across queues is an optimisation we can add later).
//
// Steps:
//   1. socket(AF_XDP, SOCK_RAW, 0)
//   2. Register UMEM via setsockopt XDP_UMEM_REG
//   3. Set RX/TX ring sizes via setsockopt
//   4. mmap the four ring buffers
//   5. bind(sockaddr_xdp{ifindex, queue_id, ...})

#![deny(unsafe_op_in_unsafe_fn)]


use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::dns::xdp::umem::{
    get_rx_tx_offsets, mmap_desc_ring, DescRing, SockaddrXdp, Umem, XdpRingSizes, SOL_XDP,
    XDP_COPY, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_RX_RING, XDP_TX_RING, XDP_USE_NEED_WAKEUP,
    XDP_ZEROCOPY,
};

// ── SIOCETHTOOL constants (linux/sockios.h + linux/ethtool.h) ─────────────

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GRINGPARAM: u32 = 0x0000_0010;
const ETHTOOL_SRINGPARAM: u32 = 0x0000_0011;
const ETHTOOL_GCHANNELS: u32 = 0x0000_003c;
const ETHTOOL_SCHANNELS: u32 = 0x0000_003d;

/// Matches `struct ethtool_ringparam` in <linux/ethtool.h>.
#[repr(C)]
struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

#[repr(C)]
struct EthtoolRingParam {
    cmd: u32,
    rx_max_pending: u32,
    rx_mini_max_pending: u32,
    rx_jumbo_max_pending: u32,
    tx_max_pending: u32,
    rx_pending: u32,
    rx_mini_pending: u32,
    rx_jumbo_pending: u32,
    tx_pending: u32,
}

/// Minimal `ifreq` layout for SIOCETHTOOL.
/// On x86-64 / aarch64: name(16) + union(24) = 40 bytes.
/// The data pointer occupies the first 8 bytes of the 24-byte union;
/// the remaining 16 are unused for SIOCETHTOOL.
#[repr(C)]
struct IfReqEthtool {
    ifr_name: [u8; 16],
    ifr_data: *mut libc::c_void,
    _pad: [u8; 16],
}

// ── Per-interface XDP state (#159: replaces singleton globals) ────────────
//
// Previously XDP_ACTIVE_IFACE / XDP_QUEUE_MODES were OnceLock<_> — only the
// first interface could register (subsequent .set() calls were silently
// ignored).  XDP_NIC_RX_RING / XDP_NIC_RX_RING_MAX were AtomicU32 scalars
// overwritten by each interface.
//
// Replaced by a Vec registry: each start_xdp_on_iface() pushes one
// XdpIfaceState.  The API reads the full Vec → metrics cover ALL interfaces.

/// Per-interface XDP metadata stored at bind time.
#[derive(Debug, Clone)]
pub struct XdpIfaceState {
    /// NIC interface name.
    pub iface:       String,
    /// Per-queue modes: (queue_id, zerocopy).
    pub queue_modes: Vec<(u32, bool)>,
    /// Applied RX ring descriptor count (0 = ethtool unavailable).
    pub nic_rx_ring: u32,
    /// Hardware maximum RX ring descriptor count (0 = unavailable).
    pub nic_rx_ring_max: u32,
    /// XSK fds of this interface, for live XDP_STATISTICS reads (read-only).
    pub xsk_fds: Vec<RawFd>,
}

/// All active XDP interfaces, registered by start_xdp_on_iface().
/// OnceLock<Mutex<Vec<_>>> so the inner Vec is append-only after first init.
pub static XDP_IFACE_REGISTRY: OnceLock<Mutex<Vec<XdpIfaceState>>> = OnceLock::new();

/// Register (or append) one interface's XDP state. Called once per interface at bind.
pub fn register_xdp_iface(state: XdpIfaceState) {
    let registry = XDP_IFACE_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = registry.lock() {
        guard.push(state);
    }
}

/// Read a snapshot of all registered XDP interface states (cheap clone).
pub fn xdp_iface_snapshot() -> Vec<XdpIfaceState> {
    XDP_IFACE_REGISTRY
        .get()
        .and_then(|m| m.lock().ok())
        .map(|g| g.clone())
        .unwrap_or_default()
}

// ── Legacy compat shims (read from registry, first iface) ─────────────────
// Kept so existing API code compiles without a rewrite in this commit.
// A follow-up can migrate callers to xdp_iface_snapshot() directly.

/// Returns the first registered active XDP interface name (compat shim).
#[allow(dead_code)]
pub fn xdp_active_iface_first() -> Option<String> {
    xdp_iface_snapshot().into_iter().next().map(|s| s.iface)
}

// Deprecated singleton globals — kept for API callers, populated from registry.
// These now aggregate (first iface) or sum across all ifaces.
/// Applied NIC RX ring size for the first XDP interface (0 = unavailable).
pub static XDP_NIC_RX_RING: AtomicU32 = AtomicU32::new(0);
/// Hardware maximum NIC RX ring size for the first XDP interface.
pub static XDP_NIC_RX_RING_MAX: AtomicU32 = AtomicU32::new(0);
/// First active XDP interface (compat, use xdp_active_iface_first() instead).
pub static XDP_ACTIVE_IFACE: OnceLock<String> = OnceLock::new();
/// Per-queue modes for the first XDP interface (compat).
pub static XDP_QUEUE_MODES: OnceLock<Vec<(u32, bool)>> = OnceLock::new();

/// Canonical XDP attach mode, published once the data path is up: 0=disabled, 1=drv, 2=skb.
/// Single source of truth for every read-only consumer that is not wired to `AppState`
/// (notably the slave relay `/system` handler in `sync.rs`, which has no `AppState`).
/// Written by `main.rs` at the same point it updates the `AppState` Arc, so they never diverge.
pub static XDP_MODE: AtomicU8 = AtomicU8::new(0);

/// `true` while the XDP fast path is attached (drv or skb).
pub fn xdp_is_active() -> bool {
    XDP_MODE.load(Ordering::Relaxed) > 0
}

/// Human-readable XDP mode for the API/WebUI: `"drv"`, `"skb"`, or `"disabled"`.
pub fn xdp_mode_str() -> &'static str {
    match XDP_MODE.load(Ordering::Relaxed) {
        1 => "drv",
        2 => "skb",
        _ => "disabled",
    }
}

pub const AF_XDP: libc::c_int = 44;

pub struct XskSocket {
    pub fd: RawFd,
    pub umem: Umem,
    pub rx: DescRing,
    pub tx: DescRing,
    /// True when the kernel accepted XDP_ZEROCOPY at bind time.
    pub zerocopy: bool,
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is the file descriptor returned by `socket(AF_XDP, …)`
        //         in `create_xsk_socket`. It has not been closed elsewhere (the
        //         `XskSocket` owns it exclusively). `Drop` is called exactly once,
        //         so there is no double-close.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Create and bind one AF_XDP socket to the given interface queue.
///
/// Tries zero-copy (DRV mode) first; falls back to copy mode if the driver
/// does not support zero-copy. Returns an error only if even copy mode fails,
/// which indicates the NIC does not support AF_XDP at all.
pub unsafe fn create_xsk_socket(
    ifindex: u32,
    queue_id: u32,
    use_zerocopy: bool,
    hugepages: bool,
    sizes: &XdpRingSizes,
) -> Result<XskSocket, String> {
    // 1. Create the socket
    // SAFETY: `socket(2)` is safe to call with valid constants. AF_XDP=44,
    //         SOCK_RAW, protocol=0 is the standard AF_XDP socket creation.
    let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_XDP) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Auto-size the AF_XDP rings to the NIC hardware ring. A fill ring SMALLER
    // than the HW RX ring starves the driver => rx_no_dma drops. We only
    // auto-upgrade values left at the default (<= 4096); explicit larger config
    // is kept. This removes the need to hand-tune xdp-*-ring-size per NIC.
    //
    // DETERMINISTIC read: query the HW ring HERE (ifindex -> name -> GRINGPARAM)
    // instead of a global atomic. The atomic is only populated AFTER the socket
    // loop, so early queues used to read 0 and stayed at fill=4096 (half the
    // queues starved -> rx_no_dma). Reading per-socket is race-free for any path.
    let hw_max: u32 = {
        let mut nbuf = [0u8; libc::IF_NAMESIZE];
        // SAFETY: if_indextoname writes a NUL-terminated name (<= IF_NAMESIZE)
        //         into nbuf, or returns null on error.
        let p = unsafe { libc::if_indextoname(ifindex, nbuf.as_mut_ptr() as *mut libc::c_char) };
        if p.is_null() {
            0
        } else {
            let nm = unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
            // GET-ONLY read (no SRINGPARAM): never reconfigure the HW ring while
            // AF_XDP sockets are attached — that resets the datapath (TX dies).
            hw_rx_ring_max(&nm)
        }
    };
    let auto_ring = |configured: u32| -> u32 {
        if configured <= 4096 && hw_max >= 4096 {
            hw_max.saturating_mul(2).next_power_of_two().clamp(8192, 65536)
        } else {
            configured
        }
    };
    let eff = XdpRingSizes {
        fill: auto_ring(sizes.fill),
        comp: auto_ring(sizes.comp),
        rx: auto_ring(sizes.rx),
        tx: auto_ring(sizes.tx),
    };
    if (eff.fill, eff.rx, eff.tx, eff.comp) != (sizes.fill, sizes.rx, sizes.tx, sizes.comp) {
        tracing::info!(hw_rx_ring = hw_max, fill = eff.fill, rx = eff.rx, tx = eff.tx,
            "XDP rings auto-sized from NIC hardware ring (no manual xdp-*-ring-size needed)");
    }

    // 2. Allocate and register UMEM (also maps fill + completion rings)
    // SAFETY: `fd` is a valid AF_XDP socket fd returned by `socket(2)` above.
    let umem = unsafe { Umem::new(fd, hugepages, &eff) }.inspect_err(|_| {
        // SAFETY: `fd` is a valid open file descriptor not yet transferred
        //         to any owner. We close it here on the error path only.
        unsafe { libc::close(fd) };
    })?;

    // 3. Set RX and TX ring sizes
    for (opt, sz) in [(XDP_RX_RING, eff.rx), (XDP_TX_RING, eff.tx)] {
        // SAFETY: `fd` is a valid AF_XDP socket fd. `&sz` points to an
        //         initialised u32 on the stack. The socklen matches sizeof(u32).
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                opt,
                &sz as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            // SAFETY: `fd` is a valid open file descriptor not yet owned by
            //         `XskSocket`. We close it here on the error path only.
            unsafe { libc::close(fd) };
            return Err(format!(
                "setsockopt ring size ({opt}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // 4. mmap RX and TX rings (offsets retrieved from the kernel)
    // SAFETY: `fd` is a valid AF_XDP socket fd with ring sizes already configured.
    let (rx_off, tx_off) = unsafe { get_rx_tx_offsets(fd) }?;
    // SAFETY: `fd` is valid; `rx_off` contains the offsets returned by the kernel.
    let rx =
        unsafe { mmap_desc_ring(fd, XDP_PGOFF_RX_RING, &rx_off, eff.rx) }.inspect_err(|_| {
            // SAFETY: `fd` is valid and not yet owned by `XskSocket`.
            unsafe { libc::close(fd) };
        })?;
    // SAFETY: `fd` is valid; `tx_off` contains the offsets returned by the kernel.
    let tx =
        unsafe { mmap_desc_ring(fd, XDP_PGOFF_TX_RING, &tx_off, eff.tx) }.inspect_err(|_| {
            // SAFETY: `fd` is valid and not yet owned by `XskSocket`.
            unsafe { libc::close(fd) };
        })?;

    // 5. Bind to the specific interface queue
    //    XDP_USE_NEED_WAKEUP: when set, we must call poll()/sendto() to kick
    //    the driver when the NEED_WAKEUP flag appears in the ring flags field.
    //    This saves CPU cycles when the driver can sleep between batches.
    let bind_flags = XDP_USE_NEED_WAKEUP | if use_zerocopy { XDP_ZEROCOPY } else { XDP_COPY };

    let sa = SockaddrXdp {
        sxdp_family: AF_XDP as u16,
        sxdp_flags: bind_flags,
        sxdp_ifindex: ifindex,
        sxdp_queue_id: queue_id,
        sxdp_shared_umem_fd: 0,
    };
    // SAFETY: `fd` is a valid AF_XDP socket fd. `&sa` is a valid pointer to a
    //         fully-initialised SockaddrXdp cast to `*const sockaddr` as required
    //         by `bind(2)`. The addrlen matches sizeof(SockaddrXdp).
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const SockaddrXdp as *const libc::sockaddr,
            std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        // SAFETY: `fd` is valid and not yet owned by `XskSocket`.
        unsafe { libc::close(fd) };
        return Err(format!(
            "bind AF_XDP (ifindex={ifindex}, queue={queue_id}, zerocopy={use_zerocopy}): {}",
            std::io::Error::last_os_error()
        ));
    }


    // #perf: NAPI busy-poll hints — best-effort, silent fallback on old kernels.
    // SO_PREFER_BUSY_POLL=1 : tells the kernel to use busy-poll for this socket.
    // SO_BUSY_POLL=20       : busy-poll time budget in µs per syscall.
    // SO_BUSY_POLL_BUDGET=64: max packets to process per busy-poll cycle.
    // All three are best-effort: ENOPROTOOPT / EINVAL on pre-5.11 kernels → ignore.
    {
        const SO_PREFER_BUSY_POLL: libc::c_int = 69;
        const SO_BUSY_POLL:        libc::c_int = 46;
        const SO_BUSY_POLL_BUDGET: libc::c_int = 70;
        for (opt, val) in [
            (SO_PREFER_BUSY_POLL, 1u32),
            (SO_BUSY_POLL,        20u32),
            (SO_BUSY_POLL_BUDGET, 64u32),
        ] {
            // SAFETY: `fd` is a valid socket fd. `&val` is a valid pointer to a u32.
            //         We ignore errors — these opts may not exist on older kernels.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            // return value intentionally ignored — best-effort
        }
    }

    Ok(XskSocket {
        fd,
        umem,
        rx,
        tx,
        zerocopy: use_zerocopy,
    })
}

/// Validate a network interface name before using it in sysfs paths.
/// Linux IFNAMSIZ is 16 (including NUL), so names are at most 15 characters.
/// Only ASCII alphanumeric, hyphen, period, and underscore are accepted.
pub(super) fn sanitize_iface_name(name: &str) -> Option<&str> {
    if !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        Some(name)
    } else {
        None
    }
}

/// Read the hardware MAC address of `iface` from sysfs.
/// Returns None if the interface does not exist or the address cannot be parsed.
pub(super) fn read_iface_mac(iface: &str) -> Option<[u8; 6]> {
    let iface = sanitize_iface_name(iface)?;
    let content = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
    let parts: Vec<u8> = content
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if parts.len() == 6 {
        Some([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
    } else {
        None
    }
}

/// Returns the number of RX queues on `iface` by counting
/// /sys/class/net/<iface>/queues/rx-* directories.
pub fn get_rx_queue_count(iface: &str) -> u32 {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return 1,
    };
    let path = format!("/sys/class/net/{iface}/queues");
    std::fs::read_dir(&path)
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
                .count() as u32
        })
        .unwrap_or(1)
        .max(1)
}

/// Convert a network interface name to its kernel ifindex.
pub fn iface_index(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `cname.as_ptr()` is a valid NUL-terminated C string whose lifetime
    //         covers the call. `if_nametoindex(3)` returns 0 on error.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// Find which network interface carries the given IP address using `getifaddrs()`.
/// Returns the interface name on success. Covers both IPv4 and IPv6.
pub fn iface_for_ip(ip: &str) -> Option<String> {
    let target: std::net::IpAddr = ip.parse().ok()?;

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `&mut ifap` is a valid out-pointer. `getifaddrs(3)` allocates a
    //         linked list that must be freed with `freeifaddrs` — done below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }

    let mut result: Option<String> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null pointer into the linked list allocated by
        //         `getifaddrs`. Each node is valid until `freeifaddrs` is called.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }

        let matched = unsafe {
            // SAFETY: `ifa.ifa_addr` is non-null (checked above). Reading
            //         `sa_family` is always safe because `sockaddr` guarantees
            //         the family field at offset 0. The subsequent casts are
            //         valid because `sa_family` determines the concrete type.
            let family = (*ifa.ifa_addr).sa_family as libc::c_int;
            match (target, family) {
                (std::net::IpAddr::V4(v4), libc::AF_INET) => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == v4
                }
                (std::net::IpAddr::V6(v6), libc::AF_INET6) => {
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr) == v6
                }
                _ => false,
            }
        };

        if matched {
            // SAFETY: `ifa.ifa_name` is a valid NUL-terminated C string owned by
            //         the `getifaddrs` allocation; it remains valid until
            //         `freeifaddrs` is called below.
            if let Ok(name) = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_str() {
                tracing::debug!(
                    iface = %name, ip = %target,
                    "XDP: selected interface because it carries IP (via getifaddrs)"
                );
                result = Some(name.to_owned());
            }
            break;
        }
    }
    // SAFETY: `ifap` is the pointer returned by `getifaddrs` above (non-null on
    //         success). Called exactly once, after we are done traversing the list.
    unsafe {
        libc::freeifaddrs(ifap);
    }
    result
}

/// Detect the default network interface by reading /proc/net/route.
/// Returns the interface name of the default (0.0.0.0) route.
pub fn default_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let mut fields = line.split('\t');
        let iface = fields.next()?.to_string();
        let dest = fields.next()?;
        if dest == "00000000" {
            tracing::debug!(
                iface = %iface,
                "XDP: selected interface via routing table (no specific IP configured)"
            );
            return Some(iface);
        }
    }
    None
}

/// Returns true if `iface` is a virtual interface (bridge, bond, veth, ipvlan, macvlan, tun/tap).
/// Physical NICs expose a `/sys/class/net/<iface>/device` symlink.
/// VLAN sub-interfaces (eth0.10, bond0.10) have `DEVTYPE=vlan` in their uevent —
/// these are XDP-capable and are NOT treated as virtual.
pub fn is_virtual_interface(iface: &str) -> bool {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return true,
    };
    if std::path::Path::new(&format!("/sys/class/net/{iface}/device")).exists() {
        return false;
    }
    let uevent =
        std::fs::read_to_string(format!("/sys/class/net/{iface}/uevent")).unwrap_or_default();
    if uevent.lines().any(|l| l.trim() == "DEVTYPE=vlan") {
        return false;
    }
    true
}

/// Try to find a physical parent interface for a virtual interface.
/// Search order:
///   1. `lower_*` sysfs entries — ipvlan / macvlan parent
///   2. `master` symlink — bond slave or bridge port
///   3. `brif/` directory — ports of a bridge interface
#[allow(dead_code)]
pub fn parent_interface(iface: &str) -> Option<String> {
    let iface = sanitize_iface_name(iface)?;
    let sysfs = format!("/sys/class/net/{iface}");
    // 1. lower_* entries (ipvlan, macvlan)
    if let Ok(entries) = std::fs::read_dir(&sysfs) {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            if let Some(lower) = name.strip_prefix("lower_") {
                if !lower.is_empty() {
                    return Some(lower.to_string());
                }
            }
        }
    }
    // 2. master symlink (bond slave / bridge port)
    let master_path = format!("{sysfs}/master");
    if let Ok(target) = std::fs::read_link(&master_path) {
        if let Some(fname) = target.file_name() {
            let master = fname.to_string_lossy().into_owned();
            if !master.is_empty() {
                if !is_virtual_interface(&master) {
                    return Some(master);
                }
                if let Some(port) = first_physical_bridge_port(&master) {
                    return Some(port);
                }
            }
        }
    }
    // 3. brif/ directory (iface IS the bridge)
    first_physical_bridge_port(iface)
}

#[allow(dead_code)]
fn first_physical_bridge_port(bridge: &str) -> Option<String> {
    let bridge = sanitize_iface_name(bridge)?;
    let brif = format!("/sys/class/net/{bridge}/brif");
    let entries = std::fs::read_dir(&brif).ok()?;
    for entry in entries.flatten() {
        let port = entry.file_name().to_string_lossy().into_owned();
        if !is_virtual_interface(&port) {
            return Some(port);
        }
    }
    None
}

// ── NIC ring-buffer tuning (#80) ──────────────────────────────────────────

/// Auto-tune NIC combined queues before XDP attach. On a Xeon v2 + X520 host
/// (PCIe-bus-bound at ~16 cores) keep the driver default. On any modern CPU,
/// raise `combined` queues to the hardware maximum, capped by physical cores and
/// `budget` (the AF-XDP / XSKMAP per-NIC limit), so XDP spreads over all cores
/// instead of the 16-queue ixgbe default. Must run BEFORE attaching XDP (a queue
/// change resets the NIC). No-op (returns current count) on Xeon v2 or any error.
pub fn auto_tune_nic_queues(iface: &str, budget: u32) -> u32 {
    if is_xeon_v2_x520_host(iface) {
        tracing::info!(iface = %iface, "XDP queues: Xeon v2 + X520 detected — keeping default (bus-bound ~16c)");
        return get_rx_queue_count(iface);
    }
    let iface_safe = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return get_rx_queue_count(iface),
    };
    // SAFETY: AF_INET/DGRAM socket used only as an ioctl handle.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return get_rx_queue_count(iface);
    }
    // SAFETY: zeroed() valid for this plain repr(C) struct of u32 fields.
    let mut ch: EthtoolChannels = unsafe { std::mem::zeroed() };
    ch.cmd = ETHTOOL_GCHANNELS;
    let mut ifr = build_ifreq(iface_safe, (&mut ch as *mut EthtoolChannels).cast());
    // SAFETY: fd valid; ifr fully initialised with a valid ifr_data pointer.
    let get_rc = unsafe {
        libc::ioctl(fd, SIOCETHTOOL as _, (&mut ifr as *mut IfReqEthtool).cast::<libc::c_void>())
    };
    if get_rc < 0 {
        // Driver doesn't support GCHANNELS (some NICs) — leave queues as-is.
        unsafe { libc::close(fd) };
        return get_rx_queue_count(iface);
    }
    let hw_max = ch.max_combined.max(ch.max_rx);
    let cores = crate::cpu::physical_cores().len() as u32;
    let target = hw_max.min(cores).min(budget.max(1)).max(1);
    if target > ch.combined_count {
        let mut sch: EthtoolChannels = unsafe { std::mem::zeroed() };
        sch.cmd = ETHTOOL_SCHANNELS;
        sch.combined_count = target;
        let mut sifr = build_ifreq(iface_safe, (&mut sch as *mut EthtoolChannels).cast());
        // SAFETY: same as the GET call above.
        let set_rc = unsafe {
            libc::ioctl(fd, SIOCETHTOOL as _, (&mut sifr as *mut IfReqEthtool).cast::<libc::c_void>())
        };
        if set_rc >= 0 {
            tracing::info!(iface = %iface, from = ch.combined_count, to = target, hw_max, cores,
                "XDP queues: auto-debrided to hardware max (non-Xeon-v2 host)");
        } else {
            tracing::warn!(iface = %iface, target, "XDP queues: SCHANNELS failed — keeping current");
        }
    }
    unsafe { libc::close(fd) };
    get_rx_queue_count(iface)
}

/// #slowpath-autotune: SET the NIC `combined` queue count to an explicit `target`
/// (capped at the hardware maximum). Unlike `auto_tune_nic_queues` (which raises queues
/// to the max for AF_XDP, one worker per queue), the kernel-UDP slow path peaks with a
/// MODERATE queue count: enough NAPI/IRQ cores to drain the RX ring at line rate, but
/// few enough that those cores don't contend with the RPS-distributed serving threads
/// that run on EVERY core. Measured X710/5995WX: 16 queues + RPS-all = 6.5M qps, vs
/// 32q 5.4M, vs 63q (one IRQ per core, no moderation) 3.4M. Returns the resulting
/// combined count. Slow-path only — never called in `xdp: yes` (the AF_XDP path uses
/// `auto_tune_nic_queues` instead), so the fast path is unaffected.
pub fn set_combined_queues(iface: &str, target: u32) -> u32 {
    let iface_safe = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return get_rx_queue_count(iface),
    };
    // SAFETY: AF_INET/DGRAM socket used only as an ioctl handle.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return get_rx_queue_count(iface);
    }
    // SAFETY: zeroed() valid for this plain repr(C) struct of u32 fields.
    let mut ch: EthtoolChannels = unsafe { std::mem::zeroed() };
    ch.cmd = ETHTOOL_GCHANNELS;
    let mut ifr = build_ifreq(iface_safe, (&mut ch as *mut EthtoolChannels).cast());
    // SAFETY: fd valid; ifr fully initialised with a valid ifr_data pointer.
    let get_rc = unsafe {
        libc::ioctl(fd, SIOCETHTOOL as _, (&mut ifr as *mut IfReqEthtool).cast::<libc::c_void>())
    };
    if get_rc < 0 {
        unsafe { libc::close(fd) };
        return get_rx_queue_count(iface);
    }
    let hw_max = ch.max_combined.max(ch.max_rx);
    let tgt = target.min(hw_max).max(1);
    let from = ch.combined_count;
    if tgt != from {
        // #190 fix: reuse the GET'd channels struct (preserving other_count/rx_count/tx_count
        // the i40e driver requires) instead of a zeroed one. A zeroed other_count made the
        // i40e reject SCHANNELS, leaving the X710 stuck at its 119-queue default. Mirrors
        // `ethtool -L combined N`, which changes only combined_count and keeps the rest.
        ch.cmd = ETHTOOL_SCHANNELS;
        ch.combined_count = tgt;
        let mut sifr = build_ifreq(iface_safe, (&mut ch as *mut EthtoolChannels).cast());
        // SAFETY: same as the GET call above.
        let set_rc = unsafe {
            libc::ioctl(fd, SIOCETHTOOL as _, (&mut sifr as *mut IfReqEthtool).cast::<libc::c_void>())
        };
        if set_rc >= 0 {
            tracing::info!(iface = %iface, from, to = tgt, hw_max,
                "slow-path: NIC combined queues set to moderate count (kernel-UDP softirq balance)");
        } else {
            tracing::warn!(iface = %iface, target = tgt, "slow-path: SCHANNELS failed — keeping current queue count");
        }
    }
    unsafe { libc::close(fd) };
    get_rx_queue_count(iface)
}

/// Maximize the NIC RX/TX ring buffers via `SIOCETHTOOL` before XDP attachment.
///
/// `target`:
///   - `None`    → GET hardware max, SET rings to max (best throughput at 10M QPS).
///   - `Some(n)` → GET hardware max (for reporting), SET rings to `n` capped at max.
///
/// Stores results in `XDP_NIC_RX_RING` / `XDP_NIC_RX_RING_MAX`.
/// On any error (EOPNOTSUPP, EPERM, virtual NIC, …) emits a `warn!` and returns
/// `(0, 0)` — startup is never aborted.
/// Read the NIC's hardware MAX RX ring depth (ETHTOOL_GRINGPARAM) WITHOUT
/// changing anything. Used to auto-size the AF_XDP rings at socket creation.
/// Returns 0 on any error (caller then keeps the configured default).
fn hw_rx_ring_max(iface: &str) -> u32 {
    let iface_safe = match sanitize_iface_name(iface) {
        Some(s) => s,
        None => return 0,
    };
    // SAFETY: AF_INET/SOCK_DGRAM socket used only as an ioctl handle.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return 0;
    }
    // SAFETY: zeroed() is valid for this plain repr(C) struct of u32 fields.
    let mut ring: EthtoolRingParam = unsafe { std::mem::zeroed() };
    ring.cmd = ETHTOOL_GRINGPARAM;
    let mut ifr = build_ifreq(iface_safe, (&mut ring as *mut EthtoolRingParam).cast());
    // SAFETY: fd valid; ifr fully initialised with a valid ifr_data pointer.
    let rc = unsafe {
        libc::ioctl(
            fd,
            SIOCETHTOOL as _,
            (&mut ifr as *mut IfReqEthtool).cast::<libc::c_void>(),
        )
    };
    // SAFETY: fd is a valid open descriptor we own; closed exactly once here.
    unsafe { libc::close(fd) };
    if rc < 0 {
        0
    } else {
        ring.rx_max_pending
    }
}

pub fn maximize_nic_ring(iface: &str, target: Option<u32>) -> (u32, u32) {
    match maximize_nic_ring_inner(iface, target) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                iface,
                "[XDP] maximize_nic_ring({iface}): {e} — continuing with default ring size"
            );
            (0, 0)
        }
    }
}

fn maximize_nic_ring_inner(iface: &str, target: Option<u32>) -> std::io::Result<(u32, u32)> {
    /// RAII fd — closes on any early return.
    struct AutoClose(libc::c_int);
    impl Drop for AutoClose {
        fn drop(&mut self) {
            // SAFETY: self.0 is the fd returned by socket(2) below; closed exactly once.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    let iface_safe = sanitize_iface_name(iface)
        .ok_or_else(|| std::io::Error::other("invalid interface name"))?;

    // SAFETY: socket(AF_INET, SOCK_DGRAM, 0) creates a standard UDP socket used
    //         only as a handle for the SIOCETHTOOL ioctl — no data is sent.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = AutoClose(fd);

    // ── GET current + hardware-maximum ring sizes ──────────────────────────
    // SAFETY: zeroed() is valid for a repr(C) struct of plain u32 fields.
    let mut ring: EthtoolRingParam = unsafe { std::mem::zeroed() };
    ring.cmd = ETHTOOL_GRINGPARAM;
    let mut ifr = build_ifreq(iface_safe, (&mut ring as *mut EthtoolRingParam).cast());

    // SAFETY: `fd` is a valid socket fd. `ifr` is fully initialised with a
    //         valid `ifr_data` pointer. The ioctl writes results back into `ring`.
    if unsafe {
        libc::ioctl(
            fd,
            SIOCETHTOOL as _,
            (&mut ifr as *mut IfReqEthtool).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let rx_cur = ring.rx_pending;
    let rx_max = ring.rx_max_pending;
    let tx_cur = ring.tx_pending;
    let tx_max = ring.tx_max_pending;

    let rx_set = target.map_or(rx_max, |n| n.min(rx_max).max(1));
    let tx_set = target.map_or(tx_max, |n| n.min(tx_max).max(1));

    // ── SET ring sizes ────────────────────────────────────────────────────
    // SAFETY: zeroed() valid for this plain C struct.
    let mut ring_s: EthtoolRingParam = unsafe { std::mem::zeroed() };
    ring_s.cmd = ETHTOOL_SRINGPARAM;
    ring_s.rx_pending = rx_set;
    ring_s.tx_pending = tx_set;
    let mut ifr_s = build_ifreq(iface_safe, (&mut ring_s as *mut EthtoolRingParam).cast());

    // SAFETY: same as the GET call above.
    if unsafe {
        libc::ioctl(
            fd,
            SIOCETHTOOL as _,
            (&mut ifr_s as *mut IfReqEthtool).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    tracing::info!(
        "[XDP] NIC {iface} ring RX {rx_cur} → {rx_set}  TX {tx_cur} → {tx_set}  \
         (max RX {rx_max}  TX {tx_max})"
    );

    XDP_NIC_RX_RING.store(rx_set, Ordering::Relaxed);
    XDP_NIC_RX_RING_MAX.store(rx_max, Ordering::Relaxed);

    Ok((rx_set, rx_max))
}

fn build_ifreq(iface: &str, data: *mut libc::c_void) -> IfReqEthtool {
    let mut ifr = IfReqEthtool {
        ifr_name: [0u8; 16],
        ifr_data: data,
        _pad: [0u8; 16],
    };
    for (i, &b) in iface.as_bytes().iter().take(15).enumerate() {
        ifr.ifr_name[i] = b;
    }
    ifr
}

/// Read the kernel RX drop counter for `iface` from sysfs.
/// Returns 0 when the file is unavailable (virtual NIC, older kernel, XDP off).
pub fn read_nic_rx_dropped(iface: &str) -> u64 {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return 0,
    };
    std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_dropped"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// AF_XDP per-socket statistics — Linux UAPI (`linux/if_xdp.h`), read via
/// getsockopt(SOL_XDP, XDP_STATISTICS). VALID under zero-copy (unlike the ethtool
/// rx_packets counters, which are blind to XDP_REDIRECT->XSK). Defined from the
/// public kernel ABI — no third-party (bpftool) code, AGPL-clean.
pub const XDP_STATISTICS: libc::c_int = 7;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XdpStatistics {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

/// Read XDP_STATISTICS for one XSK fd (read-only, thread-safe — the socket is
/// owned by its worker thread; getsockopt does not mutate it). None on error.
pub fn read_xsk_statistics(fd: RawFd) -> Option<XdpStatistics> {
    let mut st = XdpStatistics::default();
    let mut len = std::mem::size_of::<XdpStatistics>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(fd, SOL_XDP, XDP_STATISTICS,
            &mut st as *mut _ as *mut libc::c_void, &mut len)
    };
    if rc == 0 { Some(st) } else { None }
}

/// Read rx_missed_errors for `iface` from ethtool-style sysfs.
/// This counter increments when the NIC RX ring is full and incoming frames
/// are dropped by the NIC/DMA before reaching the kernel — the key indicator
/// of NIC/bus-bound saturation (as opposed to CPU-bound).
/// Falls back to 0 when unavailable (virtual NIC, old kernel).
pub fn read_nic_rx_missed(iface: &str) -> u64 {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return 0,
    };
    // Primary: sysfs statistics (available on most NICs including ixgbe)
    if let Ok(v) = std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_missed_errors")) {
        if let Ok(n) = v.trim().parse::<u64>() { return n; }
    }
    0
}

/// Read rx_no_dma_resources for `iface` — ixgbe-specific counter indicating
/// that the DMA engine ran out of descriptors (RX ring starved).
/// Only available via ethtool -S or debugfs; falls back to 0 gracefully.
pub fn read_nic_rx_no_dma(iface: &str) -> u64 {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return 0,
    };
    // debugfs path (/sys/kernel/debug/ixgbe/<PCI_BDF>/...) requires the PCI BDF,
    // not the interface name — unreliable to resolve at runtime.  Use ethtool -S
    // instead, which is universally available on ixgbe and other drivers.
    let out = std::process::Command::new("ethtool")
        .args(["-S", &iface])
        .output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("rx_no_dma_resources:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(n) = val.trim().parse::<u64>() {
                        return n;
                    }
                }
            }
        }
    }
    0
}

/// Detect if this host is a Xeon v2 (Ivy Bridge-EP, family=6 model=62) +
/// X520/ixgbe combination — the specific architecture where the PCIe bus
/// ceiling limits effective XDP workers to ~16 physical cores.
/// On any other CPU/NIC combo this returns false → no artificial cap applied.
pub fn is_xeon_v2_x520_host(iface: &str) -> bool {
    // Check CPU: family 6 model 62 = Ivy Bridge-EP (Xeon E5-2600 v2)
    let is_xeon_v2 = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            let has_family6 = s.lines().any(|l| l.starts_with("cpu family") && l.contains(": 6"));
            let has_model62 = s.lines().any(|l| l.starts_with("model") && l.contains(": 62"));
            has_family6 && has_model62
        })
        .unwrap_or(false);
    if !is_xeon_v2 { return false; }

    // Check NIC driver: ixgbe = X520/82599
    let iface_clean = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return false,
    };
    let driver_path = format!("/sys/class/net/{iface_clean}/device/driver/module");
    let is_ixgbe = std::fs::read_link(&driver_path)
        .map(|p| p.to_string_lossy().contains("ixgbe"))
        .unwrap_or(false);

    is_xeon_v2 && is_ixgbe
}

/// Emit a one-time startup hint when running on Xeon v2 + X520 (NIC/bus-bound arch).
/// On this platform, XDP saturates at ~16 cores due to PCIe bus ceiling,
/// and rx_missed_errors will be non-zero even with CPU headroom — that is expected.
pub fn maybe_warn_xeon_v2_x520(iface: &str) {
    if is_xeon_v2_x520_host(iface) {
        tracing::warn!(
            iface = %iface,
            "host likely NIC/PCIe-bus-bound (Xeon v2 + X520 ~16-core bus ceiling) —              CPU headroom is expected; read rx_missed_errors for the real wall.              XDP workers are capped to 16 NUMA-local physical cores on this arch."
        );
    }
}

/// Returns true if `iface` is a bonded interface (master bond OR slave of a bond).
/// XDP is incompatible with bonding — frames may arrive on the bond master but
/// the XSK bind must target the slave NIC's queue directly, which AF_XDP does
/// not support in zerocopy through a bond master.
pub fn is_bonded_interface(iface: &str) -> bool {
    let iface = match sanitize_iface_name(iface) {
        Some(n) => n,
        None => return false,
    };
    // Check if this iface IS a bond master (/sys/class/net/<iface>/bonding)
    if std::path::Path::new(&format!("/sys/class/net/{iface}/bonding")).exists() {
        return true;
    }
    // Check if this iface is a slave OF a bond (its master is a bond)
    let master_path = format!("/sys/class/net/{iface}/master");
    if let Ok(target) = std::fs::read_link(&master_path) {
        if let Some(master_name) = target.file_name() {
            let master = master_name.to_string_lossy();
            if std::path::Path::new(&format!("/sys/class/net/{master}/bonding")).exists() {
                return true;
            }
        }
    }
    false
}

/// Enumerate all network interfaces eligible for XDP binding (mode: auto).
///
/// Eligibility criteria:
///   - Interface is UP (IFF_UP flag set)
///   - Not a loopback interface
///   - Not a virtual interface (no /sys/class/net/<iface>/device → virtual)
///   - Not a bonded interface (master bond or slave) — XDP incompatible with bonding
///   - Not explicitly excluded by prefix: lo, vmbr*, br*, tap*, veth*
///
/// Returns a Vec of eligible interface names, or an empty Vec if none found.
/// Logs WARN for each skipped bonded interface.
pub fn list_eligible_interfaces() -> Vec<String> {
    let mut result = Vec::new();
    let sysfs_net = "/sys/class/net";

    let entries = match std::fs::read_dir(sysfs_net) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!("XDP auto: cannot read {sysfs_net}: {err}");
            return result;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();

        // Exclude loopback and explicitly virtual prefixes
        if name == "lo" {
            continue;
        }
        for prefix in &["vmbr", "br", "tap", "veth"] {
            if name.starts_with(prefix) {
                tracing::debug!(iface = %name, "XDP auto: skipping virtual interface");
                // continue outer — use a label
            }
        }
        if name.starts_with("vmbr") || name.starts_with("br")
            || name.starts_with("tap") || name.starts_with("veth")
        {
            tracing::debug!(iface = %name, "XDP auto: skipping virtual-prefix interface");
            continue;
        }

        // Check bonding BEFORE is_virtual_interface (bonds have no /device symlink)
        if is_bonded_interface(&name) {
            tracing::warn!(
                iface = %name,
                "XDP auto: skipping bonded interface — XDP incompatible with bonding"
            );
            continue;
        }

        // Check virtual (no /sys/class/net/<iface>/device symlink)
        if is_virtual_interface(&name) {
            tracing::debug!(iface = %name, "XDP auto: skipping virtual interface (no device symlink)");
            continue;
        }

        // Check UP flag via /sys/class/net/<iface>/operstate or flags
        let flags_path = format!("{sysfs_net}/{name}/flags");
        let flags: u64 = std::fs::read_to_string(&flags_path)
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        const IFF_UP: u64 = 0x1;
        if flags & IFF_UP == 0 {
            tracing::debug!(iface = %name, "XDP auto: skipping interface (not UP)");
            continue;
        }

        tracing::debug!(iface = %name, "XDP auto: eligible interface found");
        result.push(name);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── XDP mode global (single source of truth for non-AppState consumers) ──
    #[test]
    fn xdp_mode_global_maps_to_strings() {
        // No other test mutates XDP_MODE, so this is race-free; restore to 0 after.
        XDP_MODE.store(0, Ordering::Relaxed);
        assert!(!xdp_is_active());
        assert_eq!(xdp_mode_str(), "disabled");
        XDP_MODE.store(1, Ordering::Relaxed);
        assert!(xdp_is_active());
        assert_eq!(xdp_mode_str(), "drv");
        XDP_MODE.store(2, Ordering::Relaxed);
        assert!(xdp_is_active());
        assert_eq!(xdp_mode_str(), "skb");
        XDP_MODE.store(0, Ordering::Relaxed);
    }

    // ── is_bonded_interface ───────────────────────────────────────────────
    // These tests run without real hardware; they verify the sysfs-path logic
    // using the /sys/class/net filesystem of the CI worker.

    #[test]
    fn loopback_is_not_bonded() {
        // lo never has a bonding directory or a master symlink to a bond
        assert!(!is_bonded_interface("lo"));
    }

    #[test]
    fn nonexistent_iface_is_not_bonded() {
        // A nonexistent interface has no sysfs paths → not bonded
        assert!(!is_bonded_interface("nonexistent_xdp_test_iface_xyz"));
    }

    #[test]
    fn iface_name_with_path_traversal_rejected() {
        // sanitize_iface_name must reject names containing '/' or '..'
        // so a crafted path cannot escape /sys/class/net/
        assert!(!is_bonded_interface("../../../etc/bond"));
        assert!(!is_bonded_interface("eth0/../../bond0"));
    }

    // ── list_eligible_interfaces ──────────────────────────────────────────
    #[test]
    fn eligible_list_excludes_loopback() {
        // lo must never appear in the eligible list
        let list = list_eligible_interfaces();
        assert!(
            !list.contains(&"lo".to_string()),
            "loopback must be excluded from eligible interfaces"
        );
    }

    #[test]
    fn eligible_list_excludes_virtual_prefixes() {
        let list = list_eligible_interfaces();
        for name in &list {
            for prefix in &["vmbr", "br", "tap", "veth"] {
                assert!(
                    !name.starts_with(prefix),
                    "eligible list must not contain virtual-prefix interface: {name}"
                );
            }
        }
    }

    #[test]
    fn eligible_list_excludes_bonded() {
        // Every interface in the eligible list must NOT be bonded
        let list = list_eligible_interfaces();
        for name in &list {
            assert!(
                !is_bonded_interface(name),
                "bonded interface must be excluded from eligible list: {name}"
            );
        }
    }

    // ── iface_list parsing logic (mirrors main.rs resolution) ────────────
    #[test]
    fn csv_split_produces_correct_names() {
        let explicit = "nic2,nic3";
        let parts: Vec<String> = explicit
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(parts, vec!["nic2", "nic3"]);
    }

    #[test]
    fn csv_split_trims_whitespace() {
        let explicit = " nic2 , nic3 ";
        let parts: Vec<String> = explicit
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(parts, vec!["nic2", "nic3"]);
    }

    #[test]
    fn single_iface_no_comma() {
        let explicit = "nic3";
        assert!(!explicit.contains(','));
        let parts: Vec<String> = vec![explicit.to_string()];
        assert_eq!(parts, vec!["nic3"]);
    }
}
