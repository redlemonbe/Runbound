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
#![allow(dead_code)]

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use crate::dns::xdp::umem::{
    mmap_desc_ring, get_rx_tx_offsets,
    Umem, DescRing,
    SOL_XDP, XDP_RX_RING, XDP_TX_RING,
    XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    RX_RING_SIZE, TX_RING_SIZE, SockaddrXdp,
    XDP_ZEROCOPY, XDP_COPY, XDP_USE_NEED_WAKEUP,
};

// ── SIOCETHTOOL constants (linux/sockios.h + linux/ethtool.h) ─────────────

const SIOCETHTOOL:        libc::c_ulong = 0x8946;
const ETHTOOL_GRINGPARAM: u32           = 0x0000_0010;
const ETHTOOL_SRINGPARAM: u32           = 0x0000_0011;

/// Matches `struct ethtool_ringparam` in <linux/ethtool.h>.
#[repr(C)]
struct EthtoolRingParam {
    cmd:                  u32,
    rx_max_pending:       u32,
    rx_mini_max_pending:  u32,
    rx_jumbo_max_pending: u32,
    tx_max_pending:       u32,
    rx_pending:           u32,
    rx_mini_pending:      u32,
    rx_jumbo_pending:     u32,
    tx_pending:           u32,
}

/// Minimal `ifreq` layout for SIOCETHTOOL.
/// On x86-64 / aarch64: name(16) + union(24) = 40 bytes.
/// The data pointer occupies the first 8 bytes of the 24-byte union;
/// the remaining 16 are unused for SIOCETHTOOL.
#[repr(C)]
struct IfReqEthtool {
    ifr_name: [u8; 16],
    ifr_data: *mut libc::c_void,
    _pad:     [u8; 16],
}

// ── NIC ring-buffer stats, populated by maximize_nic_ring ─────────────────

/// Applied NIC RX ring size (0 = ethtool unavailable or not yet called).
pub static XDP_NIC_RX_RING:     AtomicU32 = AtomicU32::new(0);
/// Hardware maximum NIC RX ring size (0 = unavailable).
pub static XDP_NIC_RX_RING_MAX: AtomicU32 = AtomicU32::new(0);
/// Active XDP interface, set once at startup. Used to read sysfs rx_dropped.
pub static XDP_ACTIVE_IFACE: OnceLock<String> = OnceLock::new();
/// Per-queue mode set once after all AF_XDP sockets bind. Each entry is (queue_id, zerocopy).
pub static XDP_QUEUE_MODES: OnceLock<Vec<(u32, bool)>> = OnceLock::new();

pub const AF_XDP: libc::c_int = 44;

pub struct XskSocket {
    pub fd:       RawFd,
    pub umem:     Umem,
    pub rx:       DescRing,
    pub tx:       DescRing,
    /// True when the kernel accepted XDP_ZEROCOPY at bind time.
    pub zerocopy: bool,
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is the file descriptor returned by `socket(AF_XDP, …)`
        //         in `create_xsk_socket`. It has not been closed elsewhere (the
        //         `XskSocket` owns it exclusively). `Drop` is called exactly once,
        //         so there is no double-close.
        unsafe { libc::close(self.fd); }
    }
}

/// Create and bind one AF_XDP socket to the given interface queue.
///
/// Tries zero-copy (DRV mode) first; falls back to copy mode if the driver
/// does not support zero-copy. Returns an error only if even copy mode fails,
/// which indicates the NIC does not support AF_XDP at all.
pub unsafe fn create_xsk_socket(
    ifindex:      u32,
    queue_id:     u32,
    use_zerocopy: bool,
    hugepages:    bool,
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

    // 2. Allocate and register UMEM (also maps fill + completion rings)
    // SAFETY: `fd` is a valid AF_XDP socket fd returned by `socket(2)` above.
    let umem = unsafe { Umem::new(fd, hugepages) }.inspect_err(|_| {
        // SAFETY: `fd` is a valid open file descriptor not yet transferred
        //         to any owner. We close it here on the error path only.
        unsafe { libc::close(fd) };
    })?;

    // 3. Set RX and TX ring sizes
    for (opt, sz) in [(XDP_RX_RING, RX_RING_SIZE), (XDP_TX_RING, TX_RING_SIZE)] {
        // SAFETY: `fd` is a valid AF_XDP socket fd. `&sz` points to an
        //         initialised u32 on the stack. The socklen matches sizeof(u32).
        let rc = unsafe {
            libc::setsockopt(
                fd, SOL_XDP, opt,
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
    let rx = unsafe { mmap_desc_ring(fd, XDP_PGOFF_RX_RING, &rx_off, RX_RING_SIZE) }
        .inspect_err(|_| {
            // SAFETY: `fd` is valid and not yet owned by `XskSocket`.
            unsafe { libc::close(fd) };
        })?;
    // SAFETY: `fd` is valid; `tx_off` contains the offsets returned by the kernel.
    let tx = unsafe { mmap_desc_ring(fd, XDP_PGOFF_TX_RING, &tx_off, TX_RING_SIZE) }
        .inspect_err(|_| {
            // SAFETY: `fd` is valid and not yet owned by `XskSocket`.
            unsafe { libc::close(fd) };
        })?;

    // 5. Bind to the specific interface queue
    //    XDP_USE_NEED_WAKEUP: when set, we must call poll()/sendto() to kick
    //    the driver when the NEED_WAKEUP flag appears in the ring flags field.
    //    This saves CPU cycles when the driver can sleep between batches.
    let bind_flags = XDP_USE_NEED_WAKEUP
        | if use_zerocopy { XDP_ZEROCOPY } else { XDP_COPY };

    let sa = SockaddrXdp {
        sxdp_family:         AF_XDP as u16,
        sxdp_flags:          bind_flags,
        sxdp_ifindex:        ifindex,
        sxdp_queue_id:       queue_id,
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

    Ok(XskSocket { fd, umem, rx, tx, zerocopy: use_zerocopy })
}

/// Validate a network interface name before using it in sysfs paths.
/// Linux IFNAMSIZ is 16 (including NUL), so names are at most 15 characters.
/// Only ASCII alphanumeric, hyphen, period, and underscore are accepted.
pub(super) fn sanitize_iface_name(name: &str) -> Option<&str> {
    if !name.is_empty()
        && name.len() <= 15
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
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
    let parts: Vec<u8> = content.trim().split(':')
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
        None    => return 1,
    };
    let path = format!("/sys/class/net/{iface}/queues");
    std::fs::read_dir(&path)
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("rx-")
                })
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
    if idx == 0 { None } else { Some(idx) }
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
        if ifa.ifa_addr.is_null() { continue; }

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
    unsafe { libc::freeifaddrs(ifap); }
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
        None    => return true,
    };
    if std::path::Path::new(&format!("/sys/class/net/{iface}/device")).exists() {
        return false;
    }
    let uevent = std::fs::read_to_string(format!("/sys/class/net/{iface}/uevent"))
        .unwrap_or_default();
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
pub fn parent_interface(iface: &str) -> Option<String> {
    let iface = sanitize_iface_name(iface)?;
    let sysfs = format!("/sys/class/net/{iface}");
    // 1. lower_* entries (ipvlan, macvlan)
    if let Ok(entries) = std::fs::read_dir(&sysfs) {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name  = fname.to_string_lossy();
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

/// Maximize the NIC RX/TX ring buffers via `SIOCETHTOOL` before XDP attachment.
///
/// `target`:
///   - `None`    → GET hardware max, SET rings to max (best throughput at 10M QPS).
///   - `Some(n)` → GET hardware max (for reporting), SET rings to `n` capped at max.
///
/// Stores results in `XDP_NIC_RX_RING` / `XDP_NIC_RX_RING_MAX`.
/// On any error (EOPNOTSUPP, EPERM, virtual NIC, …) emits a `warn!` and returns
/// `(0, 0)` — startup is never aborted.
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
            unsafe { libc::close(self.0); }
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
    if unsafe { libc::ioctl(fd, SIOCETHTOOL as _, (&mut ifr as *mut IfReqEthtool).cast::<libc::c_void>()) } < 0 {
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
    ring_s.cmd        = ETHTOOL_SRINGPARAM;
    ring_s.rx_pending = rx_set;
    ring_s.tx_pending = tx_set;
    let mut ifr_s = build_ifreq(iface_safe, (&mut ring_s as *mut EthtoolRingParam).cast());

    // SAFETY: same as the GET call above.
    if unsafe { libc::ioctl(fd, SIOCETHTOOL as _, (&mut ifr_s as *mut IfReqEthtool).cast::<libc::c_void>()) } < 0 {
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
    let mut ifr = IfReqEthtool { ifr_name: [0u8; 16], ifr_data: data, _pad: [0u8; 16] };
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
        None    => return 0,
    };
    std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_dropped"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
