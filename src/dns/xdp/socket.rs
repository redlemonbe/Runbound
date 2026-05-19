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

#![allow(dead_code)]

use std::os::fd::RawFd;

use crate::dns::xdp::umem::{
    mmap_desc_ring, get_rx_tx_offsets,
    Umem, DescRing,
    SOL_XDP, XDP_RX_RING, XDP_TX_RING,
    XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING,
    RING_SIZE, SockaddrXdp,
    XDP_ZEROCOPY, XDP_COPY, XDP_USE_NEED_WAKEUP,
};

pub const AF_XDP: libc::c_int = 44;

pub struct XskSocket {
    pub fd:   RawFd,
    pub umem: Umem,
    pub rx:   DescRing,
    pub tx:   DescRing,
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

/// Create and bind one AF_XDP socket to the given interface queue.
///
/// Tries zero-copy (DRV mode) first; falls back to copy mode if the driver
/// does not support zero-copy. Returns an error only if even copy mode fails,
/// which indicates the NIC does not support AF_XDP at all.
pub unsafe fn create_xsk_socket(
    ifindex:  u32,
    queue_id: u32,
    use_zerocopy: bool,
) -> Result<XskSocket, String> {
    // 1. Create the socket
    let fd = libc::socket(AF_XDP, libc::SOCK_RAW, 0);
    if fd < 0 {
        return Err(format!(
            "socket(AF_XDP) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 2. Allocate and register UMEM (also maps fill + completion rings)
    let umem = Umem::new(fd).inspect_err(|_| { libc::close(fd); })?;

    // 3. Set RX and TX ring sizes
    for (opt, sz) in [(XDP_RX_RING, RING_SIZE), (XDP_TX_RING, RING_SIZE)] {
        let rc = libc::setsockopt(
            fd, SOL_XDP, opt,
            &sz as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        if rc != 0 {
            libc::close(fd);
            return Err(format!(
                "setsockopt ring size ({opt}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // 4. mmap RX and TX rings (offsets retrieved from the kernel)
    let (rx_off, tx_off) = get_rx_tx_offsets(fd)?;
    let rx = mmap_desc_ring(fd, XDP_PGOFF_RX_RING, &rx_off, RING_SIZE)
        .inspect_err(|_| { libc::close(fd); })?;
    let tx = mmap_desc_ring(fd, XDP_PGOFF_TX_RING, &tx_off, RING_SIZE)
        .inspect_err(|_| { libc::close(fd); })?;

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
    let rc = libc::bind(
        fd,
        &sa as *const SockaddrXdp as *const libc::sockaddr,
        std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
    );
    if rc != 0 {
        libc::close(fd);
        return Err(format!(
            "bind AF_XDP (ifindex={ifindex}, queue={queue_id}, zerocopy={use_zerocopy}): {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(XskSocket { fd, umem, rx, tx })
}

/// Returns the number of RX queues on `iface` by counting
/// /sys/class/net/<iface>/queues/rx-* directories.
pub fn get_rx_queue_count(iface: &str) -> u32 {
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
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

/// Find which network interface carries the given IP address using `getifaddrs()`.
/// Returns the interface name on success. Covers both IPv4 and IPv6.
pub fn iface_for_ip(ip: &str) -> Option<String> {
    let target: std::net::IpAddr = ip.parse().ok()?;

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }

    let mut result: Option<String> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() { continue; }

        let matched = unsafe {
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
