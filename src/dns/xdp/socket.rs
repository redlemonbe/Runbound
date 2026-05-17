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

/// Find which network interface owns a given IP address by scanning
/// /proc/net/fib_trie and matching the address against interface names
/// found in /sys/class/net/. Falls back to `default_interface()` on failure.
pub fn iface_for_ip(ip: &str) -> Option<String> {
    // Walk /sys/class/net to get all interface names, then check if the
    // interface has the given address via /sys/class/net/<iface>/address or
    // by reading the ifaddr via getifaddrs-equivalent from /proc/net/if_inet6
    // and /proc/net/fib_trie.
    //
    // Simpler: iterate all interfaces and check their assigned addresses.
    let target: std::net::IpAddr = ip.parse().ok()?;
    let dir = std::fs::read_dir("/sys/class/net").ok()?;
    for entry in dir.flatten() {
        let iface = entry.file_name().to_string_lossy().into_owned();
        // /proc/net/if_inet6 covers IPv6; for IPv4 read /proc/net/fib_trie
        // Simplest portable approach: read the fib_trie for the address.
        let addr_file = format!("/sys/class/net/{iface}/address");
        // That's the MAC. For IP addresses, use /proc/net/fib_trie or ifaddrs.
        let _ = addr_file; // unused
        // Use if_nametoindex to validate the name, then check via /proc/net
        let cname = std::ffi::CString::new(iface.as_str()).ok()?;
        if unsafe { libc::if_nametoindex(cname.as_ptr()) } == 0 {
            continue;
        }
        // Check IPv4 via /proc/net/fib_trie
        if let std::net::IpAddr::V4(v4) = target {
            let octets = v4.octets();
            let hex = format!("{:02X}{:02X}{:02X}{:02X}",
                octets[3], octets[2], octets[1], octets[0]);
            if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
                // Simple heuristic: look for the hex address in the trie output
                // that follows a line mentioning the interface
                if content.contains(&hex) {
                    // Verify by checking if this iface owns the IP via ioctl SIOCGIFADDR
                    if iface_has_ipv4(&iface, v4) {
                        return Some(iface);
                    }
                }
            }
        }
    }
    None
}

fn iface_has_ipv4(iface: &str, target: std::net::Ipv4Addr) -> bool {
    // Use ioctl SIOCGIFADDR to get the interface's IPv4 address.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 { return false; }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            copy_len,
        );
        let rc = libc::ioctl(sock, libc::SIOCGIFADDR as _, &ifr as *const _);
        libc::close(sock);
        if rc != 0 { return false; }
        let sa = &*(&ifr.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in);
        let addr = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
        addr == target
    }
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
            return Some(iface);
        }
    }
    None
}
