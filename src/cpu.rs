// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// CPU topology helpers — physical-core discovery and per-thread affinity pinning.
// On non-Linux targets all functions compile but pin_to_cpu() is a no-op.

/// Parse a kernel CPU-list string (e.g. "0,4" or "0-3,8-11") into CPU IDs.
fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in s.trim().split(',') {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                cpus.extend(lo..=hi);
            }
        } else if let Ok(n) = part.trim().parse::<usize>() {
            cpus.push(n);
        }
    }
    cpus
}

/// Returns one logical CPU ID per physical core, SMT/HyperThreading siblings excluded.
///
/// Reads `thread_siblings_list` for each online CPU. A CPU is a physical-core
/// representative if and only if it is the lowest-numbered CPU in its sibling group.
/// This works identically on Intel HT and AMD SMT (Threadripper PRO / EPYC).
///
/// Example — 4C/8T CPU:
///   cpu0: siblings = [0,4] → min=0 == cpu_id → keep
///   cpu4: siblings = [0,4] → min=0 ≠ cpu_id → skip (SMT sibling of cpu0)
///
/// Falls back to all available logical CPUs when `/sys` is unavailable
/// (containers, non-Linux, permission errors).
pub fn physical_cores() -> Vec<usize> {
    let mut physical = Vec::new();
    for cpu_id in 0..4096 {
        let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/topology/thread_siblings_list");
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let siblings = parse_cpu_list(&s);
                let min = siblings.iter().copied().min().unwrap_or(cpu_id);
                if min == cpu_id {
                    physical.push(cpu_id);
                }
            }
            Err(_) => break,
        }
    }
    if physical.is_empty() {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        (0..n).collect()
    } else {
        physical
    }
}


/// Pin NIC queue IRQs to their corresponding XDP worker cores.
///
/// Reads /proc/interrupts to find IRQs for `iface` (patterns: `{iface}-TxRx-N`,
/// `{iface}-rx-N`, `{iface}-N`), then writes the core bitmask to
/// `/proc/irq/<irq>/smp_affinity_list`. Silent no-op on any failure.

/// Returns the NUMA node of a NIC (`/sys/class/net/<iface>/device/numa_node`).
/// Returns 0 (fallback) if the file is absent (VM, container, non-NUMA).
pub fn nic_numa_node(iface: &str) -> usize {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/device/numa_node"))
        .ok()
        .and_then(|s| s.trim().parse::<isize>().ok())
        .map(|n| if n < 0 { 0 } else { n as usize })  // -1 → 0 (non-NUMA or VM)
        .unwrap_or(0)
}

/// Returns physical cores (SMT filtered) that belong to `numa_node`.
/// Falls back to all physical cores when NUMA topology is unavailable.
///
/// NUMA node of a CPU = the node symlink under
/// `/sys/devices/system/cpu/cpu<N>/` (e.g. `node0` → node 0).
pub fn physical_cores_numa_local(numa_node: usize) -> Vec<usize> {
    let all = physical_cores();
    let local: Vec<usize> = all.iter().copied().filter(|&cpu_id| {
        // Read the node<N> symlink directory present under the cpu topology dir.
        // /sys/devices/system/cpu/cpu<N>/node<M> exists iff cpu belongs to node M.
        let path = format!(
            "/sys/devices/system/cpu/cpu{cpu_id}/node{numa_node}"
        );
        std::path::Path::new(&path).exists()
    }).collect();
    if local.is_empty() { all } else { local }
}


/// Returns physical cores (SMT filtered) sorted NUMA-first for a given NIC node.
///
/// Order: cores local to `nic_node` first (lowest latency), then remote cores,
/// all physical (never HT siblings). This gives optimal XDP worker placement:
/// local cores fill first, remote cores used only when cap requires it.
///
/// Example — dual Xeon v2 (10+10 physical), NIC on node 0:
///   → [0,2,4,6,8,10,12,14,16,18,  1,3,5,7,9,11,13,15,17,19]
///      ↑ 10 NUMA-local              ↑ 10 NUMA-remote
pub fn physical_cores_numa_sorted(nic_node: usize) -> Vec<usize> {
    let all = physical_cores();
    let (mut local, mut remote): (Vec<usize>, Vec<usize>) = all.into_iter().partition(|&cpu_id| {
        let path = format!("/sys/devices/system/cpu/cpu{cpu_id}/node{nic_node}");
        std::path::Path::new(&path).exists()
    });
    local.sort_unstable();
    remote.sort_unstable();
    local.extend(remote);
    local
}

pub fn set_irq_affinity(iface: &str, queue_to_core: &[(u32, usize)]) {
    #[cfg(target_os = "linux")]
    {
        let content = match std::fs::read_to_string("/proc/interrupts") {
            Ok(s) => s,
            Err(_) => return,
        };
        for &(queue_id, core_id) in queue_to_core {
            if let Some(irq) = find_irq_for_queue(&content, iface, queue_id) {
                let path = format!("/proc/irq/{irq}/smp_affinity_list");
                let _ = std::fs::write(&path, format!("{core_id}"));
                tracing::debug!(iface, queue_id, core_id, irq, "IRQ affinity set");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (iface, queue_to_core);
}

#[cfg(target_os = "linux")]
fn find_irq_for_queue(proc_interrupts: &str, iface: &str, queue_id: u32) -> Option<u32> {
    let patterns = [
        format!("{iface}-TxRx-{queue_id}"),
        format!("{iface}-rx-{queue_id}"),
        format!("{iface}-{queue_id}"),
    ];
    for line in proc_interrupts.lines() {
        let trimmed = line.trim();
        let (irq_str, rest) = trimmed.split_once(':')?;
        let irq = irq_str.trim().parse::<u32>().ok()?;
        if patterns.iter().any(|p| rest.contains(p.as_str())) {
            return Some(irq);
        }
    }
    None
}

/// Pin the calling thread to `cpu_id` using `sched_setaffinity(2)`.
/// Silent no-op on failure or on non-Linux targets.
pub fn pin_to_cpu(cpu_id: usize) {
    // FIX 4 (VUL-NEW-05): cpu_set_t is 128 bytes = 1024 bits; CPU_SET is UB for cpu_id >= 1024.
    if cpu_id >= 1024 {
        return;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut set = std::mem::zeroed::<libc::cpu_set_t>();
        libc::CPU_SET(cpu_id, &mut set);
        // Errors (EPERM in containers, invalid cpu_id) are silently ignored.
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cpu_id;
}

// ── SIMD level detection ──────────────────────────────────────────────────────

use std::sync::OnceLock;

/// Available SIMD tiers, ordered weakest → strongest.
/// Each level is a strict superset of the previous on x86_64.
/// Baseline for Runbound: Sse42 (Xeon E5-2690 v2 / Ivy Bridge, 2013+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdLevel {
    Scalar,  // non-x86, or no SIMD detected
    Sse2,    // x86_64 ABI baseline — always available
    Sse42,   // Nehalem+ (2008) — CRC32, PCMPISTRI
    Avx2,    // Haswell+ (2013) — 256-bit integer SIMD
    Avx512,  // Skylake-SP+ (2017) — 512-bit SIMD
}

impl SimdLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Sse2   => "sse2",
            Self::Sse42  => "sse4.2",
            Self::Avx2   => "avx2",
            Self::Avx512 => "avx512f",
        }
    }
}

/// Detected CPU instruction-set features.
#[derive(Debug, Clone)]
pub struct CpuFeatures {
    pub sse2:    bool,
    pub sse4_2:  bool,
    pub avx:     bool,
    pub avx2:    bool,
    pub avx512f: bool,
    pub popcnt:  bool,
    pub bmi2:    bool,
}

impl CpuFeatures {
    /// Probe the running CPU once; subsequent calls return the cached result.
    pub fn get() -> &'static Self {
        static CACHE: OnceLock<CpuFeatures> = OnceLock::new();
        CACHE.get_or_init(Self::detect)
    }

    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        return Self {
            sse2:    true, // x86_64 ABI guarantee — never needs a runtime check
            sse4_2:  std::is_x86_feature_detected!("sse4.2"),
            avx:     std::is_x86_feature_detected!("avx"),
            avx2:    std::is_x86_feature_detected!("avx2"),
            avx512f: std::is_x86_feature_detected!("avx512f"),
            popcnt:  std::is_x86_feature_detected!("popcnt"),
            bmi2:    std::is_x86_feature_detected!("bmi2"),
        };
        #[allow(unreachable_code)]
        Self { sse2: false, sse4_2: false, avx: false,
               avx2: false, avx512f: false, popcnt: false, bmi2: false }
    }

    /// Best SIMD tier available on this CPU.
    pub fn best_level(&self) -> SimdLevel {
        if self.avx512f { SimdLevel::Avx512 }
        else if self.avx2 { SimdLevel::Avx2 }
        else if self.sse4_2 { SimdLevel::Sse42 }
        else if self.sse2   { SimdLevel::Sse2 }
        else                { SimdLevel::Scalar }
    }
}

/// The best SIMD level for this process. Detected once, lock-free after that.
/// Use this in hot-path dispatch: one comparison, no CPUID overhead.
#[inline]
pub fn simd_level() -> SimdLevel {
    static LEVEL: OnceLock<SimdLevel> = OnceLock::new();
    *LEVEL.get_or_init(|| CpuFeatures::get().best_level())
}

/// Log CPU capabilities and physical-core count at startup (call once).
pub fn log_cpu_info() {
    let f = CpuFeatures::get();
    let level = simd_level();
    let cores = physical_cores();
    tracing::info!(
        "[CPU] SIMD={} | sse4.2={} avx={} avx2={} avx512f={} | physical cores={} (HT excluded)",
        level.as_str(), f.sse4_2, f.avx, f.avx2, f.avx512f, cores.len()
    );
}

#[cfg(test)]
mod simd_tests {
    use super::*;

    #[test]
    fn sse2_always_on_x86_64() {
        #[cfg(target_arch = "x86_64")]
        assert!(CpuFeatures::get().sse2);
    }

    #[test]
    fn level_ordering() {
        assert!(SimdLevel::Scalar < SimdLevel::Sse2);
        assert!(SimdLevel::Sse2   < SimdLevel::Sse42);
        assert!(SimdLevel::Sse42  < SimdLevel::Avx2);
        assert!(SimdLevel::Avx2   < SimdLevel::Avx512);
    }

    #[test]
    fn best_level_consistent() {
        let f = CpuFeatures::get();
        let l = f.best_level();
        if l >= SimdLevel::Avx2  { assert!(f.avx2); }
        if l >= SimdLevel::Sse42 { assert!(f.sse4_2); }
        if l >= SimdLevel::Sse2  { assert!(f.sse2); }
    }

    #[test]
    fn simd_level_cached() {
        // Two calls must return the same value (OnceLock)
        assert_eq!(simd_level(), simd_level());
    }
}
