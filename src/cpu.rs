// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// CPU topology helpers — physical-core discovery and per-thread affinity pinning.
// On non-Linux targets all functions compile but pin_to_cpu() is a no-op.

/// Returns one logical CPU ID per physical core, HyperThreading siblings excluded.
///
/// Reads `/sys/devices/system/cpu/cpuN/topology/core_id` for each CPU.
/// The first logical CPU ID seen for each (socket, core_id) pair is kept;
/// HT siblings sharing the same physical core are dropped.
/// Falls back to `0..num_cpus::get_physical()` when `/sys` is unavailable
/// (containers, non-Linux, permission errors).
pub fn physical_cores() -> Vec<usize> {
    let mut seen = std::collections::HashSet::new();
    let mut physical = Vec::new();
    for cpu_id in 0..1024 {
        let path = format!(
            "/sys/devices/system/cpu/cpu{}/topology/core_id",
            cpu_id
        );
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                if let Ok(core_id) = s.trim().parse::<usize>() {
                    // (cpu_id / 64, core_id) approximates (socket, physical_core).
                    // Picks the first logical ID per physical core, discarding HT siblings.
                    if seen.insert((cpu_id / 64, core_id)) {
                        physical.push(cpu_id);
                    }
                }
            }
            Err(_) => break,
        }
    }
    if physical.is_empty() {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        (0..n).collect()
    } else {
        physical
    }
}

/// Pin the calling thread to `cpu_id` using `sched_setaffinity(2)`.
/// Silent no-op on failure or on non-Linux targets.
pub fn pin_to_cpu(cpu_id: usize) {
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
