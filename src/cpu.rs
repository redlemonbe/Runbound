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
        let path = format!(
            "/sys/devices/system/cpu/cpu{cpu_id}/topology/thread_siblings_list"
        );
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
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        (0..n).collect()
    } else {
        physical
    }
}

/// Read the current scaling governor for `cpu_id`.
/// Returns None when /sys/…/cpufreq/ is absent (containers, VMs, non-Linux).
pub fn read_governor(core_id: usize) -> Option<String> {
    let path = format!("/sys/devices/system/cpu/cpu{core_id}/cpufreq/scaling_governor");
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Set the scaling governor to 'performance' for `core_id`.
/// Silent no-op when the sysfs path is absent.
pub fn set_performance_governor(core_id: usize) {
    let path = format!("/sys/devices/system/cpu/cpu{core_id}/cpufreq/scaling_governor");
    let _ = std::fs::write(&path, "performance\n");
}

/// Restore a previously saved governor value for `core_id`.
/// Silent no-op on any I/O error.
pub fn restore_governor(core_id: usize, original: &str) {
    let path = format!("/sys/devices/system/cpu/cpu{core_id}/cpufreq/scaling_governor");
    let _ = std::fs::write(&path, original.as_bytes());
}

/// Pin NIC queue IRQs to their corresponding XDP worker cores.
///
/// Reads /proc/interrupts to find IRQs for `iface` (patterns: `{iface}-TxRx-N`,
/// `{iface}-rx-N`, `{iface}-N`), then writes the core bitmask to
/// `/proc/irq/<irq>/smp_affinity_list`. Silent no-op on any failure.
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
    if cpu_id >= 1024 { return; }
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
