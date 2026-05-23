// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Build script: compiles the eBPF XDP filter when the "xdp" feature is enabled.
// Requires: clang (apt install clang) + libbpf-dev (apt install libbpf-dev).
// The compiled object is embedded into the binary with include_bytes!.
// This is a BUILD-time dependency only; the final binary needs neither clang
// nor libbpf installed on the target machine.

fn main() {
    println!("cargo:rerun-if-changed=ebpf/dns_xdp.c");

    #[cfg(feature = "xdp")]
    compile_ebpf();
}

#[cfg(feature = "xdp")]
fn compile_ebpf() {
    use std::{env, path::PathBuf, process::Command};

    let out_dir      = PathBuf::from(env::var("OUT_DIR")
        .unwrap_or_else(|_| panic!("OUT_DIR not set by cargo")));
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| panic!("CARGO_MANIFEST_DIR not set by cargo")));

    // Target architecture → BPF define expected by kernel headers
    let bpf_arch_flag = match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_else(|_| "x86_64".into())
        .as_str()
    {
        "x86_64"  => "-D__TARGET_ARCH_x86",
        "aarch64" => "-D__TARGET_ARCH_arm64",
        "arm"     => "-D__TARGET_ARCH_arm",
        other     => panic!("unsupported target architecture for XDP eBPF: {other}"),
    };

    let src = manifest_dir.join("ebpf/dns_xdp.c");
    let dst = out_dir.join("dns_xdp.o");

    // On Debian/Ubuntu the asm/* kernel headers live under the multiarch path
    // (e.g. /usr/include/x86_64-linux-gnu) rather than /usr/include/asm.
    // Detect the right path and pass it to clang so <asm/types.h> resolves.
    let multiarch_inc = {
        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
        let triplet = match arch.as_str() {
            "x86_64"  => "x86_64-linux-gnu",
            "aarch64" => "aarch64-linux-gnu",
            "arm"     => "arm-linux-gnueabihf",
            _         => "",
        };
        let candidate = format!("/usr/include/{triplet}");
        if !triplet.is_empty() && std::path::Path::new(&candidate).exists() {
            Some(candidate)
        } else {
            None
        }
    };

    let mut clang_args: Vec<String> = vec![
        "-O2".into(),
        // -g on -target bpf generates BTF (.BTF/.BTF.ext sections), not DWARF.
        // aya-obj requires BTF for BTF-style map definitions (SEC(".maps")).
        "-g".into(),
        "-target".into(), "bpf".into(),
        bpf_arch_flag.into(),
        "-Wall".into(),
        "-Wno-missing-prototypes".into(),
        "-c".into(), src.to_str().unwrap_or_else(|| panic!("src path not UTF-8")).into(),
        "-o".into(), dst.to_str().unwrap_or_else(|| panic!("dst path not UTF-8")).into(),
    ];
    if let Some(inc) = multiarch_inc {
        clang_args.push(format!("-I{inc}"));
    }

    let out = Command::new("clang")
        .args(&clang_args)
        .output()
        .unwrap_or_else(|e| {
            panic!("clang not found ({e}). Install with: apt install clang libbpf-dev")
        });

    if !out.status.success() {
        eprintln!("--- eBPF compilation stderr ---");
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        panic!("eBPF compilation failed (see above)");
    }

    println!("cargo:warning=eBPF program compiled → {}", dst.display());
}
