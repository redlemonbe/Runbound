// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Build script: compiles the eBPF XDP filter when the "xdp" feature is enabled.
// Requires: clang (apt install clang) + libbpf-dev (apt install libbpf-dev).
// The compiled objects are embedded into the binary with include_bytes!.
// This is a BUILD-time dependency only; the final binary needs neither clang
// nor libbpf installed on the target machine.
//
// Two binaries are produced:
//   dns_xdp.o         — full, with BPF_MAP_TYPE_CPUMAP (domain-affinity routing)
//   dns_xdp_minimal.o — compiled with -DNO_CPUMAP; fallback on systems where
//                       CPUMAP creation fails (missing CAP_BPF or old kernel)

fn main() {
    println!("cargo:rerun-if-changed=ebpf/dns_xdp.c");
    compress_webui();

    #[cfg(feature = "xdp")]
    compile_ebpf();
}
fn compress_webui() {
    use std::{env, fs, io::Write, path::PathBuf};
    use flate2::{write::GzEncoder, Compression};

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir      = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed=examples/web-ui/index.html");

    let html = fs::read(manifest_dir.join("examples/web-ui/index.html"))
        .expect("examples/web-ui/index.html not found");

    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(&html).expect("gzip write");
    let gz = enc.finish().expect("gzip finish");

    fs::write(out_dir.join("index.html.gz"), &gz).expect("write index.html.gz");

    println!(
        "cargo:warning=WebUI gzip: {}B → {}B ({:.0}% of original)",
        html.len(), gz.len(),
        gz.len() as f64 / html.len() as f64 * 100.0
    );
}


#[cfg(feature = "xdp")]
fn compile_ebpf() {
    use std::{env, path::PathBuf};

    let out_dir =
        PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| panic!("OUT_DIR not set by cargo")));
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| panic!("CARGO_MANIFEST_DIR not set by cargo")),
    );

    // Target architecture → BPF define expected by kernel headers
    let bpf_arch_flag = match env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_else(|_| "x86_64".into())
        .as_str()
    {
        "x86_64" => "-D__TARGET_ARCH_x86",
        "aarch64" => "-D__TARGET_ARCH_arm64",
        "arm" => "-D__TARGET_ARCH_arm",
        other => panic!("unsupported target architecture for XDP eBPF: {other}"),
    };

    let src = manifest_dir.join("ebpf/dns_xdp.c");

    // On Debian/Ubuntu the asm/* kernel headers live under the multiarch path
    // (e.g. /usr/include/x86_64-linux-gnu) rather than /usr/include/asm.
    // Detect the right path and pass it to clang so <asm/types.h> resolves.
    //
    // clang executes on the HOST machine, so we must use the HOST arch's
    // multiarch path — not the cargo cross-compile target arch.  Using the
    // target arch (e.g. aarch64) when the host is x86_64 would look for
    // /usr/include/aarch64-linux-gnu which is absent on cross-compile CI.
    let multiarch_inc = {
        // HOST is set by cargo for build scripts (e.g. "x86_64-unknown-linux-gnu").
        let host = env::var("HOST").unwrap_or_else(|_| "x86_64-unknown-linux-gnu".into());
        let triplet = if host.starts_with("x86_64") {
            "x86_64-linux-gnu"
        } else if host.starts_with("aarch64") {
            "aarch64-linux-gnu"
        } else if host.starts_with("arm") {
            "arm-linux-gnueabihf"
        } else {
            ""
        };
        let candidate = format!("/usr/include/{triplet}");
        if !triplet.is_empty() && std::path::Path::new(&candidate).exists() {
            Some(candidate)
        } else {
            None
        }
    };

    // Base flags shared by both compilations.
    let mut base_flags: Vec<String> = vec![
        "-O2".into(),
        // -g on -target bpf generates BTF (.BTF/.BTF.ext sections), not DWARF.
        // aya-obj requires BTF for BTF-style map definitions (SEC(".maps")).
        "-g".into(),
        "-target".into(),
        "bpf".into(),
        bpf_arch_flag.into(),
        "-Wall".into(),
        "-Wno-missing-prototypes".into(),
    ];
    if let Some(ref inc) = multiarch_inc {
        base_flags.push(format!("-I{inc}"));
    }

    // Full binary — with BPF_MAP_TYPE_CPUMAP for domain-affinity routing.
    let dst = out_dir.join("dns_xdp.o");
    run_clang_compile(&base_flags, &src, &dst, &[]);

    // Minimal binary — CPUMAP excluded; used as fallback when CPUMAP creation
    // fails on the target host (slave VM, restricted CAP_BPF, old kernel).
    let dst_minimal = out_dir.join("dns_xdp_minimal.o");
    run_clang_compile(&base_flags, &src, &dst_minimal, &["-DNO_CPUMAP"]);

    println!(
        "cargo:warning=eBPF programs compiled: {} + {}",
        dst.display(),
        dst_minimal.display(),
    );
}

#[cfg(feature = "xdp")]
fn run_clang_compile(
    base_flags: &[String],
    src: &std::path::Path,
    dst: &std::path::Path,
    extra_flags: &[&str],
) {
    use std::process::Command;

    let mut args: Vec<String> = base_flags.to_vec();
    args.extend(extra_flags.iter().map(|s| s.to_string()));
    args.push("-c".into());
    args.push(
        src.to_str()
            .unwrap_or_else(|| panic!("src path not UTF-8"))
            .into(),
    );
    args.push("-o".into());
    args.push(
        dst.to_str()
            .unwrap_or_else(|| panic!("dst path not UTF-8"))
            .into(),
    );

    let out = Command::new("clang")
        .args(&args)
        .output()
        .unwrap_or_else(|e| {
            panic!("clang not found ({e}). Install with: apt install clang libbpf-dev")
        });

    if !out.status.success() {
        eprintln!("--- eBPF compilation stderr ({}) ---", dst.display());
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        panic!("eBPF compilation of {} failed (see above)", dst.display());
    }
}
