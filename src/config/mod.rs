// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
pub mod parser;
pub mod writer;
pub mod branding;

pub use parser::UnboundConfig;

pub fn load(path: &str) -> anyhow::Result<UnboundConfig> {
    let mut cfg = parser::parse_file(path)?;
    let base_dir = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    branding::apply(&mut cfg, base_dir);
    Ok(cfg)
}
