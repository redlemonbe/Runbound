// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
pub mod parser;
pub mod writer;

pub use parser::UnboundConfig;

pub fn load(path: &str) -> anyhow::Result<UnboundConfig> {
    parser::parse_file(path)
}
