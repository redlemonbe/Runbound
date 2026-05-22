// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
// Global runtime state initialized once at startup.
// BASE_DIR is derived from the config file's parent directory.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub static BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn base_dir() -> &'static Path {
    BASE_DIR.get().unwrap_or_else(|| panic!("BASE_DIR not initialized before use"))
}
