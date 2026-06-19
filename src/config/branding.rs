// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
//! Dedicated white-label branding file (#25).
//!
//! When the main config sets `branding: yes`, Runbound looks for a
//! `branding.conf` file in the same directory as the main config and, if
//! present, overrides the WebUI branding from it. The file uses the same
//! `key: value` syntax as the main config, so hex colours such as
//! `accent-color: "#22d3ee"` are quote-safe.
//!
//! Branding is a **WebUI-only** concern: nothing here is exposed by, or
//! depends on, the REST API.

use std::path::Path;

use crate::config::parser::{strip_inline_comment, UnboundConfig};

/// Conventional file name, resolved next to the main config.
pub const BRANDING_FILE: &str = "branding.conf";

/// If `cfg.branding` is set, load `<base_dir>/branding.conf` and apply it.
/// A missing file is non-fatal: warn and keep the built-in defaults.
pub fn apply(cfg: &mut UnboundConfig, base_dir: &Path) {
    if !cfg.branding {
        return;
    }
    let path = base_dir.join(BRANDING_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            apply_str(cfg, &content);
            tracing::info!(
                path = %path.display(),
                brand = %cfg.ui_brand_name,
                "branding: loaded dedicated branding file"
            );
        }
        Err(_) => {
            tracing::warn!(
                path = %path.display(),
                "branding: yes but branding file is missing — using built-in defaults"
            );
        }
    }
}

/// Parse `key: value` branding lines and apply them onto `cfg`. Unknown keys
/// are ignored. Split out from [`apply`] for unit testing.
pub fn apply_str(cfg: &mut UnboundConfig, content: &str) {
    for raw in content.lines() {
        let line = strip_inline_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"').to_string()),
            None => continue,
        };
        match key {
            "brand-name" => cfg.ui_brand_name = val,
            "logo-url" => cfg.ui_brand_logo_url = val,
            "accent-color" => cfg.ui_accent_color = val,
            "favicon-url" => cfg.ui_favicon_url = val,
            "about-org" => cfg.about_org = val,
            "about-text" => cfg.about_text = val,
            "about-support-url" => cfg.about_support_url = val,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_fields_and_hex_survives() {
        let mut cfg = UnboundConfig::defaults();
        cfg.branding = true;
        apply_str(
            &mut cfg,
            "brand-name: \"ACME DNS\"\n\
             accent-color: \"#ff00ff\"   # company magenta\n\
             logo-url: \"https://acme.tld/logo.svg\"\n\
             favicon-url: \"https://acme.tld/fav.ico\"\n\
             about-org: \"ACME Corporation\"\n\
             about-text: \"Internal resolver — contact IT.\"\n\
             about-support-url: \"https://acme.tld/support\"\n",
        );
        assert_eq!(cfg.ui_brand_name, "ACME DNS");
        assert_eq!(cfg.ui_accent_color, "#ff00ff");
        assert_eq!(cfg.ui_brand_logo_url, "https://acme.tld/logo.svg");
        assert_eq!(cfg.ui_favicon_url, "https://acme.tld/fav.ico");
        assert_eq!(cfg.about_org, "ACME Corporation");
        assert_eq!(cfg.about_text, "Internal resolver — contact IT.");
        assert_eq!(cfg.about_support_url, "https://acme.tld/support");
    }

    #[test]
    fn unknown_keys_ignored_and_url_colons_preserved() {
        let mut cfg = UnboundConfig::defaults();
        apply_str(&mut cfg, "bogus-key: whatever\nlogo-url: https://h:8443/l.png\n");
        assert_eq!(cfg.ui_brand_logo_url, "https://h:8443/l.png");
    }
}
