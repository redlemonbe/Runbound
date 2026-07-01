//! Block page HTTP server — serves an HTML explanation page when a domain is blocked.
//!
//! Flow:
//!   DNS query for blocked domain
//!   → ZoneAction::BlockPage
//!   → DNS answer: A record pointing to block_page_ip (usually 127.0.0.1 or the server's LAN IP)
//!   → Browser connects to block_page_port
//!   → This server responds with the HTML page

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct BlockPageConfig {
    /// IP to return in DNS answers for blocked domains. Default: 0.0.0.0 (NXDOMAIN fallback)
    #[allow(dead_code)]
    pub redirect_ip: Option<IpAddr>,
    /// Port to listen on for block page HTTP. Default: 8083.
    pub port: u16,
    /// Page title. Default: "Access Blocked".
    pub title: String,
    /// Organization name shown on the block page.
    pub org: String,
    /// Allow bypass button (opens the domain in a new tab with bypass token).
    pub allow_bypass: bool,
    /// PIN required for bypass. Empty = no PIN.
    pub bypass_pin: String,
}

impl Default for BlockPageConfig {
    fn default() -> Self {
        Self {
            redirect_ip: None,
            port: 8083,
            title: "Access Blocked".to_string(),
            org: "Runbound DNS Filter".to_string(),
            allow_bypass: false,
            bypass_pin: String::new(),
        }
    }
}

/// Spawn the block page HTTP server. Non-blocking — spawns a Tokio task.
pub async fn start(cfg: Arc<BlockPageConfig>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => { info!(port = cfg.port, "Block page server listening"); l }
        Err(e) => { warn!(error = %e, "Cannot bind block page server"); return; }
    };
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _peer)) = listener.accept().await {
                let cfg = Arc::clone(&cfg);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 { return; }
                    let req = String::from_utf8_lossy(&buf[..n]);
                    // Extract Host header and path
                    let host = req.lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                        .and_then(|l| l.splitn(2, ':').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    // XSS guard: `domain` comes from the attacker-controlled Host
                    // header and is interpolated into HTML and an inline JS string
                    // in build_page. A real DNS hostname is LDH-only, so strip
                    // everything else — this neutralises both the HTML and the JS
                    // injection contexts at the source.
                    let domain: String = host
                        .split(':')
                        .next()
                        .unwrap_or(&host)
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                        .take(253)
                        .collect();
                    let body = build_page(&cfg, &domain);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        }
    });
}

fn build_page(cfg: &BlockPageConfig, domain: &str) -> String {
    let title = &cfg.title;
    let org = &cfg.org;
    let bypass_btn = if cfg.allow_bypass {
        if cfg.bypass_pin.is_empty() {
            format!(r#"<div class="bypass"><p>Did you mean to visit this site?</p><a href="http://{domain}" class="btn-bypass">Allow once (unsafe)</a></div>"#)
        } else {
            format!(r#"<div class="bypass"><form onsubmit="checkPin(event)"><input type="password" id="pin" placeholder="Enter bypass PIN" class="pin-input"><button type="submit" class="btn-bypass">Unlock</button></form></div>
<script>function checkPin(e){{e.preventDefault();if(document.getElementById('pin').value==='{pin}')window.location='http://{domain}';else alert('Incorrect PIN');}}</script>"#,
                pin = cfg.bypass_pin, domain = domain)
        }
    } else { String::new() };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:40px;max-width:480px;width:100%;text-align:center}}
.icon{{width:64px;height:64px;background:rgba(248,81,73,.12);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}}
.icon svg{{width:32px;height:32px;stroke:#f85149;fill:none;stroke-width:2}}
h1{{font-size:22px;font-weight:700;color:#f0f6fc;margin-bottom:8px}}{title}
.domain{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 14px;font-size:14px;font-family:monospace;color:#e3b341;margin:14px 0;word-break:break-all}}
.reason{{font-size:13px;color:#8b949e;margin-bottom:20px}}
.org{{font-size:12px;color:#6e7681;margin-top:20px;padding-top:16px;border-top:1px solid #21262d}}
.bypass{{margin-top:20px}}
.bypass p{{font-size:13px;color:#8b949e;margin-bottom:10px}}
.btn-bypass{{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#f85149;padding:8px 18px;border-radius:6px;font-size:13px;text-decoration:none;cursor:pointer;display:inline-block}}
.btn-bypass:hover{{background:rgba(248,81,73,.2)}}
.pin-input{{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 12px;border-radius:6px;font-size:13px;margin-right:8px;outline:none}}
</style>
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></div>
  <h1>{title}</h1>
  <div class="domain">{domain}</div>
  <p class="reason">This domain is blocked by your network's DNS filter.</p>
  {bypass_btn}
  <div class="org">Protected by {org}</div>
</div>
</body>
</html>"#)
}
