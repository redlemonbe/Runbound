// Runbound — Automatic TLS certificate provisioning via ACME (RFC 8555)
//
// HTTP-01 challenge only — port 80 must be reachable from the internet.
// Uses reqwest as the HTTPS transport to Let's Encrypt (avoids rustls version conflicts).
// Cert freshness uses file mtime as proxy: Let's Encrypt certs are 90 days; we
// renew after 60 days (= at most 30 days before expiry).

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType,
    HttpClient, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tokio::sync::RwLock;
use tracing::{error, info};

// ── Config ─────────────────────────────────────────────────────────────────

pub struct AcmeConfig {
    pub email:          String,
    pub domains:        Vec<String>,
    pub cert_path:      PathBuf,
    pub key_path:       PathBuf,
    pub cache_dir:      PathBuf,
    pub staging:        bool,
    pub challenge_port: u16,
}

// ── Renewal check ──────────────────────────────────────────────────────────

/// Returns true if cert file is missing or was last modified more than 60 days ago.
/// Let's Encrypt certs are valid 90 days; this triggers renewal with ≥30 days left.
pub fn needs_renewal(cert_path: &Path) -> bool {
    if !cert_path.exists() {
        return true;
    }
    match std::fs::metadata(cert_path).and_then(|m| m.modified()) {
        Ok(t) => {
            std::time::SystemTime::now()
                .duration_since(t)
                .unwrap_or_default()
                > Duration::from_secs(60 * 86400)
        }
        Err(_) => true,
    }
}

// ── reqwest → instant-acme HttpClient bridge ──────────────────────────────

struct ReqwestClient(reqwest::Client);

impl HttpClient for ReqwestClient {
    fn request(
        &self,
        req: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>>
    {
        use http_body_util::BodyExt as _;

        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();

            // BodyWrapper<Bytes> has Error = Infallible — collect cannot fail.
            let body_bytes = body.collect().await
                .unwrap_or_else(|_| unreachable!("Infallible"))
                .to_bytes();

            let mut rb = client.request(parts.method.clone(), parts.uri.to_string());
            for (name, value) in &parts.headers {
                rb = rb.header(name, value);
            }
            rb = rb.body(reqwest::Body::from(body_bytes));

            let rsp = rb.send().await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            let status = http::StatusCode::from_u16(rsp.status().as_u16())
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            let mut builder = http::Response::builder().status(status);
            for (k, v) in rsp.headers() {
                builder = builder.header(k, v);
            }
            let (rsp_parts, _) = builder
                .body(())
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?
                .into_parts();

            let body_bytes: Bytes = rsp.bytes().await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            Ok(instant_acme::BytesResponse {
                parts: rsp_parts,
                body: Box::new(body_bytes),
            })
        })
    }
}

// ── Account management ─────────────────────────────────────────────────────

async fn build_account(config: &AcmeConfig) -> Result<Account> {
    let dir_url = if config.staging {
        LetsEncrypt::Staging.url().to_owned()
    } else {
        LetsEncrypt::Production.url().to_owned()
    };

    let creds_path = config.cache_dir.join("account.json");

    if creds_path.exists() {
        let json = std::fs::read_to_string(&creds_path)
            .context("read ACME account credentials")?;
        let creds: AccountCredentials = serde_json::from_str(&json)
            .context("parse ACME account credentials")?;
        return Account::builder_with_http(Box::new(ReqwestClient(reqwest::Client::new())))
            .from_credentials(creds)
            .await
            .context("restore ACME account");
    }

    let contact = format!("mailto:{}", config.email);
    let (account, creds) = Account::builder_with_http(
        Box::new(ReqwestClient(reqwest::Client::new())),
    )
    .create(
        &NewAccount {
            contact:                 &[&contact],
            terms_of_service_agreed: true,
            only_return_existing:    false,
        },
        dir_url,
        None,
    )
    .await
    .context("create ACME account")?;

    let json = serde_json::to_string_pretty(&creds)?;
    std::fs::write(&creds_path, &json).context("save ACME account credentials")?;
    info!(path = %creds_path.display(), "ACME account credentials saved");
    Ok(account)
}

// ── Certificate provisioning ───────────────────────────────────────────────

/// Provision or renew a TLS certificate via ACME HTTP-01.
/// Temporarily binds to `config.challenge_port` (default 80) for validation.
pub async fn ensure_certificate(config: &AcmeConfig) -> Result<()> {
    std::fs::create_dir_all(&config.cache_dir)
        .with_context(|| format!("create ACME cache dir: {}", config.cache_dir.display()))?;

    let account = build_account(config).await?;

    let identifiers: Vec<Identifier> = config.domains.iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("create ACME order")?;

    // Collect HTTP-01 tokens and notify ACME that challenges are ready.
    let token_map: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let mut any_pending = false;

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("fetch ACME authorization")?;
            match authz.status {
                AuthorizationStatus::Valid   => continue,
                AuthorizationStatus::Pending => any_pending = true,
                other => bail!("Authorization status {other:?} — cannot proceed"),
            }

            let Some(mut challenge) = authz.challenge(ChallengeType::Http01) else {
                bail!("No HTTP-01 challenge offered by the ACME server");
            };

            let token    = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_owned();

            token_map.write().await.insert(token, key_auth);
            challenge.set_ready().await.context("notify ACME challenge ready")?;
        }
    }

    if !any_pending {
        info!("All ACME authorizations already valid — skipping challenge phase");
    }

    // Spin up the HTTP-01 challenge server while ACME validates.
    let port   = config.challenge_port;
    let tokens = Arc::clone(&token_map);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        challenge_server(tokens, port, shutdown_rx).await;
    });

    // Give the challenge server a moment to bind before ACME polls it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let status = order.poll_ready(&RetryPolicy::default()).await
        .context("poll ACME order ready")?;

    let _ = shutdown_tx.send(());
    let _ = server.await;

    if status != OrderStatus::Ready {
        bail!("ACME order not ready after polling: {status:?}");
    }

    // Finalize — instant-acme generates a fresh ECDSA P-256 key internally.
    let private_key_pem = order.finalize().await
        .context("finalize ACME order")?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await
        .context("download certificate")?;

    // Atomic write: temp file → rename to avoid torn writes.
    let cert_tmp = config.cert_path.with_extension("pem.tmp");
    let key_tmp  = config.key_path.with_extension("pem.tmp");

    std::fs::write(&cert_tmp, &cert_chain_pem).context("write cert temp file")?;
    std::fs::write(&key_tmp,  &private_key_pem).context("write key temp file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_tmp, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&cert_tmp, &config.cert_path).context("rename cert file")?;
    std::fs::rename(&key_tmp,  &config.key_path).context("rename key file")?;

    info!(
        cert = %config.cert_path.display(),
        key  = %config.key_path.display(),
        "TLS certificate issued/renewed via Let's Encrypt"
    );
    Ok(())
}

// ── HTTP-01 challenge server ───────────────────────────────────────────────

async fn challenge_server(
    tokens:   Arc<RwLock<HashMap<String, String>>>,
    port:     u16,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    use axum::{extract::Path as APath, extract::State, http::StatusCode, routing::get, Router};

    async fn handler(
        APath(token):  APath<String>,
        State(tokens): State<Arc<RwLock<HashMap<String, String>>>>,
    ) -> (StatusCode, String) {
        let map = tokens.read().await;
        match map.get(&token) {
            Some(ka) => (StatusCode::OK,       ka.clone()),
            None     => (StatusCode::NOT_FOUND, String::new()),
        }
    }

    let app = Router::new()
        .route("/.well-known/acme-challenge/:token", get(handler))
        .with_state(tokens);

    let addr = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l)  => l,
        Err(e) => {
            error!(addr, err = %e, "ACME: cannot bind challenge server — HTTP-01 will fail");
            return;
        }
    };

    info!(addr, "ACME HTTP-01 challenge server started");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { let _ = shutdown.await; })
        .await
        .ok();
}

// ── Background renewal loop ────────────────────────────────────────────────

/// Background task: checks every 6 h and renews when ≤30 days remain.
pub async fn renewal_loop(config: AcmeConfig) {
    loop {
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        if needs_renewal(&config.cert_path) {
            info!("ACME: triggering cert renewal (≤30 days remaining)");
            match ensure_certificate(&config).await {
                Ok(()) => info!(
                    "ACME cert renewed — restart runbound to apply the new certificate"
                ),
                Err(e) => error!(err = %e, "ACME cert renewal failed — will retry in 6 h"),
            }
        }
    }
}
