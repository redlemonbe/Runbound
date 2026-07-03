//! DNS-over-QUIC listener — RFC 9250.
//!
//! Own listener built directly on `quinn` (no hickory): hickory-server used to
//! provide the QUIC transport; the de-hickory rewrite re-implemented DoT/DoH on
//! `rustls` directly but dropped DoQ. This restores it as a first-class listener
//! that reuses the same `rustls::ServerConfig` (TLS 1.3, ALPN `doq`) built by
//! [`crate::dns::server::build_tls_config`] and the same request path
//! ([`RunboundHandler::handle_request_wire`]) as DoT/DoH.
//!
//! Transport framing (RFC 9250 §4.2): each DNS query/response exchange runs on
//! its own client-initiated bidirectional stream, and the DNS message is
//! prefixed with a 2-byte big-endian length — identical to DNS-over-TCP/DoT. The
//! client sends the query then closes (FIN) its send direction; the server reads
//! to end, resolves, writes the length-prefixed response, and finishes the stream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Endpoint, ServerConfig};
use tracing::debug;

use crate::dns::server::RunboundHandler;

/// Largest DNS message we accept/emit on a stream (the 2-byte length prefix caps
/// it at 65535). Bounds the per-stream read buffer.
const MAX_DNS_MSG: usize = 65535;
/// Per-connection idle timeout — a stalled QUIC connection is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent in-flight query streams per connection (anti-amplification / DoS bound).
const MAX_BIDI_STREAMS: u32 = 128;

/// Bind a DNS-over-QUIC listener on `addr` (UDP) and spawn its accept loop.
///
/// `tls` must be the TLS 1.3-only, ALPN-`doq` config from `build_tls_config`.
/// Returns the task handle; a bind/config error is returned to the caller so the
/// other encrypted-DNS listeners can still start (parity with DoT/DoH).
pub fn spawn_doq(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    handler: Arc<RunboundHandler>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| anyhow::anyhow!("DoQ rustls->quic config: {e}"))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into());
    // Clients don't open uni streams in DoQ; reject them outright.
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .map_err(|e| anyhow::anyhow!("DoQ idle timeout: {e}"))?,
    ));
    server_config.transport_config(Arc::new(transport));

    let endpoint = Endpoint::server(server_config, addr)
        .map_err(|e| anyhow::anyhow!("DoQ bind {addr}: {e}"))?;

    Ok(tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                if let Err(e) = serve_connection(incoming, handler).await {
                    debug!(err = %e, "DoQ connection ended");
                }
            });
        }
    }))
}

/// Complete the QUIC handshake, then serve one query per bidirectional stream
/// until the peer closes the connection.
async fn serve_connection(
    incoming: quinn::Incoming,
    handler: Arc<RunboundHandler>,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let peer = conn.remote_address();
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            // Peer closed the connection: normal termination, not an error.
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            serve_stream(send, recv, peer, handler).await;
        });
    }
}

/// Read one length-prefixed query from `recv`, resolve it, write the
/// length-prefixed response on `send`, and finish the stream.
async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    handler: Arc<RunboundHandler>,
) {
    // The client FINs its send side after the query, so read_to_end terminates.
    // Cap at 2 (length prefix) + MAX_DNS_MSG to bound memory per stream.
    let buf = match recv.read_to_end(2 + MAX_DNS_MSG).await {
        Ok(b) => b,
        Err(e) => {
            debug!(err = %e, "DoQ stream read");
            return;
        }
    };
    if buf.len() < 2 {
        return;
    }
    let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if msg_len == 0 || buf.len() < 2 + msg_len {
        return;
    }

    let resp = handler.handle_request_wire(&buf[2..2 + msg_len], peer).await;
    if resp.is_empty() || resp.len() > MAX_DNS_MSG {
        return;
    }

    let mut out = Vec::with_capacity(2 + resp.len());
    out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
    out.extend_from_slice(&resp);
    if let Err(e) = send.write_all(&out).await {
        debug!(err = %e, "DoQ stream write");
        return;
    }
    let _ = send.finish();
}
