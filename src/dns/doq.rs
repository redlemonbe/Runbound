//! DNS-over-QUIC listener — RFC 9250.
//!
//! Own listener built directly on `quinn` (no hickory). DoT and DoH run on
//! `rustls` directly; this is the matching first-class DoQ listener
//! for the QUIC transport
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

use crate::alerts::{AbuseVerdict, AlertTracker};
use crate::dns::acl::{Acl, AclAction};
use crate::dns::server::{tarpit_delay, tarpit_sema, RunboundHandler, TcpConnTracker};

/// Largest DNS message we accept/emit on a stream (the 2-byte length prefix caps
/// it at 65535). Bounds the per-stream read buffer.
const MAX_DNS_MSG: usize = 65535;
/// Per-connection idle timeout — a stalled QUIC connection is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Concurrent in-flight query streams per connection (anti-amplification / DoS bound).
const MAX_BIDI_STREAMS: u32 = 128;
/// Wall-clock cap on a single stream's read+resolve+write, independent of activity.
/// Parity with the DoT/DoH `TLS_SESSION_TIMEOUT` in `run_tcp_with_limit`: `IDLE_TIMEOUT`
/// alone is reset by any packet, so a peer trickling keepalives could hold a stream
/// (and its slot) open indefinitely. This bounds each stream's total lifetime.
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Bind a DNS-over-QUIC listener on `addr` (UDP) and spawn its accept loop.
///
/// `tls` must be the TLS 1.3-only, ALPN-`doq` config from `build_tls_config`.
/// Returns the task handle; a bind/config error is returned to the caller so the
/// other encrypted-DNS listeners can still start (parity with DoT/DoH).
///
/// `acl`, `tracker` and `alert` give DoQ the same connection-level protections DoT/DoH
/// get via `run_tcp_with_limit`: the source-IP ACL, the per-IP connection cap, and the
/// abuse engine (ban check + connection-verified escalation credit). The per-query ACL
/// and abuse verdict still run inside `serve_wire`; these apply earlier, on the QUIC
/// connection itself.
#[allow(clippy::too_many_arguments)]
pub fn spawn_doq(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    handler: Arc<RunboundHandler>,
    acl: Arc<Acl>,
    tracker: Arc<TcpConnTracker>,
    alert: Option<Arc<AlertTracker>>,
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
            let acl = Arc::clone(&acl);
            let tracker = Arc::clone(&tracker);
            let alert = alert.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(incoming, handler, acl, tracker, alert).await {
                    debug!(err = %e, "DoQ connection ended");
                }
            });
        }
    }))
}

/// Releases the per-IP connection slot when the connection ends, however it ends.
struct ConnSlot {
    tracker: Arc<TcpConnTracker>,
    ip: std::net::IpAddr,
}
impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.tracker.release(self.ip);
    }
}

/// QUIC application error code sent when we refuse a connection (ACL/ban/cap).
const DOQ_REFUSED: u32 = 0x02; // DOQ_INTERNAL_ERROR-ish; the client just sees a close.

/// DOQ_PROTOCOL_ERROR (RFC 9250 §4.3) — a malformed request on a stream (e.g. a
/// non-zero DNS Message ID, forbidden by §4.2.1) is reset with this code.
const DOQ_PROTOCOL_ERROR: u32 = 0x02;

/// Minimum DNS message size (12-byte header) — a DoQ payload shorter than this
/// cannot carry a valid DNS header and is a protocol error.
const DNS_HDR_MIN: usize = 12;

/// Complete the QUIC handshake, then serve one query per bidirectional stream
/// until the peer closes the connection.
async fn serve_connection(
    incoming: quinn::Incoming,
    handler: Arc<RunboundHandler>,
    acl: Arc<Acl>,
    tracker: Arc<TcpConnTracker>,
    alert: Option<Arc<AlertTracker>>,
) -> anyhow::Result<()> {
    let conn = incoming.await?;
    let peer = conn.remote_address();
    let ip = peer.ip();
    // The per-IP connection cap keys on the /48-normalised IP (parity with the TCP/DoT/DoH
    // path via normalize_tcp_ip): otherwise an IPv6 client rotating source addresses inside
    // its /64 gets a fresh quota per /128 and defeats the cap. ACL and abuse still use the
    // raw `ip` (CIDR match / real-source ban). Loopback is decided on the raw `ip` below.
    let cap_ip = crate::dns::server::normalize_tcp_ip(ip);

    // Connection-level protections, parity with run_tcp_with_limit (DoT/DoH). Loopback
    // is exempt (health checks / local relay), matching the tracker and abuse engine.
    if !ip.is_loopback() {
        // 1) Source-IP ACL: Deny and Refuse both drop the connection (no stream served).
        if !matches!(acl.check(ip), AclAction::Allow) {
            conn.close(DOQ_REFUSED.into(), b"acl");
            return Ok(());
        }
        // 2) Abuse engine on the REAL client IP. QUIC completed a handshake, so the source
        //    is connection-verified (verified = true), exactly like DoT/DoH. Block drops;
        //    Tarpit holds a bounded delay (shared tarpit semaphore) then drops.
        if let Some(at) = &alert {
            match at.record(ip, true) {
                AbuseVerdict::Block => {
                    conn.close(DOQ_REFUSED.into(), b"blocked");
                    return Ok(());
                }
                AbuseVerdict::Tarpit => {
                    if let Ok(_permit) = tarpit_sema().try_acquire() {
                        tokio::time::sleep(tarpit_delay()).await;
                    }
                    conn.close(DOQ_REFUSED.into(), b"tarpit");
                    return Ok(());
                }
                AbuseVerdict::Serve => {}
            }
        }
        // 3) Per-IP connection cap (shared with TCP/DoT/DoH), keyed on the /48. Released on any exit.
        if !tracker.try_acquire(cap_ip) {
            conn.close(DOQ_REFUSED.into(), b"conn-cap");
            return Ok(());
        }
    }
    // Hold the slot for the connection's lifetime (no-op for loopback: try_acquire
    // returned true without incrementing, and release() is a cheap miss). Keyed on the
    // same /48-normalised IP as try_acquire so the release matches the acquire.
    let _slot = ConnSlot {
        tracker: Arc::clone(&tracker),
        ip: cap_ip,
    };

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
            // Wall-clock bound on the whole stream (parity with the DoT/DoH
            // TLS_SESSION_TIMEOUT): drop a stream that trickles bytes or stalls in
            // read_to_end instead of holding its slot open indefinitely. On timeout the
            // send/recv halves drop and quinn resets the stream.
            let _ = tokio::time::timeout(
                STREAM_TIMEOUT,
                serve_stream(send, recv, peer, handler),
            )
            .await;
        });
    }
}

/// Validate a DoQ stream payload — a 2-byte big-endian length prefix followed by
/// a DNS message (RFC 9250 §4.2). Returns the DNS message slice, or `Err(code)`
/// with the QUIC application error code to reset the stream with. Pure/sync so it
/// can be unit-tested without a live QUIC connection.
fn parse_doq_frame(buf: &[u8]) -> Result<&[u8], u32> {
    if buf.len() < 2 {
        return Err(DOQ_PROTOCOL_ERROR);
    }
    let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if msg_len == 0 || buf.len() < 2 + msg_len {
        return Err(DOQ_PROTOCOL_ERROR);
    }
    let msg = &buf[2..2 + msg_len];
    // RFC 9250 §4.2.1: the DNS Message ID MUST be 0 on DoQ.
    if msg.len() < DNS_HDR_MIN || msg[0] != 0 || msg[1] != 0 {
        return Err(DOQ_PROTOCOL_ERROR);
    }
    Ok(msg)
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
    let msg = match parse_doq_frame(&buf) {
        Ok(m) => m,
        Err(code) => {
            let _ = send.reset(quinn::VarInt::from_u32(code));
            return;
        }
    };

    let resp = handler.handle_request_wire(msg, peer).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a raw DNS message in the 2-byte length prefix (RFC 9250 §4.2).
    fn frame(msg: &[u8]) -> Vec<u8> {
        let mut v = (msg.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(msg);
        v
    }

    /// Minimal 12-byte DNS message (header only) with the given transaction ID.
    fn dns_msg(id: u16) -> Vec<u8> {
        let mut m = vec![0u8; DNS_HDR_MIN];
        m[0..2].copy_from_slice(&id.to_be_bytes());
        m
    }

    #[test]
    fn doq_frame_roundtrip_ok() {
        let msg = dns_msg(0);
        let f = frame(&msg);
        assert_eq!(parse_doq_frame(&f), Ok(&msg[..]));
    }

    #[test]
    fn doq_frame_rejects_nonzero_id() {
        // RFC 9250 §4.2.1: the DNS Message ID MUST be 0 on DoQ.
        let f = frame(&dns_msg(0x1234));
        assert_eq!(parse_doq_frame(&f), Err(DOQ_PROTOCOL_ERROR));
    }

    #[test]
    fn doq_frame_rejects_malformed_length() {
        assert_eq!(parse_doq_frame(&[0x00]), Err(DOQ_PROTOCOL_ERROR)); // no length prefix
        assert_eq!(parse_doq_frame(&[0x00, 0x00]), Err(DOQ_PROTOCOL_ERROR)); // zero-length
        assert_eq!(parse_doq_frame(&[0x00, 0x0c, 0, 0]), Err(DOQ_PROTOCOL_ERROR)); // len>data
        assert_eq!(parse_doq_frame(&frame(&[0u8; 5])), Err(DOQ_PROTOCOL_ERROR)); // < 12-byte header
    }
}
