// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Hickory-free plain DNS slow-path server — UDP and TCP.
//!
//! These are the first listeners that do not go through `hickory-server`: they
//! own the socket, parse the query with our codec, serve local zones with
//! [`crate::dns::wire_serve::answer_local`], and forward everything else to an
//! upstream over plain UDP, relaying the answer back. The fast path (XDP) is
//! unaffected; this is the slow path for `xdp: no` / non-XDP transports. TCP
//! adds the RFC 1035 §4.2.2 two-byte length framing; the serve/forward logic is
//! shared with UDP.
//!
//! Scope of the seed: plain UDP/TCP. The richer forwarding (DoT connection
//! pooling, racing, health) lives in the in-house forward pool
//! (`crate::dns::forward`); this seed module itself still does one connection
//! per query. The listener plumbing proven here is what phase 3 grows.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use crate::dns::local::LocalZoneSet;
use crate::dns::wire_serve::serve_datagram;

/// Largest UDP answer we relay/serve without TC (EDNS-bounded, DNS-flag-day).
const MAX_UDP: usize = 1232;
/// Upstream wait before giving up on a forwarded query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// How to reach the upstream for non-local queries.
#[derive(Clone)]
pub enum Upstream {
    /// Plain DNS over UDP:53 (or any explicit address).
    Udp(SocketAddr),
    /// DNS-over-TLS to `ip:853`, verifying the cert against `sni`.
    Dot {
        ip: std::net::IpAddr,
        sni: String,
        config: std::sync::Arc<rustls::ClientConfig>,
    },
}

/// Serve one received datagram: local answer from our codec, or a forwarded
/// upstream answer. Returns the response bytes to send back, or `None` to stay
/// silent (malformed query, or upstream gave nothing).
pub async fn handle_datagram(
    query: &[u8],
    zones: &LocalZoneSet,
    upstream: &Upstream,
) -> Option<Vec<u8>> {
    if let Some((local, _action)) = serve_datagram(query, zones) {
        return Some(local);
    }
    // Not locally authoritative — relay to the configured upstream.
    match upstream {
        Upstream::Udp(addr) => forward_udp(query, *addr).await,
        Upstream::Dot { ip, sni, config } => {
            forward_dot(query, *ip, sni, std::sync::Arc::clone(config)).await
        }
    }
}

/// A rustls client config trusting the Mozilla webpki roots, for DoT upstreams.
/// Built once and shared; rustls needs a crypto provider installed (the binary
/// installs ring at start-up).
pub fn dot_client_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// DNS-over-TLS forward (RFC 7858): TLS to `ip:853` with SNI `sni`, then the
/// same 2-byte length framing as TCP. A minimal seed alongside the in-house
/// forward pool's DoT client (`crate::dns::forward`); no pooling/racing here —
/// one connection per query.
pub async fn forward_dot(
    query: &[u8],
    ip: std::net::IpAddr,
    sni: &str,
    config: std::sync::Arc<rustls::ClientConfig>,
) -> Option<Vec<u8>> {
    use tokio::net::TcpStream;
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).ok()?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = timeout(UPSTREAM_TIMEOUT, TcpStream::connect((ip, 853)))
        .await
        .ok()?
        .ok()?;
    let mut tls = timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;

    let len = (query.len() as u16).to_be_bytes();
    tls.write_all(&len).await.ok()?;
    tls.write_all(query).await.ok()?;
    tls.flush().await.ok()?;

    let mut rlen = [0u8; 2];
    timeout(UPSTREAM_TIMEOUT, tls.read_exact(&mut rlen))
        .await
        .ok()?
        .ok()?;
    let n = u16::from_be_bytes(rlen) as usize;
    let mut resp = vec![0u8; n];
    tls.read_exact(&mut resp).await.ok()?;
    Some(resp)
}

/// Plain-UDP forward: send the query verbatim to `upstream`, return its raw
/// answer. No pooling/racing yet (phase 4); one ephemeral socket per query.
async fn forward_udp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let up = UdpSocket::bind(bind).await.ok()?;
    up.send_to(query, upstream).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = timeout(UPSTREAM_TIMEOUT, up.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Run the plain-UDP server loop on `sock` until the socket errors. Each query
/// is handled concurrently so a slow upstream cannot stall other clients.
pub async fn run(
    sock: Arc<UdpSocket>,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    upstream: Arc<Upstream>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let sock = Arc::clone(&sock);
        let zones = Arc::clone(&zones);
        let upstream = Arc::clone(&upstream);
        tokio::spawn(async move {
            let resp = handle_datagram(&query, &zones.load(), &upstream).await;
            if let Some(mut bytes) = resp {
                // RFC 1035 §4.1.1: this is the UDP serving path — cap the response to
                // the client's payload budget and set TC if it overflows (the XDP
                // zero-syscall fast path is untouched; this generic async path is not it).
                crate::dns::server::truncate_udp_response(&mut bytes, &query);
                let _ = sock.send_to(&bytes, peer).await;
            }
        });
    }
}

/// Plain-TCP DNS server (RFC 1035 §4.2.2 framing: a 2-byte big-endian length
/// prefixes each message). Same local-serve / forward logic as UDP, one task per
/// connection, kept alive for back-to-back queries.
pub async fn run_tcp(
    listener: TcpListener,
    zones: Arc<ArcSwap<LocalZoneSet>>,
    upstream: Arc<Upstream>,
) -> std::io::Result<()> {
    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let zones = Arc::clone(&zones);
        let upstream = Arc::clone(&upstream);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break; // peer closed
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len == 0 {
                    break;
                }
                let mut query = vec![0u8; len];
                if stream.read_exact(&mut query).await.is_err() {
                    break;
                }
                let Some(resp) = handle_datagram(&query, &zones.load(), &upstream).await else {
                    break;
                };
                let rlen = (resp.len() as u16).to_be_bytes();
                if stream.write_all(&rlen).await.is_err() || stream.write_all(&resp).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::{LocalData, LocalZone};
    use crate::dns::wire::{consts, Message, Name, Question};

    fn zoneset() -> Arc<ArcSwap<LocalZoneSet>> {
        let zones = vec![LocalZone {
            name: "local.".into(),
            zone_type: "static".into(),
        }];
        let data = vec![LocalData {
            rr: "host.local. 300 A 10.0.0.1".into(),
        }];
        Arc::new(ArcSwap::from_pointee(LocalZoneSet::from_config(
            &zones, &data,
        )))
    }

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = Message::default();
        m.header.id = 0x1234;
        m.header.set_rd(true);
        m.questions
            .push(Question::new(Name::from_ascii(name).unwrap(), qtype));
        m.encode()
    }

    /// A trivial UDP "upstream" that answers any query with a fixed A record, so
    /// the forward path can be tested without the network.
    async fn mock_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1232];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let q = Message::parse(&buf[..n]).unwrap();
                let mut r = Message {
                    header: q.header,
                    ..Default::default()
                };
                r.header.set_qr(true);
                r.header.set_ra(true);
                if let Some(question) = q.first_question() {
                    r.questions.push(question.clone());
                    r.answers.push(crate::dns::wire::Record {
                        name: question.name.clone(),
                        rtype: consts::rtype::A,
                        rclass: consts::class::IN,
                        ttl: 60,
                        rdata: crate::dns::wire::Rdata::A("203.0.113.9".parse().unwrap()),
                    });
                }
                let _ = sock.send_to(&r.encode(), peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn serves_local_and_forwards_the_rest() {
        let zones = zoneset();
        let upstream = Arc::new(Upstream::Udp(mock_upstream().await));

        // Bring up our server on an ephemeral port.
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(run(Arc::clone(&server), Arc::clone(&zones), upstream));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 1232];

        // (1) Local name — answered by our codec, authoritative, no upstream.
        client
            .send_to(&query_bytes("host.local.", consts::rtype::A), server_addr)
            .await
            .unwrap();
        let n = timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let local = Message::parse(&buf[..n]).unwrap();
        assert!(local.header.aa(), "local answer is authoritative");
        assert_eq!(local.answers.len(), 1);
        assert_eq!(
            local.answers[0].rdata,
            crate::dns::wire::Rdata::A("10.0.0.1".parse().unwrap())
        );

        // (2) Foreign name — forwarded to the upstream and relayed back.
        client
            .send_to(&query_bytes("example.com.", consts::rtype::A), server_addr)
            .await
            .unwrap();
        let n = timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let fwd = Message::parse(&buf[..n]).unwrap();
        assert!(!fwd.header.aa(), "forwarded answer is not authoritative");
        assert_eq!(fwd.answers.len(), 1);
        assert_eq!(
            fwd.answers[0].rdata,
            crate::dns::wire::Rdata::A("203.0.113.9".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn tcp_serves_local_with_length_framing() {
        use tokio::net::TcpStream;
        let zones = zoneset();
        let upstream = Arc::new(Upstream::Udp(mock_upstream().await)); // unused for a local name

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(run_tcp(listener, zones, upstream));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let q = query_bytes("host.local.", consts::rtype::A);
        stream
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&q).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; len];
        stream.read_exact(&mut resp).await.unwrap();

        let m = Message::parse(&resp).unwrap();
        assert!(m.header.aa());
        assert_eq!(m.answers.len(), 1);
        assert_eq!(
            m.answers[0].rdata,
            crate::dns::wire::Rdata::A("10.0.0.1".parse().unwrap())
        );
    }

    /// Live DoT forward against 1.1.1.1:853 — proves our rustls DoT client end to
    /// end. Network-dependent, so ignored by default; run with `--ignored`.
    #[tokio::test]
    #[ignore = "network: connects to 1.1.1.1:853"]
    async fn forward_dot_live() {
        rustls::crypto::ring::default_provider().install_default().ok();
        let cfg = dot_client_config();
        let q = query_bytes("example.com.", consts::rtype::A);
        let resp = forward_dot(&q, "1.1.1.1".parse().unwrap(), "one.one.one.one", cfg)
            .await
            .expect("DoT forward to 1.1.1.1:853 succeeds");
        let m = Message::parse(&resp).unwrap();
        assert!(m.header.qr());
        assert_eq!(m.header.rcode_low(), consts::rcode::NOERROR);
        assert!(!m.answers.is_empty(), "example.com should resolve over DoT");
    }
}
