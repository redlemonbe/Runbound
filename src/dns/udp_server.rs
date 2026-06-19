// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Hickory-free plain-UDP slow-path server (de-hickory phase 3 seed).
//!
//! This is the first listener that does not go through `hickory-server`: it owns
//! the socket, parses the query with our codec, serves local zones with
//! [`crate::dns::wire_serve::answer_local`], and forwards everything else to an
//! upstream over plain UDP, relaying the answer back. The fast path (XDP) is
//! unaffected; this is the slow path for `xdp: no` / non-XDP transports.
//!
//! Scope of the seed: plain UDP only. The richer forwarding (DoT connection
//! pooling, racing, health) stays on the hickory resolver until phase 4 lifts it
//! onto our own client; the listener plumbing proven here is what phase 3 grows.

// Ahead-of-use: exercised by the integration test below; wired into the server
// bring-up (main.rs) behind a config flag at integration. Remove the allow then.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::dns::local::LocalZoneSet;
use crate::dns::wire_serve::serve_datagram;

/// Largest UDP answer we relay/serve without TC (EDNS-bounded, DNS-flag-day).
const MAX_UDP: usize = 1232;
/// Upstream wait before giving up on a forwarded query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// Serve one received datagram: local answer from our codec, or a forwarded
/// upstream answer. Returns the response bytes to send back, or `None` to stay
/// silent (malformed query, or upstream gave nothing).
pub async fn handle_datagram(
    query: &[u8],
    zones: &LocalZoneSet,
    upstream: SocketAddr,
) -> Option<Vec<u8>> {
    if let Some(local) = serve_datagram(query, zones) {
        return Some(local);
    }
    // Not locally authoritative — relay to the upstream over plain UDP.
    forward_udp(query, upstream).await
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
    upstream: SocketAddr,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let sock = Arc::clone(&sock);
        let zones = Arc::clone(&zones);
        tokio::spawn(async move {
            let resp = handle_datagram(&query, &zones.load(), upstream).await;
            if let Some(bytes) = resp {
                let _ = sock.send_to(&bytes, peer).await;
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
        let upstream = mock_upstream().await;

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
}
