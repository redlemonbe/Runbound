//! RFC 2136 Dynamic DNS UPDATE handler (#14).

use std::{net::IpAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use arc_swap::ArcSwap;
use base64::Engine as _;
use hickory_proto::{
    op::{Metadata, ResponseCode},
    rr::{rdata::tsig::{signed_bitmessage_to_buf, TsigAlgorithm}, Name, RData, RecordType},
};
use hickory_server::{
    server::{Request, ResponseHandler, ResponseInfo},
    zone_handler::{MessageResponseBuilder, UpdateRequest},
};
use std::ops::Deref as _;
use tracing::{debug, info, warn};

use crate::dns::local::{LocalZoneSet, ZoneAction};

/// Verify a TSIG-authenticated DNS UPDATE and apply if valid.
pub async fn handle_update<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    zones: &Arc<ArcSwap<LocalZoneSet>>,
    tsig_keys: &[(String, String, String)],
    client_ip: IpAddr,
) -> ResponseInfo {
    // Request implements Deref<MessageRequest> which implements UpdateRequest.
    // additionals() and updates() come from the UpdateRequest trait.
    let additional = UpdateRequest::additionals(request.deref());
    let tsig_rec = additional.iter().find(|r| r.record_type() == RecordType::TSIG);

    if tsig_keys.is_empty() {
        warn!(%client_ip, "DNS UPDATE refused -- no TSIG keys configured");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    }
    let Some(tsig_rec) = tsig_rec else {
        warn!(%client_ip, "DNS UPDATE refused -- TSIG required");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    };
    let RData::TSIG(ref tsig) = &tsig_rec.data else {
        warn!(%client_ip, "DNS UPDATE -- invalid TSIG RR");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    };

    // Find key by name
    let key_name = tsig_rec.name.to_ascii().to_ascii_lowercase();
    let key_name = key_name.trim_end_matches('.');
    let matching = tsig_keys.iter().find(|(n, _, _)| n.to_ascii_lowercase() == key_name);
    let Some((_, alg_str, secret_b64)) = matching else {
        warn!(%client_ip, key=%key_name, "DNS UPDATE -- unknown TSIG key");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    };

    // Algorithm check
    let expected_alg = match alg_str.as_str() {
        "hmac-sha256" | "HMAC-SHA256" => TsigAlgorithm::HmacSha256,
        "hmac-sha512" | "HMAC-SHA512" => TsigAlgorithm::HmacSha512,
        "hmac-sha384" | "HMAC-SHA384" => TsigAlgorithm::HmacSha384,
        "hmac-sha1"   | "HMAC-SHA1"   => TsigAlgorithm::HmacSha1,
        other => {
            warn!(%client_ip, alg=%other, "DNS UPDATE -- unsupported algorithm");
            return rcode(request, response_handle, ResponseCode::Refused).await;
        }
    };
    if tsig.algorithm != expected_alg {
        warn!(%client_ip, "DNS UPDATE -- algorithm mismatch");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    }

    // Timestamp anti-replay (RFC 2845 s4.5.2): +/-300s window
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(tsig.time) > 300 {
        warn!(%client_ip, key=%key_name, "DNS UPDATE -- TSIG timestamp outside +/-300s");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    }

    // Decode key and verify MAC
    let Ok(key_bytes) = base64::engine::general_purpose::STANDARD.decode(secret_b64) else {
        warn!(key=%key_name, "DNS UPDATE -- key base64 decode failed");
        return rcode(request, response_handle, ResponseCode::ServFail).await;
    };
    let raw = request.as_slice();
    let Ok((signed_buf, _)) = signed_bitmessage_to_buf(raw, None, true) else {
        warn!(%client_ip, "DNS UPDATE -- signed_bitmessage_to_buf failed");
        return rcode(request, response_handle, ResponseCode::ServFail).await;
    };
    if tsig.algorithm.verify_mac(&key_bytes, &signed_buf, &tsig.mac).is_err() {
        warn!(%client_ip, key=%key_name, "DNS UPDATE -- MAC verification failed");
        return rcode(request, response_handle, ResponseCode::Refused).await;
    }

    // Apply updates from the authority section (RFC 2136 section 2.5)
    let updates = UpdateRequest::updates(request.deref());
    if updates.is_empty() {
        debug!(%client_ip, key=%key_name, "DNS UPDATE with empty update section");
        return rcode(request, response_handle, ResponseCode::NoError).await;
    }

    let current = zones.load_full();
    let mut new_zones = (*current).clone();
    let mut added = 0usize;
    let mut deleted = 0usize;

    for rr in updates {
        let name_str = rr.name.to_ascii();
        let name_str = name_str.trim_end_matches('.');
        let class_u16 = u16::from(rr.dns_class);

        match (rr.record_type(), class_u16) {
            // Delete all RRs for name: class=ANY(255), type=ANY
            (RecordType::ANY, 255) => {
                if let Ok(n) = Name::from_ascii(name_str) {
                    new_zones.records.remove(&n);
                    deleted += 1;
                }
            }
            // Delete RRset: class=ANY(255), specific type
            (rtype, 255) => {
                if let Ok(n) = Name::from_ascii(name_str) {
                    if let Some(recs) = new_zones.records.get_mut(&n) {
                        let before = recs.len();
                        recs.retain(|r| r.record_type() != rtype);
                        deleted += before - recs.len();
                    }
                }
            }
            // Delete specific RR: class=NONE(254)
            (_, 254) => {
                if let Ok(n) = Name::from_ascii(name_str) {
                    if let Some(recs) = new_zones.records.get_mut(&n) {
                        let before = recs.len();
                        recs.retain(|r| r != rr);
                        deleted += before - recs.len();
                    }
                }
            }
            // Add record: class=IN(1), supported types
            (RecordType::A | RecordType::AAAA | RecordType::CNAME | RecordType::TXT
            | RecordType::MX | RecordType::SRV | RecordType::NS | RecordType::PTR, 1) => {
                if let Ok(n) = Name::from_ascii(name_str) {
                    new_zones.zones.entry(n.clone()).or_insert(ZoneAction::Static);
                    new_zones.records.entry(n).or_default().push(rr.clone());
                    added += 1;
                }
            }
            _ => {
                debug!(%name_str, rtype=%rr.record_type(), class=class_u16,
                    "DNS UPDATE: skipping unsupported RR type/class");
            }
        }
    }

    zones.store(Arc::new(new_zones));
    info!(%client_ip, key=%key_name, added, deleted, "DNS UPDATE applied");

    rcode(request, response_handle, ResponseCode::NoError).await
}

async fn rcode<R: ResponseHandler>(
    request: &Request,
    mut rh: R,
    rc: ResponseCode,
) -> ResponseInfo {
    let mut meta = Metadata::response_from_request(&request.metadata);
    meta.response_code = rc;
    let builder = MessageResponseBuilder::from_message_request(request);
    let response = builder.build(
        meta,
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
        std::iter::empty(),
    );
    rh.send_response(response).await.unwrap_or_else(|e| {
        tracing::error!("send update response: {e}");
        let mut fail = Metadata::response_from_request(&request.metadata);
        fail.response_code = ResponseCode::ServFail;
        ResponseInfo::from(hickory_proto::op::Header {
            metadata: fail,
            counts: Default::default(),
        })
    })
}
