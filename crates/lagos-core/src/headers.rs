//! Outbound header construction.

use std::collections::HashSet;

use http::HeaderMap;

/// Headers that are meaningful only for a single hop and must never be relayed.
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The mutations to apply to a request before it goes upstream.
///
/// Built in the request filter and consumed in the upstream filter, so that all
/// header policy — core and extension alike — is decided in one place before
/// any of it is applied.
#[derive(Debug, Default, Clone)]
pub struct HeaderPlan {
    set: Vec<(String, String)>,
    remove: HashSet<String>,
}

impl HeaderPlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Force a header value, overriding anything the client sent. The name is
    /// also marked for removal so a client copy can never survive alongside it.
    pub fn set(&mut self, name: impl AsRef<str>, value: impl Into<String>) -> &mut Self {
        let name = name.as_ref().to_ascii_lowercase();
        self.remove.insert(name.clone());
        self.set.retain(|(n, _)| *n != name);
        self.set.push((name, value.into()));
        self
    }

    /// Strip a client-supplied header without replacing it.
    pub fn strip(&mut self, name: impl AsRef<str>) -> &mut Self {
        self.remove.insert(name.as_ref().to_ascii_lowercase());
        self
    }

    pub fn removals(&self) -> impl Iterator<Item = &String> {
        self.remove.iter()
    }

    pub fn additions(&self) -> impl Iterator<Item = &(String, String)> {
        self.set.iter()
    }
}

/// Build the `X-Forwarded-For` chain and the `X-Real-IP` it implies.
///
/// The chain the edge proxy already built is preserved and the socket peer is
/// appended, so upstreams see the true client for rate limiting, fraud checks
/// and audit rather than the gateway's pod IP.
pub fn forwarded_for(
    client_headers: &HeaderMap,
    peer: Option<&str>,
) -> (Option<String>, Option<String>) {
    let prior = client_headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());

    let chain: Vec<&str> = prior.into_iter().chain(peer).collect();
    let xff = if chain.is_empty() {
        None
    } else {
        Some(chain.join(", "))
    };

    let real_ip = prior
        .and_then(|p| p.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or(peer)
        .map(str::to_string);

    (xff, real_ip)
}

/// Host address of a socket peer, without the port.
///
/// IPv6 literals are parsed as a `SocketAddr` so the colons inside the address
/// are not mistaken for a port separator.
pub fn socket_peer_ip(peer: &str) -> Option<String> {
    if let Ok(addr) = peer.parse::<std::net::SocketAddr>() {
        return Some(addr.ip().to_string());
    }
    if let Ok(ip) = peer.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    None
}

/// True when `Content-Length` is present and exceeds `max`, or is unparseable.
/// Absent `Content-Length` (chunked) is not a declared oversize — the body
/// filter counts those bytes as they arrive.
pub fn content_length_over_limit(headers: &HeaderMap, max: u64) -> bool {
    let Some(raw) = headers.get("content-length").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    raw.parse::<u64>().map(|n| n > max).unwrap_or(true)
}

/// Running total for chunked / streaming bodies. `None` once the cap is crossed.
pub fn add_body_chunk(already: u64, chunk_len: usize, max: u64) -> Option<u64> {
    let next = already.saturating_add(chunk_len as u64);
    (next <= max).then_some(next)
}

/// True for content types whose bodies must be streamed verbatim and given the
/// longer upload timeout budget.
pub fn is_upload_content_type(content_type: Option<&str>) -> bool {
    let v = content_type.unwrap_or("").to_ascii_lowercase();
    v.contains("multipart/")
        || v.contains("application/octet-stream")
        || v.starts_with("image/")
        || v.starts_with("application/pdf")
        || v.starts_with("video/")
        || v.starts_with("audio/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn set_overrides_and_marks_for_removal() {
        let mut plan = HeaderPlan::new();
        plan.set("X-Api-Key", "secret");
        plan.set("x-api-key", "newer");
        let adds: Vec<_> = plan.additions().cloned().collect();
        assert_eq!(adds, vec![("x-api-key".to_string(), "newer".to_string())]);
        assert!(plan.removals().any(|r| r == "x-api-key"));
    }

    #[test]
    fn appends_socket_peer_to_existing_chain() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 70.41.3.18"),
        );
        let (xff, real) = forwarded_for(&h, Some("10.1.2.3"));
        assert_eq!(xff.unwrap(), "203.0.113.7, 70.41.3.18, 10.1.2.3");
        assert_eq!(
            real.unwrap(),
            "203.0.113.7",
            "real IP is the original client, not the last hop"
        );
    }

    #[test]
    fn falls_back_to_socket_peer_with_no_prior_chain() {
        let (xff, real) = forwarded_for(&HeaderMap::new(), Some("10.1.2.3"));
        assert_eq!(xff.unwrap(), "10.1.2.3");
        assert_eq!(real.unwrap(), "10.1.2.3");
    }

    #[test]
    fn no_peer_and_no_chain_yields_nothing() {
        let (xff, real) = forwarded_for(&HeaderMap::new(), None);
        assert!(xff.is_none() && real.is_none());
    }

    #[test]
    fn detects_upload_content_types() {
        assert!(is_upload_content_type(Some(
            "multipart/form-data; boundary=x"
        )));
        assert!(is_upload_content_type(Some("image/png")));
        assert!(is_upload_content_type(Some("APPLICATION/PDF")));
        assert!(!is_upload_content_type(Some("application/json")));
        assert!(!is_upload_content_type(None));
    }

    #[test]
    fn content_length_over_the_cap_is_refused() {
        let mut h = HeaderMap::new();
        h.insert("content-length", "100".parse().unwrap());
        assert!(content_length_over_limit(&h, 99));
        assert!(!content_length_over_limit(&h, 100));
        assert!(!content_length_over_limit(&HeaderMap::new(), 1));
    }

    #[test]
    fn an_unparseable_content_length_is_refused() {
        let mut h = HeaderMap::new();
        h.insert("content-length", "nope".parse().unwrap());
        assert!(content_length_over_limit(&h, 1_000_000));
    }

    #[test]
    fn streamed_chunks_stop_once_the_cap_is_crossed() {
        let mid = add_body_chunk(0, 50, 100).expect("under");
        assert_eq!(mid, 50);
        assert!(add_body_chunk(mid, 51, 100).is_none());
        assert_eq!(add_body_chunk(mid, 50, 100).unwrap(), 100);
    }

    #[test]
    fn socket_peer_ip_keeps_ipv4_host() {
        assert_eq!(socket_peer_ip("10.1.2.3:443").as_deref(), Some("10.1.2.3"));
    }

    #[test]
    fn socket_peer_ip_does_not_split_ipv6_on_colons() {
        assert_eq!(
            socket_peer_ip("[2001:db8::1]:8080").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            socket_peer_ip("2001:db8::1").as_deref(),
            Some("2001:db8::1")
        );
    }
}
