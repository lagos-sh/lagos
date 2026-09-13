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

/// The client address to believe, resolved against the number of proxies in
/// front of the gateway.
///
/// `X-Forwarded-For` is appended to by each hop, so entries are ordered
/// oldest-first and **only the rightmost ones are trustworthy** — anything
/// further left was written by whoever sent the request. Counting from the
/// right is what makes this safe: with `trusted_proxies: 0` nothing in the
/// header is believed and the socket peer is used; with `1` the last entry is
/// taken, which the single proxy in front appended itself.
///
/// Getting this wrong is a spoof, not a detail. Trusting the *leftmost* entry —
/// the usual shortcut — lets any caller assert any source address by sending
/// one header, which defeats every downstream control keyed on client IP:
/// per-IP quotas, geo rules, fraud scoring, abuse blocklists and audit trails.
pub fn client_address(
    forwarded_for: Option<&str>,
    peer: Option<&str>,
    trusted_proxies: usize,
) -> Option<String> {
    if trusted_proxies == 0 {
        return peer.map(str::to_string);
    }

    let mut chain: Vec<&str> = forwarded_for
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(p) = peer {
        chain.push(p);
    }

    // `trusted_proxies` hops back from the right-hand end.
    chain
        .len()
        .checked_sub(trusted_proxies)
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| chain.get(i))
        .map(|s| (*s).to_string())
        // A chain shorter than the configured depth means the request did not
        // arrive through the expected proxies. Fall back to the socket peer
        // rather than to a client-supplied entry.
        .or_else(|| peer.map(str::to_string))
}

/// Build the `X-Forwarded-For` chain and the `X-Real-IP` it implies.
///
/// `trusted_proxies` is how many hops in front of this gateway are its own
/// infrastructure — a cloud load balancer, an ingress controller — and may
/// therefore be believed.
///
/// * `0` (the default) means the gateway is the edge. Whatever chain arrived
///   was written by the caller, so it is **replaced** rather than extended:
///   the socket peer is the only address anyone has proven. An upstream that
///   reads `X-Real-IP` then gets a fact, not a client assertion.
/// * `n > 0` means the first `n` hops from the right were appended by trusted
///   proxies. The chain is preserved and the socket peer appended, and
///   `X-Real-IP` is the entry those trusted hops vouch for.
///
/// Either way `X-Real-IP` and the limiter's key come from the same
/// [`client_address`] rule, so the address an upstream blocks on is the address
/// the gateway counted.
pub fn forwarded_for(
    client_headers: &HeaderMap,
    peer: Option<&str>,
    trusted_proxies: usize,
) -> (Option<String>, Option<String>) {
    let prior = client_headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        // Nothing in front of us appended this, so none of it is evidence.
        .filter(|_| trusted_proxies > 0);

    let real_ip = client_address(prior, peer, trusted_proxies);

    let chain: Vec<&str> = prior.into_iter().chain(peer).collect();
    let xff = if chain.is_empty() {
        None
    } else {
        Some(chain.join(", "))
    };

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

    fn with_xff(value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(value));
        h
    }

    #[test]
    fn appends_socket_peer_to_a_chain_from_trusted_proxies() {
        let h = with_xff("203.0.113.7, 70.41.3.18");
        // Two hops in front, so both entries were appended by our own
        // infrastructure and the leftmost is the caller they saw.
        let (xff, real) = forwarded_for(&h, Some("10.1.2.3"), 2);
        assert_eq!(xff.unwrap(), "203.0.113.7, 70.41.3.18, 10.1.2.3");
        assert_eq!(real.unwrap(), "203.0.113.7");
    }

    #[test]
    fn an_untrusted_chain_is_discarded_rather_than_extended() {
        // The gateway is the edge. Anyone can send this header, so believing
        // any of it would let a caller pick its own source address and defeat
        // every downstream control keyed on client IP.
        let h = with_xff("1.2.3.4, 5.6.7.8");
        let (xff, real) = forwarded_for(&h, Some("10.1.2.3"), 0);
        assert_eq!(
            xff.unwrap(),
            "10.1.2.3",
            "the forged chain must not survive"
        );
        assert_eq!(real.unwrap(), "10.1.2.3");
    }

    #[test]
    fn a_forged_prefix_cannot_displace_the_trusted_hop() {
        // One trusted proxy in front. The attacker pads the chain hoping the
        // gateway reads the leftmost entry; counting from the right means the
        // answer is whatever that one proxy appended, however long the padding.
        for forged in [
            "9.9.9.9",
            "9.9.9.9, 8.8.8.8",
            "9.9.9.9, 8.8.8.8, 7.7.7.7, 6.6.6.6",
        ] {
            let mut h = HeaderMap::new();
            h.insert(
                "x-forwarded-for",
                HeaderValue::from_str(&format!("{forged}, 203.0.113.7")).unwrap(),
            );
            let (_, real) = forwarded_for(&h, Some("10.1.2.3"), 1);
            assert_eq!(
                real.as_deref(),
                Some("203.0.113.7"),
                "padding `{forged}` changed the believed client"
            );
        }
    }

    #[test]
    fn a_short_chain_falls_back_to_the_socket_peer() {
        // Configured for two proxies but only one entry arrived: the request
        // did not come the expected way, so nothing in the header is evidence.
        let h = with_xff("1.2.3.4");
        let (_, real) = forwarded_for(&h, Some("10.1.2.3"), 2);
        assert_eq!(real.as_deref(), Some("10.1.2.3"));
    }

    #[test]
    fn falls_back_to_socket_peer_with_no_prior_chain() {
        let (xff, real) = forwarded_for(&HeaderMap::new(), Some("10.1.2.3"), 1);
        assert_eq!(xff.unwrap(), "10.1.2.3");
        assert_eq!(real.unwrap(), "10.1.2.3");
    }

    #[test]
    fn no_peer_and_no_chain_yields_nothing() {
        let (xff, real) = forwarded_for(&HeaderMap::new(), None, 0);
        assert!(xff.is_none() && real.is_none());
    }

    #[test]
    fn the_limiter_and_the_upstream_agree_on_the_client() {
        // These must not drift: throttling one address while telling the
        // upstream about another makes every per-IP control unenforceable.
        for trusted in 0..3 {
            let h = with_xff("1.2.3.4, 203.0.113.7");
            let (_, real) = forwarded_for(&h, Some("10.1.2.3"), trusted);
            let keyed = client_address(
                h.get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .filter(|_| trusted > 0),
                Some("10.1.2.3"),
                trusted,
            );
            assert_eq!(real, keyed, "disagreement at trusted_proxies={trusted}");
        }
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
