//! Shared-cache eligibility and keys. These rules apply to both admission
//! and lookup; a safe fill policy alone cannot make an existing hit safe.

use std::collections::BTreeSet;

use pingora::cache::VarianceBuilder;
use pingora::cache::cache_control::{CacheControl, InterpretCacheControl};
use pingora::cache::key::{CacheKey, HashBinary};
use pingora::http::{RequestHeader, ResponseHeader};

use crate::headers::HeaderPlan;

/// `*` and malformed field names cannot select a reusable representation.
fn vary_fields(resp: &ResponseHeader) -> Option<BTreeSet<String>> {
    let mut fields = BTreeSet::new();
    for value in resp.headers.get_all(http::header::VARY) {
        for name in value
            .to_str()
            .ok()?
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if name == "*" {
                return None;
            }
            let name = http::HeaderName::from_bytes(name.as_bytes()).ok()?;
            fields.insert(name.as_str().to_string());
        }
    }
    Some(fields)
}

pub fn eligible(resp: &ResponseHeader, authorized: bool) -> bool {
    if vary_fields(resp).is_none() {
        return false;
    }
    let cc = CacheControl::from_resp_headers(resp);
    if cc.as_ref().is_some_and(|cc| cc.private() || cc.no_store()) {
        return false;
    }
    !authorized
        || cc
            .as_ref()
            .is_some_and(|cc| cc.allow_caching_authorized_req())
}

/// Length framing keeps absent, empty, repeated and combined header values
/// distinct. Names are sorted so equivalent Vary lists have identical keys.
pub fn variance(
    resp: &ResponseHeader,
    req: &RequestHeader,
    plan: &HeaderPlan,
    forwardable: impl Fn(&str) -> bool,
) -> Option<HashBinary> {
    let mut builder = VarianceBuilder::new();
    for name in vary_fields(resp)? {
        let mut bytes = Vec::new();
        // Hash the values the upstream sees, including injected identity and
        // extension headers, rather than any client-supplied impersonation.
        if let Some((_, value)) = plan.additions().find(|(n, _)| n == &name) {
            frame(&mut bytes, value.as_bytes());
        } else if !plan.removals().any(|n| n == &name) && forwardable(&name) {
            for value in req.headers.get_all(name.as_str()) {
                frame(&mut bytes, value.as_bytes());
            }
        }
        builder.add_owned_name_value(name, bytes);
    }
    builder.finalize()
}

fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&value.len().to_be_bytes());
    out.extend_from_slice(value);
}

pub fn key(parts: &[&str], tag: &str) -> CacheKey {
    let mut primary = Vec::new();
    for part in parts {
        frame(&mut primary, part.as_bytes());
    }
    CacheKey::new(primary, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::cache::key::CacheHashKey;

    fn response(vary: &str, cc: &str) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("vary", vary).unwrap();
        resp.insert_header("cache-control", cc).unwrap();
        resp
    }

    #[test]
    fn wildcard_and_malformed_vary_are_never_reusable() {
        for vary in ["*", "Accept-Language, *", "invalid name"] {
            assert!(!eligible(&response(vary, "public, max-age=60"), false));
        }
        let mut resp = response("accept-language", "public, max-age=60");
        resp.append_header("vary", "*").unwrap();
        assert!(!eligible(&resp, true));
    }

    #[test]
    fn authorized_hits_need_explicit_permission_to_share() {
        for cc in ["max-age=60", "", "private, public", "public, no-store"] {
            assert!(!eligible(&response("", cc), true), "{cc}");
        }
        for cc in ["public, max-age=60", "s-maxage=60", "must-revalidate"] {
            assert!(eligible(&response("", cc), true), "{cc}");
        }
        assert!(eligible(&response("", "max-age=60"), false));
    }

    #[test]
    fn variance_tracks_all_header_values_and_injected_identity() {
        let resp = response("Accept-Language, X-Auth-Subject", "public");
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        let mut plan = HeaderPlan::new();
        let absent = variance(&resp, &req, &plan, |_| true);
        req.insert_header("accept-language", "").unwrap();
        let empty = variance(&resp, &req, &plan, |_| true);
        assert_ne!(absent, empty);
        req.insert_header("accept-language", "en").unwrap();
        let english = variance(&resp, &req, &plan, |_| true);
        req.append_header("accept-language", "fr").unwrap();
        assert_ne!(english, variance(&resp, &req, &plan, |_| true));
        plan.set("x-auth-subject", "alice");
        let alice = variance(&resp, &req, &plan, |_| true);
        req.insert_header("x-auth-subject", "spoofed").unwrap();
        assert_eq!(alice, variance(&resp, &req, &plan, |_| true));
        plan.set("x-auth-subject", "bob");
        assert_ne!(alice, variance(&resp, &req, &plan, |_| true));
    }

    #[test]
    fn vary_order_and_dropped_headers_do_not_change_the_representation() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-dropped", "a").unwrap();
        let plan = HeaderPlan::new();
        let a = response("X-Dropped, Accept-Language", "public");
        let b = response("accept-language, x-dropped, Accept-Language", "public");
        let before = variance(&a, &req, &plan, |_| false);
        req.insert_header("x-dropped", "b").unwrap();
        assert_eq!(before, variance(&b, &req, &plan, |_| false));
    }

    #[test]
    fn namespaces_and_component_boundaries_are_part_of_the_primary_hash() {
        assert_ne!(
            key(&["generation-1", "route", "/x"], "r").combined(),
            key(&["generation-2", "route", "/x"], "r").combined()
        );
        assert_ne!(
            key(&["a", "b\u{1}c"], "r").combined(),
            key(&["a\u{1}b", "c"], "r").combined()
        );
    }
}
