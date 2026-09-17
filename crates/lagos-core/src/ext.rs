//! The extension seam.
//!
//! Deployment-specific policy — resolving a tenant, binding a query parameter
//! to the caller, injecting authorization context an upstream expects — does
//! not belong in a general-purpose gateway. Extensions are named in the route
//! file and run after authentication, before the upstream is chosen.

use std::collections::HashMap;
use std::sync::Arc;

use http::HeaderMap;

use crate::auth::Identity;
use crate::error::Rejection;
use crate::headers::HeaderPlan;
use crate::routes::RouteConfig;

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

/// Everything an extension may read about the current request, plus the header
/// plan it may mutate.
pub struct ExtensionContext<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub query: Option<&'a str>,
    pub route: &'a RouteConfig,
    /// `None` on routes declared in the `public` group.
    pub identity: Option<&'a Identity>,
    pub client_headers: &'a HeaderMap,
    pub plan: &'a mut HeaderPlan,
}

impl ExtensionContext<'_> {
    /// Read a query parameter, percent-decoding the key and value.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query?.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let key = percent_decode(k)?;
            if key == name { percent_decode(v) } else { None }
        })
    }

    pub fn client_header(&self, name: &str) -> Option<&str> {
        self.client_headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The verified caller, or a 403 if the route somehow reached an extension
    /// that requires one. Extensions should prefer this over unwrapping.
    pub fn require_identity(&self) -> Result<&Identity, Rejection> {
        self.identity.ok_or_else(|| {
            Rejection::forbidden("Authenticated user required", "extension_requires_identity")
        })
    }
}

#[async_trait::async_trait]
pub trait Extension: Send + Sync + 'static {
    /// The name routes refer to in their `extensions` array.
    fn name(&self) -> &'static str;

    async fn on_request(&self, cx: &mut ExtensionContext<'_>) -> Result<(), Rejection>;
}

#[derive(Default, Clone)]
pub struct ExtensionRegistry {
    by_name: HashMap<String, Arc<dyn Extension>>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, ext: Arc<dyn Extension>) -> &mut Self {
        self.by_name.insert(ext.name().to_string(), ext);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Extension>> {
        self.by_name.get(name)
    }

    /// Names referenced by routes but never registered. Checked at startup so a
    /// typo fails the boot instead of silently skipping a security control.
    pub fn missing<'a>(&self, referenced: impl Iterator<Item = &'a str>) -> Vec<String> {
        let mut missing: Vec<String> = referenced
            .filter(|n| !self.by_name.contains_key(*n))
            .map(str::to_string)
            .collect();
        missing.sort();
        missing.dedup();
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Noop;
    #[async_trait::async_trait]
    impl Extension for Noop {
        fn name(&self) -> &'static str {
            "noop"
        }
        async fn on_request(&self, _cx: &mut ExtensionContext<'_>) -> Result<(), Rejection> {
            Ok(())
        }
    }

    #[test]
    fn reports_unregistered_extension_names() {
        let mut reg = ExtensionRegistry::new();
        reg.register(Arc::new(Noop));
        assert!(reg.missing(["noop"].into_iter()).is_empty());
        assert_eq!(
            reg.missing(["noop", "typo", "typo"].into_iter()),
            vec!["typo"]
        );
    }

    #[test]
    fn parses_query_parameters() {
        let route = RouteConfig {
            id: "r".into(),
            prefix: "p".into(),
            upstream: "u".into(),
            methods: vec!["GET".into()],
            sse: false,
            enabled: true,
            host: Vec::new(),
            hosts: Vec::new(),
            cache: false,
            cache_authenticated: false,
            retry: None,
            retry_policy: None,
            policy_origins: Default::default(),
            rate_limit: None,
            limiter: None,
            bind: Default::default(),
            bindings: Vec::new(),
            extensions: vec![],
            auth: crate::routes::AuthTier::Required,
        };
        let headers = HeaderMap::new();
        let mut plan = HeaderPlan::new();
        let cx = ExtensionContext {
            path: "p",
            method: "GET",
            query: Some("a=1&merchantId=42&b=2"),
            route: &route,
            identity: None,
            client_headers: &headers,
            plan: &mut plan,
        };
        assert_eq!(cx.query_param("merchantId").as_deref(), Some("42"));
        assert_eq!(cx.query_param("missing"), None);
    }

    #[test]
    fn percent_decodes_query_keys_and_values() {
        let route = RouteConfig {
            id: "r".into(),
            prefix: "p".into(),
            upstream: "u".into(),
            methods: vec!["GET".into()],
            sse: false,
            enabled: true,
            host: Vec::new(),
            hosts: Vec::new(),
            cache: false,
            cache_authenticated: false,
            retry: None,
            retry_policy: None,
            policy_origins: Default::default(),
            rate_limit: None,
            limiter: None,
            bind: Default::default(),
            bindings: Vec::new(),
            extensions: vec![],
            auth: crate::routes::AuthTier::Required,
        };
        let headers = HeaderMap::new();
        let mut plan = HeaderPlan::new();
        let cx = ExtensionContext {
            path: "p",
            method: "GET",
            query: Some("merchantId=%37%37"),
            route: &route,
            identity: None,
            client_headers: &headers,
            plan: &mut plan,
        };
        assert_eq!(cx.query_param("merchantId").as_deref(), Some("77"));
    }
}
