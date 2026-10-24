//! The extension seam.
//!
//! Deployment-specific policy — resolving a tenant, binding a query parameter
//! to the caller, injecting authorization context an upstream expects — does
//! not belong in a general-purpose gateway. Extensions are named in the route
//! file and run after authentication, before the upstream is chosen.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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

type ExecutionAdmission = (Option<usize>, Option<tokio::sync::Semaphore>);

#[derive(Default, Clone)]
pub struct ExtensionRegistry {
    by_name: HashMap<String, Arc<dyn Extension>>,
    // Clones passed to public/internal listeners share one admission budget.
    admission: Arc<OnceLock<ExecutionAdmission>>,
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

    /// Run trusted hooks with cooperative per-hook and absolute chain budgets.
    /// A timeout drops the future; it cannot interrupt blocking native code or
    /// undo side effects/detached tasks already created by an extension.
    pub(crate) async fn run_chain(
        &self,
        cx: &mut ExtensionContext<'_>,
        hook_budget: Duration,
        chain_budget: Duration,
        max_inflight: Option<usize>,
    ) -> Result<(), Rejection> {
        if cx.route.extensions.is_empty() {
            return Ok(());
        }
        if max_inflight.is_some_and(|n| n == 0 || n > tokio::sync::Semaphore::MAX_PERMITS) {
            return Err(Rejection::unavailable(
                "Invalid policy execution capacity",
                "extension_capacity",
            ));
        }
        let (configured, admission) = self
            .admission
            .get_or_init(|| (max_inflight, max_inflight.map(tokio::sync::Semaphore::new)));
        if *configured != max_inflight {
            return Err(Rejection::unavailable(
                "Conflicting policy execution capacity",
                "extension_capacity",
            ));
        }
        let _permit = match admission {
            Some(gate) => Some(gate.try_acquire().map_err(|_| {
                Rejection::unavailable("Policy execution is at capacity", "extension_capacity")
            })?),
            None => None,
        };
        let started = tokio::time::Instant::now();
        let chain_deadline = started.checked_add(chain_budget).ok_or_else(|| {
            Rejection::unavailable("Invalid policy execution budget", "extension_chain_timeout")
        })?;
        let route = cx.route;
        for name in &route.extensions {
            let Some(extension) = self.get(name) else {
                return Err(Rejection::unavailable(
                    "Gateway misconfigured",
                    format!("missing_extension_{name}"),
                ));
            };
            let hook_start = tokio::time::Instant::now();
            if hook_start >= chain_deadline {
                return Err(Rejection::unavailable(
                    "Policy execution timed out",
                    "extension_chain_timeout",
                ));
            }
            let hook_deadline = hook_start
                .checked_add(hook_budget)
                .unwrap_or(chain_deadline);
            let deadline = hook_deadline.min(chain_deadline);
            let reason = if chain_deadline <= hook_deadline {
                "extension_chain_timeout"
            } else {
                "extension_timeout"
            };
            let outcome = tokio::time::timeout_at(deadline, extension.on_request(cx)).await;
            let expired = tokio::time::Instant::now() >= deadline;
            let metric_outcome = match &outcome {
                _ if expired => "timeout",
                Ok(Ok(())) => "success",
                Ok(Err(_)) => "rejected",
                Err(_) => "timeout",
            };
            if let Some(metrics) = crate::metrics::metrics() {
                metrics.record_extension(
                    extension.name(),
                    metric_outcome,
                    hook_start.elapsed().as_secs_f64(),
                );
            }
            match outcome {
                Ok(result) if !expired => result?,
                _ => {
                    tracing::warn!(event = "gateway.extension.timeout", extension = %name,
                        elapsed_ms = hook_start.elapsed().as_millis(), reason,
                        "native policy exceeded cooperative execution budget");
                    return Err(Rejection::unavailable("Policy execution timed out", reason));
                }
            }
        }
        Ok(())
    }

    /// Startup and reload share one registry check before publication.
    pub fn validate(&self, table: &crate::routes::RouteTable) -> anyhow::Result<()> {
        let missing = self.missing(table.extension_names());
        if !missing.is_empty() {
            anyhow::bail!(
                "routes reference extensions that are not registered: {}",
                missing.join(", ")
            );
        }
        Ok(())
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
    fn extension_budget_configuration_rejects_invalid_limits() {
        for settings in [
            "timeouts: {extension: 0s}",
            "timeouts: {extension: 10s, extension_chain: 1s}",
            "limits: {extension_inflight: 0}",
        ] {
            let text = format!("upstreams: {{u: 'http://127.0.0.1:1'}}\n{settings}\n");
            let (raw, expanded) = crate::config::GatewayConfig::parse("test.yml", &text).unwrap();
            assert!(raw.resolve(&expanded).is_err());
        }
    }

    struct Scripted {
        name: &'static str,
        delay: Duration,
        reject: bool,
        entered: Arc<std::sync::atomic::AtomicUsize>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }
    struct DropCount(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[async_trait::async_trait]
    impl Extension for Scripted {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn on_request(&self, cx: &mut ExtensionContext<'_>) -> Result<(), Rejection> {
            let _drop = DropCount(self.dropped.clone());
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            cx.plan.set("x-extension", self.name);
            tokio::time::sleep(self.delay).await;
            if self.reject {
                Err(Rejection::forbidden("Refused", "extension_test"))
            } else {
                Ok(())
            }
        }
    }
    fn fixture_route(names: &[&str]) -> RouteConfig {
        serde_json::from_value(
            serde_json::json!({"id":"r", "prefix":"/r", "upstream":"u", "extensions":names}),
        )
        .unwrap()
    }
    async fn execute(
        registry: &ExtensionRegistry,
        route: &RouteConfig,
        hook: Duration,
        chain: Duration,
    ) -> Result<(), Rejection> {
        let mut plan = HeaderPlan::new();
        let headers = HeaderMap::new();
        let mut cx = ExtensionContext {
            path: "r",
            method: "GET",
            query: None,
            route,
            identity: None,
            client_headers: &headers,
            plan: &mut plan,
        };
        registry.run_chain(&mut cx, hook, chain, Some(1)).await
    }
    fn scripted(name: &'static str, delay: Duration, reject: bool) -> Scripted {
        Scripted {
            name,
            delay,
            reject,
            entered: Arc::default(),
            dropped: Arc::default(),
        }
    }

    #[tokio::test]
    async fn successful_and_rejected_hooks_preserve_decisions_and_release_capacity() {
        let mut registry = ExtensionRegistry::new();
        registry.register(Arc::new(Noop));
        registry.register(Arc::new(scripted("reject", Duration::ZERO, true)));
        assert!(
            execute(
                &registry,
                &fixture_route(&["noop"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .is_ok()
        );
        assert_eq!(
            execute(
                &registry,
                &fixture_route(&["reject"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .unwrap_err()
            .status,
            403
        );
        assert!(
            execute(
                &registry,
                &fixture_route(&["noop"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn hook_timeout_drops_future_and_releases_capacity() {
        let mut registry = ExtensionRegistry::new();
        let slow = scripted("slow", Duration::from_secs(10), false);
        let dropped = slow.dropped.clone();
        registry.register(Arc::new(slow)).register(Arc::new(Noop));
        assert_eq!(
            execute(
                &registry,
                &fixture_route(&["slow"]),
                Duration::from_millis(5),
                Duration::from_secs(1)
            )
            .await
            .unwrap_err()
            .reason,
            "extension_timeout"
        );
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            execute(
                &registry,
                &fixture_route(&["noop"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn total_chain_budget_stops_later_hooks() {
        let mut registry = ExtensionRegistry::new();
        let third = scripted("third", Duration::ZERO, false);
        let entered = third.entered.clone();
        registry
            .register(Arc::new(scripted(
                "first",
                Duration::from_millis(20),
                false,
            )))
            .register(Arc::new(scripted(
                "second",
                Duration::from_millis(20),
                false,
            )))
            .register(Arc::new(third));
        assert_eq!(
            execute(
                &registry,
                &fixture_route(&["first", "second", "third"]),
                Duration::from_secs(1),
                Duration::from_millis(30)
            )
            .await
            .unwrap_err()
            .reason,
            "extension_chain_timeout"
        );
        assert_eq!(entered.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn registry_clones_share_capacity_and_cancellation_releases_it() {
        let mut registry = ExtensionRegistry::new();
        let slow = scripted("slow", Duration::from_secs(10), false);
        let entered = slow.entered.clone();
        let dropped = slow.dropped.clone();
        registry.register(Arc::new(slow)).register(Arc::new(Noop));
        let clone = registry.clone();
        let first = tokio::spawn(async move {
            execute(
                &clone,
                &fixture_route(&["slow"]),
                Duration::from_secs(20),
                Duration::from_secs(30),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while entered.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            execute(
                &registry,
                &fixture_route(&["noop"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .unwrap_err()
            .reason,
            "extension_capacity"
        );
        first.abort();
        let _ = first.await;
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            execute(
                &registry,
                &fixture_route(&["noop"]),
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .await
            .is_ok()
        );
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
            strip_prefix: false,
            enabled: true,
            client_key: None,
            host: Vec::new(),
            hosts: Vec::new(),
            cache: false,
            cache_authenticated: false,
            retry: None,
            retry_policy: None,
            policy_origins: Default::default(),
            rate_limit: None,
            limiter: None,
            concurrency: None,
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
            strip_prefix: false,
            enabled: true,
            client_key: None,
            host: Vec::new(),
            hosts: Vec::new(),
            cache: false,
            cache_authenticated: false,
            retry: None,
            retry_policy: None,
            policy_origins: Default::default(),
            rate_limit: None,
            limiter: None,
            concurrency: None,
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
