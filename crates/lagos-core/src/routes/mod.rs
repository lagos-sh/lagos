//! Route table: the allowlist, the deny-list, and how a request finds an upstream.

pub mod file;

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use schemars::JsonSchema;
use serde::Deserialize;

use crate::binding::Binding;
use crate::path::normalize_proxy_path;

/// How much the gateway insists on knowing who the caller is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthTier {
    /// No token is read, even if one is sent. Identity headers are stripped.
    Public,
    /// A token is verified and identity injected *if present*. A missing token
    /// is fine; a present-but-invalid one is still a 401, so a stale session
    /// surfaces as an error instead of silently degrading to anonymous.
    Optional,
    /// A service-to-service caller presenting a shared credential. There is no
    /// user; these routes are served only on the internal listener.
    Machine,
    /// A valid token is required. Also the default, so a tier that somehow goes
    /// missing fails closed rather than silently opening a route.
    #[default]
    Required,
}

impl AuthTier {
    /// Whether a *user* token is read on this tier.
    pub fn verifies(&self) -> bool {
        matches!(self, AuthTier::Optional | AuthTier::Required)
    }

    pub fn is_machine(&self) -> bool {
        matches!(self, AuthTier::Machine)
    }

    /// The group name this tier is written under, for diagnostics.
    pub fn group(&self) -> &'static str {
        match self {
            AuthTier::Public => "public",
            AuthTier::Optional => "optional",
            AuthTier::Machine => "machine",
            AuthTier::Required => "authenticated",
        }
    }
}

/// A `host:` pattern on a route.
///
/// # This is routing, not authorization
///
/// The `Host` header is chosen by the client, so restricting a route to a host
/// keeps *honest* traffic apart — it does not keep anyone out. A caller who can
/// reach the listener can send any `Host` they like. Where a route must be
/// unreachable from the public internet, put it in the `machine` group so it
/// binds to the internal listener, or deny-list it; those are topology, which a
/// header cannot argue with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// `api.example.com`
    Exact(String),
    /// `*.example.com` — any sub-domain, but not the bare suffix.
    Suffix(String),
}

impl HostPattern {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return Err("host pattern is empty".into());
        }
        if raw.contains('/') {
            return Err(format!(
                "host `{raw}` looks like a URL; a host is a name, optionally with a port"
            ));
        }
        match raw.strip_prefix("*.") {
            Some(suffix) if !suffix.is_empty() => Ok(Self::Suffix(suffix.to_string())),
            Some(_) => Err(format!("host `{raw}` has an empty wildcard suffix")),
            None => Ok(Self::Exact(raw)),
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(want) => host == want,
            // The leading dot is what stops `evilexample.com` matching
            // `*.example.com`.
            Self::Suffix(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host
                        .get(..host.len().saturating_sub(suffix.len()))
                        .is_some_and(|p| p.ends_with('.'))
            }
        }
    }

    /// Whether one Host value can satisfy both patterns.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Exact(a), b) => b.matches(a),
            (a, Self::Exact(b)) => a.matches(b),
            (Self::Suffix(a), Self::Suffix(b)) => {
                a == b
                    || a.strip_suffix(b)
                        .is_some_and(|prefix| prefix.ends_with('.'))
                    || b.strip_suffix(a)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// Normalize an incoming `Host` header for matching: lower-cased, port removed.
///
/// The port is a deployment detail — the same service is 8080 in a pod and 443
/// at the edge — so matching on it would make a route file environment-specific.
pub fn normalize_host(raw: &str) -> &str {
    let host = raw.trim();
    // An IPv6 literal is bracketed, and its colons are not a port separator.
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => host.get(..=end).unwrap_or(host),
            None => host,
        };
    }
    match host.split_once(':') {
        Some((h, _)) => h,
        None => host,
    }
}

/// One allowlisted public prefix.
///
/// ```yaml
/// - prefix: /users
///   upstream: users
///   methods: [GET, POST]
/// ```
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(from = "RouteInput")]
pub struct RouteConfig {
    /// Names the route in logs, metrics and `explain` output. Defaults to the
    /// prefix, which is usually the name you would have chosen anyway.
    #[serde(default)]
    pub id: String,
    /// Hosts this route serves. Omit to serve any host.
    ///
    /// Accepts one name or a list, exact (`api.example.com`) or a wildcard
    /// sub-domain (`*.example.com`). See [`HostPattern`]: this separates
    /// traffic, it does not secure it.
    #[serde(default, deserialize_with = "string_or_seq")]
    #[schemars(schema_with = "crate::config::schema::one_or_many_hosts")]
    pub host: Vec<String>,
    /// `host`, parsed. Filled during [`RouteTable::build`].
    #[serde(skip)]
    pub hosts: Vec<HostPattern>,
    /// Matched against the canonical sub-path, either exactly or as a
    /// `/`-delimited prefix.
    pub prefix: String,
    /// Key into `upstreams`.
    pub upstream: String,
    /// Allowed methods. Omit to inherit defaults, or allow any if absent; naming them is an extra restriction,
    /// not the security boundary — that is the group the route lives in.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Stream the response without buffering and use the SSE timeout budget.
    #[serde(default)]
    pub sse: bool,
    /// Remove the matched `prefix` before forwarding, so the upstream sees the
    /// path beneath it: `prefix: /svc/users` sends `/svc/users/42` as `/42`,
    /// and the bare prefix as `/`.
    ///
    /// Off by default, so the prefix is preserved as before. Every gateway
    /// decision — deny-list, matching, bindings, cache, logs — still uses the
    /// full canonical path; only the request line sent upstream changes. The
    /// query string is kept as is.
    #[serde(default)]
    pub strip_prefix: bool,
    /// Set `false` to leave the route out of the table. Combined with
    /// interpolation this is a rollout switch: `enabled: ${NEW_ROUTES:-false}`.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Values the caller must prove they own, as `source: target` pairs:
    ///
    /// ```yaml
    /// bind:
    ///   query.merchantId: identity.company_id
    /// ```
    ///
    /// Checked after authentication and before any extension runs. Any failure
    /// — missing parameter, missing claim, or mismatch — is a 403.
    #[serde(default)]
    pub bind: BTreeMap<String, String>,
    /// `bind`, parsed. Filled during [`RouteTable::build`]; a spec that does
    /// not parse lands in [`RouteTable::errors`] and fails validation, so an
    /// unparsed binding can never reach the request path.
    #[serde(skip)]
    pub bindings: Vec<Binding>,
    /// Serve this route from the shared response cache.
    ///
    /// Off by default. A cache that serves one caller's response to another is
    /// a data leak, not a performance regression, so this is never inferred.
    #[serde(default)]
    pub cache: bool,
    /// Permit caching on a tier that verifies tokens.
    ///
    /// Without this, `cache: true` on `optional` or `authenticated` is refused
    /// at startup. Responses on those tiers are usually personalised, and
    /// whether they are safe to share depends entirely on the upstream sending
    /// correct `Cache-Control` — a claim about that service which has to be
    /// made deliberately.
    #[serde(default)]
    pub cache_authenticated: bool,
    /// Retry a failed upstream attempt.
    #[serde(default)]
    pub retry: Option<crate::config::RetryConfig>,
    /// `retry`, resolved. Filled during [`RouteTable::build`].
    #[serde(skip)]
    pub retry_policy: Option<crate::retry::Policy>,
    /// Requests allowed per interval, counted locally.
    #[serde(default)]
    pub rate_limit: Option<crate::config::RateLimitConfig>,
    /// The limiter backing `rate_limit`. Built during [`RouteTable::build`]
    /// so the counters live as long as the table and are replaced with it.
    #[serde(skip)]
    pub limiter: Option<Arc<crate::ratelimit::Limiter>>,
    /// Names of extensions to run for this route, in order.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Derived from the group the route was declared in; never set in the file.
    #[serde(skip)]
    pub auth: AuthTier,
    /// Source of each effective route policy, filled by deserialization/resolution.
    #[serde(skip)]
    pub policy_origins: PolicyOrigins,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    /// Names the route in logs, metrics and `explain` output. Defaults to the
    /// prefix, which is usually the name you would have chosen anyway.
    #[serde(default)]
    pub id: String,
    /// Hosts this route serves. Omit to serve any host.
    ///
    /// Accepts one name or a list, exact (`api.example.com`) or a wildcard
    /// sub-domain (`*.example.com`). See [`HostPattern`]: this separates
    /// traffic, it does not secure it.
    #[serde(default, deserialize_with = "string_or_seq")]
    #[schemars(schema_with = "crate::config::schema::one_or_many_hosts")]
    pub host: Vec<String>,
    /// Matched against the canonical sub-path, either exactly or as a
    /// `/`-delimited prefix.
    pub prefix: String,
    /// Key into `upstreams`.
    pub upstream: String,
    /// Allowed methods. Omit to inherit defaults, or allow any if absent; naming them is an extra restriction,
    /// not the security boundary — that is the group the route lives in.
    /// An explicit empty list allows any method; null is invalid.
    #[serde(default, deserialize_with = "present_methods")]
    #[schemars(with = "Vec<String>")]
    #[schemars(transform = crate::config::schema::inherited_policy)]
    pub methods: Option<Vec<String>>,
    /// Stream the response without buffering and use the SSE timeout budget.
    #[serde(default)]
    pub sse: bool,
    /// Remove the matched `prefix` before forwarding, so the upstream sees the
    /// path beneath it: `prefix: /svc/users` sends `/svc/users/42` as `/42`,
    /// and the bare prefix as `/`.
    ///
    /// Off by default, so the prefix is preserved as before. Every gateway
    /// decision — deny-list, matching, bindings, cache, logs — still uses the
    /// full canonical path; only the request line sent upstream changes. The
    /// query string is kept as is.
    #[serde(default)]
    pub strip_prefix: bool,
    /// Set `false` to leave the route out of the table. Combined with
    /// interpolation this is a rollout switch: `enabled: ${NEW_ROUTES:-false}`.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Values the caller must prove they own, as `source: target` pairs:
    ///
    /// ```yaml
    /// bind:
    ///   query.merchantId: identity.company_id
    /// ```
    ///
    /// Checked after authentication and before any extension runs. Any failure
    /// — missing parameter, missing claim, or mismatch — is a 403.
    #[serde(default)]
    pub bind: BTreeMap<String, String>,
    /// Serve this route from the shared response cache.
    ///
    /// Off by default. A cache that serves one caller's response to another is
    /// a data leak, not a performance regression, so this is never inferred.
    #[serde(default)]
    pub cache: bool,
    /// Permit caching on a tier that verifies tokens.
    ///
    /// Without this, `cache: true` on `optional` or `authenticated` is refused
    /// at startup. Responses on those tiers are usually personalised, and
    /// whether they are safe to share depends entirely on the upstream sending
    /// correct `Cache-Control` — a claim about that service which has to be
    /// made deliberately.
    #[serde(default)]
    pub cache_authenticated: bool,
    /// Retry a failed upstream attempt.
    /// Omit to inherit global defaults; null disables; a mapping replaces the whole policy.
    #[serde(default, deserialize_with = "present_nullable")]
    #[schemars(with = "Option<crate::config::RetryConfig>")]
    #[schemars(transform = crate::config::schema::inherited_policy)]
    pub retry: Option<Option<crate::config::RetryConfig>>,
    /// Requests allowed per interval, counted locally.
    /// Omit to inherit global defaults; null disables; a mapping replaces the whole policy.
    #[serde(default, deserialize_with = "present_nullable")]
    #[schemars(with = "Option<crate::config::RateLimitConfig>")]
    #[schemars(transform = crate::config::schema::inherited_policy)]
    pub rate_limit: Option<Option<crate::config::RateLimitConfig>>,
    /// Names of extensions to run for this route, in order.
    #[serde(default)]
    pub extensions: Vec<String>,
}
impl From<RouteInput> for RouteConfig {
    fn from(input: RouteInput) -> Self {
        Self {
            id: input.id,
            host: input.host,
            prefix: input.prefix,
            upstream: input.upstream,
            sse: input.sse,
            strip_prefix: input.strip_prefix,
            enabled: input.enabled,
            bind: input.bind,
            cache: input.cache,
            cache_authenticated: input.cache_authenticated,
            extensions: input.extensions,
            policy_origins: PolicyOrigins {
                methods: if input.methods.is_some() {
                    PolicyOrigin::Route
                } else {
                    PolicyOrigin::BuiltIn
                },
                retry: if input.retry.is_some() {
                    PolicyOrigin::Route
                } else {
                    PolicyOrigin::BuiltIn
                },
                rate_limit: if input.rate_limit.is_some() {
                    PolicyOrigin::Route
                } else {
                    PolicyOrigin::BuiltIn
                },
            },
            methods: input.methods.unwrap_or_default(),
            retry: input.retry.flatten(),
            rate_limit: input.rate_limit.flatten(),
            hosts: Vec::new(),
            bindings: Vec::new(),
            retry_policy: None,
            limiter: None,
            auth: AuthTier::default(),
        }
    }
}

pub(crate) fn present_methods<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(d).map(Some)
}

fn present_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// Where a resolved policy was declared. Explicit null/empty values are route overrides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PolicyOrigin {
    #[default]
    Route,
    GlobalDefaults,
    BuiltIn,
}

impl PolicyOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::GlobalDefaults => "global defaults",
            Self::BuiltIn => "built-in",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyOrigins {
    pub methods: PolicyOrigin,
    pub retry: PolicyOrigin,
    pub rate_limit: PolicyOrigin,
}

fn enabled_by_default() -> bool {
    true
}

impl RouteConfig {
    fn matches_method(&self, normalized: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|method| method == normalized)
    }

    fn matches_host(&self, normalized: Option<&str>) -> bool {
        self.hosts.is_empty()
            || normalized.is_some_and(|host| self.hosts.iter().any(|pattern| pattern.matches(host)))
    }

    /// The canonical sub-path to send upstream for a request this route
    /// matched: `path` itself, or with `strip_prefix` the part beneath the
    /// prefix, without a leading `/` (empty for the bare prefix).
    ///
    /// `path` must be a canonical path the route matched. Because matching is
    /// on a segment boundary, what follows the prefix is either nothing or a
    /// `/`; anything else means the caller broke that contract, and the path is
    /// returned untouched rather than cut mid-segment.
    pub fn upstream_path<'a>(&self, path: &'a str) -> &'a str {
        if !self.strip_prefix {
            return path;
        }
        match path.strip_prefix(self.prefix.as_str()) {
            Some("") => "",
            Some(rest) => rest.strip_prefix('/').unwrap_or(path),
            None => path,
        }
    }
}

/// Diagnostic metadata for an enabled route with a matching path prefix.
pub(crate) struct RouteCandidate<'a> {
    pub route: &'a RouteConfig,
    pub host_matches: bool,
    pub method_matches: bool,
}

/// Accept either `host: api.example.com` or `host: [a.example.com, b.example.com]`.
fn string_or_seq<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

/// The route table as written, before tiers are flattened into one list.
///
/// Auth tier comes from the group a route lives in, never from a field on the
/// route, so a route cannot accidentally be declared public.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteGroups {
    /// Path prefixes refused on the public listener outright. Anything here is
    /// unreachable from the internet even if some other group also matches it.
    #[serde(default)]
    pub internal: Vec<String>,
    /// Service-to-service endpoints, served only on the internal listener and
    /// only to a caller presenting the machine credential.
    #[serde(default)]
    pub machine: Vec<RouteConfig>,
    /// Proxied without a token. The injected credentials are still applied.
    #[serde(default)]
    pub public: Vec<RouteConfig>,
    /// Usable signed-out, but personalised when a caller is signed in.
    #[serde(default)]
    pub optional: Vec<RouteConfig>,
    /// Require a verified bearer token.
    #[serde(default)]
    pub authenticated: Vec<RouteConfig>,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    /// Cache entries belong to this table snapshot. A reload must not reuse
    /// responses admitted under a previous route or authorization policy.
    cache_namespace: uuid::Uuid,
    deny_prefixes: Vec<String>,
    /// Sorted by prefix length descending so the most specific route wins.
    routes: Vec<RouteConfig>,
    /// Specs that did not parse. Building stays infallible so the matcher has
    /// one shape; validation turns these into a startup failure.
    errors: Vec<String>,
}

/// Whether `path` is `prefix` itself or sits beneath it, on a segment boundary.
///
/// The boundary is the whole point: a plain `starts_with` would put
/// `/users-admin` under a rule written for `/users`, which on the deny-list is
/// a bypass and on the allowlist is a route reaching an upstream nobody
/// authorized.
///
/// Written to compare in place rather than building `format!("{prefix}/")`.
/// That allocation ran once per candidate route *per request* — on the one code
/// path every request to the gateway takes, and it grew with the size of the
/// route table, so the busiest deployment paid the most for it.
fn under_prefix(path: &str, prefix: &str) -> bool {
    // Exactly `path == prefix || path.starts_with(&format!("{prefix}/"))`:
    // `strip_prefix` succeeds when `path` begins with `prefix`, an empty
    // remainder means the two are equal, and a remainder starting with `/`
    // means the match landed on a segment boundary. No special case for an
    // empty prefix — it must keep matching only the empty path, as before,
    // since on the deny-list "matches everything" would be a very loud
    // surprise.
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

#[cfg(test)]
mod prefix_tests {
    use super::under_prefix;

    #[test]
    fn matches_only_on_a_segment_boundary() {
        assert!(under_prefix("users", "users"));
        assert!(under_prefix("users/4/pets", "users"));
        assert!(!under_prefix("users-admin", "users"));
        assert!(!under_prefix("usersx/4", "users"));
        assert!(!under_prefix("use", "users"));
    }

    #[test]
    fn an_empty_prefix_still_matches_only_the_empty_path() {
        // The behaviour the `format!`-based version had. A deny-list entry that
        // normalizes to "" must not start denying the whole gateway.
        assert!(under_prefix("", ""));
        assert!(!under_prefix("users", ""));
    }
}

impl RouteTable {
    pub fn build(groups: RouteGroups) -> Self {
        Self::build_with_defaults(groups, &crate::config::RouteDefaults::default())
    }

    /// Resolve policy inheritance before deriving matchers, retry policies and limiters.
    pub fn build_with_defaults(
        groups: RouteGroups,
        defaults: &crate::config::RouteDefaults,
    ) -> Self {
        let deny_prefixes = groups
            .internal
            .iter()
            .map(|p| normalize_proxy_path(p).to_string())
            .collect();

        let mut routes: Vec<RouteConfig> = groups
            .public
            .into_iter()
            .map(|r| RouteConfig {
                auth: AuthTier::Public,
                ..r
            })
            .chain(groups.optional.into_iter().map(|r| RouteConfig {
                auth: AuthTier::Optional,
                ..r
            }))
            .chain(groups.authenticated.into_iter().map(|r| RouteConfig {
                auth: AuthTier::Required,
                ..r
            }))
            .chain(groups.machine.into_iter().map(|r| RouteConfig {
                auth: AuthTier::Machine,
                ..r
            }))
            .filter(|r| r.enabled)
            .map(|mut r| {
                if r.policy_origins.methods == PolicyOrigin::BuiltIn
                    && let Some(methods) = &defaults.methods
                {
                    r.methods = methods.clone();
                    r.policy_origins.methods = PolicyOrigin::GlobalDefaults;
                }
                if r.policy_origins.retry == PolicyOrigin::BuiltIn
                    && let Some(retry) = &defaults.retry
                {
                    r.retry = Some(retry.clone());
                    r.policy_origins.retry = PolicyOrigin::GlobalDefaults;
                }
                if r.policy_origins.rate_limit == PolicyOrigin::BuiltIn
                    && let Some(rate) = &defaults.rate_limit
                {
                    r.rate_limit = Some(rate.clone());
                    r.policy_origins.rate_limit = PolicyOrigin::GlobalDefaults;
                }
                r.prefix = normalize_proxy_path(&r.prefix).to_string();
                r.methods = r.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
                if r.id.trim().is_empty() {
                    // Host-based routing means several routes legitimately
                    // share a prefix, so the host has to be part of the
                    // derived name or they would all collide.
                    r.id = if r.host.is_empty() {
                        r.prefix.clone()
                    } else {
                        format!("{}/{}", r.host.join(","), r.prefix)
                    };
                }
                r
            })
            .collect();

        let mut errors = Vec::new();
        for r in &mut routes {
            for h in &r.host {
                match HostPattern::parse(h) {
                    Ok(p) => r.hosts.push(p),
                    Err(e) => errors.push(format!("route `{}`: {e}", r.id)),
                }
            }
            if let Some(rt) = &r.retry {
                r.retry_policy = Some(crate::retry::Policy::from_config(rt));
            }
            if let Some(rl) = &r.rate_limit {
                if rl.requests == 0 {
                    errors.push(format!(
                        "route `{}`: rate_limit.requests is 0, which would refuse every request. \
                         Remove the route instead, or set `enabled: false`.",
                        r.id
                    ));
                } else {
                    r.limiter = Some(Arc::new(crate::ratelimit::Limiter::new(rl)));
                }
            }
            for (source, target) in &r.bind {
                match Binding::parse(source, target) {
                    Ok(b) => r.bindings.push(b),
                    Err(e) => errors.push(format!("route `{}`: {e}", r.id)),
                }
            }
        }

        // A host-specific route wins over one that serves any host, and among
        // equals the longest prefix wins — so `api.example.com/users` beats a
        // catch-all `/users` regardless of the order they were written in.
        routes.sort_by_key(|r| {
            (
                std::cmp::Reverse(!r.hosts.is_empty()),
                std::cmp::Reverse(r.prefix.len()),
            )
        });
        Self {
            cache_namespace: uuid::Uuid::new_v4(),
            deny_prefixes,
            routes,
            errors,
        }
    }

    /// Binding specs that did not parse, for startup validation.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// True if the path is inside a deny-listed prefix. Checked before matching
    /// so a broad allowlist entry can never expose an internal sub-tree.
    pub fn is_denied(&self, path: &str) -> bool {
        let p = normalize_proxy_path(path);
        self.deny_prefixes.iter().any(|d| under_prefix(p, d))
    }

    pub fn match_route(&self, path: &str, method: &str) -> Option<&RouteConfig> {
        self.match_request(None, path, method)
    }

    /// Match a request, honouring any `host:` restriction.
    ///
    /// `host` is the raw `Host` header; it is normalized here so every caller
    /// agrees on case and port handling.
    pub fn match_request(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
    ) -> Option<&RouteConfig> {
        let p = normalize_proxy_path(path);
        let m = method.to_ascii_uppercase();
        let h = host.map(|h| normalize_host(h).to_ascii_lowercase());

        self.routes.iter().find(|r| {
            under_prefix(p, &r.prefix) && r.matches_method(&m) && r.matches_host(h.as_deref())
        })
    }

    /// Uses the runtime's prefix, host and method predicates. Deny rules and
    /// listener availability are reported separately by the offline caller.
    pub(crate) fn prefix_candidates(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
    ) -> Vec<RouteCandidate<'_>> {
        let p = normalize_proxy_path(path);
        let m = method.to_ascii_uppercase();
        let h = host.map(|host| normalize_host(host).to_ascii_lowercase());
        self.routes
            .iter()
            .filter(|route| under_prefix(p, &route.prefix))
            .map(|route| RouteCandidate {
                route,
                host_matches: route.matches_host(h.as_deref()),
                method_matches: route.matches_method(&m),
            })
            .collect()
    }

    pub fn routes(&self) -> &[RouteConfig] {
        &self.routes
    }

    pub fn cache_namespace(&self) -> uuid::Uuid {
        self.cache_namespace
    }

    pub fn deny_prefixes(&self) -> &[String] {
        &self.deny_prefixes
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Split into (public-listener table, internal-listener table). The machine
    /// tier never appears in the public table, so a public request cannot reach
    /// an internal route regardless of what the deny-list says.
    pub fn partition_by_listener(self) -> (RouteTable, RouteTable) {
        let (machine, public): (Vec<_>, Vec<_>) = self
            .routes
            .into_iter()
            .partition(|r| r.auth == AuthTier::Machine);
        (
            RouteTable {
                cache_namespace: self.cache_namespace,
                deny_prefixes: self.deny_prefixes.clone(),
                routes: public,
                errors: self.errors.clone(),
            },
            // The deny-list guards the public surface; the internal listener is
            // where those paths are legitimately served.
            RouteTable {
                cache_namespace: self.cache_namespace,
                deny_prefixes: Vec::new(),
                routes: machine,
                errors: self.errors,
            },
        )
    }

    /// Every extension name referenced by any loaded route, for startup validation.
    pub fn extension_names(&self) -> impl Iterator<Item = &str> {
        self.routes
            .iter()
            .flat_map(|r| r.extensions.iter().map(String::as_str))
    }
}

/// A source of route tables.
///
/// The file provider ships today. The same seam accepts a provider that watches
/// Kubernetes `Ingress`/`HTTPRoute` resources and pushes a new table on every
/// reconcile, without the proxy path changing at all.
#[async_trait::async_trait]
pub trait RouteProvider: Send + Sync + 'static {
    async fn load(&self) -> anyhow::Result<RouteTable>;
}

/// Lock-free route table handle. Readers on the request path never block, so a
/// reload cannot add latency to in-flight traffic.
#[derive(Clone)]
pub struct SharedRoutes(Arc<ArcSwap<RouteTable>>);

impl SharedRoutes {
    pub fn new(table: RouteTable) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(table)))
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<RouteTable>> {
        self.0.load()
    }

    pub fn store(&self, mut table: RouteTable) {
        table.cache_namespace = uuid::Uuid::new_v4();
        self.0.store(Arc::new(table));
    }

    /// Publish a freshly loaded table onto one or both listeners.
    ///
    /// The table is partitioned first so a reload cannot put machine routes
    /// onto the public handle — the same split applied at startup.
    pub fn publish_reload(table: RouteTable, public: &Self, machine: Option<&Self>) {
        let (public_table, machine_table) = table.partition_by_listener();
        public.store(public_table);
        if let Some(machine_routes) = machine {
            machine_routes.store(machine_table);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(yaml: &str) -> RouteGroups {
        serde_yaml_ng::from_str(yaml).expect("test fixture should parse")
    }

    #[test]
    fn reloads_change_the_cache_namespace_without_changing_inflight_snapshots() {
        let shared = SharedRoutes::new(table());
        let old = shared.load();
        shared.store(table());
        assert_ne!(old.cache_namespace(), shared.load().cache_namespace());
        let namespace = old.cache_namespace();
        shared.store(table());
        assert_eq!(old.cache_namespace(), namespace);
    }

    fn table() -> RouteTable {
        RouteTable::build(groups(
            r#"
internal: [loyalty/wallets, products/internal]
public:
  - { id: products, prefix: products, upstream: products, methods: [GET] }
authenticated:
  - { id: loyalty-wallet, prefix: loyalty/me/wallet, upstream: loyalty, methods: [GET] }
  - { id: loyalty, prefix: loyalty, upstream: loyalty, methods: [GET, POST] }
  - { id: gated, prefix: gated, upstream: loyalty, methods: [GET], enabled: false }
"#,
        ))
    }

    #[test]
    fn denies_internal_prefixes_and_their_subtrees() {
        let t = table();
        assert!(t.is_denied("loyalty/wallets"));
        assert!(t.is_denied("loyalty/wallets/42/transactions"));
        assert!(t.is_denied("products/internal/sync"));
        // A prefix must match on a segment boundary, not a raw substring.
        assert!(!t.is_denied("loyalty/walletsomething"));
        assert!(!t.is_denied("loyalty/me/wallet"));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = table();
        assert_eq!(
            t.match_route("loyalty/me/wallet", "GET").unwrap().id,
            "loyalty-wallet"
        );
        assert_eq!(
            t.match_route("loyalty/settings", "GET").unwrap().id,
            "loyalty"
        );
    }

    #[test]
    fn method_must_be_allowlisted_when_methods_are_named() {
        let t = table();
        assert!(t.match_route("products/1", "GET").is_some());
        assert!(t.match_route("products/1", "POST").is_none());
        assert!(
            t.match_route("products/1", "get").is_some(),
            "method match is case-insensitive"
        );
    }

    #[test]
    fn omitting_methods_allows_any_method() {
        let t = RouteTable::build(groups("public:\n  - { prefix: anything, upstream: u }\n"));
        for m in ["GET", "POST", "DELETE", "PATCH"] {
            assert!(t.match_route("anything/x", m).is_some(), "{m} should match");
        }
    }

    #[test]
    fn an_omitted_id_defaults_to_the_prefix() {
        let t = RouteTable::build(groups("public:\n  - { prefix: /users, upstream: u }\n"));
        assert_eq!(t.match_route("users/1", "GET").unwrap().id, "users");
    }

    #[test]
    fn strip_prefix_forwards_the_path_beneath_the_prefix() {
        let t = RouteTable::build(groups(
            r#"
public:
  - { id: stripped, prefix: /svc/users, upstream: u, strip_prefix: true }
  - { id: kept, prefix: /orders, upstream: u }
"#,
        ));
        let stripped = t.match_route("svc/users/42/pets", "GET").unwrap();
        assert_eq!(stripped.upstream_path("svc/users/42/pets"), "42/pets");
        // The bare prefix becomes the upstream's root.
        assert_eq!(stripped.upstream_path("svc/users"), "");
        // Matching itself is unchanged: still the full path, still on a
        // segment boundary.
        assert!(t.match_route("svc/usersx/1", "GET").is_none());

        let kept = t.match_route("orders/7", "GET").unwrap();
        assert!(
            !kept.strip_prefix,
            "preserving the prefix stays the default"
        );
        assert_eq!(kept.upstream_path("orders/7"), "orders/7");
    }

    #[test]
    fn upstream_path_never_cuts_mid_segment() {
        // Not reachable through match_request, which only matches on a segment
        // boundary; guarded anyway so a future caller cannot turn `users-admin`
        // into `-admin`.
        let t = RouteTable::build(groups(
            "public:\n  - { prefix: users, upstream: u, strip_prefix: true }\n",
        ));
        let r = &t.routes()[0];
        assert_eq!(r.upstream_path("users-admin/1"), "users-admin/1");
        assert_eq!(r.upstream_path("other/1"), "other/1");
    }

    #[test]
    fn routes_on_one_prefix_for_different_hosts_get_distinct_ids() {
        // The normal shape for host-based routing; identical derived ids would
        // make it fail validation for no good reason.
        let t = RouteTable::build(groups(
            r#"
public:
  - { host: a.example.com, prefix: users, upstream: u }
  - { host: b.example.com, prefix: users, upstream: u }
  - { prefix: users, upstream: u }
"#,
        ));
        let ids: Vec<&str> = t.routes().iter().map(|r| r.id.as_str()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "ids must be distinct: {ids:?}");
        assert!(ids.contains(&"a.example.com/users"));
        assert!(ids.contains(&"users"));
    }

    #[test]
    fn auth_tier_comes_from_the_group() {
        let t = table();
        assert_eq!(
            t.match_route("products/1", "GET").unwrap().auth,
            AuthTier::Public
        );
        assert_eq!(
            t.match_route("loyalty/settings", "GET").unwrap().auth,
            AuthTier::Required
        );
    }

    #[test]
    fn optional_routes_load_as_the_optional_tier() {
        let t = RouteTable::build(groups(
            "optional:\n  - { id: browse, prefix: products, upstream: p, methods: [GET] }\n",
        ));
        assert_eq!(
            t.match_route("products/1", "GET").unwrap().auth,
            AuthTier::Optional
        );
    }

    #[test]
    fn machine_routes_are_absent_from_the_public_listener() {
        let (public, machine) = RouteTable::build(groups(
            r#"
internal: [products/internal]
public:
  - { id: cat, prefix: products, upstream: p, methods: [GET] }
machine:
  - { id: sync, prefix: products/internal, upstream: p, methods: [POST] }
"#,
        ))
        .partition_by_listener();

        // Not merely deny-listed on the public side — not present at all.
        assert!(
            public
                .match_route("products/internal/sync", "POST")
                .is_none()
        );
        assert!(public.is_denied("products/internal/sync"));
        assert_eq!(public.len(), 1);

        // And served on the internal side, where the deny-list does not apply.
        assert_eq!(
            machine
                .match_route("products/internal/sync", "POST")
                .unwrap()
                .id,
            "sync"
        );
        assert!(!machine.is_denied("products/internal/sync"));
        assert_eq!(machine.len(), 1);
    }

    #[test]
    fn a_reloaded_table_is_repartitioned_onto_both_listeners() {
        let g = groups(
            r#"
internal: [products/internal]
public:
  - { id: cat, prefix: products, upstream: p, methods: [GET] }
machine:
  - { id: sync, prefix: products/internal, upstream: p, methods: [POST] }
  - { id: loyalty-internal, prefix: loyalty/internal, upstream: p, methods: [GET] }
"#,
        );
        let public = SharedRoutes::new(RouteTable::default());
        let machine = SharedRoutes::new(RouteTable::default());

        SharedRoutes::publish_reload(RouteTable::build(g), &public, Some(&machine));

        // Machine routes must not appear on the public handle — including
        // prefixes the deny-list does not cover (`loyalty/internal`).
        assert!(
            public
                .load()
                .match_route("loyalty/internal/sync", "GET")
                .is_none()
        );
        assert!(
            public
                .load()
                .match_route("products/internal/sync", "POST")
                .is_none()
        );
        assert_eq!(
            public.load().match_route("products/1", "GET").unwrap().id,
            "cat"
        );
        assert_eq!(
            machine
                .load()
                .match_route("loyalty/internal/sync", "GET")
                .unwrap()
                .id,
            "loyalty-internal"
        );
        assert_eq!(machine.load().len(), 2);
        assert_eq!(public.load().len(), 1);
    }

    #[test]
    fn machine_tier_does_not_read_a_user_token() {
        assert!(!AuthTier::Machine.verifies());
        assert!(!AuthTier::Public.verifies());
        assert!(AuthTier::Optional.verifies());
        assert!(AuthTier::Required.verifies());
    }

    #[test]
    fn an_absent_group_yields_no_routes_rather_than_defaulting_open() {
        assert!(RouteTable::build(groups("internal: []\n")).is_empty());
    }

    #[test]
    fn a_disabled_route_is_left_out_of_the_table() {
        assert!(table().match_route("gated", "GET").is_none());
        let t = RouteTable::build(groups(
            "authenticated:\n  - { id: gated, prefix: gated, upstream: loyalty, enabled: true }\n",
        ));
        assert!(t.match_route("gated", "GET").is_some());
    }

    #[test]
    fn an_unknown_route_key_is_rejected_rather_than_ignored() {
        // `prefx:` must not silently produce a route with no prefix at all.
        let e =
            serde_yaml_ng::from_str::<RouteGroups>("public:\n  - { prefx: /users, upstream: u }\n");
        assert!(e.is_err(), "a misspelled route key must be a parse error");
    }

    // --- host matching --------------------------------------------------

    fn hosted() -> RouteTable {
        RouteTable::build(groups(
            r#"
public:
  - { id: any,      prefix: users, upstream: u, methods: [GET] }
  - { id: api,      host: api.example.com, prefix: users, upstream: a, methods: [GET] }
  - { id: previews, host: "*.preview.example.com", prefix: users, upstream: p, methods: [GET] }
  - { id: multi,    host: [one.example.com, two.example.com], prefix: multi, upstream: m, methods: [GET] }
"#,
        ))
    }

    #[test]
    fn a_route_without_a_host_serves_every_host() {
        let t = hosted();
        assert_eq!(
            t.match_request(Some("anything.example.org"), "users/1", "GET")
                .unwrap()
                .id,
            "any"
        );
        assert_eq!(t.match_request(None, "users/1", "GET").unwrap().id, "any");
    }

    #[test]
    fn a_host_specific_route_wins_over_a_catch_all() {
        // Regardless of the order they were written in.
        let t = hosted();
        assert_eq!(
            t.match_request(Some("api.example.com"), "users/1", "GET")
                .unwrap()
                .id,
            "api"
        );
    }

    #[test]
    fn the_port_is_ignored_when_matching() {
        // The same service is :8080 in a pod and :443 at the edge; matching on
        // it would make the route file environment-specific.
        let t = hosted();
        assert_eq!(
            t.match_request(Some("api.example.com:8443"), "users/1", "GET")
                .unwrap()
                .id,
            "api"
        );
    }

    #[test]
    fn host_matching_ignores_case() {
        let t = hosted();
        assert_eq!(
            t.match_request(Some("API.Example.COM"), "users/1", "GET")
                .unwrap()
                .id,
            "api"
        );
    }

    #[test]
    fn a_wildcard_host_requires_the_dot_boundary() {
        let t = hosted();
        assert_eq!(
            t.match_request(Some("pr-42.preview.example.com"), "users/1", "GET")
                .unwrap()
                .id,
            "previews"
        );
        // The bare suffix is not a sub-domain of itself, and a lookalike
        // prefix must not match — both fall through to the catch-all.
        assert_eq!(
            t.match_request(Some("preview.example.com"), "users/1", "GET")
                .unwrap()
                .id,
            "any"
        );
        assert_eq!(
            t.match_request(Some("evilpreview.example.com"), "users/1", "GET")
                .unwrap()
                .id,
            "any"
        );
    }

    #[test]
    fn a_route_may_list_several_hosts() {
        let t = hosted();
        for h in ["one.example.com", "two.example.com"] {
            assert_eq!(
                t.match_request(Some(h), "multi/x", "GET").unwrap().id,
                "multi"
            );
        }
        assert!(
            t.match_request(Some("three.example.com"), "multi/x", "GET")
                .is_none()
        );
    }

    #[test]
    fn a_host_restricted_route_does_not_match_without_a_host_header() {
        let t = RouteTable::build(groups(
            "public:\n  - { id: api, host: api.example.com, prefix: only, upstream: a }\n",
        ));
        assert!(t.match_request(None, "only/x", "GET").is_none());
        assert!(
            t.match_request(Some("api.example.com"), "only/x", "GET")
                .is_some()
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets() {
        assert_eq!(normalize_host("[::1]:8080"), "[::1]");
        assert_eq!(normalize_host("[::1]"), "[::1]");
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host(" example.com "), "example.com");
    }

    #[test]
    fn a_malformed_host_pattern_is_recorded_as_an_error() {
        let t = RouteTable::build(groups(
            "public:\n  - { id: bad, host: \"https://api.example.com/x\", prefix: a, upstream: u }\n",
        ));
        assert!(!t.errors().is_empty(), "a URL is not a host pattern");
    }

    #[test]
    fn prefix_match_respects_segment_boundaries() {
        let t = table();
        // `productsfoo` must not match the `products` route.
        assert!(t.match_route("productsfoo", "GET").is_none());
    }
}

#[cfg(test)]
mod candidate_tests {
    use super::*;

    #[test]
    fn diagnostic_predicates_agree_with_runtime_selection() {
        let groups: RouteGroups = serde_yaml_ng::from_str(
            r#"
public:
  - id: exact
    prefix: /users
    host: api.example.com
    methods: [GET]
    upstream: users
  - id: wildcard
    prefix: /users
    host: '*.example.net'
    methods: [POST]
    upstream: users
  - id: any
    prefix: /any
    upstream: users
  - id: disabled
    prefix: /users
    enabled: false
    upstream: users
machine:
  - id: machine
    prefix: /users
    upstream: users
"#,
        )
        .unwrap();
        let (public, internal) = RouteTable::build(groups).partition_by_listener();
        for table in [&public, &internal] {
            for (host, path, method) in [
                (Some("API.EXAMPLE.COM:443"), "users/42", "get"),
                (Some("a.example.net"), "users", "POST"),
                (Some("example.net"), "users", "POST"),
                (None, "users", "GET"),
                (None, "users-admin", "GET"),
                (None, "any/42", "PATCH"),
            ] {
                let candidates = table.prefix_candidates(host, path, method);
                assert!(!candidates.iter().any(|c| c.route.id == "disabled"));
                let eligible = candidates
                    .iter()
                    .find(|c| c.host_matches && c.method_matches)
                    .map(|c| c.route.id.as_str());
                assert_eq!(
                    eligible,
                    table
                        .match_request(host, path, method)
                        .map(|r| r.id.as_str())
                );
            }
        }
        assert!(
            public
                .prefix_candidates(None, "users-admin", "GET")
                .is_empty()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod defaults_tests {
    use super::*;
    use crate::config::RouteDefaults;

    fn defaults() -> RouteDefaults {
        serde_yaml_ng::from_str("methods: [get]\nretry: {attempts: 2, non_idempotent: true}\nrate_limit: {requests: 1, interval: 120s, key: route}\n").unwrap()
    }

    #[test]
    fn inheritance_applies_to_every_group_before_runtime_policy_construction() {
        for group in ["public", "optional", "authenticated", "machine"] {
            let groups =
                serde_yaml_ng::from_str(&format!("{group}: [{{prefix: /items, upstream: u}}]"))
                    .unwrap();
            let table = RouteTable::build_with_defaults(groups, &defaults());
            let route = &table.routes()[0];
            assert_eq!(route.methods, ["GET"]);
            assert!(table.match_request(None, "items", "POST").is_none());
            assert!(table.match_request(None, "items", "get").is_some());
            assert_eq!(route.retry.as_ref().unwrap().attempts, 2);
            assert!(route.retry_policy.is_some());
            let limiter = route.limiter.as_ref().unwrap();
            assert!(limiter.check("caller").allowed);
            assert!(!limiter.check("caller").allowed);
            assert_eq!(route.policy_origins.methods, PolicyOrigin::GlobalDefaults);
            assert_eq!(route.policy_origins.retry, PolicyOrigin::GlobalDefaults);
            assert_eq!(
                route.policy_origins.rate_limit,
                PolicyOrigin::GlobalDefaults
            );
            assert!(!route.cache);
            assert!(!route.cache_authenticated);
        }
    }

    #[test]
    fn explicit_null_and_empty_methods_disable_inherited_policies() {
        let groups = serde_yaml_ng::from_str(
            "public: [{prefix: /items, upstream: u, methods: [], retry: null, rate_limit: null}]",
        )
        .unwrap();
        let table = RouteTable::build_with_defaults(groups, &defaults());
        let route = &table.routes()[0];
        assert!(table.match_request(None, "items", "PATCH").is_some());
        assert!(route.retry.is_none());
        assert!(route.retry_policy.is_none());
        assert!(route.rate_limit.is_none());
        assert!(route.limiter.is_none());
        assert_eq!(route.policy_origins, PolicyOrigins::default());
    }

    #[test]
    fn replacements_do_not_merge_with_global_fields() {
        let groups = serde_yaml_ng::from_str("public: [{prefix: /items, upstream: u, methods: [post], retry: {attempts: 0}, rate_limit: {requests: 5}}]").unwrap();
        let table = RouteTable::build_with_defaults(groups, &defaults());
        let route = &table.routes()[0];
        assert_eq!(route.methods, ["POST"]);
        assert_eq!(route.retry.as_ref().unwrap().attempts, 0);
        assert!(!route.retry.as_ref().unwrap().non_idempotent);
        let rate = route.rate_limit.as_ref().unwrap();
        assert_eq!(rate.interval, std::time::Duration::from_secs(60));
        assert!(matches!(rate.key, crate::config::RateLimitKey::Ip));
        assert_eq!(route.policy_origins, PolicyOrigins::default());
        for policy in [
            "retry: {non_idempotent: false}",
            "rate_limit: {key: ip}",
            "methods: null",
        ] {
            assert!(
                serde_yaml_ng::from_str::<RouteGroups>(&format!(
                    "public: [{{prefix: /items, upstream: u, {policy}}}]"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn no_defaults_preserves_builtin_behavior_and_explicit_policies() {
        let groups = serde_yaml_ng::from_str("public: [{prefix: /any, upstream: u}, {prefix: /get, upstream: u, methods: [GET], retry: {attempts: 1}, rate_limit: {requests: 2}}]").unwrap();
        let table = RouteTable::build(groups);
        let any = table.match_request(None, "any", "PATCH").unwrap();
        assert!(any.retry.is_none() && any.limiter.is_none());
        assert_eq!(any.policy_origins.methods, PolicyOrigin::BuiltIn);
        assert_eq!(any.policy_origins.retry, PolicyOrigin::BuiltIn);
        assert_eq!(any.policy_origins.rate_limit, PolicyOrigin::BuiltIn);
        let explicit = table.match_request(None, "get", "GET").unwrap();
        assert_eq!(explicit.retry.as_ref().unwrap().attempts, 1);
        assert!(explicit.limiter.is_some());
    }

    #[test]
    fn each_route_gets_its_own_limiter_even_when_inheriting_the_same_default() {
        let groups = serde_yaml_ng::from_str(
            "public: [{prefix: /one, upstream: u}, {prefix: /two, upstream: u}]",
        )
        .unwrap();
        let table = RouteTable::build_with_defaults(groups, &defaults());
        let one = table
            .match_request(None, "one", "GET")
            .unwrap()
            .limiter
            .as_ref()
            .unwrap();
        let two = table
            .match_request(None, "two", "GET")
            .unwrap()
            .limiter
            .as_ref()
            .unwrap();
        assert!(one.check("same-key").allowed);
        assert!(!one.check("same-key").allowed);
        assert!(two.check("same-key").allowed);
    }
}
