//! Explicit safe projection; runtime config is never serialized or Debugged.
use std::collections::BTreeMap;
use std::io::Write;

use serde_json::{Value, json};

use crate::config::interpolate::{Inspection, inspect, interpolate_env};
use crate::config::{GatewayConfig, ResolvedConfig};
use crate::routes::{RouteGroups, RouteTable};

const REDACTED: &str = "<redacted>";

struct Source {
    label: &'static str,
    inspection: Inspection,
    masked: Option<serde_yaml_ng::Value>,
    expanded: Option<serde_yaml_ng::Value>,
}

impl Source {
    fn read(label: &'static str, text: &str) -> anyhow::Result<Self> {
        let inspection = inspect(text, |name| std::env::var(name).ok())
            .map_err(|error| super::diagnostics::interpolation(label, error))?;
        let masked = serde_yaml_ng::from_str(&inspection.masked).ok();
        let expanded = interpolate_env(text)
            .map_err(|error| super::diagnostics::interpolation(label, error))?;
        let expanded = serde_yaml_ng::from_str(&expanded.text).ok();
        Ok(Self {
            label,
            inspection,
            masked,
            expanded,
        })
    }

    fn contains_interpolation(&self, value: &serde_yaml_ng::Value) -> bool {
        use serde_yaml_ng::Value as Yaml;
        match value {
            Yaml::String(value) => self.inspection.contains_marker(value),
            Yaml::Sequence(values) => values.iter().any(|v| self.contains_interpolation(v)),
            Yaml::Mapping(values) => values.iter().any(|(key, value)| {
                self.contains_interpolation(key) || self.contains_interpolation(value)
            }),
            Yaml::Tagged(value) => self.contains_interpolation(&value.value),
            _ => false,
        }
    }

    fn field(&self, path: &str, safe: Option<Value>) -> Value {
        use serde_yaml_ng::Value as Yaml;
        let mut node = self.masked.as_ref();
        let mut expanded_node = self.expanded.as_ref();
        let mut tainted = node.is_none() || expanded_node.is_none();
        for part in path.split('.') {
            expanded_node = expanded_node.and_then(|value| value.get(part));
            if let Some(current) = node {
                // Whole structures and interpolated keys obscure all child
                // origins. Refuse to infer a built-in default in that case.
                match current {
                    Yaml::Mapping(map) => {
                        tainted |= map.keys().any(|key| self.contains_interpolation(key));
                        node = map.get(Yaml::String(part.into()));
                    }
                    _ => {
                        tainted |= self.contains_interpolation(current);
                        node = None;
                    }
                }
            }
        }
        tainted |= node.is_some_and(|value| self.contains_interpolation(value));
        // Interpolation can inject same-line flow-map fields without a
        // newline. Added, moved or changed fields must never be mistaken for
        // literal settings or built-in defaults.
        tainted |= node != expanded_node;
        let origin = if node.is_some() || tainted {
            format!("{}.{}", self.label, path)
        } else {
            "built-in".into()
        };
        let redacted = tainted || safe.is_none();
        json!({"value": if redacted { json!(REDACTED) } else { safe.unwrap_or(Value::Null) }, "origin": origin, "redacted": redacted})
    }

    fn safe(&self, path: &str, value: Value) -> Value {
        self.field(path, Some(value))
    }
    fn hidden(&self, path: &str) -> Value {
        self.field(path, None)
    }
}

// Keep the route group guard even for inherited/built-in settings: an
// interpolated route fragment can obscure which policy was omitted or disabled.
fn policy(
    s: &Source,
    rs: &Source,
    path: &str,
    name: &str,
    origin: crate::routes::PolicyOrigin,
    value: Value,
) -> Value {
    use crate::routes::PolicyOrigin;
    let field = match origin {
        PolicyOrigin::Route => rs.safe(path, value),
        PolicyOrigin::GlobalDefaults => s.safe(&format!("defaults.{name}"), value),
        PolicyOrigin::BuiltIn => json!({"value": value, "origin": "built-in", "redacted": false}),
    };
    let guard = rs.safe(path, Value::Null);
    let redacted = guard
        .get("redacted")
        .and_then(Value::as_bool)
        .unwrap_or(true)
        || field
            .get("redacted")
            .and_then(Value::as_bool)
            .unwrap_or(true);
    json!({
        "value": if redacted { json!(REDACTED) } else { field.get("value").cloned().unwrap_or(Value::Null) },
        "origin": field.get("origin"),
        "redacted": redacted,
        "policy_origin": origin.label(),
    })
}

pub(super) fn run(given: Option<String>) -> anyhow::Result<()> {
    let path = super::resolve_config_path(given)?;
    // Snapshot each input once. The source projection and runtime resolution
    // are derived from those same bytes, not a second read of a live file.
    let text = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("cannot read CONFIG as UTF-8"))?;
    let source = Source::read("CONFIG", &text)?;
    let (mut raw, expanded) = GatewayConfig::parse(&path, &text)
        .map_err(|error| super::diagnostics::configuration("CONFIG", error))?;
    raw.resolve_route_file_against(&path);
    let cfg = raw
        .resolve(&expanded)
        .map_err(|error| super::diagnostics::configuration("CONFIG", error))?;
    let external = if let Some(file) = &cfg.raw.routes.file {
        let text = std::fs::read_to_string(file)
            .map_err(|_| anyhow::anyhow!("cannot read routes.file as UTF-8"))?;
        let source = Source::read("routes.file", &text)?;
        let expanded = interpolate_env(&text)
            .map_err(|error| super::diagnostics::interpolation("routes.file", error))?;
        let groups: RouteGroups = serde_yaml_ng::from_str(&expanded.text)
            .map_err(|_| anyhow::anyhow!("routes.file: invalid route input"))?;
        Some((source, groups))
    } else {
        None
    };
    let groups = external
        .as_ref()
        .map_or_else(|| cfg.raw.routes.groups(), |(_, groups)| groups.clone());
    let table = RouteTable::build_with_defaults(groups, &cfg.raw.defaults);
    cfg.validate_table(&table)
        .map_err(|error| super::diagnostics::configuration("routes", error))?;
    let route_source = external.as_ref().map_or(&source, |(source, _)| source);
    let view = project(&cfg, &table, &source, route_source, external.is_some());
    let mut serialized = serde_json::to_string_pretty(&view)?;
    serialized.push('\n');
    std::io::stdout().lock().write_all(serialized.as_bytes())?;
    Ok(())
}

fn project(
    cfg: &ResolvedConfig,
    table: &RouteTable,
    s: &Source,
    rs: &Source,
    external: bool,
) -> Value {
    let c = &cfg.raw;
    // Every string-bearing or unclassified surface defaults to hidden. Only
    // reviewed booleans, numbers, typed durations, and fixed enums enter safe().
    let timeout = |name: &str, duration: std::time::Duration| {
        s.safe(&format!("timeouts.{name}"), json!(format!("{duration:?}")))
    };
    let upstream_ids: BTreeMap<_, _> = c
        .upstreams
        .keys()
        .enumerate()
        .map(|(index, name)| (name, format!("upstream-{}", index + 1)))
        .collect();
    let upstreams: Vec<_> = c
        .upstreams
        .iter()
        .map(|(name, upstream)| {
            json!({
                "reference": upstream_ids.get(name),
                "name": s.hidden("upstreams"),
                "targets": s.hidden("upstreams"),
                "balance": s.safe("upstreams", json!(match upstream.balance {
            crate::config::Balance::RoundRobin => "round_robin",
            crate::config::Balance::Random => "random",
            crate::config::Balance::Consistent => "consistent",
        })),
                "hash_on": s.hidden("upstreams"),
                "health_check": s.safe("upstreams", json!(upstream.health_check.as_ref().map(|health| json!({"path": REDACTED, "interval": format!("{:?}", health.interval), "timeout": format!("{:?}", health.timeout), "healthy_after": health.healthy_after, "unhealthy_after": health.unhealthy_after})))),
                "circuit_breaker": s.safe("upstreams", json!(upstream.circuit_breaker.as_ref().map(|breaker| json!({"failures": breaker.failures, "window": format!("{:?}", breaker.window), "cooldown": format!("{:?}", breaker.cooldown), "successes_to_close": breaker.successes_to_close, "max_trials": breaker.max_trials})))),
                "target_count": s.safe("upstreams", json!(upstream.targets.len()))
            })
        })
        .collect();
    let routes: Vec<_> = table.routes().iter().enumerate().map(|(index, route)| {
        let group = route.auth.group();
        let path = if external { group.to_string() } else { format!("routes.{group}") };
        // Group provenance is conservative: any interpolation in that group
        // hides its policy values, including whole-fragment substitutions.
        let methods: Vec<_> = route.methods.iter().map(|method| match method.as_str() {
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "CONNECT" | "TRACE" => method.as_str(),
            _ => REDACTED,
        }).collect();
        let retry = route.retry.as_ref().map(|retry| json!({"attempts": retry.attempts, "non_idempotent": retry.non_idempotent, "on": retry.on.iter().map(|failure| match failure {
            crate::config::RetryOn::ConnectionFailure => "connection_failure",
            crate::config::RetryOn::TransportError => "transport_error",
        }).collect::<Vec<_>>()}));
        let rate = route.rate_limit.as_ref().map(|rate| json!({"requests": rate.requests, "interval": format!("{:?}", rate.interval), "key": match rate.key { crate::config::RateLimitKey::Ip => "ip", crate::config::RateLimitKey::Identity => "identity", crate::config::RateLimitKey::Route => "route", crate::config::RateLimitKey::Header(_) => REDACTED }, "counter": match rate.counter { crate::config::Counter::Exact => "exact", crate::config::Counter::Sketch => "sketch" }, "trusted_proxies": rate.trusted_proxies, "max_keys": rate.max_keys}));
        json!({
            "reference": format!("route-{}", index + 1), "listener": if route.auth.is_machine() { "internal" } else { "public" },
            "group": group, "id": rs.hidden(&path), "prefix": rs.hidden(&path), "host": rs.hidden(&path),
            "upstream": rs.safe(&path, json!(upstream_ids.get(&route.upstream))),
            "methods": policy(s, rs, &path, "methods", route.policy_origins.methods, json!(methods)), "enabled": rs.safe(&path, json!(route.enabled)),
            "sse": rs.safe(&path, json!(route.sse)), "strip_prefix": rs.safe(&path, json!(route.strip_prefix)), "cache": rs.safe(&path, json!(route.cache)),
            "retry": policy(s, rs, &path, "retry", route.policy_origins.retry, json!(retry)), "rate_limit": policy(s, rs, &path, "rate_limit", route.policy_origins.rate_limit, json!(rate)),
            "bind": rs.hidden(&path), "extensions": {"value": REDACTED, "status": "unchecked", "origin": format!("{}.{}", rs.label, path)}
        })
    }).collect();
    let mut sources = vec![
        json!({"label": "CONFIG", "path": REDACTED, "path_redacted": true, "provenance_available": s.masked.is_some() && s.expanded.is_some()}),
    ];
    if external {
        sources.push(json!({"label": "routes.file", "path": REDACTED, "path_redacted": true, "provenance_available": rs.masked.is_some() && rs.expanded.is_some()}));
    }
    json!({
        "diagnostic": true, "suitable_for_deployment": false, "is_running_snapshot": false,
        "scope": "current input files and environment for this invocation; inputs are not an atomic multi-file snapshot",
        "redaction": "unclassified strings and paths, credentials, URLs, extension data, and interpolated settings are hidden; route policies use conservative group provenance",
        "sources": sources,
        "checked": ["input parsing", "configuration resolution", "route table validation"],
        "unchecked": ["extension registration and configuration introspection", "credential verification", "listener binding", "DNS and upstream availability", "rate-limit state, cache, and running services"],
        "configuration": {
            "defaults": s.hidden("defaults"),
            "server": {
                "listen": s.hidden("server.listen"), "internal_listen": s.hidden("server.internal_listen"), "mounts": s.hidden("server.mounts"),
                "health_path": s.hidden("server.health_path"), "service_name": s.hidden("server.service_name"), "threads": s.safe("server.threads", json!(c.server.threads)),
                "tcp_keepalive": s.safe("server.tcp_keepalive", json!(c.server.tcp_keepalive.as_ref().map(|tcp| json!({"idle": format!("{:?}", tcp.idle), "interval": format!("{:?}", tcp.interval), "count": tcp.count})))),
                "shutdown_grace": s.safe("server.shutdown_grace", json!(c.server.shutdown_grace.map(|v| format!("{v:?}")))),
                "graceful_shutdown": s.safe("server.graceful_shutdown", json!(format!("{:?}", c.server.graceful_shutdown)))
            },
            "timeouts": {
                "connect": timeout("connect", c.timeouts.connect), "default": timeout("default", c.timeouts.default), "sse": timeout("sse", c.timeouts.sse), "upload": timeout("upload", c.timeouts.upload),
                "upstream_idle": timeout("upstream_idle", c.timeouts.upstream_idle), "downstream_read": timeout("downstream_read", c.timeouts.downstream_read),
                "downstream_write": timeout("downstream_write", c.timeouts.downstream_write), "downstream_drain": timeout("downstream_drain", c.timeouts.downstream_drain), "downstream_keepalive": timeout("downstream_keepalive", c.timeouts.downstream_keepalive)
            },
            "limits": {"max_body": s.safe("limits.max_body", json!(c.limits.max_body)), "max_token": s.safe("limits.max_token", json!(c.limits.max_token)), "keepalive_requests": s.safe("limits.keepalive_requests", json!(c.limits.keepalive_requests)), "upstream_pool": s.safe("limits.upstream_pool", json!(c.limits.upstream_pool)), "connections_per_ip": s.safe("limits.connections_per_ip", json!(c.limits.connections_per_ip.as_ref().map(|limit| json!({"connections": limit.connections, "interval": format!("{:?}", limit.interval), "max_tracked": limit.max_tracked})))), "min_send_rate": s.safe("limits.min_send_rate", json!(c.limits.min_send_rate))},
            "dns": {"cache_ttl": s.safe("dns.cache_ttl", json!(format!("{:?}", c.dns.cache_ttl))), "max_entries": s.safe("dns.max_entries", json!(c.dns.max_entries))},
            "cache": s.safe("cache", json!(c.cache.as_ref().map(|cache| json!({"max_size": cache.max_size, "max_object_size": cache.max_object_size, "default_ttl": format!("{:?}", cache.default_ttl), "stale_while_revalidate": format!("{:?}", cache.stale_while_revalidate)})))),
            "auth": s.hidden("auth"), "inject": s.hidden("inject"), "identity": s.hidden("identity"), "reject": s.hidden("reject"), "cors": s.hidden("cors"), "forward": s.hidden("forward"), "observability": s.hidden("observability"),
            "upstreams": upstreams, "routes": routes, "routes_file": s.hidden("routes.file"), "deny_rules": rs.hidden(if external { "internal" } else { "routes.internal" })
        }
    })
}
