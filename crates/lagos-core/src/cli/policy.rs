//! Offline checks over the same resolved route table used by the gateway.
//! These tools deliberately do not fetch keys, verify tokens, or run extensions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    Listener, load_with_fallback, placeheld_in_both, resolve_config_path, strip_mount,
    unset_placeholder,
};
use crate::auth::Identity;
use crate::config::ResolvedConfig;
use crate::path::canonicalize_proxy_path;
use crate::routes::{RouteConfig, RouteTable};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSuite {
    tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestCase {
    name: String,
    request: TestRequest,
    expect: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestRequest {
    path: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    listener: Listener,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Synthetic, already-verified identity for evaluating `bind`.
    #[serde(default)]
    identity: Option<TestIdentity>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestIdentity {
    subject: String,
    #[serde(default)]
    claims: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResultKind {
    Route,
    Denied,
    NoRoute,
    OutsideMount,
    UnsafePath,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    result: ResultKind,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    upstream: Option<String>,
    /// Whether every ownership binding permits the synthetic identity.
    #[serde(default)]
    bindings: Option<bool>,
}

#[derive(Debug)]
struct Actual {
    result: ResultKind,
    route: Option<String>,
    tier: Option<String>,
    upstream: Option<String>,
    bindings: Option<bool>,
}

impl Actual {
    fn simple(result: ResultKind) -> Self {
        Self {
            result,
            route: None,
            tier: None,
            upstream: None,
            bindings: None,
        }
    }
}

fn cases_path(config: &str, given: Option<String>) -> PathBuf {
    given.map_or_else(
        || Path::new(config).with_file_name("gateway.test.yml"),
        PathBuf::from,
    )
}

pub(super) fn test(
    config: Option<String>,
    cases: Option<String>,
    allow_unset: bool,
) -> anyhow::Result<()> {
    let config = resolve_config_path(config)?;
    let fallback = allow_unset.then_some(unset_placeholder as fn(&str) -> String);
    let (cfg, table) = load_with_fallback(&config, fallback)?;
    let path = cases_path(&config, cases);
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read test cases {}", path.display()))?;
    let suite: TestSuite = serde_yaml_ng::from_str(&source)
        .with_context(|| format!("invalid test cases {}", path.display()))?;
    if suite.tests.is_empty() {
        bail!("{} contains no tests", path.display());
    }

    println!("Offline policy checks: token verification and extensions are not executed.\n");
    let (public, internal) = table.partition_by_listener();
    let mut names = BTreeSet::new();
    let mut failures = 0;
    for case in &suite.tests {
        validate_case(case)?;
        if !names.insert(&case.name) {
            bail!("duplicate test name `{}` in {}", case.name, path.display());
        }
        let selected = match case.request.listener {
            Listener::Public => &public,
            Listener::Internal => &internal,
        };
        let actual = decide(&cfg, selected, &case.request);
        let differences = compare(&case.expect, &actual);
        if differences.is_empty() {
            println!("✓ {}", case.name);
        } else {
            failures += 1;
            println!("✗ {}", case.name);
            for difference in differences {
                println!("  {difference}");
            }
        }
    }
    println!(
        "\n{} passed, {failures} failed",
        suite.tests.len() - failures
    );
    let unchecked = placeheld_in_both(&cfg, fallback);
    if !unchecked.is_empty() {
        println!("Unchecked environment values: {unchecked:?}");
    }
    if failures > 0 {
        bail!("{failures} policy test(s) failed");
    }
    Ok(())
}

fn validate_case(case: &TestCase) -> anyhow::Result<()> {
    if case.name.trim().is_empty() {
        bail!("a test name is empty");
    }
    if !case.request.path.starts_with('/') || case.request.path.contains('?') {
        bail!(
            "test `{}`: request.path must start with / and exclude the query; use request.query",
            case.name
        );
    }
    if case.request.method.trim().is_empty() {
        bail!("test `{}`: request.method is empty", case.name);
    }
    if case.expect.result == ResultKind::Route {
        if case.expect.route.as_deref().is_none_or(str::is_empty) {
            bail!("test `{}`: a route result requires expect.route", case.name);
        }
    } else if case.expect.route.is_some()
        || case.expect.tier.is_some()
        || case.expect.upstream.is_some()
        || case.expect.bindings.is_some()
    {
        bail!(
            "test `{}`: route, tier, upstream, and bindings apply only to a route result",
            case.name
        );
    }
    Ok(())
}

fn decide(cfg: &ResolvedConfig, table: &RouteTable, request: &TestRequest) -> Actual {
    let Some((_, sub)) = strip_mount(cfg, &request.path) else {
        return Actual::simple(ResultKind::OutsideMount);
    };
    let Some(canonical) = canonicalize_proxy_path(&sub) else {
        return Actual::simple(ResultKind::UnsafePath);
    };
    if table.is_denied(&canonical) {
        return Actual::simple(ResultKind::Denied);
    }
    let Some(route) = table.match_request(request.host.as_deref(), &canonical, &request.method)
    else {
        return Actual::simple(ResultKind::NoRoute);
    };

    let bindings = if route.bindings.is_empty() {
        None
    } else {
        let identity = request.identity.as_ref().map(|value| Identity {
            subject: value.subject.clone(),
            issuer: String::new(),
            audience: String::new(),
            claims: value.claims.clone(),
        });
        let headers: BTreeMap<_, _> = request
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
            .collect();
        let query = request.query.as_deref().map(|q| q.trim_start_matches('?'));
        Some(identity.is_some_and(|identity| {
            route.bindings.iter().all(|binding| {
                binding.permits(&identity, query, |name| {
                    headers.get(&name.to_ascii_lowercase()).copied()
                })
            })
        }))
    };
    Actual {
        result: ResultKind::Route,
        route: Some(route.id.clone()),
        tier: Some(route.auth.group().to_string()),
        upstream: Some(route.upstream.clone()),
        bindings,
    }
}

fn compare(expected: &Expected, actual: &Actual) -> Vec<String> {
    let mut differences = Vec::new();
    if expected.result != actual.result {
        differences.push(format!(
            "result: expected {:?}, got {:?}",
            expected.result, actual.result
        ));
        if actual.result == ResultKind::Route {
            differences.push(format!(
                "matched route {:?} on tier {:?}",
                actual.route, actual.tier
            ));
        }
    }
    for (field, want, got) in [
        ("route", expected.route.as_ref(), actual.route.as_ref()),
        ("tier", expected.tier.as_ref(), actual.tier.as_ref()),
        (
            "upstream",
            expected.upstream.as_ref(),
            actual.upstream.as_ref(),
        ),
    ] {
        if let Some(want) = want
            && Some(want) != got
        {
            differences.push(format!("{field}: expected {want:?}, got {got:?}"));
        }
    }
    if let Some(want) = expected.bindings
        && Some(want) != actual.bindings
    {
        differences.push(format!(
            "bindings: expected {want}, got {:?}",
            actual.bindings
        ));
    }
    differences
}

fn route_fields(route: &RouteConfig) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("tier", route.auth.group().to_string()),
        ("prefix", route.prefix.clone()),
        ("hosts", format!("{:?}", route.host)),
        ("methods", format!("{:?}", route.methods)),
        (
            "methods_origin",
            route.policy_origins.methods.label().into(),
        ),
        ("retry_origin", route.policy_origins.retry.label().into()),
        (
            "rate_limit_origin",
            route.policy_origins.rate_limit.label().into(),
        ),
        ("upstream", route.upstream.clone()),
        ("bindings", format!("{:?}", route.bind)),
        ("extensions", format!("{:?}", route.extensions)),
        ("rate_limit", format!("{:?}", route.rate_limit)),
        ("retry", format!("{:?}", route.retry)),
        ("cache", route.cache.to_string()),
        ("cache_authenticated", route.cache_authenticated.to_string()),
        ("sse", route.sse.to_string()),
    ])
}

pub(super) fn diff(old: &str, new: &str, allow_unset: bool) -> anyhow::Result<()> {
    let fallback = allow_unset.then_some(unset_placeholder as fn(&str) -> String);
    let (old_cfg, old_table) = load_with_fallback(old, fallback)
        .with_context(|| format!("failed to load old configuration {old}"))?;
    let (new_cfg, new_table) = load_with_fallback(new, fallback)
        .with_context(|| format!("failed to load new configuration {new}"))?;
    let old_routes: BTreeMap<_, _> = old_table
        .routes()
        .iter()
        .map(|r| (r.id.as_str(), route_fields(r)))
        .collect();
    let new_routes: BTreeMap<_, _> = new_table
        .routes()
        .iter()
        .map(|r| (r.id.as_str(), route_fields(r)))
        .collect();
    let mut changes = 0;

    for name in old_routes
        .keys()
        .chain(new_routes.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        match (old_routes.get(name), new_routes.get(name)) {
            (None, Some(fields)) => {
                println!(
                    "+ route {name} ({} /{} → {})",
                    fields["tier"], fields["prefix"], fields["upstream"]
                );
                changes += 1;
            }
            (Some(fields), None) => {
                println!(
                    "- route {name} ({} /{} → {})",
                    fields["tier"], fields["prefix"], fields["upstream"]
                );
                changes += 1;
            }
            (Some(before), Some(after)) => {
                for (field, old_value) in before {
                    let new_value = &after[field];
                    if old_value != new_value {
                        println!("~ route {name}: {field}: {old_value} → {new_value}");
                        changes += 1;
                    }
                }
            }
            (None, None) => {}
        }
    }

    let old_denied: BTreeSet<_> = old_table.deny_prefixes().iter().collect();
    let new_denied: BTreeSet<_> = new_table.deny_prefixes().iter().collect();
    for path in old_denied.difference(&new_denied) {
        println!("- denied /{path}");
        changes += 1;
    }
    for path in new_denied.difference(&old_denied) {
        println!("+ denied /{path}");
        changes += 1;
    }
    if old_cfg.base_paths != new_cfg.base_paths {
        println!(
            "~ mounts: {:?} → {:?}",
            old_cfg.base_paths, new_cfg.base_paths
        );
        changes += 1;
    }

    for name in old_cfg
        .raw
        .upstreams
        .keys()
        .chain(new_cfg.raw.upstreams.keys())
        .collect::<BTreeSet<_>>()
    {
        match (
            old_cfg.raw.upstreams.get(name),
            new_cfg.raw.upstreams.get(name),
        ) {
            (None, Some(_)) => {
                println!("+ upstream {name}");
                changes += 1;
            }
            (Some(_), None) => {
                println!("- upstream {name}");
                changes += 1;
            }
            (Some(before), Some(after)) if format!("{before:?}") != format!("{after:?}") => {
                println!("~ upstream {name}: target or policy changed (values hidden)");
                changes += 1;
            }
            _ => {}
        }
    }

    if changes == 0 {
        println!("No route-surface changes.");
    } else {
        println!("\n{changes} route-surface change(s).");
    }
    let old_unset = placeheld_in_both(&old_cfg, fallback);
    let new_unset = placeheld_in_both(&new_cfg, fallback);
    if !old_unset.is_empty() || !new_unset.is_empty() {
        println!("Unchecked environment values: old={old_unset:?}, new={new_unset:?}");
    }
    println!(
        "Scope: effective routes (including defaults and policy origins), deny-list, mounts, and upstream targets. Top-level defaults require restart; route-file policies can reload. Review the YAML diff for auth, headers, listeners, and secrets."
    );
    Ok(())
}
