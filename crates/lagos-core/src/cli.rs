//! The `gateway` command line.
//!
//! The commands exist so that gateway behaviour can be understood *before*
//! traffic reaches it: `validate` proves a document is loadable, `routes`
//! prints the table the way the matcher sees it, and `explain` answers "what
//! would happen to this request" without a server running.

use std::path::Path;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use crate::config::{GatewayConfig, ResolvedConfig};
use crate::ext::{Extension, ExtensionRegistry};
use crate::routes::{
    RouteProvider, RouteTable,
    file::{FileRouteProvider, InlineRouteProvider},
};

const DEFAULT_CONFIG: &str = "gateway.yml";

/// Candidate names tried when no path is given, so `gateway run` works in a
/// directory that was set up by `gateway init`.
const CONFIG_CANDIDATES: &[&str] = &["gateway.yml", "gateway.yaml", "config/gateway.yml"];

#[derive(Parser)]
#[command(
    name = "lagos",
    about = "An identity-aware API gateway built on Pingora",
    version,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Write a starter gateway.yml in the current directory
    Init {
        /// Where to write it
        #[arg(default_value = DEFAULT_CONFIG)]
        path: String,
        /// Overwrite an existing file
        #[arg(long)]
        force: bool,
    },
    /// Serve traffic
    Run {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Serve with readable per-request output, reloading on change
    Dev {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Load and check a configuration without serving anything
    Validate {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Print the route table as the matcher sees it
    Routes {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Show how one request would be handled
    Explain {
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long)]
        path: String,
        /// The `Host` header to match against, for host-restricted routes
        #[arg(short = 'H', long)]
        host: Option<String>,
        #[arg(short, long, value_name = "CONFIG")]
        config: Option<String>,
    },
}

impl Cli {
    /// Parse the command line and run it, with `extensions` available to any
    /// route that names one.
    ///
    /// A deployment-specific binary registers its own extensions and calls
    /// this, so it gets the same tooling as the stock build.
    pub fn run(extensions: Vec<Arc<dyn Extension>>) -> anyhow::Result<()> {
        let mut registry = ExtensionRegistry::new();
        for e in extensions {
            registry.register(e);
        }

        match Cli::parse().command {
            // Bare `gateway` serves, so a container entrypoint needs no
            // argument and the common case stays the shortest.
            None => serve(None, registry),
            Some(Command::Run { path }) => serve(path, registry),
            Some(Command::Dev { path }) => dev(path, registry),
            Some(Command::Init { path, force }) => init(&path, force),
            Some(Command::Validate { path }) => validate(path, &registry),
            Some(Command::Routes { path }) => routes(path),
            Some(Command::Explain {
                method,
                path,
                host,
                config,
            }) => explain(config, &method, &path, host.as_deref()),
        }
    }
}

/// Find the configuration file: an explicit path, then `GATEWAY_CONFIG`, then
/// the conventional names.
fn resolve_config_path(given: Option<String>) -> anyhow::Result<String> {
    if let Some(p) = given {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("GATEWAY_CONFIG")
        && !p.trim().is_empty()
    {
        return Ok(p);
    }
    for candidate in CONFIG_CANDIDATES {
        if Path::new(candidate).is_file() {
            return Ok((*candidate).to_string());
        }
    }
    anyhow::bail!(
        "no configuration file found.\n\
         Looked for {}.\n\
         Pass one explicitly (`gateway run path/to/gateway.yml`), set GATEWAY_CONFIG, \
         or create one with `gateway init`.",
        CONFIG_CANDIDATES.join(", ")
    )
}

fn serve(path: Option<String>, registry: ExtensionRegistry) -> anyhow::Result<()> {
    crate::runtime::Runtime::from_registry(resolve_config_path(path)?, registry).run()
}

/// Load a document and its route table without binding a socket.
fn load(path: &str) -> anyhow::Result<(Arc<ResolvedConfig>, RouteTable)> {
    let (raw, expanded) = GatewayConfig::load(path)?;
    let cfg = Arc::new(raw.resolve(&expanded)?);

    let provider: Box<dyn RouteProvider> = match &cfg.raw.routes.file {
        Some(f) => Box::new(FileRouteProvider::new(f.clone())),
        None => Box::new(InlineRouteProvider::new(cfg.raw.routes.groups())),
    };
    let table = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(provider.load())?;

    cfg.validate_table(&table)?;
    Ok((cfg, table))
}

fn validate(path: Option<String>, registry: &ExtensionRegistry) -> anyhow::Result<()> {
    let path = resolve_config_path(path)?;
    let (cfg, table) = load(&path)?;

    let missing = registry.missing(table.extension_names());
    if !missing.is_empty() {
        anyhow::bail!(
            "routes reference extensions that are not registered: {}.\n\
             A route naming an unknown extension is refused rather than silently \
             skipped — otherwise a typo would drop a security control.",
            missing.join(", ")
        );
    }

    let mut by_tier: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in table.routes() {
        *by_tier.entry(r.auth.group()).or_default() += 1;
    }
    let breakdown = by_tier
        .iter()
        .map(|(t, n)| format!("{n} {t}"))
        .collect::<Vec<_>>()
        .join(", ");

    println!("✓ syntax");
    println!("✓ upstreams   {}", cfg.upstreams.len());
    println!("✓ routes      {}  ({breakdown})", table.len());
    println!("✓ deny-list   {}", table.deny_prefixes().len());
    let issuers = cfg.raw.auth.jwt.len()
        + cfg
            .raw
            .auth
            .firebase
            .as_ref()
            .map_or(0, |_| cfg.firebase_project_ids.len());
    if issuers > 0 {
        println!("✓ issuers     {issuers}");
    }
    if let Some(c) = &cfg.raw.cache {
        let cached = table.routes().iter().filter(|r| r.cache).count();
        println!(
            "✓ cache       {} route(s), max {} bytes",
            cached, c.max_size
        );
    }
    if let Some(t) = &cfg.raw.observability.tracing {
        match &t.otlp {
            Some(o) => println!("✓ tracing     {} (sample {})", o.endpoint, t.sample_ratio),
            None => println!("✓ tracing     propagation only (no otlp endpoint)"),
        }
    }
    if let Some(c) = &cfg.raw.cors {
        println!(
            "✓ cors        {} origin(s){}",
            c.origins.len(),
            if c.credentials { ", credentials" } else { "" }
        );
    }
    let limited = table
        .routes()
        .iter()
        .filter(|r| r.rate_limit.is_some())
        .count();
    if limited > 0 {
        println!("✓ rate limits {limited}");
    }
    let bound: usize = table.routes().iter().map(|r| r.bindings.len()).sum();
    if bound > 0 {
        println!("✓ bindings    {bound}");
    }
    if !cfg.raw.identity.claims.is_empty() {
        println!("✓ claims      {}", cfg.raw.identity.claims.len());
    }
    if !cfg.referenced_env.is_empty() {
        println!("✓ environment {}", cfg.referenced_env.join(", "));
    }
    if !cfg.defaulted_env.is_empty() {
        // Worth calling out: these are exactly the values that will differ
        // between a laptop and a cluster.
        println!("\n  using defaults for: {}", cfg.defaulted_env.join(", "));
    }
    println!("\n{path} is valid.");
    Ok(())
}

fn routes(path: Option<String>) -> anyhow::Result<()> {
    let path = resolve_config_path(path)?;
    let (cfg, table) = load(&path)?;

    if !table.deny_prefixes().is_empty() {
        println!("DENIED (404 on the public listener, whatever else matches)\n");
        for d in table.deny_prefixes() {
            println!("  /{d}");
        }
        println!();
    }

    println!("ROUTES (most specific first — the order the matcher tries them)\n");
    let width = table
        .routes()
        .iter()
        .map(|r| r.prefix.len())
        .max()
        .unwrap_or(0)
        + 1;
    for r in table.routes() {
        let methods = if r.methods.is_empty() {
            "ANY".to_string()
        } else {
            r.methods.join(",")
        };
        let mut notes = Vec::new();
        if r.sse {
            notes.push("sse".to_string());
        }
        if !r.extensions.is_empty() {
            notes.push(r.extensions.join("+"));
        }
        for b in &r.bindings {
            notes.push(b.describe());
        }
        if let Some(rl) = &r.rate_limit {
            notes.push(format!("{}/{:?}", rl.requests, rl.interval));
        }
        if let Some(rt) = &r.retry {
            notes.push(format!("retry x{}", rt.attempts));
        }
        let note = if notes.is_empty() {
            String::new()
        } else {
            format!("  [{}]", notes.join(" "))
        };
        let host = if r.host.is_empty() {
            String::new()
        } else {
            format!("{} ", r.host.join(","))
        };
        println!(
            "  {:<14} {host}/{:<width$} → {:<14} {}{}",
            r.auth.group(),
            r.prefix,
            r.upstream,
            methods,
            note,
            width = width
        );
    }

    println!("\nUPSTREAMS\n");
    for (name, up) in &cfg.upstreams {
        let urls: Vec<&str> = up.targets.iter().map(|t| t.url.as_str()).collect();
        let breaker = match &up.circuit_breaker {
            Some(cb) => format!(
                "  [breaker {}/{:?} cooldown {:?}]",
                cb.failures, cb.window, cb.cooldown
            ),
            None => String::new(),
        };
        let health = match &up.health_check {
            Some(h) => match &h.path {
                Some(p) => format!("  [health {p} every {:?}]", h.interval),
                None => format!("  [health tcp every {:?}]", h.interval),
            },
            None => String::new(),
        };
        println!("  {name:<16} {}{health}{breaker}", urls.join(", "));
    }
    Ok(())
}

fn explain(
    config: Option<String>,
    method: &str,
    request_path: &str,
    host: Option<&str>,
) -> anyhow::Result<()> {
    let path = resolve_config_path(config)?;
    let (cfg, table) = load(&path)?;
    let (public, _machine) = table.partition_by_listener();

    match host {
        Some(h) => println!("Request\n\n  {} {h}{request_path}\n", method.to_uppercase()),
        None => println!("Request\n\n  {} {request_path}\n", method.to_uppercase()),
    }

    // 1. Mount. Longest first, matching the proxy.
    let stripped = cfg.base_paths.iter().find_map(|base| {
        let p = request_path.trim_start_matches('/');
        if base.is_empty() {
            return Some((base.as_str(), p.to_string()));
        }
        let rest = p.strip_prefix(base.as_str())?;
        if rest.is_empty() {
            Some((base.as_str(), String::new()))
        } else {
            rest.strip_prefix('/')
                .map(|r| (base.as_str(), r.to_string()))
        }
    });

    let Some((mount, sub)) = stripped else {
        println!("  ✗ no mount matches. Mounts are: {:?}", cfg.base_paths);
        println!("\nResult\n\n  404 (outside_base_path)");
        return Ok(());
    };
    println!("Mount\n\n  ✓ /{mount}  →  sub-path `{sub}`\n");

    // 2. Canonicalization — the same check the proxy runs.
    let Some(canonical) = crate::path::canonicalize_proxy_path(&sub) else {
        println!(
            "Path\n\n  ✗ rejected as unsafe (dot-segment, backslash, control char, or stray %)"
        );
        println!("\nResult\n\n  404 (unsafe_path)");
        return Ok(());
    };
    if canonical != sub {
        println!("Path\n\n  ✓ canonicalized to `{canonical}`\n");
    }

    // 3. Deny-list, before anything else can match.
    if public.is_denied(&canonical) {
        println!("Deny-list\n\n  ✗ matches an `internal:` prefix");
        println!(
            "\nResult\n\n  404 (deny_list) — refusals are 404, never 403, so the\n  deny-list cannot be enumerated."
        );
        return Ok(());
    }
    println!("Deny-list\n\n  ✓ not denied\n");

    // 4. Route match.
    let Some(route) = public.match_request(host, &canonical, method) else {
        println!("Route\n\n  ✗ no route matches");
        let any = public
            .routes()
            .iter()
            .find(|r| canonical == r.prefix || canonical.starts_with(&format!("{}/", r.prefix)));
        if let Some(r) = any {
            println!(
                "\n  `{}` matches the path but allows only {}",
                r.id,
                r.methods.join(", ")
            );
        }
        println!("\nResult\n\n  404 (not_allowlisted)");
        return Ok(());
    };

    println!(
        "Route\n\n  ✓ {}  (group: {})\n",
        route.id,
        route.auth.group()
    );

    println!("Authentication\n");
    match route.auth {
        crate::routes::AuthTier::Public => {
            println!("  no token is read, even if one is sent");
            println!("  identity headers are stripped before proxying")
        }
        crate::routes::AuthTier::Optional => {
            println!("  no token      → proxied anonymously");
            println!("  valid token   → proxied with identity");
            println!("  invalid token → 401")
        }
        crate::routes::AuthTier::Required => {
            println!("  a valid token is required; anything else is 401")
        }
        crate::routes::AuthTier::Machine => {
            println!("  shared credential on the internal listener only")
        }
    }
    println!();

    if let Some(rt) = &route.retry {
        println!("Retries\n");
        println!("  up to {} after the first attempt", rt.attempts);
        if rt.non_idempotent {
            println!("  including POST and PATCH (non_idempotent: true)");
        } else if !crate::retry::is_idempotent(&route.methods.join(",")) {
            println!(
                "  a connect failure retries any method; after connecting,\n\
                 \x20 only idempotent methods are repeated"
            );
        }
        println!();
    }

    if let Some(rl) = &route.rate_limit {
        println!("Rate limit\n");
        println!(
            "  {} requests per {:?}, keyed on {}",
            rl.requests,
            rl.interval,
            match &rl.key {
                crate::config::RateLimitKey::Ip => "the client address".to_string(),
                crate::config::RateLimitKey::Identity => "the caller's subject".to_string(),
                crate::config::RateLimitKey::Route => "this route as a whole".to_string(),
                crate::config::RateLimitKey::Header(h) => format!("header `{h}`"),
            }
        );
        if matches!(rl.key, crate::config::RateLimitKey::Ip) && rl.trusted_proxies == 0 {
            println!(
                "  note: trusted_proxies is 0, so the socket peer is used —\n\
                 \x20       behind an ingress every client shares one bucket"
            );
        }
        println!();
    }

    if !route.bindings.is_empty() {
        println!("Ownership\n");
        for b in &route.bindings {
            println!(
                "  {}   (403 if missing, unprovable, or unequal)",
                b.describe()
            );
        }
        println!();
    }

    if !route.extensions.is_empty() {
        println!("Extensions\n");
        for (i, e) in route.extensions.iter().enumerate() {
            println!("  {}. {e}", i + 1);
        }
        println!();
    }

    println!("Upstream\n");
    let urls = cfg
        .upstreams
        .get(&route.upstream)
        .map(|u| {
            u.targets
                .iter()
                .map(|t| t.url.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| "<undefined>".to_string());
    println!("  {}  {urls}/{canonical}", route.upstream);

    let timeout = if route.sse {
        cfg.raw.timeouts.sse
    } else {
        cfg.raw.timeouts.default
    };
    println!(
        "  timeout {timeout:?}{}",
        if route.sse { " (sse)" } else { "" }
    );

    if !cfg.injected_headers.is_empty() {
        println!("\nInjected headers\n");
        for (name, _) in &cfg.injected_headers {
            // Values are credentials; the point is which headers appear.
            println!("  {name}: <redacted>");
        }
    }
    Ok(())
}

const STARTER: &str = include_str!("../templates/gateway.yml");

fn init(path: &str, force: bool) -> anyhow::Result<()> {
    if Path::new(path).exists() && !force {
        anyhow::bail!("{path} already exists. Pass --force to overwrite it.");
    }
    std::fs::write(path, STARTER)?;
    println!("Created {path}\n");
    println!("  gateway validate {path}   check it");
    println!("  gateway routes   {path}   see the route table");
    println!("  gateway run      {path}   serve traffic");
    Ok(())
}

/// `gateway dev`: supervise a child gateway and restart it when the document
/// changes.
///
/// Routes already hot-reload in the running process, so only a change to the
/// main document — listeners, credentials, upstreams — needs a restart. The
/// replacement configuration is validated *before* the running child is
/// stopped, so a typo leaves the gateway up and prints the error instead.
fn dev(path: Option<String>, registry: ExtensionRegistry) -> anyhow::Result<()> {
    // The supervised child is this same binary, so a deployment-specific build
    // supervises itself and keeps its own extensions.
    let exe = std::env::current_exe()?;
    let path = resolve_config_path(path)?;

    let (cfg, table) = load(&path)?;
    let missing = registry.missing(table.extension_names());
    if !missing.is_empty() {
        anyhow::bail!(
            "routes reference extensions that are not registered: {}",
            missing.join(", ")
        );
    }

    println!("\x1b[1mGateway\x1b[0m  dev mode\n");
    println!("  listening   http://{}", cfg.raw.server.listen);
    if let Some(internal) = &cfg.raw.server.internal_listen {
        println!("  internal    http://{internal}");
    }
    println!("  health      {}", cfg.raw.server.health_path);
    println!("  config      {path}");
    if let Some(f) = &cfg.raw.routes.file {
        println!("  routes      {f}  (hot-reloads, no restart)");
    }
    println!("\n\x1b[1mRoutes\x1b[0m\n");
    for r in table.routes() {
        let methods = if r.methods.is_empty() {
            "ANY".to_string()
        } else {
            r.methods.join(",")
        };
        println!(
            "  {:<7} {:<14} /{} → {}",
            methods,
            r.auth.group(),
            r.prefix,
            r.upstream
        );
    }
    println!("\nWatching for changes. Ctrl-C to stop.");

    let mtime = || std::fs::metadata(&path).ok()?.modified().ok();
    let mut last = mtime();

    loop {
        let mut child = std::process::Command::new(&exe)
            .arg("run")
            .arg(&path)
            .env("LAGOS_DEV", "1")
            .spawn()?;

        // Watch while it serves. `try_wait` so a child that dies on its own —
        // a port already in use, say — surfaces instead of hanging here.
        loop {
            std::thread::sleep(std::time::Duration::from_millis(400));

            if let Some(status) = child.try_wait()? {
                anyhow::bail!("gateway exited ({status})");
            }

            let current = mtime();
            if current == last {
                continue;
            }
            last = current;

            println!("\n\x1b[1mconfiguration changed\x1b[0m");
            match load(&path) {
                Ok((_, table)) => {
                    let n = table.len();
                    let plural = if n == 1 { "route" } else { "routes" };
                    println!("  ✓ parsed\n  ✓ validated\n  ✓ {n} {plural}\n");
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                Err(e) => {
                    // The running gateway is untouched: a broken edit must not
                    // take traffic down, in dev any more than in production.
                    println!("  ✗ {e}\n\n  keeping the running configuration");
                }
            }
        }
    }
}
