//! The gateway command line.
//!
//! The commands exist so that gateway behaviour can be understood *before*
//! traffic reaches it: `validate` proves a document is loadable, `routes`
//! prints the table the way the matcher sees it, and `explain` answers "what
//! would happen to this request" without a server running.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::config::{GatewayConfig, ResolvedConfig};
use crate::ext::{Extension, ExtensionRegistry};
use crate::routes::{
    RouteProvider, RouteTable,
    file::{FileRouteProvider, InlineRouteProvider},
};

mod diagnostics;
mod effective;
mod explanation;
mod policy;
mod vars;

const DEFAULT_CONFIG: &str = "gateway.yml";

/// Candidate locations tried when no path is given, so `run` works in a
/// directory that was set up by `init` and in an image that simply copied a
/// configuration directory in.
///
/// Order is most specific first, and `/etc/lagos` is last so a file in the
/// working directory always wins over one baked into an image — that is what
/// makes `-v ./gateway.yml:/app/gateway.yml` still override a config the
/// Dockerfile copied. It is also the only absolute entry, so it resolves the
/// same whatever the working directory is.
const CONFIG_CANDIDATES: &[&str] = &[
    "gateway.yml",
    "gateway.yaml",
    "config/gateway.yml",
    "lagos/gateway.yml",
    "deploy/gateway.yml",
    "/etc/lagos/gateway.yml",
];

/// Substituted for an unset variable by `validate --allow-unset`.
///
/// A bare hostname, which is the one shape that satisfies every string field a
/// variable commonly feeds: an upstream parses it (the scheme defaults to
/// `http`), a route `host:` accepts it (a host must *not* carry a scheme, so a
/// URL is refused there), and issuers, JWKS URLs and audiences are checked for
/// emptiness rather than syntax. A URL-shaped placeholder passes the first and
/// fails the second.
///
/// The `.invalid` TLD is reserved by RFC 2606 and can never resolve, so if one
/// of these ever escaped into a running configuration it would fail closed
/// rather than reach a host someone else controls.
///
/// A variable landing in a numeric or boolean field still fails to parse. That
/// is deliberate: the fix is a default in the document (`${PORT:-8080}`), which
/// makes the field checkable at build time and is better configuration anyway.
/// Encode the variable name so different unset hosts cannot collapse into the
/// same derived route id. Hex preserves case and underscores while keeping the
/// value usable as a bare host in every field that accepts one.
fn unset_placeholder(name: &str) -> String {
    let encoded = name
        .bytes()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    format!("unset-{encoded}.lagos.invalid")
}

#[derive(Parser)]
// `name` is deliberately absent: it is set at runtime from argv[0] in `run`,
// because this CLI is linked into whatever binary a deployment builds.
#[command(
    about = "An identity-aware API gateway built on Pingora",
    version,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, Default, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Listener {
    #[default]
    Public,
    Internal,
}

impl Listener {
    fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Show a redacted offline configuration view, unsuitable for deployment
    Config {
        #[arg(long, required = true)]
        effective: bool,
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// List environment references without printing values or defaults
    Vars {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Write JSON Schema to stdout without loading configuration or extensions
    Schema {
        /// Describe a standalone routes file instead of gateway.yml
        #[arg(long)]
        routes: bool,
    },
    /// Write a starter gateway.yml in the current directory
    Init {
        /// Where to write it
        #[arg(default_value = DEFAULT_CONFIG)]
        path: String,
        /// Overwrite an existing file
        #[arg(long)]
        force: bool,
        /// Create a two-file Docker deployment (gateway.yml and Dockerfile)
        #[arg(long)]
        docker: bool,
        /// Include a conventional ext/ crate compiled into the gateway image
        #[arg(long, requires = "docker")]
        extensions: bool,
        /// Editor schema path or URL; official release images use a pinned URL
        #[arg(long, value_name = "PATH_OR_URL")]
        schema: Option<String>,
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
        /// Check structure where `${VAR}`s are not set, as in a container build
        ///
        /// Unset variables with no default expand to a placeholder instead of
        /// failing, and are listed in the output as unchecked.
        #[arg(long)]
        allow_unset: bool,
    },
    /// Print the route table as the matcher sees it
    Routes {
        #[arg(value_name = "CONFIG")]
        path: Option<String>,
    },
    /// Check request and policy examples without contacting upstreams
    Test {
        #[arg(value_name = "CONFIG")]
        config: Option<String>,
        #[arg(value_name = "CASES")]
        cases: Option<String>,
        /// Check structure where `${VAR}`s are not set
        #[arg(long)]
        allow_unset: bool,
    },
    /// Compare the effective route surface of two configurations
    Diff {
        #[arg(value_name = "OLD")]
        old: String,
        #[arg(value_name = "NEW")]
        new: String,
        /// Check structure where `${VAR}`s are not set
        #[arg(long)]
        allow_unset: bool,
    },
    /// Show how one request would be handled
    Explain {
        /// List prefix candidates and the constraints that exclude them
        #[arg(long)]
        why_not: bool,
        /// Listener whose route table should handle this request
        #[arg(long, value_enum, default_value = "public")]
        listener: Listener,
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

/// The name this executable was invoked as.
///
/// The CLI lives in `lagos-core` but is linked into whatever binary a
/// deployment builds, so a hard-coded name would make every extension build
/// call itself `lagos` -- in `--version`, in usage, and in the commands `init`
/// prints for the reader to copy. Falls back to the crate name when the
/// executable path cannot be read, which is not worth failing a command over.
fn bin_name() -> &'static str {
    // `clap::builder::Str` takes a `&'static str`, and the name is also wanted
    // on paths that run after startup. A `OnceLock` gives both without leaking
    // and without recomputing.
    static BIN_NAME: OnceLock<String> = OnceLock::new();
    BIN_NAME
        .get_or_init(|| {
            let exe = std::env::current_exe().ok();
            exe.as_deref()
                .and_then(Path::file_stem)
                .and_then(OsStr::to_str)
                // Falls back to the project's own binary name rather than the
                // crate name, which is the library `lagos-core`.
                .unwrap_or("lagos")
                .to_owned()
        })
        .as_str()
}

impl Cli {
    /// Parse the command line and run it, with the extensions `make_extensions`
    /// returns available to any route that names one.
    ///
    /// A deployment-specific binary registers its own extensions and calls
    /// this, so it gets the same tooling as the stock build.
    ///
    /// Extensions are built **after** the command line is parsed, and only for
    /// the commands that can use them. An extension that reads configuration to
    /// construct -- a credential, an upstream URL -- would otherwise make
    /// `--help`, `--version` and `init` fail on a machine that has no
    /// production environment set, which is every developer's machine. The
    /// commands that do serve or validate traffic still build eagerly, so a
    /// missing value is still a startup failure rather than a per-request one.
    ///
    /// ```no_run
    /// # use lagos_core::Cli;
    /// Cli::run(|| Ok(Vec::new()))
    /// # ;
    /// ```
    pub fn run<F>(make_extensions: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<Vec<Arc<dyn Extension>>>,
    {
        Self::run_inner(None, make_extensions)
    }

    /// Run a gateway whose available extension names are known before their
    /// runtime constructors need credentials or network access. The names are
    /// checked by `validate --allow-unset`; `run` and ordinary `validate` still
    /// build the actual extensions and refuse missing registrations.
    pub fn run_with_extension_names<F>(
        extension_names: &[&str],
        make_extensions: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<Vec<Arc<dyn Extension>>>,
    {
        Self::run_inner(Some(extension_names), make_extensions)
    }

    fn run_inner<F>(extension_names: Option<&[&str]>, make_extensions: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<Vec<Arc<dyn Extension>>>,
    {
        // Deliberately not a closure over `registry`: `make_extensions` is
        // FnOnce, so each arm may call it at most once, and the type checker
        // enforces that rather than a convention.
        fn registry_from(
            make: impl FnOnce() -> anyhow::Result<Vec<Arc<dyn Extension>>>,
        ) -> anyhow::Result<ExtensionRegistry> {
            let mut registry = ExtensionRegistry::new();
            for e in make()? {
                registry.register(e);
            }
            Ok(registry)
        }

        let cli = Cli::from_arg_matches(&Cli::command().name(bin_name()).get_matches())?;

        match cli.command {
            // Bare `gateway` serves, so a container entrypoint needs no
            // argument and the common case stays the shortest.
            None => serve(None, registry_from(make_extensions)?),
            Some(Command::Run { path }) => serve(path, registry_from(make_extensions)?),
            Some(Command::Dev { path }) => dev(path, registry_from(make_extensions)?),
            Some(Command::Validate { path, allow_unset }) => {
                if allow_unset && let Some(names) = extension_names {
                    validate(path, None, Some(names), allow_unset)
                } else {
                    validate(
                        path,
                        Some(&registry_from(make_extensions)?),
                        None,
                        allow_unset,
                    )
                }
            }
            // These commands neither serve traffic nor resolve an extension
            // name, so they must work without extension setup.
            Some(Command::Init {
                path,
                force,
                docker,
                extensions,
                schema,
            }) => init(&path, force, docker, extensions, schema.as_deref()),
            Some(Command::Schema { routes }) => {
                use std::io::Write;
                std::io::stdout()
                    .lock()
                    .write_all(crate::config::schema::formatted(routes)?.as_bytes())?;
                Ok(())
            }
            Some(Command::Config {
                effective: true,
                path,
            }) => effective::run(path),
            Some(Command::Config {
                effective: false, ..
            }) => anyhow::bail!("config requires --effective"),
            Some(Command::Vars { path }) => vars::run(path),
            Some(Command::Routes { path }) => routes(path),
            Some(Command::Test {
                config,
                cases,
                allow_unset,
            }) => policy::test(config, cases, allow_unset),
            Some(Command::Diff {
                old,
                new,
                allow_unset,
            }) => policy::diff(&old, &new, allow_unset),
            Some(Command::Explain {
                why_not,
                listener,
                method,
                path,
                host,
                config,
            }) => explain(config, &method, &path, host.as_deref(), listener, why_not),
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
         Pass one explicitly (`{bin} run path/to/gateway.yml`), set GATEWAY_CONFIG, \
         or create one with `{bin} init`.",
        CONFIG_CANDIDATES.join(", "),
        bin = bin_name()
    )
}

fn serve(path: Option<String>, registry: ExtensionRegistry) -> anyhow::Result<()> {
    crate::runtime::Runtime::from_registry(resolve_config_path(path)?, registry).run()
}

/// Load a document and its route table without binding a socket.
fn load(path: &str) -> anyhow::Result<(Arc<ResolvedConfig>, RouteTable)> {
    load_with_fallback(path, None)
}

/// As [`load`], but `fallback` fills any `${VAR}` the environment does not set
/// and the document does not default. Reaches both the main document and the
/// route file, which are expanded separately.
fn load_with_fallback(
    path: &str,
    fallback: Option<fn(&str) -> String>,
) -> anyhow::Result<(Arc<ResolvedConfig>, RouteTable)> {
    let (raw, expanded) = GatewayConfig::load_with_fallback(
        path,
        fallback.as_ref().map(|f| f as &dyn Fn(&str) -> String),
    )?;
    if let Some(file) = raw.routes.file.as_deref()
        && expanded
            .placeheld
            .iter()
            .any(|name| file.contains(&unset_placeholder(name)))
    {
        anyhow::bail!(
            "routes.file depends on an unset variable, so its route table cannot be checked. \
             Use a fixed path or give the variable a default (for example, \
             `${{ROUTES_FILE:-routes.yml}}`)."
        );
    }
    let cfg = Arc::new(raw.resolve(&expanded)?);

    let provider: Box<dyn RouteProvider> = match &cfg.raw.routes.file {
        Some(f) => {
            let p = FileRouteProvider::new(f.clone()).with_defaults(cfg.raw.defaults.clone());
            Box::new(match fallback {
                Some(f) => p.allowing_unset(f),
                None => p,
            })
        }
        None => Box::new(
            InlineRouteProvider::new(cfg.raw.routes.groups())
                .with_defaults(cfg.raw.defaults.clone()),
        ),
    };
    let table = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(provider.load())?;

    cfg.validate_table(&table)?;
    Ok((cfg, table))
}

/// Every name left as a placeholder, across both documents.
///
/// The route file is expanded by its provider, separately from the main
/// document, so its unset variables never reach `cfg.placeheld_env`. Listing
/// only half of them would understate what went unchecked — which is the one
/// thing this report exists to prevent — so the route file is re-expanded here
/// to collect the rest.
fn placeheld_in_both(cfg: &ResolvedConfig, fallback: Option<fn(&str) -> String>) -> Vec<String> {
    let mut names = cfg.placeheld_env.clone();
    let (Some(file), Some(fallback)) = (&cfg.raw.routes.file, fallback) else {
        return names;
    };
    // The provider has already read and expanded this file successfully, so a
    // failure here means it changed underneath us. Not worth failing a check
    // that has otherwise passed -- but not worth hiding either, because the
    // list below would then be short without saying so.
    match std::fs::read_to_string(file)
        .map_err(|e| e.to_string())
        .and_then(|text| {
            crate::config::interpolate::interpolate_env_with_fallback(
                &text,
                Some(&fallback as &dyn Fn(&str) -> String),
            )
            .map_err(|e| e.to_string())
        }) {
        Ok(expanded) => {
            for name in expanded.placeheld {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        Err(e) => println!(
            "\n  note: {file} could not be re-read ({e}); variables it sets are \n  \
             missing from the list below."
        ),
    }
    names
}

fn validate(
    path: Option<String>,
    registry: Option<&ExtensionRegistry>,
    extension_names: Option<&[&str]>,
    allow_unset: bool,
) -> anyhow::Result<()> {
    let path = resolve_config_path(path)?;
    let fallback = allow_unset.then_some(unset_placeholder as fn(&str) -> String);
    let (cfg, table) = load_with_fallback(&path, fallback)?;

    let missing = match (extension_names, registry) {
        (Some(names), _) => {
            let available: std::collections::BTreeSet<_> = names.iter().copied().collect();
            table
                .extension_names()
                .filter(|name| !available.contains(name))
                .map(str::to_string)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        }
        (None, Some(registry)) => registry.missing(table.extension_names()),
        (None, None) => anyhow::bail!("extension validation requires names or a registry"),
    };
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
    if extension_names.is_some() {
        println!("✓ extensions  names checked; runtime initialization unchecked");
    }
    println!("✓ upstreams   {}", cfg.upstreams.len());
    println!("✓ routes      {}  ({breakdown})", table.len());
    println!("✓ deny-list   {}", table.deny_prefixes().len());
    // Which addresses upstreams will be told about is a security decision, and
    // the wrong answer is invisible in traffic: forged and genuine client IPs
    // look identical downstream. Print it so it is reviewed like the rest.
    match cfg.raw.forward.trusted_proxies {
        0 => println!(
            "✓ client ip   socket peer (forward.trusted_proxies: 0 — any arriving \
             X-Forwarded-For is discarded)"
        ),
        n => println!("✓ client ip   {n} hop(s) back in X-Forwarded-For"),
    }
    if !cfg.raw.forward.trusted_proxy_ips.is_empty() {
        println!(
            "✓ proxy peers {}",
            cfg.raw.forward.trusted_proxy_ips.join(", ")
        );
    }
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
    // Never a silent pass. Whatever these variables feed was checked against a
    // placeholder, so the reader has to know which parts of the document this
    // run did not actually prove anything about.
    let placeheld = placeheld_in_both(&cfg, fallback);
    if placeheld.is_empty() {
        println!("\n{path} is valid.");
    } else {
        // Never a silent pass. Whatever these variables feed was checked
        // against a placeholder, so the reader has to know which parts of the
        // document this run proved nothing about.
        println!(
            "\n  NOT checked, unset and left as a placeholder: {}",
            placeheld.join(", ")
        );
        println!(
            "  Structure was checked; the values these feed were not. Give one a\n  \
             default (`${{NAME:-value}}`) to have it checked here too."
        );
        println!(
            "\n{path} is structurally valid ({} unset).",
            placeheld.len()
        );
    }
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
        if r.strip_prefix {
            notes.push("strip-prefix".to_string());
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
        notes.push(format!(
            "origins: methods={}, retry={}, rate_limit={}",
            r.policy_origins.methods.label(),
            r.policy_origins.retry.label(),
            r.policy_origins.rate_limit.label()
        ));
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

/// Strip the longest configured mount using the same segment boundary rule
/// as the request path. Shared by `explain` and offline policy tests.
fn strip_mount<'a>(cfg: &'a ResolvedConfig, request_path: &str) -> Option<(&'a str, String)> {
    cfg.base_paths.iter().find_map(|base| {
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
    })
}

fn explain(
    config: Option<String>,
    method: &str,
    request_path: &str,
    host: Option<&str>,
    listener: Listener,
    why_not: bool,
) -> anyhow::Result<()> {
    let path = resolve_config_path(config)?;
    let (cfg, table) = load(&path)?;
    let (public, machine) = table.partition_by_listener();
    let (selected, other) = match listener {
        Listener::Public => (&public, &machine),
        Listener::Internal => (&machine, &public),
    };

    match host {
        Some(h) => println!("Request\n\n  {} {h}{request_path}\n", method.to_uppercase()),
        None => println!("Request\n\n  {} {request_path}\n", method.to_uppercase()),
    }

    println!("Listener\n\n  {}\n", listener.label());
    println!(
        "Offline checks\n\n  UNCHECKED: credentials, client-header/body checks, rate limits, ownership,\n  extensions, cache, CORS preflight, and upstream availability.\n  Results describe route selection, not a verified or proxied request.\n"
    );
    if matches!(listener, Listener::Internal) && cfg.raw.server.internal_listen.is_none() {
        println!("Result\n\n  listener unavailable: server.internal_listen is not configured");
        return Ok(());
    }
    // The proxy matches URI.path(), independently of its query string.
    let request_path = request_path
        .split_once('?')
        .map_or(request_path, |(path, _)| path);
    if request_path == cfg.raw.server.health_path {
        println!(
            "Health\n\n  local health response; route matching and authentication are bypassed"
        );
        println!("\nResult\n\n  200 (local_health)");
        return Ok(());
    }

    // 1. Mount. Longest first, matching the proxy.
    let stripped = strip_mount(&cfg, request_path);

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
    if selected.is_denied(&canonical) {
        println!("Deny-list\n\n  ✗ matches an `internal:` prefix");
        if why_not {
            explanation::candidates(selected, other, host, &canonical, method, listener, true);
        }
        println!(
            "\nResult\n\n  404 (deny_list) — refusals are 404, never 403, so the\n  deny-list cannot be enumerated."
        );
        return Ok(());
    }
    println!("Deny-list\n\n  ✓ not denied\n");

    // 4. Route match.
    let Some(route) = selected.match_request(host, &canonical, method) else {
        println!("Route\n\n  ✗ no route matches");
        if why_not {
            explanation::candidates(selected, other, host, &canonical, method, listener, false);
        }
        println!("\nResult\n\n  404 (not_allowlisted)");
        return Ok(());
    };

    println!(
        "Route\n\n  ✓ {}  (group: {})\n",
        route.id,
        route.auth.group()
    );

    println!(
        "Policy origins\n\n  methods: {}\n  retry: {}\n  rate_limit: {}\n",
        route.policy_origins.methods.label(),
        route.policy_origins.retry.label(),
        route.policy_origins.rate_limit.label()
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
        } else if !crate::retry::is_idempotent(&method.to_ascii_uppercase()) {
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
    println!(
        "  {}  {urls}/{}",
        route.upstream,
        route.upstream_path(&canonical)
    );
    if route.strip_prefix {
        println!("  prefix `/{}` stripped before forwarding", route.prefix);
    }

    let timeout = if route.sse {
        cfg.raw.timeouts.sse
    } else {
        cfg.raw.timeouts.default
    };
    println!(
        "  timeout {timeout:?}{}",
        if route.sse { " (sse)" } else { "" }
    );

    let injected = match listener {
        Listener::Public => &cfg.injected_headers,
        Listener::Internal => &cfg.machine_injected_headers,
    };
    if !injected.is_empty() {
        println!("\nInjected headers\n");
        for (name, _) in injected {
            // Values are credentials; the point is which headers appear.
            println!("  {name}: <redacted>");
        }
    }
    println!("\nResult\n\n  route selected (request outcome unchecked)");
    Ok(())
}

const STARTER: &str = include_str!("../templates/minimal-gateway.yml");
const DOCKER_STARTER: &str = include_str!("../templates/docker-gateway.yml");
const DOCKERFILE_TEMPLATE: &str = include_str!("../templates/Dockerfile");
const EXTENSION_STARTER: &str = include_str!("../templates/extension-gateway.yml");
const EXTENSION_DOCKERFILE_TEMPLATE: &str = include_str!("../templates/extension-Dockerfile");
const EXTENSION_MANIFEST: &str = include_str!("../templates/extension-Cargo.toml");
const EXTENSION_SOURCE: &str = include_str!("../templates/extension-lib.rs");

fn editor_schema_reference(
    given: Option<&str>,
    release: Option<&str>,
) -> anyhow::Result<Option<String>> {
    if let Some(reference) = given {
        if reference.trim().is_empty() || reference.chars().any(char::is_control) {
            anyhow::bail!("--schema needs a nonempty single-line path or URL");
        }
        return Ok(Some(reference.trim().to_string()));
    }
    // Local/source builds cannot assume that a matching version has been
    // published. Only the official tag build opts into the remote artifact.
    Ok(release.filter(|v| *v == env!("CARGO_PKG_VERSION")).map(|version| {
        format!("https://raw.githubusercontent.com/lagos-sh/lagos/v{version}/schemas/gateway.schema.json")
    }))
}

#[cfg(test)]
mod schema_tests {
    use super::editor_schema_reference;

    #[test]
    fn remote_reference_requires_matching_release_build() {
        assert_eq!(editor_schema_reference(None, None).unwrap(), None);
        assert_eq!(
            editor_schema_reference(None, Some("unpublished")).unwrap(),
            None
        );
        let version = env!("CARGO_PKG_VERSION");
        let expected = format!(
            "https://raw.githubusercontent.com/lagos-sh/lagos/v{version}/schemas/gateway.schema.json"
        );
        assert_eq!(
            editor_schema_reference(None, Some(version)).unwrap(),
            Some(expected)
        );
        assert_eq!(
            editor_schema_reference(Some("./local.json"), Some(version)).unwrap(),
            Some("./local.json".into())
        );
    }

    #[test]
    fn editor_reference_cannot_inject_another_line() {
        for reference in [
            "",
            "  ",
            "file.json\ninject: {}",
            "file.json\r",
            "file.json\t",
        ] {
            assert!(editor_schema_reference(Some(reference), None).is_err());
        }
    }
}

fn init(
    path: &str,
    force: bool,
    docker: bool,
    extensions: bool,
    schema: Option<&str>,
) -> anyhow::Result<()> {
    if docker && path != DEFAULT_CONFIG {
        anyhow::bail!(
            "--docker writes gateway.yml and a Dockerfile beside it; omit PATH or use gateway.yml"
        );
    }
    let dockerfile = DOCKERFILE_TEMPLATE.replace("{{LAGOS_VERSION}}", env!("CARGO_PKG_VERSION"));
    let extension_dockerfile =
        EXTENSION_DOCKERFILE_TEMPLATE.replace("{{LAGOS_VERSION}}", env!("CARGO_PKG_VERSION"));
    let starter = if extensions {
        EXTENSION_STARTER
    } else if docker {
        DOCKER_STARTER
    } else {
        STARTER
    };
    let reference = editor_schema_reference(schema, option_env!("LAGOS_SCHEMA_RELEASE"))?;
    let gateway = if let Some(reference) = reference {
        format!("# yaml-language-server: $schema={reference}\n{starter}")
    } else {
        starter.to_string()
    };
    let files = if extensions {
        vec![
            (path, gateway.as_str()),
            ("Dockerfile", extension_dockerfile.as_str()),
            ("ext/Cargo.toml", EXTENSION_MANIFEST),
            ("ext/src/lib.rs", EXTENSION_SOURCE),
        ]
    } else if docker {
        vec![
            (path, gateway.as_str()),
            ("Dockerfile", dockerfile.as_str()),
        ]
    } else {
        vec![(path, gateway.as_str())]
    };
    // Check every destination before writing any of them. A directory that
    // already contains either file must stay untouched unless --force is
    // explicit, including when the other destination does not yet exist.
    for (destination, _) in &files {
        if Path::new(destination).exists() && !force {
            anyhow::bail!("{destination} already exists. Pass --force to overwrite it.");
        }
        if Path::new(destination).is_dir() {
            anyhow::bail!("{destination} is a directory, not a file.");
        }
    }
    if extensions && Path::new("ext").exists() && !Path::new("ext").is_dir() {
        anyhow::bail!("ext exists and is not a directory");
    }
    if extensions {
        std::fs::create_dir_all("ext/src")?;
    }
    for (destination, contents) in &files {
        std::fs::write(destination, contents)?;
    }
    let bin = bin_name();
    if docker {
        if extensions {
            println!("Created gateway.yml, Dockerfile, and ext/\n");
        } else {
            println!("Created gateway.yml and Dockerfile\n");
        }
        println!("  docker build -t my-gateway .");
        println!(
            "  docker run --rm -p 8080:8080 --add-host=host.docker.internal:host-gateway my-gateway"
        );
    } else {
        println!("Created {path}\n");
        println!("  {bin} validate {path}   check it");
        println!("  {bin} routes   {path}   see the route table");
        println!("  {bin} run      {path}   serve traffic");
        println!("\nFor a two-file Docker deployment: {bin} init --docker");
    }
    Ok(())
}

/// `dev`: supervise a child gateway and restart it when the document
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

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately asserted as data rather than by creating files and changing
    // directory: the working directory is process-global, so a test that moved
    // it would race every other test in the binary. The behaviour that depends
    // on a real filesystem is covered in tests/e2e/run.sh.
    #[test]
    fn a_working_directory_config_outranks_the_image_one() {
        let etc = CONFIG_CANDIDATES
            .iter()
            .position(|c| *c == "/etc/lagos/gateway.yml")
            .expect("the image location is a candidate");
        assert_eq!(
            etc,
            CONFIG_CANDIDATES.len() - 1,
            "/etc/lagos must be tried last, so a file mounted over the working \
             directory still overrides a config an image baked in"
        );
        assert_eq!(
            CONFIG_CANDIDATES.first().copied(),
            Some(DEFAULT_CONFIG),
            "the file `init` writes must be found first"
        );
    }

    #[test]
    fn only_the_image_candidate_is_absolute() {
        for candidate in CONFIG_CANDIDATES {
            assert_eq!(
                Path::new(candidate).is_absolute(),
                *candidate == "/etc/lagos/gateway.yml",
                "{candidate} is relative to the working directory or is the image path"
            );
        }
    }

    // A URL-shaped placeholder passes upstream parsing and then fails on any
    // route `host:`, which is where the first version of this went wrong.
    #[test]
    fn the_placeholder_is_a_bare_host() {
        let placeholder = unset_placeholder("PUBLIC_HOST");
        assert!(
            !placeholder.contains("://"),
            "a scheme makes the placeholder invalid in a route `host:`"
        );
        assert!(
            placeholder.ends_with(".invalid"),
            "RFC 2606 reserves .invalid, so a placeholder that escaped into a \
             running config cannot reach a host someone else controls"
        );
        assert_ne!(unset_placeholder("HOST_A"), unset_placeholder("HOST_B"));
        assert_ne!(unset_placeholder("host"), unset_placeholder("HOST"));
    }
}
