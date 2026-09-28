//! Startup and process lifecycle.
//!
//! Both the generic binary and any deployment-specific binary share this, so
//! the only difference between them is which extensions are registered.

use std::sync::Arc;
use std::time::Duration;

use pingora::server::Server;
use pingora::services::background::{BackgroundService, background_service};
use pingora::services::listening::Service;

use crate::config::{GatewayConfig, ResolvedConfig};
use crate::downstream::DeadlineProxy;
use crate::ext::{Extension, ExtensionRegistry};
use crate::proxy::Gateway;
use crate::routes::{
    RouteProvider, SharedRoutes,
    file::{FileRouteProvider, InlineRouteProvider},
};

pub struct Runtime {
    config_path: String,
    extensions: ExtensionRegistry,
}

impl Runtime {
    pub fn new(config_path: impl Into<String>) -> Self {
        Self {
            config_path: config_path.into(),
            extensions: ExtensionRegistry::new(),
        }
    }

    /// Build with an already-populated registry, as the CLI does.
    pub fn from_registry(config_path: impl Into<String>, extensions: ExtensionRegistry) -> Self {
        Self {
            config_path: config_path.into(),
            extensions,
        }
    }

    pub fn with_extension(mut self, ext: Arc<dyn Extension>) -> Self {
        self.extensions.register(ext);
        self
    }

    /// Boot the gateway. Does not return until the process is shut down.
    ///
    /// Every failure here is fatal by design: a gateway that starts with an
    /// unresolvable upstream, an unreadable route file, or a missing extension
    /// would silently serve a weaker policy than the one that was written down.
    pub fn run(self) -> anyhow::Result<()> {
        let (raw, expanded) = GatewayConfig::load(&self.config_path)?;
        let cfg = Arc::new(raw.resolve(&expanded)?);

        crate::telemetry::init(
            &cfg.raw.server.service_name,
            &std::env::var("DEPLOYMENT_ENV").unwrap_or_else(|_| "unknown".into()),
        );

        let (upstreams, health_services) = crate::upstream::resolve_all(&cfg.upstreams)?;

        // Routes live either inline in the document or in a file of their own.
        // Only a file can be reloaded: the document itself also carries
        // listeners and credentials, which cannot change without a restart.
        // Built before the routes, because routes that set `counter: shared`
        // need it to build their limiters. Connecting is lazy, so this does no
        // I/O and a cache that is down cannot stop the gateway from starting.
        let shared_counters = shared_counter_factory(&cfg)?;

        let route_file = cfg.raw.routes.file.clone();
        let provider: Arc<dyn RouteProvider> = match &route_file {
            Some(path) => Arc::new(
                FileRouteProvider::new(path.clone())
                    .with_defaults(cfg.raw.defaults.clone())
                    .with_shared_counters(shared_counters.clone()),
            ),
            None => Arc::new(
                InlineRouteProvider::new(cfg.raw.routes.groups())
                    .with_defaults(cfg.raw.defaults.clone())
                    .with_shared_counters(shared_counters.clone()),
            ),
        };

        // A small runtime just for startup I/O; Pingora owns the serving ones.
        let boot = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let table = boot.block_on(provider.load())?;

        cfg.validate_table(&table)?;

        // Whether the backend must be reachable depends on what the routes ask
        // of it, which is only knowable now. `approximate` degrades gracefully
        // and gets a warning; `exact` cannot work at all without `RLCHECK`, so
        // it is verified here rather than discovered per request.
        if let Some(factory) = &shared_counters {
            boot.block_on(verify_shared_counters(factory, &table))?;
        }

        let referenced: Vec<String> = table.extension_names().map(String::from).collect();
        let missing = self
            .extensions
            .missing(referenced.iter().map(String::as_str));
        if !missing.is_empty() {
            anyhow::bail!(
                "routes reference extensions that are not registered: {}",
                missing.join(", ")
            );
        }

        tracing::info!(
            routes = table.len(),
            upstreams = upstreams.len(),
            listen = %cfg.raw.server.listen,
            trusted_proxies = cfg.raw.forward.trusted_proxies,
            "gateway configured",
        );

        if cfg.raw.forward.trusted_proxies == 0 {
            // Not an error: the edge is exactly where this default is right.
            // But behind an ingress it means upstreams see the ingress address
            // rather than the caller's, and that is a silent behaviour change
            // an operator should hear about once at boot rather than discover
            // in an audit log.
            tracing::info!(
                event = "gateway.forward.untrusted_chain",
                "forward.trusted_proxies is 0: any arriving X-Forwarded-For is discarded and \
                 X-Forwarded-For / X-Real-IP are rebuilt from the socket peer. If this gateway \
                 sits behind a load balancer or ingress, set it to the number of hops in front \
                 or upstreams will see that hop's address as the client.",
            );
        }

        // Two tables, two sockets. Machine routes are simply absent from the
        // public gateway, so reaching one from the internet is not a matter of
        // the deny-list being correct — there is nothing there to reach.
        let total_routes = table.len();
        let gauge_upstreams = upstreams.clone();
        let (public_table, machine_table) = table.partition_by_listener();
        let machine_count = machine_table.len();
        let routes = SharedRoutes::new(public_table);
        let machine_routes = SharedRoutes::new(machine_table);

        // One router over every configured provider, dispatching on the
        // token's `iss`. Firebase is simply one provider among them.
        let mut router = crate::auth::jwt::IssuerRouter::new();

        if let Some(fb) = &cfg.raw.auth.firebase {
            let verifier = Arc::new(crate::auth::firebase::FirebaseVerifier::new(
                cfg.firebase_project_ids.clone(),
                fb.certs_url.clone(),
                fb.clock_skew,
                fb.min_cert_ttl,
            ));
            let issuers = verifier.issuers();
            router
                .register(issuers, verifier as Arc<dyn crate::auth::TokenVerifier>)
                .map_err(|e| anyhow::anyhow!("auth.firebase: {e}"))?;
        }

        for j in &cfg.raw.auth.jwt {
            let algorithms = j
                .algorithms
                .iter()
                .filter_map(|a| crate::config::parse_algorithm(a))
                .collect();
            let verifier = Arc::new(crate::auth::jwt::JwtVerifier::new(
                j.issuer.clone(),
                j.audience.clone(),
                j.resolved_jwks_url(),
                algorithms,
                j.required_claims.clone(),
                j.clock_skew,
                j.min_key_ttl,
            ));
            router
                .register(
                    vec![j.issuer.clone()],
                    verifier as Arc<dyn crate::auth::TokenVerifier>,
                )
                .map_err(|e| anyhow::anyhow!("auth.jwt: {e}"))?;
        }

        if !router.is_empty() {
            tracing::info!(
                issuers = router.issuers().count(),
                "token verification configured",
            );
        }

        let verifier: Option<Arc<dyn crate::auth::TokenVerifier>> = if router.is_empty() {
            None
        } else {
            Some(Arc::new(router))
        };

        let conf = pingora::server::configuration::ServerConf {
            graceful_shutdown_timeout_seconds: Some(cfg.raw.server.graceful_shutdown.as_secs()),
            // Spent before draining starts, so a load balancer can stop sending
            // new connections here while the in-flight ones still finish.
            grace_period_seconds: cfg.raw.server.shutdown_grace.map(|d| d.as_secs()),
            threads: cfg.raw.server.threads,
            // Idle upstream connections held for reuse. The main thing setting
            // the gateway's steady-state memory once it is busy.
            upstream_keepalive_pool_size: cfg.raw.limits.upstream_pool,
            ..Default::default()
        };
        let mut server = Server::new_with_opt_and_conf(None, conf);
        server.bootstrap();

        // Pools that health-check need their checker running: the balancer is
        // itself the background service, and registering it is the only thing
        // that keeps an unhealthy backend out of rotation.
        if !health_services.is_empty() {
            tracing::info!(pools = health_services.len(), "health checking enabled");
            server.add_services(health_services);
        }

        let gateway = Gateway::new(
            cfg.clone(),
            routes.clone(),
            upstreams.clone(),
            verifier.clone(),
            self.extensions.clone(),
        );
        let mut app = pingora::proxy::http_proxy(&server.configuration, gateway);
        app.server_options = Some(downstream_server_options(&cfg));
        let mut proxy = Service::new(
            "Lagos public proxy".into(),
            DeadlineProxy::new(app, cfg.raw.timeouts.downstream_read),
        );
        add_listener(&mut proxy, &cfg.raw.server.listen, &cfg);
        server.add_service(proxy);

        if let Some(addr) = &cfg.raw.server.internal_listen {
            let internal = Gateway::new(
                cfg.clone(),
                machine_routes.clone(),
                upstreams,
                verifier,
                self.extensions.clone(),
            )
            .for_machine_tier();
            let mut app = pingora::proxy::http_proxy(&server.configuration, internal);
            app.server_options = Some(downstream_server_options(&cfg));
            let mut svc = Service::new(
                "Lagos internal proxy".into(),
                DeadlineProxy::new(app, cfg.raw.timeouts.downstream_read),
            );
            add_listener(&mut svc, addr, &cfg);
            server.add_service(svc);
            tracing::info!(
                routes = machine_count,
                listen = %addr,
                "internal listener configured",
            );
        }

        // Only a separate route file is watched; inline routes cannot change
        // without the document that holds them being re-read.
        if let Some(path) = route_file {
            server.add_service(background_service(
                "route-reloader",
                RouteReloader {
                    provider,
                    config: cfg.clone(),
                    shared: shared_counters.clone(),
                    public: routes.clone(),
                    machine: cfg
                        .raw
                        .server
                        .internal_listen
                        .as_ref()
                        .map(|_| machine_routes.clone()),
                    interval: cfg.raw.routes.reload,
                    path,
                },
            ));
        }

        if let Some(factory) = &shared_counters {
            server.add_service(background_service(
                "shared-limit-sync",
                SharedLimitSync {
                    public: routes.clone(),
                    machine: cfg
                        .raw
                        .server
                        .internal_listen
                        .as_ref()
                        .map(|_| machine_routes.clone()),
                    interval: factory.sync_interval(),
                },
            ));
            tracing::info!(
                sync = ?factory.sync_interval(),
                "shared rate-limit counters configured",
            );
        }

        if let Some(t) = &cfg.raw.observability.tracing {
            if let Some(otlp) = &t.otlp {
                // Started on Pingora's runtime, which is where the exporter's
                // background task has to live.
                server.add_service(background_service(
                    "otlp-exporter",
                    TraceExporter {
                        endpoint: otlp.endpoint.clone(),
                        service_name: cfg.raw.server.service_name.clone(),
                    },
                ));
                tracing::info!(endpoint = %otlp.endpoint, "OTLP trace export configured");
            } else {
                tracing::info!(
                    "trace context propagation enabled; no OTLP endpoint, so no spans are exported"
                );
            }
        }

        if let Some(m) = &cfg.raw.observability.metrics {
            if let Some(registry) = crate::metrics::metrics() {
                registry.set_routes(total_routes);
            }

            // Pingora serves the process-global registry; everything recorded
            // through `crate::metrics` lands here. Split out of pingora-core in
            // 0.9, so core itself no longer carries a prometheus dependency.
            let mut svc = pingora_prometheus::prometheus_http_service();
            svc.add_tcp(&m.listen);
            server.add_service(svc);

            server.add_service(background_service(
                "pool-health-gauge",
                PoolHealthGauge {
                    upstreams: gauge_upstreams,
                    interval: m.pool_sample_interval,
                },
            ));

            tracing::info!(listen = %m.listen, "metrics listener configured");
        }

        server.run_forever();
    }
}

/// Bind a listener with the socket options and accept-time filter configured.
///
/// Both listeners get the same treatment: the internal one is reachable by
/// anything that can route to its address, and "it is on a private network" has
/// never been a reason to leave a socket unbounded.
fn add_listener<A>(
    svc: &mut pingora::services::listening::Service<A>,
    addr: &str,
    cfg: &ResolvedConfig,
) {
    match &cfg.raw.server.tcp_keepalive {
        Some(k) => {
            let mut opts = pingora::listeners::TcpSocketOptions::default();
            opts.tcp_keepalive = Some(pingora::protocols::l4::ext::TcpKeepalive {
                idle: k.idle,
                interval: k.interval,
                count: k.count,
                // Linux-only field; the others are portable.
                #[cfg(target_os = "linux")]
                user_timeout: Duration::ZERO,
            });
            svc.add_tcp_with_settings(addr, opts);
        }
        None => svc.add_tcp(addr),
    }

    // Refuses a connection immediately after accept, before it costs a task or
    // a TLS handshake. Nothing else in the gateway runs this early.
    if let Some(limit) = &cfg.raw.limits.connections_per_ip {
        svc.set_connection_filter(Arc::new(crate::accept::ConnectionLimiter::new(limit)));
        tracing::info!(
            listen = %addr,
            connections = limit.connections,
            interval = ?limit.interval,
            "per-address connection limit enabled",
        );
    }
}

/// Per-connection limits for a downstream listener.
///
/// `keepalive_request_limit` is Pingora's, and it has no default — nginx's own
/// documentation for the equivalent setting explains why that is the wrong
/// answer: per-connection allocations are only reclaimed when the connection
/// closes, so an unbounded connection is a slow leak and holding one open is a
/// cheap way to keep it.
///
/// `h2c` stays off. Plaintext HTTP/2 on the wire would put the gateway's
/// downstream side on a protocol whose stream-multiplexing attacks (Rapid
/// Reset and its relatives) are only bounded by Pingora's `H2Options`, which
/// nothing here has had reason to tune.
fn downstream_server_options(cfg: &ResolvedConfig) -> pingora::apps::HttpServerOptions {
    let mut opts = pingora::apps::HttpServerOptions::default();
    opts.keepalive_request_limit = match cfg.raw.limits.keepalive_requests {
        0 => None,
        n => Some(n),
    };
    opts
}

/// Picks up route-file changes without a restart.
///
/// Polls mtime rather than watching a signal: Pingora reserves SIGHUP for
/// zero-downtime binary upgrades, and a Kubernetes ConfigMap update surfaces
/// precisely as a changed mtime on the projected file.
struct RouteReloader {
    provider: Arc<dyn RouteProvider>,
    /// Kept so a reload is validated against the same upstreams and listeners
    /// the running gateway was booted with.
    config: Arc<ResolvedConfig>,
    shared: Option<crate::ratelimit::SharedCounterFactory>,
    public: SharedRoutes,
    machine: Option<SharedRoutes>,
    interval: Duration,
    path: String,
}

impl RouteReloader {
    async fn publish(&self, table: crate::routes::RouteTable) -> anyhow::Result<usize> {
        self.config.validate_table(&table)?;
        if let Some(factory) = &self.shared {
            verify_shared_counters(factory, &table).await?;
        }
        let total = table.len();
        SharedRoutes::publish_reload(table, &self.public, self.machine.as_ref());
        Ok(total)
    }

    fn mtime(&self) -> Option<std::time::SystemTime> {
        std::fs::metadata(&self.path).ok()?.modified().ok()
    }
}

#[async_trait::async_trait]
impl BackgroundService for RouteReloader {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut last = self.mtime();
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = ticker.tick() => {}
            }

            let current = self.mtime();
            if current == last {
                continue;
            }

            match self.provider.load().await {
                Ok(table) => {
                    // A table that names a missing upstream would answer 502 on
                    // every request it matched. Reject it and keep serving the
                    // one that works — the same fail-closed rule as at boot.
                    let total = match self.publish(table).await {
                        Ok(total) => total,
                        Err(e) => {
                            tracing::error!(
                                event = "gateway.routes.reload_rejected",
                                error = %e,
                                "route reload rejected; keeping the previous table",
                            );
                            continue;
                        }
                    };
                    // Only advance `last` on success, so a half-written file is
                    // retried on the next tick instead of being skipped.
                    last = current;
                    tracing::info!(
                        event = "gateway.routes.reloaded",
                        routes = total,
                        "route table reloaded",
                    );
                }
                Err(e) => tracing::error!(
                    event = "gateway.routes.reload_failed",
                    error = %e,
                    "route reload failed; keeping the previous table",
                ),
            }
        }
    }
}

/// Publishes this replica's rate-limit usage and reads the cluster's back.
///
/// A background service rather than a task spawned from the request path: the
/// entire premise of `mode: approximate` is that no request waits on the cache,
/// and a reconciliation driven by request arrival would not be that.
///
/// It re-reads the route table every tick rather than holding its own list, so a
/// route reload that replaces a limiter is picked up immediately and a limiter
/// nothing points at any more stops being reconciled.
struct SharedLimitSync {
    public: SharedRoutes,
    machine: Option<SharedRoutes>,
    interval: Duration,
}

#[async_trait::async_trait]
impl BackgroundService for SharedLimitSync {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut ticker = tokio::time::interval(self.interval);
        // `Delay` rather than `Skip`: a tick that overran should push the next
        // one out, not fire immediately behind it. Bursting reconciliations at a
        // cache that is already slow is how a slow cache becomes a dead one.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = ticker.tick() => {}
            }

            let mut counters = self.public.shared_counters();
            if let Some(machine) = &self.machine {
                counters.extend(machine.shared_counters());
            }

            // One pipelined round trip per limiter, sequentially. Routes are
            // configuration-bounded and each tick is one round trip per route,
            // so this stays small; it is deliberately not a fan-out, which
            // would multiply a cache hiccup by the route count.
            for counters in counters {
                counters.sync_once(std::time::SystemTime::now()).await;
            }
        }
    }
}

/// Build the shared-counter backend, or `None` when nothing is configured.
#[cfg(feature = "shared-limits")]
fn shared_counter_factory(
    cfg: &ResolvedConfig,
) -> anyhow::Result<Option<crate::ratelimit::SharedCounterFactory>> {
    let Some(shared) = &cfg.raw.shared_counters else {
        return Ok(None);
    };
    let backend = crate::ratelimit::resp::RespBackend::connect(shared)
        .map_err(|e| anyhow::anyhow!("shared_counters: {e}"))?;
    tracing::info!(url = %backend.url(), "shared rate-limit counter store configured");
    Ok(Some(crate::ratelimit::SharedCounterFactory::new(
        Arc::new(backend),
        shared.clone(),
    )))
}

/// Without the feature there is no backend to build.
///
/// A configuration that asks for one is refused by validation, naming the
/// feature — so reaching here with `shared_counters` set means no route uses it,
/// which is worth one line and not an error.
#[cfg(not(feature = "shared-limits"))]
fn shared_counter_factory(
    cfg: &ResolvedConfig,
) -> anyhow::Result<Option<crate::ratelimit::SharedCounterFactory>> {
    if cfg.raw.shared_counters.is_some() {
        tracing::warn!(
            "shared_counters is configured but this binary was built without the \
             `shared-limits` feature; no route uses it, so it is ignored",
        );
    }
    Ok(None)
}

/// Check the backend can do what the routes ask of it.
///
/// Reuses the factory's own connection rather than opening a second one, and is
/// compiled in every build: without the `shared-limits` feature no factory is
/// ever built, so this is simply never called.
async fn verify_shared_counters(
    factory: &crate::ratelimit::SharedCounterFactory,
    table: &crate::routes::RouteTable,
) -> anyhow::Result<()> {
    use crate::config::{Counter, LimitMode};

    if !table.routes().iter().any(|r| {
        r.rate_limit
            .as_ref()
            .is_some_and(|rl| rl.counter == Counter::Shared)
    }) {
        return Ok(());
    }

    let needs_exact = table.routes().iter().any(|r| {
        r.rate_limit
            .as_ref()
            .is_some_and(|rl| rl.counter == Counter::Shared && rl.mode == LimitMode::Exact)
    });

    match factory.probe().await {
        Ok((server, supports_exact)) => {
            tracing::info!(%server, "shared rate-limit counter store reached");
            if needs_exact && !supports_exact {
                anyhow::bail!(
                    "a route sets `rate_limit.mode: exact`, which needs Recached's RLCHECK, \
                     but shared_counters.url answered as {server}. RLCHECK has no Redis or \
                     Valkey equivalent and cannot be emulated without EVAL, which Recached \
                     does not implement either. Use `mode: approximate`, or point \
                     shared_counters at Recached."
                );
            }
        }
        Err(e) if needs_exact => {
            // Nothing to degrade to. An exact limit is a promise that cannot be
            // kept without the backend, and starting anyway would mean every
            // request quietly falling back to the per-process count the
            // operator explicitly rejected.
            anyhow::bail!(
                "a route sets `rate_limit.mode: exact`, but the shared counter store could \
                 not be reached: {e}"
            );
        }
        Err(e) => {
            // `approximate` has a local answer for every request and reconciles
            // once the cache comes back, so this is a degraded start rather
            // than a failed one.
            tracing::warn!(
                event = "gateway.ratelimit.store_unreachable",
                error = %e,
                "shared counter store unreachable at startup; limits count per process until \
                 it answers. Watch gateway_shared_limit_errors_total.",
            );
        }
    }
    Ok(())
}

/// Samples each pool's health into `gateway_pool_backends`.
///
/// Health lives inside the balancer and changes on its own schedule, so it is
/// polled rather than pushed. Sampling is cheap — a read of an `ArcSwap` per
/// pool — and it is the gauge operators actually alert on.
struct PoolHealthGauge {
    upstreams: std::collections::HashMap<String, Arc<crate::upstream::Upstream>>,
    interval: Duration,
}

#[async_trait::async_trait]
impl BackgroundService for PoolHealthGauge {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = ticker.tick() => {}
            }

            let Some(metrics) = crate::metrics::metrics() else {
                return;
            };
            for (name, upstream) in &self.upstreams {
                if let Some((healthy, unhealthy)) = upstream.health_counts() {
                    metrics.set_pool_health(name, healthy, unhealthy);
                }
            }
        }
    }
}

/// Owns the OTLP exporter's background task.
///
/// A background service rather than a bare `tokio::spawn` so it starts on
/// Pingora's own runtime and is told about shutdown like everything else.
struct TraceExporter {
    endpoint: String,
    service_name: String,
}

#[async_trait::async_trait]
impl BackgroundService for TraceExporter {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        if let Err(e) = crate::otel::init(&self.endpoint, &self.service_name) {
            // Telemetry that cannot start must not stop the gateway serving.
            tracing::error!(error = %e, "trace export disabled");
            return;
        }
        // The exporter runs on its own task; this one only waits for shutdown.
        let _ = shutdown.changed().await;
    }
}

#[cfg(all(test, feature = "shared-limits"))]
mod shared_limit_tests {
    use super::*;
    use crate::ratelimit::shared::{Backend, BackendError, Publish, Totals};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Debug, Default)]
    struct Store {
        supports_exact: AtomicBool,
        unavailable: AtomicBool,
        probes: AtomicU64,
    }

    #[async_trait::async_trait]
    impl Backend for Store {
        async fn reconcile(&self, batch: &[Publish]) -> Result<Vec<Totals>, BackendError> {
            Ok(vec![
                Totals {
                    current: 0,
                    previous: 0
                };
                batch.len()
            ])
        }
        async fn check_exact(
            &self,
            _: &str,
            limit: u64,
            _: Duration,
        ) -> Result<crate::ratelimit::Decision, BackendError> {
            Ok(crate::ratelimit::Decision::allow(limit, 0))
        }
        async fn probe(&self) -> Result<(String, bool), BackendError> {
            self.probes.fetch_add(1, Ordering::Relaxed);
            if self.unavailable.load(Ordering::Relaxed) {
                Err(BackendError::Unavailable("offline".into()))
            } else {
                Ok((
                    "test server".into(),
                    self.supports_exact.load(Ordering::Relaxed),
                ))
            }
        }
    }

    fn config(mode: &str) -> ResolvedConfig {
        let text = format!(
            "shared_counters:\n  url: redis://cache:6379\nupstreams: {{ users: http://users:3000 }}\nroutes:\n  public:\n    - prefix: /users\n      upstream: users\n      rate_limit: {{ requests: 10, interval: 1m, counter: shared, mode: {mode} }}\n"
        );
        let (raw, expanded) = crate::config::GatewayConfig::parse("test.yml", &text).unwrap();
        raw.resolve(&expanded).unwrap()
    }

    fn reloader(backend: Arc<Store>) -> RouteReloader {
        let config = Arc::new(config("approximate"));
        let factory = crate::ratelimit::SharedCounterFactory::new(
            backend,
            config.raw.shared_counters.clone().unwrap(),
        );
        let table = crate::routes::RouteTable::build_with(
            config.raw.routes.groups(),
            &config.raw.defaults,
            Some(&factory),
        );
        RouteReloader {
            provider: Arc::new(InlineRouteProvider::new(config.raw.routes.groups())),
            config,
            shared: Some(factory),
            public: SharedRoutes::new(table),
            machine: None,
            interval: Duration::from_secs(1),
            path: "test.yml".into(),
        }
    }

    fn exact_table(reloader: &RouteReloader) -> crate::routes::RouteTable {
        let cfg = config("exact");
        crate::routes::RouteTable::build_with(
            cfg.raw.routes.groups(),
            &cfg.raw.defaults,
            reloader.shared.as_ref(),
        )
    }

    #[tokio::test]
    async fn exact_reloads_are_rejected_until_the_backend_can_honour_them() {
        let backend = Arc::new(Store::default());
        let reloader = reloader(backend.clone());
        let original = reloader.public.load();
        assert!(
            reloader
                .publish(exact_table(&reloader))
                .await
                .unwrap_err()
                .to_string()
                .contains("RLCHECK")
        );
        assert!(Arc::ptr_eq(&original, &reloader.public.load()));

        backend.supports_exact.store(true, Ordering::Relaxed);
        backend.unavailable.store(true, Ordering::Relaxed);
        assert!(
            reloader
                .publish(exact_table(&reloader))
                .await
                .unwrap_err()
                .to_string()
                .contains("could not be reached")
        );
        assert!(Arc::ptr_eq(&original, &reloader.public.load()));

        backend.unavailable.store(false, Ordering::Relaxed);
        assert_eq!(reloader.publish(exact_table(&reloader)).await.unwrap(), 1);
        assert!(!Arc::ptr_eq(&original, &reloader.public.load()));
    }

    #[tokio::test]
    async fn approximate_reloads_tolerate_outages_and_unused_backends_are_not_probed() {
        let backend = Arc::new(Store::default());
        backend.unavailable.store(true, Ordering::Relaxed);
        let reloader = reloader(backend.clone());
        let cfg = config("approximate");
        let table = crate::routes::RouteTable::build_with(
            cfg.raw.routes.groups(),
            &cfg.raw.defaults,
            reloader.shared.as_ref(),
        );
        assert_eq!(reloader.publish(table).await.unwrap(), 1);
        assert_eq!(backend.probes.load(Ordering::Relaxed), 1);

        let local = crate::routes::RouteTable::build(
            serde_yaml_ng::from_str(
                "public: [{prefix: /users, upstream: users, rate_limit: {requests: 10}}]",
            )
            .unwrap(),
        );
        assert_eq!(reloader.publish(local).await.unwrap(), 1);
        assert_eq!(backend.probes.load(Ordering::Relaxed), 1);
    }
}
