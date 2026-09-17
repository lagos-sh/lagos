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
        let route_file = cfg.raw.routes.file.clone();
        let provider: Arc<dyn RouteProvider> = match &route_file {
            Some(path) => Arc::new(
                FileRouteProvider::new(path.clone()).with_defaults(cfg.raw.defaults.clone()),
            ),
            None => Arc::new(
                InlineRouteProvider::new(cfg.raw.routes.groups())
                    .with_defaults(cfg.raw.defaults.clone()),
            ),
        };

        // A small runtime just for startup I/O; Pingora owns the serving ones.
        let boot = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let table = boot.block_on(provider.load())?;

        cfg.validate_table(&table)?;

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
                    public: routes,
                    machine: cfg
                        .raw
                        .server
                        .internal_listen
                        .as_ref()
                        .map(|_| machine_routes),
                    interval: cfg.raw.routes.reload,
                    path,
                },
            ));
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
    public: SharedRoutes,
    machine: Option<SharedRoutes>,
    interval: Duration,
    path: String,
}

impl RouteReloader {
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
                    if let Err(e) = self.config.validate_table(&table) {
                        tracing::error!(
                            event = "gateway.routes.reload_rejected",
                            error = %e,
                            "route reload rejected; keeping the previous table",
                        );
                        continue;
                    }
                    // Only advance `last` on success, so a half-written file is
                    // retried on the next tick instead of being skipped.
                    last = current;
                    let total = table.len();
                    SharedRoutes::publish_reload(table, &self.public, self.machine.as_ref());
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
