//! Resolved upstream targets, and pools of them.
//!
//! A single-target upstream keeps its hostname and is dialled directly, so DNS
//! is resolved per connection and a record change is picked up without a
//! restart. A pool is handed to Pingora's load balancer, which works on
//! addresses and therefore resolves its members once at startup. That
//! difference is the reason pools are opt-in rather than the default shape.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use pingora::lb::selection::{Consistent, Random, RoundRobin};
use pingora::lb::{Backend, Backends, LoadBalancer};

use crate::config::{Balance, HealthCheckConfig, UpstreamConfig};
use crate::path::normalize_proxy_path;

/// A destination the gateway can dial, precomputed at startup so the request
/// path never parses a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// `host:port`, ready for `HttpPeer`.
    pub addr: String,
    pub tls: bool,
    pub sni: String,
    /// Path prefix the upstream itself is mounted under; usually empty.
    pub base_path: String,
}

impl UpstreamTarget {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let uri: http::Uri = url
            .parse()
            .map_err(|e| anyhow::anyhow!("upstream URL `{url}` is not a valid URI: {e}"))?;
        let scheme = uri.scheme_str().unwrap_or("http");
        let tls = match scheme {
            "http" => false,
            "https" => true,
            other => anyhow::bail!("upstream URL `{url}` has unsupported scheme `{other}`"),
        };
        let host = uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("upstream URL `{url}` has no host"))?
            .to_string();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let base_path = normalize_proxy_path(uri.path()).to_string();

        Ok(Self {
            addr: format!("{host}:{port}"),
            tls,
            sni: host,
            base_path,
        })
    }
}

/// Pingora's balancer, one variant per selection algorithm.
///
/// The algorithm is a type parameter upstream, so an enum is what lets it be
/// chosen from configuration.
pub enum Balancer {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    Random(Arc<LoadBalancer<Random>>),
    /// Ketama consistent hashing — `pingora-ketama`, reached through the load
    /// balancing crate rather than depended on separately.
    Consistent(Arc<LoadBalancer<Consistent>>),
}

impl Balancer {
    fn select(&self, key: &[u8]) -> Option<Backend> {
        // 256 is Pingora's own suggested ceiling on how many backends to skip
        // past while looking for a healthy one.
        match self {
            Self::RoundRobin(lb) => lb.select(key, 256),
            Self::Random(lb) => lb.select(key, 256),
            Self::Consistent(lb) => lb.select(key, 256),
        }
    }
}

/// One logical backend: a single target, or several behind a balancer.
pub enum Kind {
    Single(UpstreamTarget),
    Pool {
        balancer: Balancer,
        /// `host:port` → the target it came from, since a [`Backend`] carries
        /// only an address and the TLS settings still have to be recovered.
        members: HashMap<String, UpstreamTarget>,
    },
}

pub struct Upstream {
    kind: Kind,
    /// Shuts traffic off when this upstream stops working. `None` when no
    /// breaker is configured, which is the default.
    breaker: Option<crate::breaker::CircuitBreaker>,
}

impl Upstream {
    fn new(kind: Kind, cfg: &UpstreamConfig) -> Self {
        Self {
            kind,
            breaker: cfg
                .circuit_breaker
                .as_ref()
                .map(crate::breaker::CircuitBreaker::new),
        }
    }

    pub fn breaker(&self) -> Option<&crate::breaker::CircuitBreaker> {
        self.breaker.as_ref()
    }

    /// The target to dial for this request, or `None` when a pool has no
    /// healthy member left.
    ///
    /// `key` matters only to hashing algorithms; round robin and random ignore
    /// it.
    pub fn select(&self, key: &[u8]) -> Option<&UpstreamTarget> {
        match &self.kind {
            Kind::Single(t) => Some(t),
            Kind::Pool { balancer, members } => {
                let backend = balancer.select(key)?;
                members.get(&backend.addr.to_string())
            }
        }
    }

    /// Every target, for `validate` and `routes` output.
    pub fn targets(&self) -> Vec<&UpstreamTarget> {
        match &self.kind {
            Kind::Single(t) => vec![t],
            Kind::Pool { members, .. } => members.values().collect(),
        }
    }

    /// How many backends are currently usable, and how many are not.
    ///
    /// `None` for a single target: there is no pool to be partly healthy, and
    /// reporting `1 healthy` would imply a check that is not running.
    pub fn health_counts(&self) -> Option<(usize, usize)> {
        let balancer = self.balancer()?;
        let (backends, ready): (_, fn(&Backends, &Backend) -> bool) = match balancer {
            Balancer::RoundRobin(lb) => (lb.backends(), Backends::ready),
            Balancer::Random(lb) => (lb.backends(), Backends::ready),
            Balancer::Consistent(lb) => (lb.backends(), Backends::ready),
        };
        let all = backends.get_backend();
        let healthy = all.iter().filter(|b| ready(backends, b)).count();
        Some((healthy, all.len().saturating_sub(healthy)))
    }

    /// The balancer, when there is one, so the caller can register its health
    /// checks as a background service.
    pub fn balancer(&self) -> Option<&Balancer> {
        match &self.kind {
            Kind::Single(_) => None,
            Kind::Pool { balancer, .. } => Some(balancer),
        }
    }
}

/// Build a health check from configuration.
///
/// Without a path this is a TCP connect check, which proves only that
/// something accepted a socket. A path makes it an HTTP check, which is what
/// actually shows the service can serve.
fn health_check(
    cfg: &HealthCheckConfig,
    target: &UpstreamTarget,
) -> Box<dyn pingora::lb::health_check::HealthCheck + Send + Sync + 'static> {
    match &cfg.path {
        Some(path) => {
            let mut check =
                pingora::lb::health_check::HttpHealthCheck::new(&target.sni, target.tls);
            check.consecutive_success = cfg.healthy_after;
            check.consecutive_failure = cfg.unhealthy_after;
            check.peer_template.options.connection_timeout = Some(cfg.timeout);
            check.peer_template.options.read_timeout = Some(cfg.timeout);
            if let Ok(req) = pingora::http::RequestHeader::build("GET", path.as_bytes(), None) {
                check.req = req;
            }
            Box::new(check)
        }
        None => {
            let mut check = pingora::lb::health_check::TcpHealthCheck::new();
            check.consecutive_success = cfg.healthy_after;
            check.consecutive_failure = cfg.unhealthy_after;
            check.peer_template.options.connection_timeout = Some(cfg.timeout);
            check
        }
    }
}

/// A health checker that must be registered with the server for a pool's
/// health state to be maintained.
pub type HealthService = Box<dyn pingora::services::ServiceWithDependents>;

/// Drive a future that is known not to await anything.
///
/// [`Backends::update`] is async because discovery *can* be — but a static set
/// of backends resolves immediately, and this runs at startup where there is
/// no runtime to block on yet. `Pending` would mean the assumption is wrong,
/// so it is reported rather than ignored.
fn poll_once<F: std::future::Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

fn build_pool(name: &str, cfg: &UpstreamConfig) -> anyhow::Result<(Kind, Option<HealthService>)> {
    let mut backends = BTreeSet::new();
    let mut members = HashMap::new();

    for t in &cfg.targets {
        let target = UpstreamTarget::parse(&t.url)?;
        // Resolves DNS. A pool member that cannot be resolved at startup is
        // fatal on purpose: silently starting with a smaller pool than was
        // written down hides a real outage behind apparently healthy traffic.
        let backend = Backend::new_with_weight(&target.addr, t.weight).map_err(|e| {
            anyhow::anyhow!("upstream `{name}`: cannot resolve `{}`: {e}", target.addr)
        })?;
        members.insert(backend.addr.to_string(), target);
        backends.insert(backend);
    }

    let mut discovered = Backends::new(pingora::lb::discovery::Static::new(backends));
    if let Some(hc) = &cfg.health_check {
        // Any member will do as the template: the check replaces the address
        // per backend, and TLS settings are uniform across a pool.
        let first = UpstreamTarget::parse(
            &cfg.targets
                .first()
                .ok_or_else(|| anyhow::anyhow!("upstream `{name}` has no targets"))?
                .url,
        )?;
        discovered.set_health_check(health_check(hc, &first));
    }

    let interval = cfg.health_check.as_ref().map(|h| h.interval);
    let checked = cfg.health_check.is_some();

    // The balancer runs its own health loop, and the server owns that loop.
    // `background_service` takes the balancer by value and hands back the
    // `Arc` the request path selects through, so the service has to be built
    // even when no checks are configured — it is simply not registered then.
    let (balancer, service): (Balancer, Option<HealthService>) = match cfg.balance {
        Balance::RoundRobin => {
            let mut lb = LoadBalancer::<RoundRobin>::from_backends(discovered);
            lb.health_check_frequency = interval;
            let svc =
                pingora::services::background::background_service(&format!("health-{name}"), lb);
            let handle = svc.task();
            prime(name, &handle)?;
            (
                Balancer::RoundRobin(handle),
                checked.then(|| Box::new(svc) as HealthService),
            )
        }
        Balance::Random => {
            let mut lb = LoadBalancer::<Random>::from_backends(discovered);
            lb.health_check_frequency = interval;
            let svc =
                pingora::services::background::background_service(&format!("health-{name}"), lb);
            let handle = svc.task();
            prime(name, &handle)?;
            (
                Balancer::Random(handle),
                checked.then(|| Box::new(svc) as HealthService),
            )
        }
        Balance::Consistent => {
            let mut lb = LoadBalancer::<Consistent>::from_backends(discovered);
            lb.health_check_frequency = interval;
            let svc =
                pingora::services::background::background_service(&format!("health-{name}"), lb);
            let handle = svc.task();
            prime(name, &handle)?;
            (
                Balancer::Consistent(handle),
                checked.then(|| Box::new(svc) as HealthService),
            )
        }
    };

    Ok((Kind::Pool { balancer, members }, service))
}

/// Build every upstream, plus the health-check services the caller must
/// register with the server.
/// Populate the balancer's selection state.
///
/// `from_backends` builds an empty selector; without this the pool would pick
/// nothing until the first health tick, and a pool with no health check would
/// never pick anything at all.
fn prime<S>(name: &str, lb: &LoadBalancer<S>) -> anyhow::Result<()>
where
    S: pingora::lb::selection::BackendSelection + Send + Sync + 'static,
    S::Iter: pingora::lb::selection::BackendIter,
{
    poll_once(lb.update())
        .ok_or_else(|| anyhow::anyhow!("upstream `{name}`: backend discovery did not complete"))?
        .map_err(|e| anyhow::anyhow!("upstream `{name}`: {e}"))
}

/// Every upstream by name, and the health checkers that must be registered
/// with the server for their pools to stay accurate.
pub type ResolvedUpstreams = (HashMap<String, Arc<Upstream>>, Vec<HealthService>);

pub fn resolve_all(
    configured: &HashMap<String, UpstreamConfig>,
) -> anyhow::Result<ResolvedUpstreams> {
    let mut upstreams = HashMap::with_capacity(configured.len());
    let mut services = Vec::new();

    for (name, cfg) in configured {
        let upstream = if cfg.is_pool() {
            let (pool, service) = build_pool(name, cfg)?;
            if let Some(s) = service {
                services.push(s);
            }
            pool
        } else {
            let url = &cfg
                .targets
                .first()
                .ok_or_else(|| anyhow::anyhow!("upstream `{name}` has no targets"))?
                .url;
            Kind::Single(
                UpstreamTarget::parse(url)
                    .map_err(|e| anyhow::anyhow!("upstream `{name}`: {e}"))?,
            )
        };
        upstreams.insert(name.clone(), Arc::new(Upstream::new(upstream, cfg)));
    }

    Ok((upstreams, services))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamTargetConfig;

    fn single(url: &str) -> UpstreamConfig {
        UpstreamConfig {
            targets: vec![UpstreamTargetConfig {
                url: url.into(),
                weight: 1,
            }],
            balance: Balance::RoundRobin,
            hash_on: crate::config::HashKey::default(),
            health_check: None,
            circuit_breaker: None,
        }
    }

    #[test]
    fn parses_cluster_style_urls() {
        let t = UpstreamTarget::parse("http://loyalty-service:3000").unwrap();
        assert_eq!(t.addr, "loyalty-service:3000");
        assert!(!t.tls);
        assert_eq!(t.base_path, "");
    }

    #[test]
    fn defaults_the_port_from_the_scheme() {
        assert_eq!(
            UpstreamTarget::parse("https://api.example.com")
                .unwrap()
                .addr,
            "api.example.com:443"
        );
        assert_eq!(
            UpstreamTarget::parse("http://api.example.com")
                .unwrap()
                .addr,
            "api.example.com:80"
        );
    }

    #[test]
    fn captures_a_mount_prefix() {
        let t = UpstreamTarget::parse("http://legacy:3006/legacy/").unwrap();
        assert_eq!(t.base_path, "legacy");
    }

    #[test]
    fn rejects_unusable_urls() {
        assert!(UpstreamTarget::parse("ftp://x:1").is_err());
        assert!(UpstreamTarget::parse("not a url").is_err());
    }

    #[test]
    fn a_single_target_keeps_its_hostname_rather_than_an_address() {
        // The whole reason pools are opt-in: this one still resolves per
        // connection, so a DNS change lands without a restart.
        let map = HashMap::from([("users".to_string(), single("http://users-service:3000"))]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let up = resolved.get("users").expect("present");
        assert_eq!(up.select(b"").unwrap().addr, "users-service:3000");
        assert!(
            up.balancer().is_none(),
            "no balancer, so no health checking"
        );
    }

    #[test]
    fn a_pool_balances_across_its_members() {
        let cfg = UpstreamConfig {
            targets: vec![
                UpstreamTargetConfig {
                    url: "http://127.0.0.1:9001".into(),
                    weight: 1,
                },
                UpstreamTargetConfig {
                    url: "http://127.0.0.1:9002".into(),
                    weight: 1,
                },
            ],
            balance: Balance::RoundRobin,
            hash_on: crate::config::HashKey::default(),
            health_check: None,
            circuit_breaker: None,
        };
        let map = HashMap::from([("orders".to_string(), cfg)]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let up = resolved.get("orders").expect("present");
        assert!(up.balancer().is_some());

        let seen: std::collections::HashSet<String> = (0..20)
            .filter_map(|_| up.select(b"").map(|t| t.addr.clone()))
            .collect();
        assert_eq!(
            seen.len(),
            2,
            "round robin should use both members: {seen:?}"
        );
    }

    fn pool(ports: &[u16], balance: Balance) -> UpstreamConfig {
        UpstreamConfig {
            targets: ports
                .iter()
                .map(|p| UpstreamTargetConfig {
                    url: format!("http://127.0.0.1:{p}"),
                    weight: 1,
                })
                .collect(),
            balance,
            hash_on: crate::config::HashKey::default(),
            health_check: None,
            circuit_breaker: None,
        }
    }

    #[test]
    fn consistent_hashing_sends_a_key_to_the_same_backend() {
        let map = HashMap::from([(
            "u".to_string(),
            pool(&[9001, 9002, 9003], Balance::Consistent),
        )]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let up = &resolved["u"];

        let first = up.select(b"/products/42").expect("a backend").addr.clone();
        for _ in 0..50 {
            assert_eq!(
                up.select(b"/products/42").expect("a backend").addr,
                first,
                "the same key must not move between requests"
            );
        }
    }

    #[test]
    fn removing_a_backend_moves_only_its_own_share() {
        // The property that makes consistent hashing worth the complexity: with
        // round robin, changing the pool size reshuffles everything and every
        // upstream cache is cold at once.
        let keys: Vec<String> = (0..300).map(|i| format!("/item/{i}")).collect();

        let before = {
            let map = HashMap::from([(
                "u".to_string(),
                pool(&[9001, 9002, 9003], Balance::Consistent),
            )]);
            let (r, _) = resolve_all(&map).expect("resolves");
            keys.iter()
                .map(|k| r["u"].select(k.as_bytes()).expect("backend").addr.clone())
                .collect::<Vec<_>>()
        };
        let after = {
            let map = HashMap::from([("u".to_string(), pool(&[9001, 9002], Balance::Consistent))]);
            let (r, _) = resolve_all(&map).expect("resolves");
            keys.iter()
                .map(|k| r["u"].select(k.as_bytes()).expect("backend").addr.clone())
                .collect::<Vec<_>>()
        };

        let moved = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        // Losing one of three backends should move roughly a third of the keys.
        // Anything near all of them means the hash ring is not doing its job.
        assert!(
            moved < keys.len() / 2,
            "{moved} of {} keys moved; a reshuffle, not a consistent hash",
            keys.len()
        );
    }

    #[test]
    fn round_robin_does_not_pin_a_key() {
        // The contrast: the same key spreads across the pool.
        let map = HashMap::from([("u".to_string(), pool(&[9001, 9002], Balance::RoundRobin))]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let seen: std::collections::HashSet<String> = (0..20)
            .filter_map(|_| resolved["u"].select(b"/same/key").map(|t| t.addr.clone()))
            .collect();
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn a_pool_member_that_cannot_be_resolved_is_fatal() {
        // Starting with a smaller pool than was configured would hide an
        // outage behind traffic that still looks healthy.
        let cfg = UpstreamConfig {
            targets: vec![
                UpstreamTargetConfig {
                    url: "http://127.0.0.1:9001".into(),
                    weight: 1,
                },
                UpstreamTargetConfig {
                    url: "http://no-such-host.invalid:9002".into(),
                    weight: 1,
                },
            ],
            balance: Balance::RoundRobin,
            hash_on: crate::config::HashKey::default(),
            health_check: None,
            circuit_breaker: None,
        };
        let map = HashMap::from([("orders".to_string(), cfg)]);
        assert!(resolve_all(&map).is_err());
    }

    #[test]
    fn a_health_check_alone_makes_a_single_target_a_pool() {
        // Health state has to live somewhere, and that somewhere is the
        // balancer — so asking for checks opts into pool behaviour.
        let mut cfg = single("http://127.0.0.1:9001");
        cfg.health_check = Some(crate::config::HealthCheckConfig {
            path: Some("/health".into()),
            interval: std::time::Duration::from_secs(10),
            timeout: std::time::Duration::from_secs(2),
            healthy_after: 1,
            unhealthy_after: 2,
        });
        assert!(cfg.is_pool());
        let map = HashMap::from([("u".to_string(), cfg)]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        assert!(resolved["u"].balancer().is_some());
    }
}
