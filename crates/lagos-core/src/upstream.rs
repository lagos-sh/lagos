//! Resolved upstream targets, and pools of them.
//!
//! A single-target upstream keeps its hostname and is dialled directly, so DNS
//! is resolved per connection and a record change is picked up without a
//! restart. A pool is handed to Pingora's load balancer, which works on
//! addresses: every address a target name resolves to becomes a member, and
//! the member remembers which target it came from so the authority, TLS
//! settings and health check still follow the configured name. Members are
//! resolved once at startup, or refreshed in the background with `discovery`.
//! That difference is the reason pools are opt-in rather than the default
//! shape.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::health_check::{HealthCheck, HttpHealthCheck};
use pingora::lb::selection::{BackendIter, BackendSelection, Consistent, Random, RoundRobin};
use pingora::lb::{Backend, Backends, LoadBalancer};

use crate::config::{Balance, DEFAULT_MAX_MEMBERS, HealthCheckConfig, UpstreamConfig};
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
        /// The configured targets, indexed by each member's [`TargetIndex`],
        /// since a [`Backend`] carries only an address and the authority and
        /// TLS settings still have to be recovered.
        targets: Vec<UpstreamTarget>,
    },
}

/// Which configured target a pool member was resolved from, carried in the
/// member's [`Backend::ext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetIndex(usize);

/// The backend chosen for one request.
#[derive(Debug, Clone, Copy)]
pub struct Selected<'a> {
    /// The configured target: authority, TLS settings and mount prefix.
    pub target: &'a UpstreamTarget,
    /// For a pool member, the address the balancer chose. Dial exactly this:
    /// resolving `target.addr` again could land on a different member, or on
    /// one the health checks have taken out of rotation.
    pub addr: Option<SocketAddr>,
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
    pub fn select(&self, key: &[u8]) -> Option<Selected<'_>> {
        match &self.kind {
            Kind::Single(target) => Some(Selected { target, addr: None }),
            Kind::Pool { balancer, targets } => {
                let backend = balancer.select(key)?;
                let TargetIndex(index) = *backend.ext.get::<TargetIndex>()?;
                Some(Selected {
                    target: targets.get(index)?,
                    addr: backend.addr.as_inet().copied(),
                })
            }
        }
    }

    /// Every target, for `validate` and `routes` output.
    pub fn targets(&self) -> Vec<&UpstreamTarget> {
        match &self.kind {
            Kind::Single(t) => vec![t],
            Kind::Pool { targets, .. } => targets.iter().collect(),
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

/// Build Pingora's HTTP checker with this target's authority and TLS settings.
fn http_health_check(
    cfg: &HealthCheckConfig,
    target: &UpstreamTarget,
    path: &str,
) -> pingora::Result<HttpHealthCheck> {
    let mut check = HttpHealthCheck::new(&target.sni, target.tls);
    check.req.insert_header("Host", target.addr.as_str())?;
    check.consecutive_success = cfg.healthy_after;
    check.consecutive_failure = cfg.unhealthy_after;
    check.peer_template.options.connection_timeout = Some(cfg.timeout);
    check.peer_template.options.read_timeout = Some(cfg.timeout);
    check.peer_template.options.write_timeout = Some(cfg.timeout);
    let req = pingora::http::RequestHeader::build("GET", path.as_bytes(), None)?;
    check.req.set_uri(req.uri.clone());
    Ok(check)
}

/// Dispatch to Pingora's HTTP checker using the selected backend's authority
/// and TLS settings. Pingora replaces only the address in its peer template.
struct PoolHttpHealthCheck {
    /// One per configured target, indexed by [`TargetIndex`].
    checks: Vec<HttpHealthCheck>,
    healthy_after: usize,
    unhealthy_after: usize,
}

#[async_trait::async_trait]
impl HealthCheck for PoolHttpHealthCheck {
    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let check = target
            .ext
            .get::<TargetIndex>()
            .and_then(|TargetIndex(index)| self.checks.get(*index));
        let check = check.ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "health check has no matching upstream target",
            )
        })?;
        check.check(target).await
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.healthy_after
        } else {
            self.unhealthy_after
        }
    }
}

/// A health checker that must be registered with the server for a pool's
/// health state to be maintained.
pub type HealthService = Box<dyn pingora::services::ServiceWithDependents>;

/// Drive a future that is known not to await anything.
///
/// [`Backends::update`] is async because discovery *can* be — but a static set
/// of backends resolves immediately, as does the first call to
/// [`DnsDiscovery`], which hands back the set resolved at startup. This runs
/// before there is a runtime to block on. `Pending` would mean the assumption is wrong,
/// so it is reported rather than ignored.
fn poll_once<F: std::future::Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

/// One target's DNS answer.
struct Answer {
    index: usize,
    weight: usize,
    addrs: Vec<SocketAddr>,
}

/// Build a pool's member set from resolved answers, refusing anything that
/// would make selection ambiguous or unbounded.
///
/// `owners` is the address-to-target map of the set currently in service, if
/// any. Pingora compares members by address and weight only, so an address that
/// moved to a different target would keep the old target's authority and TLS
/// settings; such an answer is refused rather than applied half-way.
fn member_set(
    targets: &[UpstreamTarget],
    answers: &[Answer],
    max_members: usize,
    owners: Option<&HashMap<SocketAddr, usize>>,
) -> Result<(BTreeSet<Backend>, HashMap<SocketAddr, usize>), String> {
    let mut members = BTreeSet::new();
    let mut owner = HashMap::new();
    for answer in answers {
        let name = targets.get(answer.index).map_or("?", |t| t.addr.as_str());
        if answer.addrs.is_empty() {
            return Err(format!("`{name}` resolved to no addresses"));
        }
        for addr in &answer.addrs {
            match owner.insert(*addr, answer.index) {
                // The same name listed an address twice.
                Some(previous) if previous == answer.index => continue,
                Some(_) => {
                    return Err(format!(
                        "multiple targets resolve to backend `{addr}`; \
                         each pool member must have a distinct address and port"
                    ));
                }
                None => {}
            }
            if owners
                .and_then(|o| o.get(addr))
                .is_some_and(|previous| *previous != answer.index)
            {
                return Err(format!(
                    "backend `{addr}` moved from one target to another; \
                     restart to apply a change of target ownership"
                ));
            }
            let mut ext = http::Extensions::new();
            ext.insert(TargetIndex(answer.index));
            members.insert(Backend {
                addr: pingora::protocols::l4::socket::SocketAddr::Inet(*addr),
                weight: answer.weight,
                ext,
            });
        }
    }
    if members.len() > max_members {
        return Err(format!(
            "resolved {} members, more than the limit of {max_members}",
            members.len()
        ));
    }
    Ok((members, owner))
}

/// How [`DnsDiscovery`] resolves a name; replaceable in tests.
type Lookup = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

fn system_lookup() -> Lookup {
    Arc::new(|addr| Box::pin(async move { Ok(tokio::net::lookup_host(addr).await?.collect()) }))
}

/// Longest a single target's lookup may take during a refresh.
const DISCOVERY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Periodic re-resolution of a pool's target names.
///
/// Runs inside the balancer's background service, never on the request path.
/// Returning an error leaves Pingora's current member set in place, which is
/// what every refused refresh relies on.
struct DnsDiscovery {
    upstream: String,
    targets: Vec<UpstreamTarget>,
    weights: Vec<usize>,
    max_members: usize,
    lookup_timeout: Duration,
    lookup: Lookup,
    /// The startup set, handed out by the first call so the balancer can be
    /// primed synchronously.
    primed: Mutex<Option<BTreeSet<Backend>>>,
    /// Address owners of the set in service.
    owners: Mutex<HashMap<SocketAddr, usize>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // Nothing here can leave the data half-updated, so a panic elsewhere is no
    // reason to stop refreshing.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl DnsDiscovery {
    fn refused(&self, outcome: &str, reason: String) -> Box<pingora::Error> {
        tracing::warn!(
            event = "gateway.upstream.discovery",
            upstream = %self.upstream,
            outcome,
            reason = %reason,
            "pool refresh discarded; keeping the current members",
        );
        if let Some(m) = crate::metrics::metrics() {
            m.record_discovery(&self.upstream, outcome);
        }
        pingora::Error::explain(pingora::ErrorType::InternalError, reason)
    }
}

#[async_trait::async_trait]
impl ServiceDiscovery for DnsDiscovery {
    async fn discover(&self) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        if let Some(first) = locked(&self.primed).take() {
            return Ok((first, HashMap::new()));
        }

        let mut answers = Vec::with_capacity(self.targets.len());
        for (index, target) in self.targets.iter().enumerate() {
            let lookup = (self.lookup)(target.addr.clone());
            let addrs = match tokio::time::timeout(self.lookup_timeout, lookup).await {
                Ok(Ok(addrs)) => addrs,
                Ok(Err(e)) => {
                    return Err(
                        self.refused("failed", format!("cannot resolve `{}`: {e}", target.addr))
                    );
                }
                Err(_) => {
                    return Err(self.refused(
                        "failed",
                        format!(
                            "`{}` did not resolve within {:?}",
                            target.addr, self.lookup_timeout
                        ),
                    ));
                }
            };
            answers.push(Answer {
                index,
                weight: self.weights.get(index).copied().unwrap_or(1),
                addrs,
            });
        }

        let current = locked(&self.owners).clone();
        let (members, owners) =
            member_set(&self.targets, &answers, self.max_members, Some(&current))
                .map_err(|reason| self.refused("rejected", reason))?;
        let changed = owners != current;
        *locked(&self.owners) = owners;
        if changed {
            tracing::info!(
                event = "gateway.upstream.discovery",
                upstream = %self.upstream,
                members = members.len(),
                "pool membership changed",
            );
        }
        if let Some(m) = crate::metrics::metrics() {
            m.record_discovery(
                &self.upstream,
                if changed { "updated" } else { "unchanged" },
            );
        }
        Ok((members, HashMap::new()))
    }
}

/// Resolve every target now, on the calling thread. Startup only: there is no
/// runtime yet and no traffic to hold up.
fn resolve_at_startup(
    name: &str,
    cfg: &UpstreamConfig,
    targets: &[UpstreamTarget],
) -> anyhow::Result<Vec<Answer>> {
    use std::net::ToSocketAddrs;
    targets
        .iter()
        .zip(&cfg.targets)
        .enumerate()
        .map(|(index, (target, configured))| {
            // A pool member that cannot be resolved at startup is fatal on
            // purpose: silently starting with a smaller pool than was written
            // down hides a real outage behind apparently healthy traffic.
            let addrs: Vec<SocketAddr> = target
                .addr
                .to_socket_addrs()
                .map_err(|e| {
                    anyhow::anyhow!("upstream `{name}`: cannot resolve `{}`: {e}", target.addr)
                })?
                .collect();
            if cfg.health_check.is_none()
                && addrs.iter().any(SocketAddr::is_ipv4)
                && addrs.iter().any(SocketAddr::is_ipv6)
            {
                tracing::warn!(
                    event = "gateway.upstream.dual_stack",
                    upstream = %name,
                    target = %target.addr,
                    "pool target resolves to IPv4 and IPv6 addresses and has no health check; \
                     members of an unreachable address family will fail requests",
                );
            }
            Ok(Answer {
                index,
                weight: configured.weight,
                addrs,
            })
        })
        .collect()
}

fn build_pool(name: &str, cfg: &UpstreamConfig) -> anyhow::Result<(Kind, Option<HealthService>)> {
    let targets = cfg
        .targets
        .iter()
        .map(|t| UpstreamTarget::parse(&t.url))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let max_members = cfg
        .discovery
        .as_ref()
        .map_or(DEFAULT_MAX_MEMBERS, |d| d.max_members);
    let answers = resolve_at_startup(name, cfg, &targets)?;
    let (backends, owners) = member_set(&targets, &answers, max_members, None)
        .map_err(|e| anyhow::anyhow!("upstream `{name}`: {e}"))?;

    let mut discovered = match &cfg.discovery {
        Some(d) => Backends::new(Box::new(DnsDiscovery {
            upstream: name.to_string(),
            targets: targets.clone(),
            weights: cfg.targets.iter().map(|t| t.weight).collect(),
            max_members,
            lookup_timeout: d.interval.min(DISCOVERY_LOOKUP_TIMEOUT),
            lookup: system_lookup(),
            primed: Mutex::new(Some(backends)),
            owners: Mutex::new(owners),
        })),
        None => Backends::new(pingora::lb::discovery::Static::new(backends)),
    };
    if let Some(hc) = &cfg.health_check {
        match &hc.path {
            Some(path) => {
                let checks = targets
                    .iter()
                    .map(|target| {
                        http_health_check(hc, target, path).map_err(|e| {
                            anyhow::anyhow!("upstream `{name}`: invalid HTTP health check: {e}")
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                discovered.set_health_check(Box::new(PoolHttpHealthCheck {
                    checks,
                    healthy_after: hc.healthy_after,
                    unhealthy_after: hc.unhealthy_after,
                }));
            }
            None => {
                let mut check = pingora::lb::health_check::TcpHealthCheck::new();
                check.consecutive_success = hc.healthy_after;
                check.consecutive_failure = hc.unhealthy_after;
                check.peer_template.options.connection_timeout = Some(hc.timeout);
                discovered.set_health_check(check);
            }
        }
    }

    let balancer = match cfg.balance {
        Balance::RoundRobin => start_balancer(name, discovered, cfg, Balancer::RoundRobin),
        Balance::Random => start_balancer(name, discovered, cfg, Balancer::Random),
        Balance::Consistent => start_balancer(name, discovered, cfg, Balancer::Consistent),
    };
    let (balancer, service) = balancer?;
    Ok((Kind::Pool { balancer, targets }, service))
}

/// Build and prime one balancer, plus the background service that keeps its
/// health state and membership current.
///
/// The balancer runs its own loop, and the server owns that loop.
/// `background_service` takes the balancer by value and hands back the `Arc`
/// the request path selects through, so the service has to be built even when
/// nothing is periodic -- it is simply not registered then.
fn start_balancer<S>(
    name: &str,
    discovered: Backends,
    cfg: &UpstreamConfig,
    wrap: fn(Arc<LoadBalancer<S>>) -> Balancer,
) -> anyhow::Result<(Balancer, Option<HealthService>)>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
{
    let mut lb = LoadBalancer::<S>::from_backends(discovered);
    lb.health_check_frequency = cfg.health_check.as_ref().map(|h| h.interval);
    lb.update_frequency = cfg.discovery.as_ref().map(|d| d.interval);
    let svc = pingora::services::background::background_service(&format!("health-{name}"), lb);
    let handle = svc.task();
    prime(name, &handle)?;
    let periodic = cfg.health_check.is_some() || cfg.discovery.is_some();
    Ok((
        wrap(handle),
        periodic.then(|| Box::new(svc) as HealthService),
    ))
}

/// Populate the balancer's selection state.
///
/// `from_backends` builds an empty selector; without this the pool would pick
/// nothing until the first health tick, and a pool with no health check would
/// never pick anything at all.
fn prime<S>(name: &str, lb: &LoadBalancer<S>) -> anyhow::Result<()>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
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
            discovery: None,
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
        assert_eq!(up.select(b"").unwrap().target.addr, "users-service:3000");
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
            discovery: None,
        };
        let map = HashMap::from([("orders".to_string(), cfg)]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let up = resolved.get("orders").expect("present");
        assert!(up.balancer().is_some());

        let seen: std::collections::HashSet<String> = (0..20)
            .filter_map(|_| up.select(b"").map(|s| s.target.addr.clone()))
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
            discovery: None,
        }
    }

    #[test]
    fn http_health_checks_preserve_each_targets_authority_and_tls_server_name() {
        let cfg = HealthCheckConfig {
            path: Some("/ready".into()),
            interval: std::time::Duration::from_secs(1),
            timeout: std::time::Duration::from_secs(1),
            healthy_after: 2,
            unhealthy_after: 3,
        };
        for (url, authority, sni) in [
            ("http://plain.example:8080", "plain.example:8080", ""),
            (
                "https://secure.example:8443",
                "secure.example:8443",
                "secure.example",
            ),
        ] {
            let target = UpstreamTarget::parse(url).unwrap();
            let check = http_health_check(&cfg, &target, "/ready").unwrap();
            assert_eq!(check.req.headers["host"], authority);
            assert_eq!(check.req.uri.path(), "/ready");
            assert_eq!(check.peer_template.is_tls(), target.tls);
            assert_eq!(check.peer_template.sni, sni);
        }
    }

    #[test]
    fn colliding_pool_targets_are_rejected_instead_of_overwriting_settings() {
        let mut cfg = pool(&[9001, 9001], Balance::RoundRobin);
        cfg.targets[1].url = "https://127.0.0.1:9001/other".into();
        let configured = HashMap::from([("u".to_string(), cfg)]);
        let error = match resolve_all(&configured) {
            Ok(_) => panic!("colliding HTTP and HTTPS targets must not share backend settings"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("upstream `u`"));
        assert!(error.to_string().contains("multiple targets resolve"));
    }

    #[test]
    fn consistent_hashing_sends_a_key_to_the_same_backend() {
        let map = HashMap::from([(
            "u".to_string(),
            pool(&[9001, 9002, 9003], Balance::Consistent),
        )]);
        let (resolved, _) = resolve_all(&map).expect("resolves");
        let up = &resolved["u"];

        let first = up
            .select(b"/products/42")
            .expect("a backend")
            .target
            .addr
            .clone();
        for _ in 0..50 {
            assert_eq!(
                up.select(b"/products/42").expect("a backend").target.addr,
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
                .map(|k| {
                    r["u"]
                        .select(k.as_bytes())
                        .expect("backend")
                        .target
                        .addr
                        .clone()
                })
                .collect::<Vec<_>>()
        };
        let after = {
            let map = HashMap::from([("u".to_string(), pool(&[9001, 9002], Balance::Consistent))]);
            let (r, _) = resolve_all(&map).expect("resolves");
            keys.iter()
                .map(|k| {
                    r["u"]
                        .select(k.as_bytes())
                        .expect("backend")
                        .target
                        .addr
                        .clone()
                })
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
            .filter_map(|_| {
                resolved["u"]
                    .select(b"/same/key")
                    .map(|s| s.target.addr.clone())
            })
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
            discovery: None,
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

    fn ip(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn named(urls: &[&str]) -> Vec<UpstreamTarget> {
        urls.iter()
            .map(|u| UpstreamTarget::parse(u).unwrap())
            .collect()
    }

    fn index_of(backend: &Backend) -> usize {
        backend.ext.get::<TargetIndex>().unwrap().0
    }

    #[test]
    fn a_hostname_pool_starts_and_dials_the_address_it_selected() {
        // Pingora's `Backend::new` parses socket addresses only, so a pool of
        // names (`http://orders-1:3000`) used to be refused at startup.
        let mut cfg = pool(&[9001, 9002], Balance::RoundRobin);
        cfg.targets[0].url = "http://localhost:9001".into();
        let map = HashMap::from([("orders".to_string(), cfg)]);
        let (resolved, _) = resolve_all(&map).expect("a hostname pool resolves");
        let up = &resolved["orders"];
        let mut saw_name = false;
        for _ in 0..8 {
            let s = up.select(b"").expect("a backend");
            let addr = s.addr.expect("a pool member carries its address");
            assert_eq!(
                addr.port(),
                s.target
                    .addr
                    .rsplit(':')
                    .next()
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
            );
            if s.target.addr == "localhost:9001" {
                saw_name = true;
                assert!(addr.ip().is_loopback());
                assert_eq!(
                    s.target.sni, "localhost",
                    "the name, not the address, is the authority"
                );
            }
        }
        assert!(saw_name);
    }

    #[test]
    fn a_single_target_selection_leaves_resolution_to_the_dialer() {
        let map = HashMap::from([("u".to_string(), single("http://users-service:3000"))]);
        let (resolved, _) = resolve_all(&map).unwrap();
        assert!(resolved["u"].select(b"").unwrap().addr.is_none());
    }

    #[test]
    fn every_address_of_a_name_is_a_member_carrying_its_target() {
        let targets = named(&["https://api.example.test:8443", "http://10.0.0.9:80"]);
        let answers = [
            Answer {
                index: 0,
                weight: 3,
                addrs: vec![
                    ip("10.0.0.1:8443"),
                    ip("10.0.0.2:8443"),
                    ip("10.0.0.1:8443"),
                ],
            },
            Answer {
                index: 1,
                weight: 1,
                addrs: vec![ip("10.0.0.9:80")],
            },
        ];
        let (members, owners) = member_set(&targets, &answers, 8, None).unwrap();
        assert_eq!(
            members.len(),
            3,
            "a name repeating an address is one member"
        );
        for b in &members {
            let expected = if b.addr.as_inet().unwrap().port() == 8443 {
                (0, 3)
            } else {
                (1, 1)
            };
            assert_eq!((index_of(b), b.weight), expected);
        }
        assert_eq!(owners.len(), 3);
    }

    #[test]
    fn ambiguous_or_unbounded_member_sets_are_refused() {
        let targets = named(&["http://a.test:80", "http://b.test:80"]);
        let answer = |index, addrs: &[&str]| Answer {
            index,
            weight: 1,
            addrs: addrs.iter().map(|a| ip(a)).collect(),
        };
        let shared = [answer(0, &["10.0.0.1:80"]), answer(1, &["10.0.0.1:80"])];
        assert!(
            member_set(&targets, &shared, 8, None)
                .unwrap_err()
                .contains("multiple targets resolve")
        );

        let empty = [answer(0, &["10.0.0.1:80"]), answer(1, &[])];
        assert!(
            member_set(&targets, &empty, 8, None)
                .unwrap_err()
                .contains("no addresses")
        );

        let many = [
            answer(0, &["10.0.0.1:80", "10.0.0.2:80"]),
            answer(1, &["10.0.0.3:80"]),
        ];
        assert!(
            member_set(&targets, &many, 2, None)
                .unwrap_err()
                .contains("limit of 2")
        );

        let moved = [answer(0, &["10.0.0.1:80"]), answer(1, &["10.0.0.2:80"])];
        let owners = HashMap::from([(ip("10.0.0.2:80"), 0)]);
        assert!(
            member_set(&targets, &moved, 8, Some(&owners))
                .unwrap_err()
                .contains("moved")
        );
    }

    type Script = Arc<Mutex<Vec<std::io::Result<Vec<SocketAddr>>>>>;

    /// A discovery whose lookups answer from `script`, front first, then hang.
    fn scripted(targets: Vec<UpstreamTarget>, initial: &[&str], script: Script) -> DnsDiscovery {
        let answers = [Answer {
            index: 0,
            weight: 1,
            addrs: initial.iter().map(|a| ip(a)).collect(),
        }];
        let (members, owners) = member_set(&targets, &answers, 4, None).unwrap();
        DnsDiscovery {
            upstream: "u".into(),
            weights: vec![1; targets.len()],
            targets,
            max_members: 4,
            lookup_timeout: Duration::from_millis(50),
            lookup: Arc::new(move |_| {
                let next = {
                    let mut script = locked(&script);
                    (!script.is_empty()).then(|| script.remove(0))
                };
                Box::pin(async move {
                    match next {
                        Some(answer) => answer,
                        None => std::future::pending().await,
                    }
                })
            }),
            primed: Mutex::new(Some(members)),
            owners: Mutex::new(owners),
        }
    }

    fn addrs(lb: &LoadBalancer<RoundRobin>) -> BTreeSet<SocketAddr> {
        lb.backends()
            .get_backend()
            .iter()
            .map(|b| *b.addr.as_inet().unwrap())
            .collect()
    }

    #[test]
    fn discovery_replaces_members_and_keeps_the_last_good_set_on_failure() {
        let script: Script = Arc::new(Mutex::new(vec![
            Ok(vec![ip("10.0.0.2:80"), ip("10.0.0.3:80")]),
            Err(std::io::Error::other("resolver down")),
            Ok(Vec::new()),
            Ok((1..=5).map(|i| ip(&format!("10.0.1.{i}:80"))).collect()),
            // then: no answer at all, so the lookup times out
        ]));
        let discovery = scripted(named(&["http://pods.test:80"]), &["10.0.0.1:80"], script);
        let lb = LoadBalancer::<RoundRobin>::from_backends(Backends::new(Box::new(discovery)));
        prime("u", &lb).expect("the startup set primes synchronously");
        assert_eq!(addrs(&lb), BTreeSet::from([ip("10.0.0.1:80")]));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            lb.update().await.expect("a good answer applies");
            let current = BTreeSet::from([ip("10.0.0.2:80"), ip("10.0.0.3:80")]);
            assert_eq!(addrs(&lb), current);
            let chosen = lb.select(b"", 256).unwrap();
            assert_eq!(index_of(&chosen), 0, "new members still know their target");

            for case in [
                "lookup error",
                "empty answer",
                "over max_members",
                "timeout",
            ] {
                assert!(lb.update().await.is_err(), "{case} must be refused");
                assert_eq!(addrs(&lb), current, "{case} must keep the last good set");
            }
        });
    }

    #[test]
    fn discovery_registers_a_background_service_even_without_health_checks() {
        let mut cfg = pool(&[9001, 9002], Balance::Random);
        cfg.discovery = Some(crate::config::DiscoveryConfig {
            interval: Duration::from_secs(30),
            max_members: 4,
        });
        let map = HashMap::from([("u".to_string(), cfg)]);
        let (resolved, services) = resolve_all(&map).unwrap();
        assert_eq!(services.len(), 1, "something has to run the refresh");
        assert!(resolved["u"].select(b"").is_some());

        let mut static_pool =
            HashMap::from([("u".to_string(), pool(&[9001, 9002], Balance::Random))]);
        assert!(resolve_all(&static_pool).unwrap().1.is_empty());

        let mut tiny = pool(&[9001, 9002, 9003], Balance::Random);
        tiny.discovery = Some(crate::config::DiscoveryConfig {
            interval: Duration::from_secs(30),
            max_members: 2,
        });
        static_pool.insert("u".into(), tiny);
        let Err(err) = resolve_all(&static_pool) else {
            panic!("startup honours max_members")
        };
        assert!(err.to_string().contains("limit of 2"));
    }
}
