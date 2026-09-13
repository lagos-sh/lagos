//! The Pingora `ProxyHttp` implementation.
//!
//! Request lifecycle:
//!
//! 1. `request_filter` makes every decision — health, credential rejection,
//!    path canonicalization, deny-list, allowlist, authentication, header
//!    policy, extensions — and either answers the client or records a plan.
//! 2. `upstream_peer` turns the matched route into a dialable peer.
//! 3. `upstream_request_filter` rewrites the URI and applies the header plan.
//!
//! Nothing downstream of step 1 may make an authorization decision, so there is
//! exactly one place to audit.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::auth::TokenVerifier;
use crate::binding::Binding;
use crate::config::{ForwardMode, ResolvedConfig};
use crate::error::Rejection;
use crate::ext::{ExtensionContext, ExtensionRegistry};
use crate::headers::{
    HOP_BY_HOP, HeaderPlan, add_body_chunk, content_length_over_limit, forwarded_for,
    is_upload_content_type,
};
use crate::path::{canonicalize_proxy_path, encode_path_segments};
use crate::routes::{AuthTier, RouteTable, SharedRoutes};
use crate::upstream::{Upstream, UpstreamTarget};
use subtle::ConstantTimeEq;

pub struct Gateway {
    cfg: Arc<ResolvedConfig>,
    routes: SharedRoutes,
    upstreams: HashMap<String, Arc<Upstream>>,
    verifier: Option<Arc<dyn TokenVerifier>>,
    extensions: ExtensionRegistry,
    /// Mount prefixes, normalized and longest-first.
    base_paths: Vec<String>,
    /// Which tier this listener serves. A gateway instance serves exactly one
    /// side of the public/machine split, so the two cannot bleed together.
    serves_machine: bool,
    /// Lower-cased set of client headers allowed upstream in allowlist mode.
    forwardable: std::collections::HashSet<String>,
    /// Narrate each request instead of emitting one structured log line.
    /// Set by `gateway dev`; never on in production.
    dev: bool,
    /// Fraction of new traces to sample, when tracing is enabled.
    sample_ratio: Option<f64>,
    /// The shared response cache, when one is configured.
    #[cfg(feature = "cache")]
    cache: Option<&'static crate::cache::Cache>,
}

/// Headers required for the request to remain well-formed. Removing these would
/// break body framing or content negotiation, so they bypass the allowlist.
const STRUCTURAL_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "expect",
    "range",
];

/// Whether a new trace should be sampled.
///
/// A request that already carries a sampling decision keeps it; this only
/// applies to traces the gateway starts itself.
fn sample(ratio: f64) -> bool {
    if ratio >= 1.0 {
        return true;
    }
    if ratio <= 0.0 {
        return false;
    }
    // Drawn from the OS CSPRNG via uuid v4. Comparing the low 32 bits avoids
    // converting a 128-bit value to a float.
    let bucket = (uuid::Uuid::new_v4().as_u128() & 0xffff_ffff) as u32;
    f64::from(bucket) / f64::from(u32::MAX) < ratio
}

/// Per-request state carried between the filters.
#[derive(Default)]
pub struct Ctx {
    pub request_id: String,
    pub method: String,
    /// Canonical, decoded sub-path used for every authorization decision.
    pub path: String,
    pub query: Option<String>,
    pub route_id: String,
    pub upstream_name: String,
    pub plan: HeaderPlan,
    pub sse: bool,
    pub timeout: Duration,
    pub started: Option<Instant>,
    pub status: u16,
    /// Bytes of the request body seen so far. Used to enforce `limits.max_body`
    /// on chunked uploads that do not declare Content-Length.
    pub body_bytes: u64,

    // --- `gateway dev` narration ----------------------------------------
    // Populated only in dev mode. In production these stay empty and the
    // access log is the structured JSON line it has always been.
    /// Mount prefix that matched, before stripping.
    pub mount: String,
    /// Tier of the matched route, once one is found.
    pub tier: Option<AuthTier>,
    /// Subject of the verified caller, if the route read a token.
    pub subject: Option<String>,
    /// Extensions that ran, in order.
    pub extensions_run: Vec<String>,
    /// Why the request was refused: (event, reason).
    pub rejection: Option<(&'static str, String)>,
    /// The binding that refused the request, if one did.
    pub failed_binding: Option<String>,
    /// Bindings the caller satisfied.
    pub bindings_met: Vec<String>,
    /// Remaining and total quota, for `gateway dev`.
    pub rate_limit: Option<(u64, u64)>,
    /// Seconds to put in `Retry-After` on a 429.
    pub retry_after: Option<u64>,
    /// Cross-origin headers this response must carry.
    pub cors: Option<crate::cors::Headers>,
    /// Whether the matched route may be served from cache.
    pub cacheable_route: bool,
    /// The exact route snapshot that authorized this request.
    pub cache_namespace: uuid::Uuid,
    /// Whether the *client* sent an Authorization header.
    ///
    /// RFC 9111 forbids storing a response to an authorized request unless the
    /// response explicitly permits it. The gateway strips that header before
    /// proxying, so the fact has to be carried here or the rule cannot be
    /// applied.
    pub client_authorized: bool,
    /// Upstream whose circuit must be told how this request went.
    pub breaker_upstream: Option<String>,
    /// Circuit state when a request was shed, for `gateway dev`.
    pub circuit: Option<crate::breaker::State>,
    /// Retry rules for the matched route.
    pub retry: Option<crate::retry::Policy>,
    /// Retries already performed, not counting the first attempt.
    pub attempts: u32,
    /// This request's place in the distributed trace.
    pub trace: Option<crate::trace::TraceContext>,
    /// The backend chosen for this request. Selected once in `upstream_peer`
    /// and reused, so a pool cannot dial one member while addressing another.
    pub target: Option<UpstreamTarget>,
}

impl Gateway {
    pub fn new(
        cfg: Arc<ResolvedConfig>,
        routes: SharedRoutes,
        upstreams: HashMap<String, Arc<Upstream>>,
        verifier: Option<Arc<dyn TokenVerifier>>,
        extensions: ExtensionRegistry,
    ) -> Self {
        let dev = crate::telemetry::dev_mode();
        let sample_ratio = cfg
            .raw
            .observability
            .tracing
            .as_ref()
            .map(|t| t.sample_ratio);

        // Leaked on purpose: `pingora-cache` requires `&'static` storage, and
        // there is exactly one cache for the life of the process.
        #[cfg(feature = "cache")]
        let cache = cfg
            .raw
            .cache
            .as_ref()
            .map(|c| &*Box::leak(Box::new(crate::cache::Cache::new(c))));

        let base_paths = cfg.base_paths.clone();

        let mut forwardable: std::collections::HashSet<String> =
            STRUCTURAL_HEADERS.iter().map(|h| h.to_string()).collect();
        forwardable.extend(
            cfg.raw
                .forward
                .headers
                .iter()
                .map(|h| h.to_ascii_lowercase()),
        );
        if cfg.raw.forward.authorization {
            forwardable.insert("authorization".into());
        }
        // Anything the gateway sets itself is re-applied after the sweep; keep
        // it in the set so the removal pass does not fight the plan.
        forwardable.extend(cfg.injected_headers.iter().map(|(n, _)| n.clone()));
        forwardable.extend(cfg.machine_injected_headers.iter().map(|(n, _)| n.clone()));

        Self {
            cfg,
            routes,
            upstreams,
            verifier,
            extensions,
            base_paths,
            dev,
            sample_ratio,
            #[cfg(feature = "cache")]
            cache,
            serves_machine: false,
            forwardable,
        }
    }

    /// Serve only the `machine` tier. Used for the internal listener.
    pub fn for_machine_tier(mut self) -> Self {
        self.serves_machine = true;
        self
    }

    /// Strip a mount prefix, returning the raw (still encoded) remainder.
    /// `None` when the request is not under any of the gateway's mount points.
    fn strip_base<'a>(&self, request_path: &'a str) -> Option<&'a str> {
        let p = request_path.trim_start_matches('/');
        for base in &self.base_paths {
            if base.is_empty() {
                // Root mount: everything is in scope. Listed last by sort order.
                return Some(p);
            }
            if let Some(rest) = p.strip_prefix(base.as_str()) {
                // Must break on a segment boundary: `/bff/v1x` is not `/bff/v1`.
                match rest.chars().next() {
                    None => return Some(""),
                    Some('/') => return Some(&rest[1..]),
                    Some(_) => continue,
                }
            }
        }
        None
    }

    /// The mount that matched, for `gateway dev` narration only. `strip_base`
    /// deliberately returns just the remainder; this re-derives which prefix
    /// won so the trace can name it.
    fn matched_mount(&self, request_path: &str) -> &str {
        let p = request_path.trim_start_matches('/');
        self.base_paths
            .iter()
            .find(|base| {
                base.is_empty()
                    || p == base.as_str()
                    || p.strip_prefix(base.as_str())
                        .is_some_and(|r| r.starts_with('/'))
            })
            .map_or("", String::as_str)
    }

    /// One human-readable block per request, for `gateway dev`.
    ///
    /// The point is to answer "why did that happen" without reading the
    /// configuration: every step the request passed, the one that refused it,
    /// and where it ended up.
    fn narrate(&self, ctx: &Ctx, status: u16, latency_ms: u128, err: Option<&pingora::Error>) {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(256);
        let _ = writeln!(out, "\n\x1b[1m{} /{}\x1b[0m", ctx.method, ctx.path);

        let ok = "\x1b[32m✓\x1b[0m";
        let no = "\x1b[31m✗\x1b[0m";

        if !ctx.mount.is_empty() {
            let _ = writeln!(out, "  {ok} mount      /{}", ctx.mount);
        }

        if !ctx.route_id.is_empty() {
            let tier = ctx.tier.map(|t| t.group()).unwrap_or("");
            let _ = writeln!(out, "  {ok} route      {}  ({tier})", ctx.route_id);
        }

        match (&ctx.subject, ctx.tier) {
            (Some(sub), _) => {
                let _ = writeln!(out, "  {ok} identity   {sub}");
            }
            (None, Some(AuthTier::Optional)) => {
                let _ = writeln!(out, "  {ok} identity   anonymous (optional tier)");
            }
            _ => {}
        }

        if let Some((remaining, limit)) = ctx.rate_limit {
            let marker = if ctx.retry_after.is_some() { no } else { ok };
            let _ = writeln!(
                out,
                "  {marker} rate-limit {} / {limit} remaining",
                remaining
            );
        }

        for b in &ctx.bindings_met {
            let _ = writeln!(out, "  {ok} bind       {b}");
        }
        if let Some(b) = &ctx.failed_binding {
            let _ = writeln!(out, "  {no} bind       {b}");
        }

        for name in &ctx.extensions_run {
            let _ = writeln!(out, "  {ok} extension  {name}");
        }

        if let Some((event, reason)) = &ctx.rejection {
            let _ = writeln!(out, "  {no} refused    {reason}  [{event}]");
        } else if !ctx.upstream_name.is_empty() {
            let target = self
                .upstreams
                .get(&ctx.upstream_name)
                .and_then(|u| u.select(b"").map(|t| t.addr.clone()))
                .unwrap_or_else(|| "?".to_string());
            let _ = writeln!(
                out,
                "  → upstream   {} {target}{}",
                ctx.upstream_name,
                if ctx.sse { "  (sse)" } else { "" }
            );
        }

        if let Some(t) = &ctx.trace {
            let _ = writeln!(out, "  {ok} trace      {}", t.trace_id_hex());
        }

        if let Some(state) = ctx.circuit {
            let _ = writeln!(
                out,
                "  {no} circuit    {} for {}",
                state.as_str(),
                ctx.upstream_name
            );
        }

        if ctx.attempts > 0 {
            let _ = writeln!(out, "  {no} retried    {} time(s)", ctx.attempts);
        }

        if let Some(e) = err {
            let _ = writeln!(out, "  {no} upstream   {e}");
        }

        let colour = if status < 400 { "\x1b[32m" } else { "\x1b[31m" };
        let _ = write!(out, "  ← {colour}{status}\x1b[0m  {latency_ms}ms");
        println!("{out}");
    }

    /// Preflight headers, or `None` when this is not an allowable preflight.
    ///
    /// The browser's intended method comes from `Access-Control-Request-Method`;
    /// matching the route on `OPTIONS` would find nothing, since routes list the
    /// methods they actually serve.
    fn preflight_headers(
        &self,
        session: &Session,
        table: &RouteTable,
        ctx: &Ctx,
    ) -> Option<crate::cors::Headers> {
        let cors = self.cfg.cors.as_ref()?;
        let headers = &session.req_header().headers;
        let origin = headers.get("origin")?.to_str().ok()?;
        let requested = headers
            .get("access-control-request-method")?
            .to_str()
            .ok()?;

        // The gateway must not advertise a route it would not serve — including
        // when that route is restricted to another host.
        let host = headers.get("host").and_then(|v| v.to_str().ok());
        table.match_request(host, &ctx.path, requested)?;
        cors.preflight(origin, requested)
    }

    /// A preflight is answered with 204 and no body.
    async fn send_preflight(
        &self,
        session: &mut Session,
        headers: crate::cors::Headers,
    ) -> Result<()> {
        let mut resp = ResponseHeader::build(204, Some(headers.len() + 1))?;
        for (name, value) in &headers {
            resp.insert_header(*name, value.as_str())?;
        }
        resp.insert_header("content-length", "0")?;
        session.write_response_header(Box::new(resp), true).await?;
        Ok(())
    }

    /// The value a consistent-hash upstream balances on.
    ///
    /// Round robin and random ignore it, so it is only computed as configured —
    /// the request id would be a fresh value every request, which for a
    /// consistent hash is the one thing that must not happen.
    fn hash_key(&self, session: &Session, ctx: &Ctx) -> String {
        use crate::config::HashKey;

        let Some(hash_on) = self
            .cfg
            .upstreams
            .get(&ctx.upstream_name)
            .filter(|u| u.balance == crate::config::Balance::Consistent)
            .map(|u| &u.hash_on)
        else {
            // Nothing hashes on this; the value is discarded by the selector.
            return ctx.request_id.clone();
        };

        match hash_on {
            HashKey::Path => ctx.path.clone(),
            HashKey::Identity => ctx.subject.clone().unwrap_or_default(),
            HashKey::Ip => session
                .client_addr()
                .map(|a| a.to_string())
                .as_deref()
                .and_then(crate::headers::socket_peer_ip)
                .unwrap_or_default(),
            HashKey::Header(name) => session
                .req_header()
                .headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        }
    }

    /// The configured cooldown for an upstream, in whole seconds, for
    /// `Retry-After`.
    fn circuit_cooldown(&self, upstream: &str) -> u64 {
        self.cfg
            .upstreams
            .get(upstream)
            .and_then(|u| u.circuit_breaker.as_ref())
            .map_or(1, |cb| cb.cooldown.as_secs().max(1))
    }

    fn is_forwardable(&self, name: &str) -> bool {
        self.forwardable.contains(name)
    }

    /// Count one request against the route's limiter.
    ///
    /// `Ok(true)` means the client has been answered with a 429 and the filter
    /// must stop. Split out because the limiter is consulted twice: once before
    /// token verification for keys that do not need one, and once after for
    /// `identity`. Sharing the body is what keeps the two passes from drifting
    /// into two different notions of a quota.
    #[allow(clippy::too_many_arguments)]
    async fn check_rate_limit(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        cfg: &crate::config::RateLimitConfig,
        route: &crate::routes::RouteConfig,
        limiter: &crate::ratelimit::Limiter,
        subject: Option<&str>,
        peer_ip: Option<&str>,
    ) -> Result<bool> {
        let key = {
            let headers = &session.req_header().headers;
            crate::ratelimit::key_for(
                cfg,
                &route.id,
                subject,
                headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
                peer_ip,
                |name| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                },
            )
        };

        let Some(key) = key else {
            return Ok(false);
        };
        let decision = limiter.check(&key);
        if self.dev {
            ctx.rate_limit = Some((decision.remaining, decision.limit));
        }
        if decision.allowed {
            return Ok(false);
        }
        let retry = decision.retry_after.as_secs().max(1);
        ctx.retry_after = Some(retry);
        self.reject(session, ctx, Rejection::rate_limited(retry))
            .await
    }

    async fn send_with_retry_after(
        &self,
        session: &mut Session,
        status: u16,
        body: Vec<u8>,
        retry_after: Option<u64>,
        cors: Option<&crate::cors::Headers>,
    ) -> Result<()> {
        let mut resp = ResponseHeader::build(status, Some(6))?;
        resp.insert_header("content-type", "application/json")?;
        resp.insert_header("content-length", body.len().to_string())?;
        for (name, value) in cors.into_iter().flatten() {
            resp.insert_header(*name, value.as_str())?;
        }
        if let Some(secs) = retry_after {
            // Without this a throttled client has no idea when to return and
            // will usually retry immediately, which is what the limit exists
            // to prevent.
            resp.insert_header("retry-after", secs.to_string())?;
        }
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(())
    }

    async fn send(&self, session: &mut Session, status: u16, body: Vec<u8>) -> Result<()> {
        let mut resp = ResponseHeader::build(status, None)?;
        resp.insert_header("content-type", "application/json")?;
        resp.insert_header("content-length", body.len().to_string())?;
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(())
    }

    async fn reject(&self, session: &mut Session, ctx: &mut Ctx, rej: Rejection) -> Result<bool> {
        // In dev the refusal is narrated in full below; logging it here too
        // would interleave a second copy with the block it belongs to.
        if !self.dev {
            tracing::warn!(
                event = rej.event,
                reason = %rej.reason,
                status = rej.status,
                path = %ctx.path,
                request_id = %ctx.request_id,
                "request rejected",
            );
        }
        if let Some(m) = crate::metrics::metrics() {
            m.record_rejection(rej.event, &rej.reason);
        }
        ctx.status = rej.status;
        if self.dev {
            ctx.rejection = Some((rej.event, rej.reason.to_string()));
        }
        self.send_with_retry_after(
            session,
            rej.status,
            rej.body_bytes(),
            ctx.retry_after,
            ctx.cors.as_ref(),
        )
        .await?;
        Ok(true)
    }

    /// Core header policy, applied before extensions so an extension can
    /// override anything here deliberately rather than by accident.
    fn base_header_plan(&self, req: &RequestHeader, peer: Option<&str>) -> HeaderPlan {
        let mut plan = HeaderPlan::new();

        for h in HOP_BY_HOP {
            plan.strip(*h);
        }

        // Credentials the gateway owns. `set` also strips any client copy, so a
        // caller cannot smuggle its own value alongside ours.
        //
        // The internal listener injects its own set: an internal upstream
        // expects the higher-trust credential, and handing it the public one
        // would merge two tiers this platform keeps deliberately apart.
        let injected = if self.serves_machine {
            &self.cfg.machine_injected_headers
        } else {
            &self.cfg.injected_headers
        };
        for (name, value) in injected {
            plan.set(name, value.clone());
        }
        if self.serves_machine {
            // Whatever credential the caller presented has been verified; it
            // must not travel onward under a name the upstream also trusts.
            for name in ["x-api-key", "x-internal-api-key"] {
                if !injected.iter().any(|(n, _)| n == name) {
                    plan.strip(name);
                }
            }
        }

        let (xff, real_ip) =
            forwarded_for(&req.headers, peer, self.cfg.raw.forward.trusted_proxies);
        if let Some(v) = xff {
            plan.set("x-forwarded-for", v);
        }
        if let Some(v) = real_ip {
            plan.set("x-real-ip", v);
        }

        plan
    }
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    /// Bound what one downstream connection can hold before the request is even
    /// looked at.
    ///
    /// Every setting here is one Pingora already exposes on `ServerSession`;
    /// most are unset by default, which for an edge gateway means *unbounded*.
    /// A client that connects, sends a request a byte at a time, then reads the
    /// response a byte at a time, costs the attacker one socket and holds a
    /// worker task plus an upstream connection for as long as it likes. That is
    /// slowloris, and it needs no traffic volume to work.
    ///
    /// This runs before [`Self::request_filter`], so it applies to requests
    /// that are about to be refused as well as ones that are served — a refusal
    /// that can be made to hang is not a refusal.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let t = &self.cfg.raw.timeouts;
        // Reading the request: header trickled a byte at a time, or a body that
        // stops mid-upload. Pingora defaults to 60s; this is configurable and
        // shorter.
        session.set_read_timeout(Some(t.downstream_read));
        // Writing the response. Pingora leaves this unset, so without it a
        // client that stops reading pins the exchange forever.
        session.set_write_timeout(Some(t.downstream_write));
        // Discarding a body belonging to a request we are refusing. Also unset
        // by default, which makes rejecting a large upload cost more than
        // serving it.
        session.set_total_drain_timeout(Some(t.downstream_drain));
        session.set_keepalive(Some(t.downstream_keepalive.as_secs()));

        // A write timeout alone cannot express "slow but making progress": a
        // large response legitimately takes longer than a small one. Pingora
        // scales the timeout by how much is being written when a floor rate is
        // set. Off unless an operator asks for it, since a real client on a bad
        // link is not an attacker.
        if let Some(rate) = self.cfg.raw.limits.min_send_rate.filter(|r| *r > 0) {
            session.set_min_send_rate(Some(rate));
        }
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.started = Some(Instant::now());

        // Copy everything needed out of the borrowed request header up front,
        // so the rest of the filter can borrow the session mutably to respond.
        let (method, request_path, query, request_id, content_type, authorization) = {
            let req = session.req_header();
            (
                req.method.as_str().to_string(),
                req.uri.path().to_string(),
                req.uri.query().map(str::to_string),
                req.headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                req.headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
                req.headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            )
        };
        let origin_header = session
            .req_header()
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        ctx.request_id = request_id;
        ctx.client_authorized = session.req_header().headers.contains_key("authorization");

        // Resolved before any refusal can be issued, so *every* response to a
        // given origin carries the same cross-origin headers.
        //
        // This is load-bearing, not a convenience: a deny-listed path and an
        // unknown one both answer 404 precisely so the deny-list cannot be
        // enumerated. If one of those 404s carried `Access-Control-Allow-Origin`
        // and the other did not, a page could tell them apart and learn which
        // internal routes exist.
        if let (Some(cors), Some(origin)) = (&self.cfg.cors, &origin_header) {
            ctx.cors = cors.response(origin);
        }
        // Needed by metrics as well as dev narration, so it is always recorded.
        ctx.method = method.clone();
        ctx.query = query;

        if request_path == self.cfg.raw.server.health_path {
            ctx.status = 200;
            let body = serde_json::json!({
                "status": "ok",
                "service": self.cfg.raw.server.service_name,
                "routes": self.routes.load().len(),
            });
            self.send(session, 200, serde_json::to_vec(&body).unwrap_or_default())
                .await?;
            return Ok(true);
        }

        if content_length_over_limit(&session.req_header().headers, self.cfg.raw.limits.max_body) {
            return self
                .reject(session, ctx, Rejection::payload_too_large())
                .await;
        }

        // Credentials the gateway injects itself must never arrive from a
        // client; treating them as an error (not silently stringing them along)
        // makes a misconfigured caller loud instead of subtly over-privileged.
        //
        // Skipped on the internal listener: a machine caller's whole identity
        // *is* that header.
        for name in self
            .cfg
            .raw
            .reject
            .client_headers
            .iter()
            .filter(|_| !self.serves_machine)
        {
            let present = session
                .req_header()
                .headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| !v.is_empty());
            if present {
                let rej = Rejection::forbidden("Forbidden", format!("client_sent_{name}"));
                return self
                    .reject(
                        session,
                        ctx,
                        Rejection {
                            event: "gateway.credential.rejected",
                            ..rej
                        },
                    )
                    .await;
            }
        }

        if self.dev {
            ctx.mount = self.matched_mount(&request_path).to_string();
        }
        let Some(raw_sub) = self.strip_base(&request_path) else {
            return self
                .reject(
                    session,
                    ctx,
                    Rejection::not_found("gateway.route.denied", "outside_base_path"),
                )
                .await;
        };
        let Some(path) = canonicalize_proxy_path(raw_sub) else {
            return self
                .reject(
                    session,
                    ctx,
                    Rejection::not_found("gateway.route.denied", "unsafe_path"),
                )
                .await;
        };
        ctx.path = path;

        // Snapshot the table once: a concurrent reload must not change the
        // answer between the deny check and the allowlist match.
        let table = self.routes.load();

        if table.is_denied(&ctx.path) {
            return self
                .reject(
                    session,
                    ctx,
                    Rejection::not_found("gateway.route.denied", "deny_list"),
                )
                .await;
        }

        // --- CORS preflight --------------------------------------------------
        // Answered here, before authentication: a browser sends no credentials
        // on a preflight, so requiring a token would make every cross-origin
        // call to a protected route fail at the first hop. It is still after
        // the deny-list, so a preflight cannot confirm an internal path exists.
        if method == "OPTIONS"
            && let Some(headers) = self.preflight_headers(session, table.as_ref(), ctx)
        {
            ctx.status = 204;
            ctx.cors = Some(headers.clone());
            self.send_preflight(session, headers).await?;
            return Ok(true);
        }

        let host_header = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());

        let Some(route) = table.match_request(host_header, &ctx.path, &method) else {
            return self
                .reject(
                    session,
                    ctx,
                    Rejection::not_found("gateway.route.denied", "not_allowlisted"),
                )
                .await;
        };

        if !self.upstreams.contains_key(&route.upstream) {
            return self
                .reject(
                    session,
                    ctx,
                    Rejection::unavailable(
                        "Upstream not configured",
                        format!("no_upstream_{}", route.upstream),
                    ),
                )
                .await;
        }

        // --- authentication -------------------------------------------------
        // Three tiers. `Public` never reads a token, so a signed-in caller is
        // indistinguishable from an anonymous one. `Optional` reads it when
        // offered, which is what a catalog wants: browsable signed-out,
        // personalised signed-in.
        if route.auth == AuthTier::Machine {
            let Some(expected) = self.cfg.machine_secret.as_deref() else {
                return self
                    .reject(
                        session,
                        ctx,
                        Rejection::unavailable(
                            "Machine authentication is not configured",
                            "no_machine_secret",
                        ),
                    )
                    .await;
            };
            const DEFAULT_MACHINE_HEADERS: [&str; 2] = ["x-internal-api-key", "x-api-key"];
            let names: Vec<&str> = match self.cfg.raw.auth.machine.as_ref() {
                Some(m) => m.headers.iter().map(String::as_str).collect(),
                None => DEFAULT_MACHINE_HEADERS.to_vec(),
            };
            let presented = names
                .iter()
                .find_map(|n| session.req_header().headers.get(*n))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            // Constant time: a byte-by-byte comparison leaks the secret to a
            // caller willing to time enough requests.
            let ok: bool = presented.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1;
            if !ok {
                // 404, like every other refusal, so the internal surface is not
                // enumerable by anyone who reaches this listener.
                return self
                    .reject(
                        session,
                        ctx,
                        Rejection::not_found("gateway.machine.rejected", "bad_machine_credential"),
                    )
                    .await;
            }
        }

        let peer_ip_for_limit = session
            .client_addr()
            .map(|a| a.to_string())
            .as_deref()
            .and_then(crate::headers::socket_peer_ip);

        // --- rate limiting, part one: everything that does not need identity --
        //
        // Verifying a token is the most expensive thing on this path — a
        // public-key signature check per request — and it happens before the
        // caller has proved anything. Running the limiter afterwards would mean
        // an unauthenticated flood of well-formed, badly-signed tokens is never
        // throttled: each one is refused, but only after being paid for.
        //
        // A limit keyed on IP, header or route already knows its key here, so
        // it is applied now. `identity` keys genuinely cannot be, and are
        // checked after verification below.
        if let (Some(cfg), Some(limiter)) = (&route.rate_limit, &route.limiter)
            && !matches!(cfg.key, crate::config::RateLimitKey::Identity)
            && self
                .check_rate_limit(
                    session,
                    ctx,
                    cfg,
                    route,
                    limiter,
                    None,
                    peer_ip_for_limit.as_deref(),
                )
                .await?
        {
            return Ok(true);
        }

        let mut identity = None;
        if route.auth.verifies() {
            let bearer = authorization.as_deref().and_then(crate::auth::bearer_token);

            // Capped before anything reads it. Finding the issuer means
            // base64-decoding the payload and parsing it as JSON, and a
            // recognised issuer then costs a public-key signature check — all
            // of it on an unauthenticated request, all of it ahead of any limit
            // keyed on who the caller turns out to be.
            //
            // Refused outright rather than treated as absent: on an `Optional`
            // route "no token" means serve anonymously, and silently
            // downgrading an oversized token to that would hide the problem
            // from the client instead of reporting it.
            if bearer.is_some_and(|t| t.len() as u64 > self.cfg.raw.limits.max_token) {
                return self
                    .reject(session, ctx, Rejection::invalid_token("token_too_long"))
                    .await;
            }

            match (bearer, route.auth) {
                // Signed out on a route that permits it.
                (None, AuthTier::Optional) => {}
                (None, _) => {
                    return self.reject(session, ctx, Rejection::missing_bearer()).await;
                }
                (Some(token), _) => {
                    let Some(verifier) = self.verifier.as_ref() else {
                        return self
                            .reject(
                                session,
                                ctx,
                                Rejection::unavailable(
                                    "Authentication is not configured",
                                    "no_verifier",
                                ),
                            )
                            .await;
                    };

                    match verifier.verify(token).await {
                        Ok(id) => identity = Some(id),
                        Err(crate::auth::AuthError::UnknownIssuer(project)) => {
                            return self
                                .reject(
                                    session,
                                    ctx,
                                    Rejection::unavailable(
                                        "Token issuer is not configured on this gateway",
                                        format!("unknown_issuer_{project}"),
                                    ),
                                )
                                .await;
                        }
                        Err(crate::auth::AuthError::Unavailable(detail)) => {
                            return self
                                .reject(
                                    session,
                                    ctx,
                                    Rejection::unavailable("Unable to verify credentials", detail),
                                )
                                .await;
                        }
                        // Deliberately a 401 even on an Optional route: a stale
                        // token is a bug the client must see, not a reason to
                        // quietly serve anonymous content.
                        Err(crate::auth::AuthError::Invalid(detail)) => {
                            return self
                                .reject(session, ctx, Rejection::invalid_token(detail))
                                .await;
                        }
                    }
                }
            }
        }

        // --- rate limiting, part two: identity keys ---------------------------
        // These need a verified subject, so this is the earliest they can run.
        if let (Some(cfg), Some(limiter)) = (&route.rate_limit, &route.limiter)
            && matches!(cfg.key, crate::config::RateLimitKey::Identity)
            && self
                .check_rate_limit(
                    session,
                    ctx,
                    cfg,
                    route,
                    limiter,
                    identity.as_ref().map(|i| i.subject.as_str()),
                    peer_ip_for_limit.as_deref(),
                )
                .await?
        {
            return Ok(true);
        }

        // --- ownership bindings ---------------------------------------------
        // Before any header is built, so a route that binds a value can never
        // reach an upstream with identity attached unless the caller proved
        // they own what they asked for.
        if !route.bindings.is_empty() {
            let Some(id) = identity.as_ref() else {
                // A binding needs an identity to compare against. Reaching here
                // means the tier did not produce one, which validation refuses
                // at boot — so this is belt and braces, and it fails closed.
                return self
                    .reject(
                        session,
                        ctx,
                        Rejection::forbidden("Forbidden", "bind_without_identity"),
                    )
                    .await;
            };

            let headers = &session.req_header().headers;
            for binding in &route.bindings {
                let permitted = binding.permits(id, ctx.query.as_deref(), |name| {
                    let mut values = headers.get_all(name).iter();
                    let value = values.next()?.to_str().ok()?;
                    values.next().is_none().then_some(value)
                });
                if !permitted {
                    if self.dev {
                        ctx.failed_binding = Some(binding.describe());
                    }
                    // One answer for missing, mismatched and unprovable alike:
                    // distinguishing them would let a caller probe which
                    // identifiers exist.
                    return self
                        .reject(
                            session,
                            ctx,
                            Rejection::forbidden("Forbidden", "binding_refused"),
                        )
                        .await;
                }
            }
        }

        // --- header policy + extensions -------------------------------------
        let peer = session.client_addr().map(|a| a.to_string());
        let peer_ip = peer.as_deref().and_then(crate::headers::socket_peer_ip);
        let mut plan = self.base_header_plan(session.req_header(), peer_ip.as_deref());
        plan.set("x-request-id", ctx.request_id.clone());

        // Continue the caller's trace and name *this* hop as the upstream's
        // parent. Relaying `traceparent` untouched would hide the gateway from
        // the trace and charge its latency to the service behind it.
        if let Some(ratio) = self.sample_ratio {
            let incoming = session
                .req_header()
                .headers
                .get("traceparent")
                .and_then(|v| v.to_str().ok());
            let cx = crate::trace::TraceContext::continue_from(incoming, sample(ratio));
            plan.set("traceparent", cx.to_header());
            ctx.trace = Some(cx);
        }

        // Describe the caller to the upstream. On a public route this only
        // strips, so an unauthenticated request can never carry identity.
        match &identity {
            Some(id) => {
                if let Err(e) = crate::identity::apply(
                    &mut plan,
                    &self.cfg.raw.identity,
                    self.cfg.identity_secret.as_deref(),
                    id,
                ) {
                    // A token the gateway cannot describe to an upstream is a
                    // 401, not a 503: nothing here is broken, the credential
                    // just carries something that cannot be a header value.
                    // Answering 503 would tell the client to retry the one
                    // thing that can never succeed, and page an operator for it.
                    let rej = match &e {
                        crate::identity::IdentityError::Claim(_) => {
                            Rejection::invalid_token(format!("unrepresentable_identity: {e}"))
                        }
                        crate::identity::IdentityError::Mint(_) => Rejection::unavailable(
                            "Unable to sign caller identity",
                            format!("identity_mint_failed: {e}"),
                        ),
                    };
                    return self.reject(session, ctx, rej).await;
                }
            }
            None => crate::identity::strip_all(&mut plan, &self.cfg.raw.identity),
        }

        if !self.cfg.raw.forward.authorization {
            // Upstreams read identity from the injected headers; the original
            // credential has no reason to travel further.
            plan.strip("authorization");
        }

        for name in &route.extensions {
            let Some(ext) = self.extensions.get(name) else {
                // Startup validation should make this unreachable; failing
                // closed here means a missing policy hook can never be skipped.
                return self
                    .reject(
                        session,
                        ctx,
                        Rejection::unavailable(
                            "Gateway misconfigured",
                            format!("missing_extension_{name}"),
                        ),
                    )
                    .await;
            };
            let mut cx = ExtensionContext {
                path: &ctx.path,
                method: &method,
                query: ctx.query.as_deref(),
                route,
                identity: identity.as_ref(),
                client_headers: &session.req_header().headers,
                plan: &mut plan,
            };
            if let Err(rej) = ext.on_request(&mut cx).await {
                return self.reject(session, ctx, rej).await;
            }
        }

        ctx.plan = plan;
        // Consistent hashing uses the subject in production too.
        ctx.subject = identity.as_ref().map(|i| i.subject.clone());
        if self.dev {
            ctx.bindings_met = route.bindings.iter().map(Binding::describe).collect();
            ctx.tier = Some(route.auth);
            ctx.extensions_run = route.extensions.clone();
        }
        ctx.cacheable_route = route.cache;
        ctx.cache_namespace = table.cache_namespace();
        ctx.retry = route.retry_policy;
        ctx.route_id = route.id.clone();
        ctx.upstream_name = route.upstream.clone();
        ctx.sse = route.sse;
        if route.sse {
            // An event stream is a long-lived response by design. The write
            // timeout only fires on a *stalled* write, but a stream with sparse
            // events is close enough to that shape to be worth the wider budget
            // the operator already wrote down for SSE.
            session.set_write_timeout(Some(self.cfg.raw.timeouts.sse));
        }
        ctx.timeout = if route.sse {
            self.cfg.raw.timeouts.sse
        } else if is_upload_content_type(content_type.as_deref()) {
            self.cfg.raw.timeouts.upload
        } else {
            self.cfg.raw.timeouts.default
        };

        Ok(false)
    }

    /// Admit a circuit trial only after local policy and cache lookup have
    /// finished. A refusal or cache hit tells us nothing about upstream health.
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        if let Some(breaker) = self
            .upstreams
            .get(&ctx.upstream_name)
            .and_then(|u| u.breaker())
        {
            if !breaker.allow() {
                ctx.retry_after = Some(self.circuit_cooldown(&ctx.upstream_name));
                ctx.circuit = Some(breaker.state());
                self.reject(
                    session,
                    ctx,
                    Rejection::circuit_open(ctx.retry_after.unwrap_or(1)),
                )
                .await?;
                return Ok(false);
            }
            ctx.breaker_upstream = Some(ctx.upstream_name.clone());
        }
        Ok(true)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(chunk) = body {
            match add_body_chunk(ctx.body_bytes, chunk.len(), self.cfg.raw.limits.max_body) {
                Some(next) => ctx.body_bytes = next,
                None => {
                    return Err(pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(413),
                        "payload too large",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let upstream = self.upstreams.get(&ctx.upstream_name).ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::InternalError, "upstream vanished")
        })?;

        // Choose once, here, and remember it: `upstream_request_filter` sets
        // the Host header from the same backend, and a second selection could
        // name a different one.
        let key = self.hash_key(session, ctx);
        let target = upstream
            .select(key.as_bytes())
            .ok_or_else(|| {
                pingora::Error::explain(
                    pingora::ErrorType::ConnectError,
                    "every backend in the pool is unhealthy",
                )
                .into_up()
            })?
            .clone();

        // Resolved here rather than inside `HttpPeer::new`, which takes anything
        // `ToInetSocketAddrs` and unwraps it (pingora-core 0.9
        // `upstreams/peer.rs:719`, carrying pingora's own `//TODO: handle
        // error`). A name that stops resolving -- a DNS blip, a Service scaled
        // to zero, a typo in an upstream URL -- would otherwise panic the proxy
        // worker for every request instead of failing the one request. The
        // lookup itself is the same blocking call pingora was already making;
        // this moves it, it does not add one.
        let addr = resolve_peer_addr(&target.addr)?;
        let mut peer = HttpPeer::new(addr, target.tls, target.sni.clone());
        peer.options.connection_timeout = Some(self.cfg.raw.timeouts.connect);
        peer.options.total_connection_timeout = Some(self.cfg.raw.timeouts.connect * 2);
        peer.options.read_timeout = Some(ctx.timeout);
        peer.options.write_timeout = Some(ctx.timeout);
        peer.options.idle_timeout = Some(self.cfg.raw.timeouts.upstream_idle);
        ctx.target = Some(target);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let target = ctx.target.as_ref().ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::InternalError, "no backend was selected")
        })?;

        let mut uri = String::with_capacity(ctx.path.len() + 32);
        if !target.base_path.is_empty() {
            uri.push('/');
            uri.push_str(&target.base_path);
        }
        uri.push('/');
        uri.push_str(&encode_path_segments(&ctx.path));
        if let Some(q) = &ctx.query {
            uri.push('?');
            uri.push_str(q);
        }
        let parsed: http::Uri = uri.parse().map_err(|_| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "unbuildable upstream URI",
            )
        })?;
        upstream.set_uri(parsed);

        if !self.cfg.raw.forward.preserve_host {
            // Match what an HTTP client library would send. Preserving the
            // client's Host is opt-in because upstreams sometimes build URLs
            // from it.
            upstream.insert_header("host", target.addr.as_str())?;
        }

        if self.cfg.raw.forward.mode == ForwardMode::Allowlist {
            let doomed: Vec<String> = upstream
                .headers
                .keys()
                .map(|k| k.as_str().to_string())
                .filter(|name| !self.is_forwardable(name))
                .collect();
            for name in doomed {
                upstream.remove_header(name.as_str());
            }
        }

        for name in ctx.plan.removals() {
            upstream.remove_header(name.as_str());
        }
        for (name, value) in ctx.plan.additions() {
            upstream.insert_header(name.clone(), value.as_str())?;
        }
        Ok(())
    }

    /// No connection was established, so the request was never delivered —
    /// safe to send again regardless of method.
    ///
    /// Pingora calls [`Self::upstream_peer`] again on a retry, so a pooled
    /// upstream naturally lands on a different backend.
    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        let Some(policy) = ctx.retry else {
            return e;
        };
        let replayable = !session.as_ref().retry_buffer_truncated();

        if policy.should_retry(
            crate::retry::Failure::Connect,
            ctx.attempts,
            &ctx.method,
            replayable,
        ) {
            ctx.attempts = ctx.attempts.saturating_add(1);
            tracing::warn!(
                event = "gateway.upstream.retry",
                request_id = %ctx.request_id,
                route = %ctx.route_id,
                upstream = %ctx.upstream_name,
                attempt = ctx.attempts,
                failure = "connect",
                "retrying after a connect failure",
            );
            if let Some(m) = crate::metrics::metrics() {
                m.record_retry(&ctx.upstream_name);
            }
            e.set_retry(true);
        }
        e
    }

    /// The connection was established, so the upstream may already have acted
    /// on the request. Only idempotent methods are sent again.
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<pingora::Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<pingora::Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        // Pingora's own rule first: an error on a *reused* keepalive connection
        // usually means the server closed it before reading the request.
        let replayable = !session.as_ref().retry_buffer_truncated();
        e.retry.decide_reuse(client_reused && replayable);

        let Some(policy) = ctx.retry else {
            return e;
        };
        // Only ever narrow Pingora's decision, never widen it.
        if !e.retry() {
            return e;
        }

        if policy.should_retry(
            crate::retry::Failure::Transport,
            ctx.attempts,
            &ctx.method,
            replayable,
        ) {
            ctx.attempts = ctx.attempts.saturating_add(1);
            tracing::warn!(
                event = "gateway.upstream.retry",
                request_id = %ctx.request_id,
                route = %ctx.route_id,
                upstream = %ctx.upstream_name,
                attempt = ctx.attempts,
                failure = "transport",
                "retrying after a transport error",
            );
            if let Some(m) = crate::metrics::metrics() {
                m.record_retry(&ctx.upstream_name);
            }
        } else {
            e.set_retry(false);
        }
        e
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.status = upstream_response.status.as_u16();
        if let Some(headers) = &ctx.cors {
            for (name, value) in headers {
                if *name == "vary" {
                    // CORS adds another varying field; it must not erase the
                    // origin's language, encoding, or authorization variance.
                    upstream_response.append_header(*name, value.as_str())?;
                } else {
                    upstream_response.insert_header(*name, value.as_str())?;
                }
            }
        }
        if ctx.sse {
            // Intermediaries must not buffer an event stream.
            upstream_response.insert_header("cache-control", "no-cache")?;
            upstream_response.insert_header("x-accel-buffering", "no")?;
        }
        Ok(())
    }

    /// Turn an upstream failure into the same JSON envelope every other
    /// rejection uses.
    ///
    /// Pingora's default answers any upstream error with a bare 502 and an
    /// empty body, which collapses "upstream is down" and "upstream is too
    /// slow" into one code. Clients act on that difference: a 504 is worth
    /// retrying, a 502 usually is not.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy {
        use pingora::ErrorType::{ConnectTimedout, HTTPStatus, ReadTimedout, WriteTimedout};

        let rejection = match e.etype() {
            ConnectTimedout | ReadTimedout | WriteTimedout => Rejection::gateway_timeout(),
            HTTPStatus(413) => Rejection::payload_too_large(),
            _ => Rejection::new(
                502,
                serde_json::json!({
                    "statusCode": 502,
                    "message": "Bad Gateway",
                    "error": "Bad Gateway",
                }),
                "gateway.upstream.unreachable",
                e.etype().as_str(),
            ),
        };

        tracing::warn!(
            event = rejection.event,
            reason = %rejection.reason,
            status = rejection.status,
            route = %ctx.route_id,
            upstream = %ctx.upstream_name,
            path = %ctx.path,
            request_id = %ctx.request_id,
            "upstream failed",
        );
        ctx.status = rejection.status;

        if session.response_written().is_none() {
            let _ = self
                .send(session, rejection.status, rejection.body_bytes())
                .await;
        }

        pingora::proxy::FailToProxy {
            error_code: rejection.status,
            // The downstream connection saw a partial or failed exchange.
            can_reuse_downstream: false,
        }
    }

    /// Turn the cache on for routes that asked for it.
    ///
    /// Runs after `request_filter`, so the route has already been matched and
    /// authorized — a cached response is never served to a request that would
    /// otherwise have been refused.
    #[cfg(feature = "cache")]
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let (Some(cache), true) = (self.cache, ctx.cacheable_route) else {
            return Ok(());
        };
        if !matches!(
            session.req_header().method,
            http::Method::GET | http::Method::HEAD
        ) || ctx.sse
        {
            return Ok(());
        }
        session.cache.enable(
            cache.storage,
            Some(cache.eviction),
            None,
            Some(cache.lock),
            None,
        );
        session
            .cache
            .set_max_file_size_bytes(cache.max_object_bytes);
        Ok(())
    }

    /// Build the cache key.
    ///
    /// Mandatory once caching is on — the default implementation is a `todo!()`
    /// that panics the worker thread.
    ///
    /// The key is **host + method + path + query**, and the host matters: this
    /// gateway routes on it, so two tenants can share a path and serve
    /// different content. Leaving it out would let one tenant's response be
    /// served to another — the worst bug a cache can have.
    ///
    /// Route id, upstream and table generation are part of the primary key.
    /// `user_tag` is only an accounting label; Pingora does not hash it.
    #[cfg(feature = "cache")]
    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> Result<pingora::cache::CacheKey> {
        let req = session.req_header();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let uri = req
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or_else(|| req.uri.path());

        Ok(crate::cache::policy::key(
            &[
                &ctx.cache_namespace.to_string(),
                &ctx.route_id,
                &ctx.upstream_name,
                &host,
                req.method.as_str(),
                uri,
            ],
            &ctx.route_id,
        ))
    }

    #[cfg(feature = "cache")]
    fn cache_vary_filter(
        &self,
        meta: &pingora::cache::CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<pingora::cache::key::HashBinary> {
        crate::cache::policy::variance(meta.response_header(), req, &ctx.plan, |name| {
            self.cfg.raw.forward.mode == ForwardMode::Passthrough || self.is_forwardable(name)
        })
    }

    #[cfg(feature = "cache")]
    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        meta: &pingora::cache::CacheMeta,
        _hit_handler: &mut pingora::cache::storage::HitHandler,
        _is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<pingora::cache::ForcedFreshness>> {
        Ok(
            (!crate::cache::policy::eligible(meta.response_header(), ctx.client_authorized))
                .then_some(pingora::cache::ForcedFreshness::ForceMiss),
        )
    }

    /// Decide whether the upstream's response may be stored.
    ///
    /// The decision is `pingora-cache`'s RFC 9111 implementation, not ours —
    /// `no-store`, `private`, `max-age`, and the rule that a response to an
    /// authorized request is not stored unless it says otherwise. Reimplementing
    /// any of that is how a gateway ends up serving one customer's data to
    /// another.
    #[cfg(feature = "cache")]
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<pingora::cache::RespCacheable> {
        let Some(cache) = self.cache else {
            return Ok(pingora::cache::RespCacheable::Uncacheable(
                pingora::cache::NoCacheReason::Custom("cache not configured"),
            ));
        };
        if !crate::cache::policy::eligible(resp, ctx.client_authorized) {
            return Ok(pingora::cache::RespCacheable::Uncacheable(
                pingora::cache::NoCacheReason::Custom("response cannot be shared"),
            ));
        }
        let cc = pingora::cache::cache_control::CacheControl::from_resp_headers(resp);
        Ok(pingora::cache::filters::resp_cacheable(
            cc.as_ref(),
            resp.clone(),
            ctx.client_authorized,
            &cache.defaults,
        ))
    }

    /// Pingora logs every proxy failure itself, and [`Self::logging`] logs the
    /// same one with the request id, route, upstream and latency attached.
    /// Leaving both on doubles the log volume during an incident — exactly when
    /// volume hurts most — and the second line carries strictly less context.
    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        _error: &pingora::Error,
    ) -> bool {
        true
    }

    /// Same reasoning for retryable failures, which would otherwise log once
    /// per attempt.
    ///
    /// Pingora warns that suppressing this can remove the only per-retry
    /// record; it does not here. Every retry is logged as
    /// `gateway.upstream.retry` with its attempt number and counted in
    /// `gateway_retries_total`.
    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        _error: &pingora::Error,
        _context: pingora::proxy::ProxyWarnLogContext,
    ) -> bool {
        true
    }

    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(ctx.status);
        let latency_ms = ctx.started.map(|s| s.elapsed().as_millis()).unwrap_or(0);

        // Tell the circuit how this went — once, after any retries, so a
        // request that eventually succeeded counts as a success.
        if let Some(name) = &ctx.breaker_upstream
            && let Some(breaker) = self.upstreams.get(name).and_then(|u| u.breaker())
        {
            // A 5xx counts against the upstream; a 4xx is the caller's
            // problem and must not trip the circuit.
            if e.is_some_and(|e| *e.esource() != pingora::ErrorSource::Upstream) {
                // A disconnected client or gateway-side failure is not a
                // failed upstream trial, nor evidence of recovery.
                breaker.cancel();
            } else if e.is_some() || status >= 500 {
                breaker.record_failure();
            } else {
                breaker.record_success();
            }
            if let Some(m) = crate::metrics::metrics() {
                m.set_circuit_state(name, breaker.state().as_metric());
            }
        }

        // One span per request, queued without blocking. A span is only worth
        // exporting if the trace is sampled.
        if let Some(trace) = ctx.trace.filter(|t| t.sampled()) {
            let elapsed = ctx.started.map(|s| s.elapsed()).unwrap_or_default();
            let end = std::time::SystemTime::now();
            crate::otel::record(crate::otel::FinishedSpan {
                trace,
                name: if ctx.route_id.is_empty() {
                    ctx.method.clone()
                } else {
                    format!("{} {}", ctx.method, ctx.route_id)
                },
                route: ctx.route_id.clone(),
                upstream: ctx.upstream_name.clone(),
                method: ctx.method.clone(),
                path: format!("/{}", ctx.path),
                status,
                retries: ctx.attempts,
                start: end.checked_sub(elapsed).unwrap_or(end),
                end,
            });
        }

        #[cfg(feature = "cache")]
        if ctx.cacheable_route
            && let Some(m) = crate::metrics::metrics()
        {
            // `CachePhase` is a bounded enum, so it is a safe label.
            m.record_cache(&ctx.route_id, session.cache.phase().as_str());
        }

        if let Some(m) = crate::metrics::metrics() {
            let seconds = ctx
                .started
                .map(|s| s.elapsed().as_secs_f64())
                .unwrap_or_default();
            m.record_request(&ctx.route_id, &ctx.method, status, seconds);
            if e.is_some() {
                m.record_upstream_error(&ctx.upstream_name);
            }
        }

        if self.dev {
            self.narrate(ctx, status, latency_ms, e);
            return;
        }

        if let Some(err) = e {
            tracing::warn!(
                event = "gateway.upstream.error",
                request_id = %ctx.request_id,
                route = %ctx.route_id,
                upstream = %ctx.upstream_name,
                // Pingora's own line named the peer; its log is suppressed, so
                // the address has to appear here or it is lost.
                peer = ctx.target.as_ref().map(|t| t.addr.as_str()).unwrap_or("-"),
                path = %ctx.path,
                status,
                latency_ms,
                retries = ctx.attempts,
                error = %err,
                "upstream error",
            );
            return;
        }

        tracing::info!(
            event = "gateway.access",
            request_id = %ctx.request_id,
            route = %ctx.route_id,
            upstream = %ctx.upstream_name,
            path = %ctx.path,
            status,
            latency_ms,
            retries = ctx.attempts,
            trace_id = ctx.trace.as_ref().map(|t| t.trace_id_hex()).unwrap_or_default(),
            "request complete",
        );
    }
}

/// Resolve an upstream `host:port` to a socket address.
///
/// Exists so that a resolution failure is a 502 like any other connect failure,
/// rather than a panic inside pingora. Both failure modes are covered: the
/// lookup erroring, and the lookup succeeding with no addresses.
///
/// The error text names only the configured upstream address, which is operator
/// configuration rather than anything a client supplied, and it reaches logs
/// rather than the response body.
fn resolve_peer_addr(addr: &str) -> pingora::Result<SocketAddr> {
    let mut iter = addr.to_socket_addrs().map_err(|e| {
        pingora::Error::explain(
            pingora::ErrorType::ConnectError,
            format!("upstream address {addr} did not resolve: {e}"),
        )
        .into_up()
    })?;

    iter.next().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::ConnectError,
            format!("upstream address {addr} resolved to no addresses"),
        )
        .into_up()
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_peer_addr;

    // pingora's HttpPeer::new unwraps the resolution, so before this helper the
    // three cases below aborted the proxy worker rather than failing a request.
    #[test]
    fn unresolvable_host_is_an_error_not_a_panic() {
        let err = resolve_peer_addr("no-such-host.invalid:3002")
            .expect_err("a name that cannot resolve must not yield a peer");
        assert_eq!(err.etype(), &pingora::ErrorType::ConnectError);
    }

    #[test]
    fn malformed_address_is_an_error_not_a_panic() {
        // No port: `to_socket_addrs` rejects this before any lookup happens.
        assert!(resolve_peer_addr("products-service").is_err());
        assert!(resolve_peer_addr("").is_err());
    }

    #[test]
    fn resolvable_address_still_works() {
        let addr = resolve_peer_addr("127.0.0.1:3002").expect("a literal must resolve");
        assert_eq!(addr.port(), 3002);
        assert!(addr.ip().is_loopback());
    }
    use super::*;
    use crate::config::GatewayConfig;

    fn gateway_with_base(base: &str) -> Gateway {
        let yaml = format!(
            r#"
server:
  listen: 0.0.0.0:1
  mounts: [{base}]
  service_name: test
upstreams:
  u: http://svc:1234
routes:
  public:
    - {{ prefix: /u, upstream: u }}
"#
        );
        let (cfg, expanded) = GatewayConfig::parse("test.yml", &yaml).unwrap();
        let resolved = Arc::new(cfg.resolve(&expanded).unwrap());
        let (upstreams, _) = crate::upstream::resolve_all(&resolved.upstreams).unwrap();
        Gateway::new(
            resolved,
            SharedRoutes::new(Default::default()),
            upstreams,
            None,
            ExtensionRegistry::new(),
        )
    }

    #[test]
    fn the_narrated_mount_is_the_one_that_actually_matched() {
        // `matched_mount` re-derives what `strip_base` consumed. If the two
        // ever disagree, `gateway dev` would narrate a mount the request did
        // not take, which is worse than printing nothing.
        let g = gateway_with_base(r#""/bff/v1", "/""#);
        for path in [
            "/bff/v1/loyalty/settings",
            "/loyalty/settings",
            "/bff/v1",
            "/",
        ] {
            let mount = g.matched_mount(path);
            let stripped = g.strip_base(path);
            assert!(
                stripped.is_some(),
                "{path} should strip against one of the mounts"
            );
            assert!(
                g.base_paths.iter().any(|b| b == mount),
                "{path}: narrated mount `{mount}` is not a configured mount"
            );
        }
    }

    #[test]
    fn strips_the_mount_prefix() {
        let g = gateway_with_base(r#""/bff/v1""#);
        assert_eq!(
            g.strip_base("/bff/v1/loyalty/settings"),
            Some("loyalty/settings")
        );
        assert_eq!(g.strip_base("/bff/v1/"), Some(""));
        assert_eq!(g.strip_base("/bff/v1"), Some(""));
    }

    #[test]
    fn refuses_paths_outside_the_mount_prefix() {
        let g = gateway_with_base(r#""/bff/v1""#);
        assert_eq!(g.strip_base("/loyalty/settings"), None);
        assert_eq!(g.strip_base("/bff/v2/loyalty"), None);
        // Must not match on a partial segment.
        assert_eq!(g.strip_base("/bff/v1x/loyalty"), None);
    }

    #[test]
    fn serves_both_the_versioned_mount_and_the_bare_service_path() {
        // One gateway fronting `/bff/v1/loyalty/...` and the legacy
        // `/loyalty/...` at once, so clients migrate on their own schedule.
        let g = gateway_with_base(r#""/bff/v1", "/""#);
        assert_eq!(
            g.strip_base("/bff/v1/loyalty/settings"),
            Some("loyalty/settings")
        );
        assert_eq!(g.strip_base("/loyalty/settings"), Some("loyalty/settings"));
    }

    #[test]
    fn the_longest_mount_wins_over_a_root_mount() {
        let g = gateway_with_base(r#""/", "/bff/v1""#);
        // Declared first, but `/bff/v1` must still be stripped rather than
        // leaving `bff/v1/...` as the sub-path.
        assert_eq!(
            g.strip_base("/bff/v1/loyalty/settings"),
            Some("loyalty/settings")
        );
    }

    #[test]
    fn an_empty_base_path_mounts_at_the_root() {
        let g = gateway_with_base(r#""""#);
        assert_eq!(g.strip_base("/loyalty/settings"), Some("loyalty/settings"));
    }
}
