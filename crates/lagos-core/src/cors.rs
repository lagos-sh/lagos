//! Cross-origin resource sharing.
//!
//! ```yaml
//! cors:
//!   origins: [https://app.example.com, "https://*.preview.example.com"]
//!   methods: [GET, POST]
//!   headers: [content-type, authorization]
//!   credentials: true
//!   max_age: 10m
//! ```
//!
//! CORS is a browser-enforced policy, which makes a permissive gateway
//! configuration a real vulnerability rather than a cosmetic one: the browser
//! is the only thing stopping another site from reading an authenticated
//! response, and it stops only what these headers tell it to.
//!
//! Three rules are enforced here rather than left to the operator:
//!
//! 1. `credentials: true` with `origins: ["*"]` is refused **at startup**. The
//!    combination is invalid per the standard and browsers reject it, but the
//!    intent behind it — "let any site make authenticated calls" — is what a
//!    naive echo implementation actually delivers.
//! 2. When a specific origin is echoed, `Vary: Origin` is always set. Without
//!    it a shared cache can hand one origin's `Access-Control-Allow-Origin` to
//!    another, which re-creates the hole the policy just closed.
//! 3. Origins match on the whole value — scheme, host and port — never as a
//!    substring, so `https://evil-example.com` cannot satisfy a rule written
//!    for `https://example.com`.

use crate::config::CorsConfig;

/// A pattern from `origins`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginRule {
    /// `*` — any origin. Only legal without credentials.
    Any,
    /// An exact origin, compared whole.
    Exact(String),
    /// `https://*.example.com` — any sub-domain under a suffix.
    Suffix { scheme: String, suffix: String },
}

impl OriginRule {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw == "*" {
            return Ok(Self::Any);
        }
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| format!("origin `{raw}` has no scheme; write `https://example.com`"))?;
        if rest.is_empty() {
            return Err(format!("origin `{raw}` has no host"));
        }
        if rest.contains('/') {
            return Err(format!(
                "origin `{raw}` has a path; an origin is scheme, host and port only"
            ));
        }

        match rest.strip_prefix("*.") {
            Some(suffix) if !suffix.is_empty() => Ok(Self::Suffix {
                scheme: scheme.to_ascii_lowercase(),
                suffix: suffix.to_ascii_lowercase(),
            }),
            Some(_) => Err(format!("origin `{raw}` has an empty wildcard suffix")),
            None => Ok(Self::Exact(raw.to_ascii_lowercase())),
        }
    }

    fn matches(&self, origin: &str) -> bool {
        let origin = origin.trim().to_ascii_lowercase();
        match self {
            Self::Any => true,
            Self::Exact(want) => &origin == want,
            Self::Suffix { scheme, suffix } => {
                let Some((got_scheme, host)) = origin.split_once("://") else {
                    return false;
                };
                // The leading dot is what stops `evilexample.com` satisfying a
                // rule written for `*.example.com`.
                got_scheme == scheme
                    && host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host
                        .get(..host.len().saturating_sub(suffix.len()))
                        .is_some_and(|p| p.ends_with('.'))
            }
        }
    }
}

/// Compiled CORS policy.
#[derive(Debug, Clone)]
pub struct Cors {
    rules: Vec<OriginRule>,
    methods: Vec<String>,
    headers: Vec<String>,
    expose: Vec<String>,
    credentials: bool,
    max_age: u64,
    /// True when the only rule is `*` and credentials are off, in which case
    /// the literal `*` may be sent and no `Vary` is needed.
    wildcard_without_credentials: bool,
}

/// Headers to add to a response.
pub type Headers = Vec<(&'static str, String)>;

impl Cors {
    pub fn compile(cfg: &CorsConfig) -> Result<Self, String> {
        if cfg.origins.is_empty() {
            return Err("cors.origins is empty; no cross-origin request could succeed".into());
        }

        let rules = cfg
            .origins
            .iter()
            .map(|o| OriginRule::parse(o))
            .collect::<Result<Vec<_>, _>>()?;

        let any = rules.iter().any(|r| matches!(r, OriginRule::Any));
        if any && cfg.credentials {
            return Err(
                "cors sets `credentials: true` with origin `*`. Browsers refuse that \
                 combination, and honouring it would let any site read authenticated \
                 responses. List the origins that may send credentials."
                    .into(),
            );
        }

        Ok(Self {
            wildcard_without_credentials: any && !cfg.credentials,
            rules,
            methods: cfg.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
            headers: cfg.headers.iter().map(|h| h.to_ascii_lowercase()).collect(),
            expose: cfg.expose.iter().map(|h| h.to_ascii_lowercase()).collect(),
            credentials: cfg.credentials,
            max_age: cfg.max_age.as_secs(),
        })
    }

    fn allows(&self, origin: &str) -> bool {
        self.rules.iter().any(|r| r.matches(origin))
    }

    /// What `Access-Control-Allow-Origin` should say, plus whether the answer
    /// depends on the request's `Origin`.
    fn allow_origin(&self, origin: &str) -> Option<(String, bool)> {
        if !self.allows(origin) {
            return None;
        }
        if self.wildcard_without_credentials {
            // A constant answer, so no cache can mix two origins up.
            Some(("*".to_string(), false))
        } else {
            Some((origin.to_string(), true))
        }
    }

    /// Headers for a preflight, or `None` when the origin is not allowed.
    ///
    /// `requested_method` comes from `Access-Control-Request-Method`, which is
    /// the method the browser intends to use — the preflight itself is always
    /// `OPTIONS`, so matching on that would allow nothing.
    pub fn preflight(&self, origin: &str, requested_method: &str) -> Option<Headers> {
        let (value, varies) = self.allow_origin(origin)?;
        let method = requested_method.trim().to_ascii_uppercase();
        if !self.methods.contains(&method) {
            return None;
        }

        let mut out: Headers = vec![
            ("access-control-allow-origin", value),
            ("access-control-allow-methods", self.methods.join(", ")),
            ("access-control-max-age", self.max_age.to_string()),
        ];
        if !self.headers.is_empty() {
            out.push(("access-control-allow-headers", self.headers.join(", ")));
        }
        if self.credentials {
            out.push(("access-control-allow-credentials", "true".to_string()));
        }
        if varies {
            // Without this a shared cache may serve one origin's allowance to
            // another.
            out.push(("vary", "Origin, Access-Control-Request-Method".to_string()));
        }
        Some(out)
    }

    /// Headers to add to an ordinary (non-preflight) cross-origin response.
    pub fn response(&self, origin: &str) -> Option<Headers> {
        let (value, varies) = self.allow_origin(origin)?;
        let mut out: Headers = vec![("access-control-allow-origin", value)];
        if self.credentials {
            out.push(("access-control-allow-credentials", "true".to_string()));
        }
        if !self.expose.is_empty() {
            out.push(("access-control-expose-headers", self.expose.join(", ")));
        }
        if varies {
            out.push(("vary", "Origin".to_string()));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg(origins: &[&str], credentials: bool) -> CorsConfig {
        CorsConfig {
            origins: origins.iter().map(|s| (*s).to_string()).collect(),
            methods: vec!["GET".into(), "POST".into()],
            headers: vec!["content-type".into()],
            expose: vec!["x-request-id".into()],
            credentials,
            max_age: Duration::from_secs(600),
        }
    }

    fn cors(origins: &[&str], credentials: bool) -> Cors {
        Cors::compile(&cfg(origins, credentials)).expect("valid policy")
    }

    fn value<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
        h.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    #[test]
    fn an_allowed_origin_is_echoed_back() {
        let c = cors(&["https://app.example.com"], false);
        let h = c.response("https://app.example.com").expect("allowed");
        assert_eq!(
            value(&h, "access-control-allow-origin"),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn an_unlisted_origin_gets_nothing() {
        let c = cors(&["https://app.example.com"], false);
        assert!(c.response("https://evil.example.net").is_none());
        assert!(c.preflight("https://evil.example.net", "GET").is_none());
    }

    #[test]
    fn a_similar_looking_origin_does_not_match() {
        // The classic substring bug: `evil-example.com` containing `example.com`.
        let c = cors(&["https://example.com"], false);
        assert!(c.response("https://evil-example.com").is_none());
        assert!(c.response("https://example.com.evil.net").is_none());
        assert!(c.response("https://sub.example.com").is_none());
    }

    #[test]
    fn scheme_and_port_are_part_of_the_origin() {
        let c = cors(&["https://example.com"], false);
        assert!(c.response("http://example.com").is_none(), "scheme matters");
        assert!(
            c.response("https://example.com:8443").is_none(),
            "port matters"
        );
    }

    #[test]
    fn echoing_an_origin_always_varies_on_it() {
        // Otherwise a shared cache serves one origin's allowance to another.
        let c = cors(&["https://a.example.com", "https://b.example.com"], false);
        let h = c.response("https://a.example.com").expect("allowed");
        assert_eq!(value(&h, "vary"), Some("Origin"));
    }

    #[test]
    fn a_bare_wildcard_needs_no_vary() {
        // The answer is constant, so there is nothing for a cache to confuse.
        let c = cors(&["*"], false);
        let h = c.response("https://anything.example").expect("allowed");
        assert_eq!(value(&h, "access-control-allow-origin"), Some("*"));
        assert_eq!(value(&h, "vary"), None);
    }

    #[test]
    fn credentials_with_a_wildcard_origin_is_refused_at_startup() {
        // Honouring it would let any site read authenticated responses.
        let e = Cors::compile(&cfg(&["*"], true)).expect_err("must not compile");
        assert!(e.contains("credentials"), "{e}");
    }

    #[test]
    fn credentials_are_allowed_with_named_origins() {
        let c = cors(&["https://app.example.com"], true);
        let h = c.response("https://app.example.com").expect("allowed");
        assert_eq!(value(&h, "access-control-allow-credentials"), Some("true"));
        assert_eq!(value(&h, "vary"), Some("Origin"));
    }

    #[test]
    fn a_wildcard_subdomain_matches_only_below_the_suffix() {
        let c = cors(&["https://*.preview.example.com"], false);
        assert!(c.response("https://pr-42.preview.example.com").is_some());
        assert!(c.response("https://a.b.preview.example.com").is_some());
        // The suffix itself is not a sub-domain of itself.
        assert!(c.response("https://preview.example.com").is_none());
        // And the dot boundary must hold.
        assert!(c.response("https://evilpreview.example.com").is_none());
        assert!(c.response("http://pr-42.preview.example.com").is_none());
    }

    #[test]
    fn preflight_answers_for_the_requested_method_not_options() {
        let c = cors(&["https://app.example.com"], false);
        let h = c
            .preflight("https://app.example.com", "POST")
            .expect("POST is allowed");
        assert!(value(&h, "access-control-allow-methods").is_some_and(|m| m.contains("POST")));
        assert_eq!(value(&h, "access-control-max-age"), Some("600"));
        // A method outside the list is refused, so the browser blocks the call.
        assert!(c.preflight("https://app.example.com", "DELETE").is_none());
    }

    #[test]
    fn preflight_varies_on_the_request_method_too() {
        let c = cors(&["https://app.example.com"], false);
        let h = c
            .preflight("https://app.example.com", "GET")
            .expect("allowed");
        assert_eq!(
            value(&h, "vary"),
            Some("Origin, Access-Control-Request-Method")
        );
    }

    #[test]
    fn exposed_headers_are_listed_on_real_responses_only() {
        let c = cors(&["https://app.example.com"], false);
        let real = c.response("https://app.example.com").expect("allowed");
        assert_eq!(
            value(&real, "access-control-expose-headers"),
            Some("x-request-id")
        );
        let pre = c
            .preflight("https://app.example.com", "GET")
            .expect("allowed");
        assert_eq!(value(&pre, "access-control-expose-headers"), None);
    }

    #[test]
    fn origin_comparison_ignores_case() {
        let c = cors(&["https://App.Example.com"], false);
        assert!(c.response("https://app.example.COM").is_some());
    }

    #[test]
    fn a_malformed_origin_is_refused_at_startup() {
        assert!(
            Cors::compile(&cfg(&["example.com"], false)).is_err(),
            "no scheme"
        );
        assert!(
            Cors::compile(&cfg(&["https://example.com/app"], false)).is_err(),
            "has a path"
        );
        assert!(
            Cors::compile(&cfg(&["https://"], false)).is_err(),
            "no host"
        );
        assert!(
            Cors::compile(&cfg(&["https://*."], false)).is_err(),
            "empty suffix"
        );
    }

    #[test]
    fn an_empty_origin_list_is_refused() {
        assert!(Cors::compile(&cfg(&[], false)).is_err());
    }
}
