//! Opt-in origin protection for gateway-selected cookie credentials.
//! CORS controls response access; this policy refuses unsafe requests.

use crate::config::CookieProtectionConfig;
use http::{HeaderMap, Method};

#[derive(Debug, Clone)]
pub struct CookieProtection {
    origins: Vec<String>,
    referer_fallback: bool,
}

fn origin(raw: &str, referer: bool) -> Option<String> {
    if raw.contains('*')
        || raw.len() > 2048
        || raw.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'\\')
    {
        return None;
    }
    let url = reqwest::Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (!referer && (url.path() != "/" || url.query().is_some() || url.fragment().is_some()))
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, &'static str> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("cookie_origin_ambiguous");
    }
    value.to_str().map(Some).map_err(|_| "cookie_origin_denied")
}

impl CookieProtection {
    pub fn compile(config: &CookieProtectionConfig) -> Result<Self, String> {
        if config.origins.is_empty() {
            return Err("origins must not be empty".into());
        }
        let origins = config.origins.iter().map(|raw| origin(raw, false)
            .ok_or_else(|| "origins must be exact HTTP(S) origins without credentials, paths or wildcards".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            origins,
            referer_fallback: config.referer_fallback,
        })
    }

    /// Call only when a cookie actually supplies the gateway credential.
    pub fn check(&self, headers: &HeaderMap, method: &Method) -> Result<(), &'static str> {
        if matches!(
            *method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        ) {
            return Ok(());
        }
        let candidate = match single(headers, "origin")? {
            Some(raw) => origin(raw, false),
            None if self.referer_fallback => {
                single(headers, "referer")?.and_then(|raw| origin(raw, true))
            }
            None => return Err("cookie_origin_required"),
        }
        .ok_or("cookie_origin_denied")?;
        if self.origins.contains(&candidate) {
            Ok(())
        } else {
            Err("cookie_origin_denied")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_unambiguous_origins_can_authorize_unsafe_cookie_requests() {
        let policy = CookieProtection::compile(&CookieProtectionConfig {
            origins: vec!["https://app.test".into()],
            referer_fallback: true,
        })
        .unwrap();
        let mut headers = HeaderMap::new();
        assert!(policy.check(&headers, &Method::GET).is_ok());
        assert!(policy.check(&headers, &Method::POST).is_err());
        for denied in [
            "null",
            "https://evil-app.test",
            "https://app.test.evil",
            "http://app.test",
            "https://app.test/path",
            "https://user@app.test",
            "https://app.test https://evil.test",
            "https://app.test\\evil",
        ] {
            headers.insert("origin", http::HeaderValue::from_str(denied).unwrap());
            assert!(policy.check(&headers, &Method::POST).is_err(), "{denied}");
        }
        headers.insert(
            "origin",
            http::HeaderValue::from_static("https://APP.test:443"),
        );
        assert!(policy.check(&headers, &Method::POST).is_ok());
        headers.append("origin", http::HeaderValue::from_static("https://app.test"));
        assert_eq!(
            policy.check(&headers, &Method::POST),
            Err("cookie_origin_ambiguous")
        );
        headers.remove("origin");
        headers.insert(
            "referer",
            http::HeaderValue::from_static("https://app.test/page?query=x"),
        );
        assert!(policy.check(&headers, &Method::POST).is_ok());
        headers.insert(
            "origin",
            http::HeaderValue::from_static("https://evil.test"),
        );
        assert!(
            policy.check(&headers, &Method::POST).is_err(),
            "Referer never overrides an Origin"
        );
    }

    #[test]
    fn unsafe_origin_configuration_is_refused() {
        for raw in [
            "*",
            "https://*.test",
            "https://app.test/path",
            "null",
            "file:///tmp",
            "https://user@app.test",
        ] {
            assert!(
                CookieProtection::compile(&CookieProtectionConfig {
                    origins: vec![raw.into()],
                    referer_fallback: false
                })
                .is_err(),
                "{raw}"
            );
        }
    }
}
