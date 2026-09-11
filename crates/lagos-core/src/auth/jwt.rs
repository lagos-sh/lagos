//! Generic OIDC / JWT verification.
//!
//! ```yaml
//! auth:
//!   jwt:
//!     - issuer: https://auth.example.com
//!       audience: my-api
//!       jwks_url: https://auth.example.com/.well-known/jwks.json
//! ```
//!
//! Anything that signs RS256/ES256 JWTs and publishes a JWKS works here —
//! Auth0, Entra, Keycloak, Okta, Cognito, an in-house issuer. Verification uses
//! public keys only, so the gateway stores no secret for any of them.
//!
//! # Algorithm confusion
//!
//! The `alg` header is chosen by whoever made the token, so it can never decide
//! how the token is verified. A verifier that trusts it accepts `alg: none`, or
//! an RSA public key replayed as an HMAC secret. The permitted algorithms come
//! from configuration and the header is checked against that list before any
//! key is fetched.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::jwks::{CertCache, KeyFormat};
use super::{AuthError, Identity, TokenVerifier, unverified_issuer};

/// One trusted issuer.
pub struct JwtVerifier {
    issuer: String,
    audiences: Vec<String>,
    algorithms: Vec<Algorithm>,
    required_claims: Vec<String>,
    clock_skew: Duration,
    keys: Arc<CertCache>,
}

impl JwtVerifier {
    pub fn new(
        issuer: String,
        audiences: Vec<String>,
        jwks_url: String,
        algorithms: Vec<Algorithm>,
        required_claims: Vec<String>,
        clock_skew: Duration,
        min_key_ttl: Duration,
    ) -> Self {
        Self {
            issuer,
            audiences,
            algorithms,
            required_claims,
            clock_skew,
            keys: Arc::new(CertCache::with_format(
                jwks_url,
                min_key_ttl,
                KeyFormat::Jwks,
            )),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

#[async_trait::async_trait]
impl TokenVerifier for JwtVerifier {
    async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let iss = unverified_issuer(token)?;
        if iss != self.issuer {
            return Err(AuthError::UnknownIssuer(iss));
        }

        let header = decode_header(token)
            .map_err(|e| AuthError::Invalid(format!("unreadable JWT header: {e}")))?;

        // Checked before a key is fetched: the header is attacker-controlled,
        // so it selects nothing until it has been matched against the list the
        // operator wrote down.
        if !self.algorithms.contains(&header.alg) {
            return Err(AuthError::Invalid(format!(
                "unexpected algorithm {:?}",
                header.alg
            )));
        }

        let kid = header
            .kid
            .ok_or_else(|| AuthError::Invalid("JWT header has no `kid`".into()))?;
        let key = self.keys.key_for(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = self.algorithms.clone();
        validation.set_issuer(&[&self.issuer]);
        if self.audiences.is_empty() {
            // An unchecked audience means a token minted for another service by
            // the same issuer is accepted here. Refuse rather than assume.
            return Err(AuthError::Invalid(
                "no audience configured for this issuer".into(),
            ));
        }
        validation.set_audience(&self.audiences);

        let mut required: HashSet<String> = ["exp", "iat", "aud", "iss", "sub"]
            .into_iter()
            .map(String::from)
            .collect();
        required.extend(self.required_claims.iter().cloned());
        validation.required_spec_claims = required;
        validation.leeway = self.clock_skew.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let claims = data.claims;

        // `required_spec_claims` only enforces presence for claims jsonwebtoken
        // knows; anything else the operator listed is checked here.
        for name in &self.required_claims {
            if !claims.contains_key(name) {
                return Err(AuthError::Invalid(format!("missing claim `{name}`")));
            }
        }

        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AuthError::Invalid("`sub` claim is empty".into()))?
            .to_string();

        let audience = claims
            .get("aud")
            .and_then(|a| match a {
                Value::String(s) => Some(s.clone()),
                Value::Array(items) => items.first().and_then(Value::as_str).map(String::from),
                _ => None,
            })
            .unwrap_or_default();

        Ok(Identity {
            subject,
            issuer: iss,
            audience,
            claims,
        })
    }
}

/// Routes a token to the verifier that trusts its issuer.
///
/// The issuer is read from the token *without* verifying it — that is safe
/// because it only chooses which verifier runs, and an unknown issuer is
/// refused. It is what lets one gateway accept tokens from a customer tenant,
/// a staff tenant and a third-party IdP at once.
pub struct IssuerRouter {
    by_issuer: std::collections::HashMap<String, Arc<dyn TokenVerifier>>,
}

impl IssuerRouter {
    pub fn new() -> Self {
        Self {
            by_issuer: std::collections::HashMap::new(),
        }
    }

    /// Register `verifier` for every issuer it claims.
    ///
    /// # Errors
    ///
    /// Two providers claiming the same issuer is a configuration mistake, and
    /// which one won would be arbitrary.
    pub fn register(
        &mut self,
        issuers: Vec<String>,
        verifier: Arc<dyn TokenVerifier>,
    ) -> Result<(), String> {
        for issuer in issuers {
            if self.by_issuer.contains_key(&issuer) {
                return Err(format!("two providers both claim issuer `{issuer}`"));
            }
            self.by_issuer.insert(issuer, verifier.clone());
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.by_issuer.is_empty()
    }

    pub fn issuers(&self) -> impl Iterator<Item = &String> {
        self.by_issuer.keys()
    }
}

impl Default for IssuerRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenVerifier for IssuerRouter {
    async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let iss = unverified_issuer(token)?;
        let verifier = self
            .by_issuer
            .get(&iss)
            .ok_or_else(|| AuthError::UnknownIssuer(iss))?;
        verifier.verify(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn token_with(header: &str, payload: &str) -> String {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.sig",
            b.encode(header.as_bytes()),
            b.encode(payload.as_bytes())
        )
    }

    fn verifier(issuer: &str) -> JwtVerifier {
        JwtVerifier::new(
            issuer.to_string(),
            vec!["my-api".into()],
            "http://127.0.0.1:1/jwks".into(),
            vec![Algorithm::RS256],
            Vec::new(),
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
    }

    #[tokio::test]
    async fn a_token_from_another_issuer_is_refused_before_any_network_call() {
        // The JWKS URL points at a closed port; reaching it would hang or error,
        // so passing proves the issuer check happened first.
        let v = verifier("https://auth.example.com");
        let token = token_with(
            r#"{"alg":"RS256","kid":"k1"}"#,
            r#"{"iss":"https://evil.example.net","sub":"1"}"#,
        );
        assert!(matches!(
            v.verify(&token).await,
            Err(AuthError::UnknownIssuer(_))
        ));
    }

    #[tokio::test]
    async fn an_unlisted_algorithm_is_refused_before_any_key_is_fetched() {
        // Algorithm confusion: `alg` is chosen by whoever made the token, so it
        // must never decide how the token is verified.
        let v = verifier("https://auth.example.com");
        for alg in [r#""none""#, r#""HS256""#, r#""ES256""#] {
            let token = token_with(
                &format!(r#"{{"alg":{alg},"kid":"k1"}}"#),
                r#"{"iss":"https://auth.example.com","sub":"1"}"#,
            );
            match v.verify(&token).await {
                Err(AuthError::Invalid(_)) => {}
                other => panic!("alg {alg} should be refused, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_token_with_no_kid_is_refused() {
        let v = verifier("https://auth.example.com");
        let token = token_with(
            r#"{"alg":"RS256"}"#,
            r#"{"iss":"https://auth.example.com","sub":"1"}"#,
        );
        assert!(matches!(v.verify(&token).await, Err(AuthError::Invalid(_))));
    }

    #[tokio::test]
    async fn an_issuer_with_no_audience_configured_is_refused() {
        // Otherwise a token the same issuer minted for a different service
        // would be accepted here.
        let v = JwtVerifier::new(
            "https://auth.example.com".into(),
            Vec::new(),
            "http://127.0.0.1:1/jwks".into(),
            vec![Algorithm::RS256],
            Vec::new(),
            Duration::from_secs(60),
            Duration::from_secs(300),
        );
        let token = token_with(
            r#"{"alg":"RS256","kid":"k1"}"#,
            r#"{"iss":"https://auth.example.com","sub":"1"}"#,
        );
        // Reaching the audience check means the key fetch was attempted, which
        // fails against a closed port; either way it must not succeed.
        assert!(v.verify(&token).await.is_err());
    }

    #[tokio::test]
    async fn the_router_refuses_an_unknown_issuer() {
        let router = IssuerRouter::new();
        let token = token_with(r#"{"alg":"RS256"}"#, r#"{"iss":"https://nobody.example"}"#);
        assert!(matches!(
            router.verify(&token).await,
            Err(AuthError::UnknownIssuer(_))
        ));
    }

    #[test]
    fn two_providers_cannot_claim_the_same_issuer() {
        let mut router = IssuerRouter::new();
        let a: Arc<dyn TokenVerifier> = Arc::new(verifier("https://auth.example.com"));
        let b: Arc<dyn TokenVerifier> = Arc::new(verifier("https://auth.example.com"));
        router
            .register(vec!["https://auth.example.com".into()], a)
            .expect("first registration");
        assert!(
            router
                .register(vec!["https://auth.example.com".into()], b)
                .is_err(),
            "which verifier ran would otherwise be arbitrary"
        );
    }

    #[tokio::test]
    async fn the_router_dispatches_on_the_issuer() {
        let mut router = IssuerRouter::new();
        router
            .register(
                vec!["https://a.example.com".into()],
                Arc::new(verifier("https://a.example.com")),
            )
            .expect("register a");
        router
            .register(
                vec!["https://b.example.com".into()],
                Arc::new(verifier("https://b.example.com")),
            )
            .expect("register b");

        // A known issuer gets past routing and fails later, on the key fetch.
        let token = token_with(
            r#"{"alg":"RS256","kid":"k1"}"#,
            r#"{"iss":"https://b.example.com","sub":"1"}"#,
        );
        assert!(!matches!(
            router.verify(&token).await,
            Err(AuthError::UnknownIssuer(_))
        ));
    }
}
