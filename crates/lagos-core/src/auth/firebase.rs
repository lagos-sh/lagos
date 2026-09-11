//! Firebase ID token verification across several projects.
//!
//! Mirrors what the Firebase Admin SDK's `verifyIdToken` checks: RS256
//! signature against Google's current signing certificates, plus `iss`, `aud`,
//! `exp`, `iat`, `auth_time` and a non-empty `sub`.
//!
//! Revocation is not checked, matching the reference implementation — that
//! would require a per-request round trip to Firebase.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::jwks::CertCache;
use super::{AuthError, Identity, TokenVerifier, unverified_issuer};

const ISS_PREFIX: &str = "https://securetoken.google.com/";

pub struct FirebaseVerifier {
    project_ids: HashSet<String>,
    certs: CertCache,
    clock_skew: Duration,
}

impl FirebaseVerifier {
    pub fn new(
        project_ids: impl IntoIterator<Item = String>,
        certs_url: String,
        clock_skew: Duration,
        min_cert_ttl: Duration,
    ) -> Self {
        Self {
            project_ids: project_ids.into_iter().collect(),
            certs: CertCache::new(certs_url, min_cert_ttl),
            clock_skew,
        }
    }

    /// Issuer URLs this verifier accepts, one per configured project.
    pub fn issuers(&self) -> Vec<String> {
        self.project_ids
            .iter()
            .map(|p| format!("{ISS_PREFIX}{p}"))
            .collect()
    }

    pub fn project_ids(&self) -> impl Iterator<Item = &String> {
        self.project_ids.iter()
    }
}

/// Read the `iss` claim without verifying anything, purely to decide *which*
/// project's rules to validate against. Nothing from this is trusted: the
/// returned project ID must be one we are configured for, and the full
/// signature check happens afterwards with that project pinned as the audience.
fn project_id_from_issuer(iss: &str) -> Option<&str> {
    iss.strip_prefix(ISS_PREFIX).filter(|p| !p.is_empty())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[async_trait::async_trait]
impl TokenVerifier for FirebaseVerifier {
    async fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let iss = unverified_issuer(token)?;
        let project_id = project_id_from_issuer(&iss)
            .ok_or_else(|| AuthError::Invalid(format!("issuer `{iss}` is not a Firebase issuer")))?
            .to_string();

        if !self.project_ids.contains(&project_id) {
            return Err(AuthError::UnknownIssuer(project_id));
        }

        let header = decode_header(token)
            .map_err(|e| AuthError::Invalid(format!("unreadable JWT header: {e}")))?;
        if header.alg != Algorithm::RS256 {
            // Refusing anything but RS256 closes the algorithm-confusion class
            // of attack, where a caller re-signs a token with a weaker alg.
            return Err(AuthError::Invalid(format!(
                "unexpected algorithm {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::Invalid("JWT header has no `kid`".into()))?;

        let key = self.certs.key_for(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&project_id]);
        validation.set_issuer(&[format!("{ISS_PREFIX}{project_id}")]);
        validation.set_required_spec_claims(&["exp", "iat", "aud", "iss", "sub"]);
        validation.leeway = self.clock_skew.as_secs();
        validation.validate_exp = true;
        validation.validate_nbf = false;

        let data = decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let claims = data.claims;

        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AuthError::Invalid("`sub` claim is empty".into()))?
            .to_string();

        // `auth_time` in the future means the token describes a sign-in that has
        // not happened. The Admin SDK rejects these; jsonwebtoken does not know
        // the claim, so check it here.
        if let Some(auth_time) = claims.get("auth_time").and_then(Value::as_u64)
            && auth_time > now_secs().saturating_add(self.clock_skew.as_secs())
        {
            return Err(AuthError::Invalid("`auth_time` is in the future".into()));
        }

        Ok(Identity {
            subject,
            issuer: iss,
            audience: project_id,
            claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn token_with_payload(json: &str) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b64.encode(b"{}"),
            b64.encode(json.as_bytes()),
            "sig"
        )
    }

    #[test]
    fn extracts_project_id_from_firebase_issuer() {
        assert_eq!(
            project_id_from_issuer("https://securetoken.google.com/demo-project"),
            Some("demo-project")
        );
    }

    #[test]
    fn rejects_non_firebase_and_empty_issuers() {
        assert_eq!(project_id_from_issuer("https://accounts.google.com"), None);
        assert_eq!(
            project_id_from_issuer("https://securetoken.google.com/"),
            None
        );
        // A lookalike host must not be accepted.
        assert_eq!(
            project_id_from_issuer("https://securetoken.google.com.evil.tld/p"),
            None
        );
    }

    #[test]
    fn reads_issuer_without_verifying() {
        let t = token_with_payload(r#"{"iss":"https://securetoken.google.com/p1","sub":"7"}"#);
        assert_eq!(
            unverified_issuer(&t).unwrap(),
            "https://securetoken.google.com/p1"
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        assert!(unverified_issuer("not-a-jwt").is_err());
        assert!(unverified_issuer("aaa.!!!not-base64!!!.ccc").is_err());
        assert!(unverified_issuer(&token_with_payload("{}")).is_err());
    }

    #[tokio::test]
    async fn unconfigured_project_is_refused_before_any_network_call() {
        // certs_url is deliberately unroutable: reaching it would fail the test.
        let v = FirebaseVerifier::new(
            ["configured-project".to_string()],
            "http://127.0.0.1:1/unreachable".into(),
            Duration::from_secs(60),
            Duration::from_secs(300),
        );
        let t = token_with_payload(r#"{"iss":"https://securetoken.google.com/other","sub":"1"}"#);
        match v.verify(&t).await {
            Err(AuthError::UnknownIssuer(p)) => assert_eq!(p, "other"),
            other => panic!("expected UnknownIssuer, got {other:?}"),
        }
    }
}
