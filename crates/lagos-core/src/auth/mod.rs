//! Token verification and the identity it produces.

pub mod firebase;
pub mod jwks;
pub mod jwt;

use base64::Engine as _;
use serde_json::{Map, Value};

/// A verified caller. This is what the gateway forwards to upstreams, so that
/// services never need to re-verify a token or know which IdP issued it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The `sub` claim — the stable user ID.
    pub subject: String,
    pub issuer: String,
    /// The `aud` claim; for Firebase, the project ID.
    pub audience: String,
    pub claims: Map<String, Value>,
}

impl Identity {
    /// Read a string claim, tolerating both `camelCase` and `snake_case`
    /// spellings — Firebase custom claims are set by application code and both
    /// conventions appear in practice.
    /// Resolve a dotted claim path, e.g. `company.id`.
    ///
    /// Each segment tolerates both `camelCase` and `snake_case` for the same
    /// reason [`Self::claim_str`] does: custom claims are set by application
    /// code and both conventions appear in practice.
    pub fn claim_at(&self, path: &str) -> Option<&Value> {
        let mut segments = path.split('.');
        let first = segments.next()?;
        let mut current = self
            .claims
            .get(first)
            .or_else(|| self.claims.get(&to_snake_case(first)))?;

        for segment in segments {
            let object = current.as_object()?;
            current = object
                .get(segment)
                .or_else(|| object.get(&to_snake_case(segment)))?;
        }
        Some(current)
    }

    pub fn claim_str(&self, name: &str) -> Option<&str> {
        if let Some(v) = self.claims.get(name).and_then(Value::as_str) {
            return Some(v);
        }
        let alt = to_snake_case(name);
        self.claims.get(&alt).and_then(Value::as_str)
    }

    /// Read a claim without interpreting it, tolerating both spellings.
    ///
    /// Needed wherever a claim is meaningfully **tri-state**: `Some(Value::Null)`
    /// (the issuer asserted "none") and `None` (the issuer said nothing) are
    /// different facts, and [`claim_str`](Self::claim_str) collapses both to
    /// `None`. Callers that must tell them apart use this.
    pub fn claim_raw(&self, name: &str) -> Option<&Value> {
        if let Some(v) = self.claims.get(name) {
            return Some(v);
        }
        let alt = to_snake_case(name);
        self.claims.get(&alt)
    }
}

fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract the token from an `Authorization` header.
///
/// The scheme comparison is case-insensitive (`Bearer`, `bearer`, `BEARER`).
/// Surrounding whitespace is ignored. Any other scheme, or an empty token,
/// is `None`.
pub fn unverified_issuer(token: &str) -> Result<String, AuthError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::Invalid("token is not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::Invalid("token payload is not base64url".into()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::Invalid("token payload is not JSON".into()))?;
    value
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| AuthError::Invalid("token has no `iss` claim".into()))
}

pub fn bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let (scheme, rest) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let rest = rest.trim();
    (!rest.is_empty()).then_some(rest)
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The token is well-formed but issued by a project this gateway is not
    /// configured for. Distinguished from `Invalid` because it is an operator
    /// misconfiguration, not a caller error.
    #[error("unknown issuer: {0}")]
    UnknownIssuer(String),
    /// Signing keys could not be fetched. Fails closed.
    #[error("verifier unavailable: {0}")]
    Unavailable(String),
}

#[async_trait::async_trait]
pub trait TokenVerifier: Send + Sync + 'static {
    async fn verify(&self, token: &str) -> Result<Identity, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_lookup_accepts_either_spelling() {
        let mut claims = Map::new();
        claims.insert("user_type".into(), Value::String("V".into()));
        let id = Identity {
            subject: "1".into(),
            issuer: "i".into(),
            audience: "a".into(),
            claims,
        };
        assert_eq!(id.claim_str("userType"), Some("V"));
        assert_eq!(id.claim_str("user_type"), Some("V"));
        assert_eq!(id.claim_str("missing"), None);
    }

    #[test]
    fn raw_claim_lookup_distinguishes_null_from_absent() {
        // The distinction is load-bearing: an issuer that asserts `null` is
        // saying something, and an issuer that omits the claim is not.
        let mut claims = Map::new();
        claims.insert("employer_company_id".into(), Value::Null);
        let id = Identity {
            subject: "1".into(),
            issuer: "i".into(),
            audience: "a".into(),
            claims,
        };
        assert_eq!(id.claim_raw("employerCompanyId"), Some(&Value::Null));
        assert_eq!(id.claim_raw("missing"), None);
        // claim_str cannot tell these apart, which is why claim_raw exists.
        assert_eq!(id.claim_str("employerCompanyId"), None);
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("BEARER abc"), Some("abc"));
        assert_eq!(bearer_token("  Bearer   abc  "), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer "), None);
    }
}
