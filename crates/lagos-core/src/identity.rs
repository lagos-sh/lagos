//! Describing the verified caller to upstreams.
//!
//! An upstream behind this gateway should not need an identity-provider SDK.
//! It reads who the caller is from headers set here — and, when configured,
//! verifies a short-lived signature proving the gateway set them.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Serialize;

use crate::auth::Identity;
use crate::config::{IdentityConfig, IdentityTokenConfig};
use crate::headers::HeaderPlan;

#[derive(Serialize)]
struct IdentityClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    /// The original token's audience — for Firebase, the project ID, which is
    /// how an upstream can tell a customer token from a merchant one.
    tenant: &'a str,
    iat: u64,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
}

/// Why identity headers could not be built.
///
/// The split is what the caller answers with: a token whose claims will not fit
/// in a header is the *caller's* problem and must read as 401, while a signing
/// key that will not sign is the *gateway's* and must read as 503. Collapsing
/// them — as a single string error does — means a malformed token pages an
/// operator, and a broken key tells the client to get a new token.
#[derive(Debug)]
pub enum IdentityError {
    /// A claim cannot be represented as a header value.
    Claim(String),
    /// Minting the signed identity token failed.
    Mint(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Claim(d) | Self::Mint(d) => f.write_str(d),
        }
    }
}

/// Write the identity headers into the plan.
///
/// Uses [`HeaderPlan::set`], which strips any client-supplied copy first, so a
/// caller cannot assert an identity of its own.
///
/// # Errors
///
/// Returns an error when a claim cannot become a header value, or when token
/// minting is configured and signing fails. The caller must fail the request
/// rather than forwarding partial or unsigned headers.
pub fn apply(
    plan: &mut HeaderPlan,
    cfg: &IdentityConfig,
    secret: Option<&[u8]>,
    identity: &Identity,
) -> Result<(), IdentityError> {
    // `sub` and `iss` come out of a *verified* token, but "verified" says the
    // issuer signed them, not that they are shaped like a header value. A
    // control character or a non-ASCII subject would be refused by the HTTP
    // stack when the request is built, several phases later, and surface as a
    // 502 from a request that should have been a clean 401. Checked here so the
    // answer is about the token, which is what it is actually about.
    if !cfg.subject_header.is_empty() {
        if !is_header_safe(&identity.subject) {
            return Err(IdentityError::Claim(format!(
                "`sub` contains a character that cannot appear in header `{}`",
                cfg.subject_header
            )));
        }
        plan.set(&cfg.subject_header, identity.subject.clone());
    }
    if !cfg.issuer_header.is_empty() {
        if !is_header_safe(&identity.issuer) {
            return Err(IdentityError::Claim(format!(
                "`iss` contains a character that cannot appear in header `{}`",
                cfg.issuer_header
            )));
        }
        plan.set(&cfg.issuer_header, identity.issuer.clone());
    }
    if !cfg.claims_header.is_empty()
        && let Ok(json) = serde_json::to_vec(&identity.claims)
    {
        plan.set(
            &cfg.claims_header,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json),
        );
    }

    apply_claim_headers(plan, cfg, identity)?;

    if let (Some(token_cfg), Some(secret)) = (&cfg.token, secret) {
        match mint(token_cfg, secret, identity) {
            Ok(token) => {
                plan.set(&token_cfg.header, token);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to mint identity token");
                return Err(IdentityError::Mint(e.to_string()));
            }
        }
    } else if let Some(token_cfg) = &cfg.token {
        // Belt and braces: never let a client-supplied value sit in the slot
        // where a signed token is expected.
        plan.strip(&token_cfg.header);
    }
    Ok(())
}

/// Copy configured claims into upstream headers.
///
/// Three states, deliberately distinct, because an upstream making an
/// authorization decision reads them differently:
///
/// | claim | header |
/// |---|---|
/// | a scalar | the value |
/// | JSON `null` | `when_null`, or omitted when that is unset |
/// | absent | **omitted** |
///
/// Collapsing "absent" into "null" is the bug this table exists to prevent: if
/// an identity provider omits a claim because its own lookup failed, emitting
/// a definite value would tell the upstream something the gateway does not
/// know.
fn apply_claim_headers(
    plan: &mut HeaderPlan,
    cfg: &IdentityConfig,
    identity: &Identity,
) -> Result<(), IdentityError> {
    for (header, mapping) in &cfg.claims {
        if header.is_empty() {
            continue;
        }
        // Strip first and unconditionally: on the paths where no value is set
        // the header must still not survive from the client request.
        plan.strip(header);

        let Some(value) = identity.claim_at(&mapping.claim) else {
            continue;
        };

        let rendered = match value {
            serde_json::Value::String(v) => Some(v.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            serde_json::Value::Null => mapping.when_null.clone(),
            // An object or array has no single obvious spelling; inventing one
            // would be a silent guess about what the upstream expects.
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                return Err(IdentityError::Claim(format!(
                    "claim `{}` is a structure and cannot become header `{header}`",
                    mapping.claim
                )));
            }
        };

        let Some(rendered) = rendered else {
            continue;
        };

        // Claims are signed, but their *contents* are often user-supplied — a
        // display name, a custom claim set by application code. A CR or LF
        // here would split the header block, so refuse the request rather than
        // emit it or silently drop an authority header the upstream needs.
        if !is_header_safe(&rendered) {
            return Err(IdentityError::Claim(format!(
                "claim `{}` contains a character that cannot appear in header `{header}`",
                mapping.claim
            )));
        }

        plan.set(header, rendered);
    }
    Ok(())
}

/// Whether a string can be sent as a header value: visible ASCII and spaces or
/// tabs only. Excludes CR and LF, which is the point.
fn is_header_safe(value: &str) -> bool {
    value.chars().all(|c| c == '\t' || (' '..='~').contains(&c))
}

/// Strip every identity header without setting one — used on public routes, so
/// an unauthenticated request can never carry identity headers upstream.
pub fn strip_all(plan: &mut HeaderPlan, cfg: &IdentityConfig) {
    for h in [&cfg.subject_header, &cfg.issuer_header, &cfg.claims_header] {
        if !h.is_empty() {
            plan.strip(h);
        }
    }
    // Mapped claim headers too: on a public route these must never arrive from
    // the client and be mistaken upstream for something the gateway asserted.
    for h in cfg.claims.keys() {
        if !h.is_empty() {
            plan.strip(h);
        }
    }
    if let Some(t) = &cfg.token {
        plan.strip(&t.header);
    }
}

fn mint(
    cfg: &IdentityTokenConfig,
    secret: &[u8],
    identity: &Identity,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let claims = IdentityClaims {
        sub: &identity.subject,
        iss: &identity.issuer,
        tenant: &identity.audience,
        iat: now,
        exp: now.saturating_add(cfg.ttl.as_secs()),
        aud: cfg.audience.as_deref(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClaimMapping;

    fn id_with(subject: &str, issuer: &str) -> Identity {
        Identity {
            subject: subject.into(),
            issuer: issuer.into(),
            audience: "aud".into(),
            claims: Default::default(),
        }
    }

    fn subject_issuer_cfg() -> IdentityConfig {
        IdentityConfig {
            subject_header: "x-auth-subject".into(),
            issuer_header: "x-auth-issuer".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_subject_that_cannot_be_a_header_is_refused_as_a_claim_error() {
        // A signed token still only means the issuer vouched for the bytes.
        // Left unchecked these reach `insert_header` three phases later and
        // come back as a 502 blaming the upstream.
        for bad in [
            "4821\r\nx-auth-subject: 1",
            "4821\nx-admin: 1",
            "usuário",
            "a\u{0}b",
        ] {
            let mut plan = HeaderPlan::new();
            let err = apply(&mut plan, &subject_issuer_cfg(), None, &id_with(bad, "iss"))
                .expect_err("an unrepresentable subject must not be forwarded");
            assert!(
                matches!(err, IdentityError::Claim(_)),
                "{bad:?} should be a caller error, not a gateway one"
            );
            // Nothing partial may survive: the header must not be set to a
            // truncated or sanitized version of what the token said.
            assert!(
                !plan.additions().any(|(n, _)| n == "x-auth-subject"),
                "{bad:?} left a subject header behind"
            );
        }
    }

    #[test]
    fn an_unrepresentable_issuer_is_refused_too() {
        let mut plan = HeaderPlan::new();
        let err = apply(
            &mut plan,
            &subject_issuer_cfg(),
            None,
            &id_with("4821", "https://issuer\r\nx-api-key: stolen"),
        )
        .expect_err("an unrepresentable issuer must not be forwarded");
        assert!(matches!(err, IdentityError::Claim(_)));
    }

    #[test]
    fn an_ordinary_identity_still_passes() {
        let mut plan = HeaderPlan::new();
        apply(
            &mut plan,
            &subject_issuer_cfg(),
            None,
            &id_with("4821", "https://securetoken.google.com/petsocare"),
        )
        .expect("a normal token must not be affected by the safety check");
        let adds: Vec<_> = plan.additions().cloned().collect();
        assert!(adds.contains(&("x-auth-subject".into(), "4821".into())));
    }

    fn mapped(claims: serde_json::Value, spec: &[(&str, ClaimMapping)]) -> HeaderPlan {
        let cfg = IdentityConfig {
            claims: spec
                .iter()
                .map(|(h, m)| ((*h).to_string(), m.clone()))
                .collect(),
            ..Default::default()
        };
        let identity = Identity {
            subject: "4821".into(),
            issuer: "iss".into(),
            audience: "aud".into(),
            claims: claims.as_object().expect("object").clone(),
        };
        let mut plan = HeaderPlan::new();
        apply_claim_headers(&mut plan, &cfg, &identity).expect("mapping should succeed");
        plan
    }

    fn simple(claim: &str) -> ClaimMapping {
        ClaimMapping {
            claim: claim.into(),
            when_null: None,
        }
    }

    fn header_of(plan: &HeaderPlan, name: &str) -> Option<String> {
        plan.additions()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn a_scalar_claim_becomes_its_header() {
        let p = mapped(
            serde_json::json!({ "user_type": "V", "company_id": 11 }),
            &[
                ("x-user-type", simple("user_type")),
                ("x-company-id", simple("company_id")),
            ],
        );
        assert_eq!(header_of(&p, "x-user-type").as_deref(), Some("V"));
        assert_eq!(header_of(&p, "x-company-id").as_deref(), Some("11"));
    }

    #[test]
    fn an_absent_claim_leaves_the_header_absent() {
        // The tri-state rule: absence must survive as absence, so an upstream
        // deciding on it can fail closed rather than read a definite value.
        let p = mapped(
            serde_json::json!({}),
            &[(
                "x-employer",
                ClaimMapping {
                    claim: "employerCompanyId".into(),
                    when_null: Some("none".into()),
                },
            )],
        );
        assert_eq!(header_of(&p, "x-employer"), None);
        assert!(
            p.removals().any(|r| r == "x-employer"),
            "still stripped from the client"
        );
    }

    #[test]
    fn a_null_claim_uses_its_configured_spelling() {
        let p = mapped(
            serde_json::json!({ "employerCompanyId": null }),
            &[(
                "x-employer",
                ClaimMapping {
                    claim: "employerCompanyId".into(),
                    when_null: Some("none".into()),
                },
            )],
        );
        assert_eq!(header_of(&p, "x-employer").as_deref(), Some("none"));
    }

    #[test]
    fn a_null_claim_without_a_spelling_is_omitted() {
        let p = mapped(
            serde_json::json!({ "employerCompanyId": null }),
            &[("x-employer", simple("employerCompanyId"))],
        );
        assert_eq!(header_of(&p, "x-employer"), None);
    }

    #[test]
    fn a_claim_carrying_crlf_fails_the_request() {
        // Claims are signed, but their contents are often user-supplied. A CRLF
        // here would split the header block.
        let cfg = IdentityConfig {
            claims: [("x-name".to_string(), simple("name"))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let identity = Identity {
            subject: "1".into(),
            issuer: "i".into(),
            audience: "a".into(),
            claims: serde_json::json!({ "name": "bob\r\nx-admin: true" })
                .as_object()
                .expect("object")
                .clone(),
        };
        let mut plan = HeaderPlan::new();
        assert!(apply_claim_headers(&mut plan, &cfg, &identity).is_err());
    }

    #[test]
    fn a_structured_claim_fails_rather_than_guessing_a_spelling() {
        let cfg = IdentityConfig {
            claims: [("x-co".to_string(), simple("company"))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let identity = Identity {
            subject: "1".into(),
            issuer: "i".into(),
            audience: "a".into(),
            claims: serde_json::json!({ "company": { "id": 1 } })
                .as_object()
                .expect("object")
                .clone(),
        };
        let mut plan = HeaderPlan::new();
        assert!(apply_claim_headers(&mut plan, &cfg, &identity).is_err());
    }

    #[test]
    fn mapped_headers_are_stripped_on_a_public_route() {
        let cfg = IdentityConfig {
            claims: [("x-user-type".to_string(), simple("user_type"))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut plan = HeaderPlan::new();
        strip_all(&mut plan, &cfg);
        assert!(
            plan.removals().any(|r| r == "x-user-type"),
            "a client must not be able to assert a mapped claim header"
        );
    }
    use serde_json::{Map, Value};
    use std::time::Duration;

    fn identity() -> Identity {
        let mut claims = Map::new();
        claims.insert("user_type".into(), Value::String("V".into()));
        Identity {
            subject: "4821".into(),
            issuer: "https://securetoken.google.com/demo-project".into(),
            audience: "demo-project".into(),
            claims,
        }
    }

    fn find(plan: &HeaderPlan, name: &str) -> Option<String> {
        plan.additions()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn sets_plain_identity_headers() {
        let mut plan = HeaderPlan::new();
        apply(&mut plan, &IdentityConfig::default(), None, &identity()).unwrap();
        assert_eq!(find(&plan, "x-auth-subject").unwrap(), "4821");
        assert_eq!(
            find(&plan, "x-auth-issuer").unwrap(),
            "https://securetoken.google.com/demo-project"
        );
        let claims = find(&plan, "x-auth-claims").unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .unwrap();
        let parsed: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(parsed["user_type"], "V");
    }

    #[test]
    fn identity_headers_are_stripped_from_the_client_request() {
        let mut plan = HeaderPlan::new();
        apply(&mut plan, &IdentityConfig::default(), None, &identity()).unwrap();
        // `set` implies `strip`, so a client copy cannot survive alongside ours.
        for h in ["x-auth-subject", "x-auth-issuer", "x-auth-claims"] {
            assert!(plan.removals().any(|r| r == h), "{h} was not stripped");
        }
    }

    #[test]
    fn public_routes_strip_identity_headers_entirely() {
        let cfg = IdentityConfig {
            token: Some(IdentityTokenConfig {
                header: "x-auth-token".into(),
                secret: "unused".into(),
                ttl: Duration::from_secs(60),
                audience: None,
            }),
            ..Default::default()
        };
        let mut plan = HeaderPlan::new();
        strip_all(&mut plan, &cfg);
        for h in [
            "x-auth-subject",
            "x-auth-issuer",
            "x-auth-claims",
            "x-auth-token",
        ] {
            assert!(plan.removals().any(|r| r == h), "{h} was not stripped");
        }
        assert_eq!(
            plan.additions().count(),
            0,
            "public routes must assert no identity"
        );
    }

    #[test]
    fn mints_a_verifiable_short_lived_token() {
        let cfg = IdentityConfig {
            token: Some(IdentityTokenConfig {
                header: "x-auth-token".into(),
                secret: "unused".into(),
                ttl: Duration::from_secs(60),
                audience: Some("internal".into()),
            }),
            ..Default::default()
        };
        let mut plan = HeaderPlan::new();
        apply(&mut plan, &cfg, Some(b"topsecret"), &identity()).unwrap();

        let token = find(&plan, "x-auth-token").expect("no token minted");
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.set_audience(&["internal"]);
        let data = jsonwebtoken::decode::<Map<String, Value>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(b"topsecret"),
            &v,
        )
        .expect("gateway-minted token failed verification");

        assert_eq!(data.claims["sub"], "4821");
        assert_eq!(data.claims["tenant"], "demo-project");
        let exp = data.claims["exp"].as_u64().unwrap();
        let iat = data.claims["iat"].as_u64().unwrap();
        assert_eq!(exp - iat, 60);
    }

    #[test]
    fn a_token_signed_with_another_key_is_rejected() {
        let cfg = IdentityConfig {
            token: Some(IdentityTokenConfig {
                header: "x-auth-token".into(),
                secret: "unused".into(),
                ttl: Duration::from_secs(60),
                audience: None,
            }),
            ..Default::default()
        };
        let mut plan = HeaderPlan::new();
        apply(&mut plan, &cfg, Some(b"attacker-key"), &identity()).unwrap();
        let token = find(&plan, "x-auth-token").unwrap();

        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        v.validate_aud = false;
        assert!(
            jsonwebtoken::decode::<Map<String, Value>>(
                &token,
                &jsonwebtoken::DecodingKey::from_secret(b"real-key"),
                &v,
            )
            .is_err()
        );
    }
}
