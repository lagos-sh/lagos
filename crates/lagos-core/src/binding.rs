//! Binding a request value to the verified caller.
//!
//! A multi-tenant API almost always has an endpoint selected by an identifier
//! the client supplies — `?merchantId=11`, `?accountId=…` — where nothing in
//! the path itself says the caller owns that thing. Left unchecked, any
//! authenticated tenant can read another's data by changing a number.
//!
//! A binding states the rule declaratively:
//!
//! ```yaml
//! - prefix: /events/orders
//!   upstream: realtime
//!   bind:
//!     query.merchantId: identity.company_id
//! ```
//!
//! Every failure mode is the same answer — **403** — because they are all the
//! same thing: the caller did not demonstrate ownership. Missing parameter,
//! missing claim, and mismatch are deliberately not distinguished, so the
//! response cannot be used to probe which tenants exist.

use serde_json::Value;

use crate::auth::Identity;

/// Where the value to check comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Query(String),
    Header(String),
}

/// What it must equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The `sub` claim.
    Subject,
    /// A dotted claim path.
    Claim(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub source: Source,
    pub target: Target,
}

impl Binding {
    /// Parse `query.merchantId: identity.company_id`.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message naming what was expected. Callers
    /// surface this at startup, so a typo can never reach the request path as
    /// a check that silently does nothing.
    pub fn parse(source: &str, target: &str) -> Result<Self, String> {
        let source = match source.split_once('.') {
            Some(("query", name)) if !name.is_empty() => Source::Query(name.to_string()),
            Some(("header", name)) if !name.is_empty() => Source::Header(name.to_ascii_lowercase()),
            _ => {
                return Err(format!(
                    "`{source}` is not a bindable source; expected `query.<name>` or `header.<name>`"
                ));
            }
        };

        let target = match target {
            "identity.subject" | "identity.sub" => Target::Subject,
            other => match other.strip_prefix("identity.") {
                Some(claim) if !claim.is_empty() => Target::Claim(claim.to_string()),
                _ => {
                    return Err(format!(
                        "`{other}` is not a bindable target; expected `identity.subject` \
                         or `identity.<claim>`"
                    ));
                }
            },
        };

        Ok(Self { source, target })
    }

    /// The value the client supplied, decoded.
    fn supplied<'a>(
        &self,
        query: Option<&str>,
        header: impl Fn(&str) -> Option<&'a str>,
    ) -> Option<String> {
        match &self.source {
            Source::Query(name) => query_param(query?, name),
            Source::Header(name) => header(name).map(str::to_string),
        }
    }

    /// The value the caller's identity proves.
    fn proven(&self, identity: &Identity) -> Option<String> {
        match &self.target {
            Target::Subject => Some(identity.subject.clone()),
            Target::Claim(path) => identity.claim_at(path).and_then(scalar_to_string),
        }
    }

    /// Whether the caller may act on what they asked for.
    pub fn permits<'a>(
        &self,
        identity: &Identity,
        query: Option<&str>,
        header: impl Fn(&str) -> Option<&'a str>,
    ) -> bool {
        // An absent value on either side is a refusal, never a pass. A binding
        // that quietly does nothing when a claim is missing is worse than no
        // binding at all, because the configuration says the check is there.
        match (self.supplied(query, header), self.proven(identity)) {
            (Some(supplied), Some(proven)) => supplied == proven,
            _ => false,
        }
    }

    /// How the binding reads in `explain` output and startup logs.
    pub fn describe(&self) -> String {
        let source = match &self.source {
            Source::Query(n) => format!("query.{n}"),
            Source::Header(n) => format!("header.{n}"),
        };
        let target = match &self.target {
            Target::Subject => "identity.subject".to_string(),
            Target::Claim(c) => format!("identity.{c}"),
        };
        format!("{source} == {target}")
    }
}

/// Render a JSON scalar the way it would appear as an identifier.
///
/// Objects and arrays are deliberately not comparable: a binding exists to
/// match one identifier against another, and stringifying a structure would
/// invent an equality rule nobody wrote down.
fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Read one query parameter, percent-decoding the key and the value.
fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        let key = percent_decode(k)?;
        if key == name { percent_decode(v) } else { None }
    })
}

fn percent_decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity(claims: serde_json::Value) -> Identity {
        Identity {
            subject: "4821".into(),
            issuer: "https://issuer".into(),
            audience: "aud".into(),
            claims: claims.as_object().expect("object").clone(),
        }
    }

    fn no_headers(_: &str) -> Option<&'static str> {
        None
    }

    fn bind(source: &str, target: &str) -> Binding {
        Binding::parse(source, target).expect("valid binding")
    }

    #[test]
    fn a_matching_value_is_permitted() {
        let id = identity(json!({ "company_id": 11 }));
        assert!(bind("query.merchantId", "identity.company_id").permits(
            &id,
            Some("merchantId=11"),
            no_headers
        ));
    }

    #[test]
    fn another_tenants_identifier_is_refused() {
        let id = identity(json!({ "company_id": 11 }));
        assert!(!bind("query.merchantId", "identity.company_id").permits(
            &id,
            Some("merchantId=12"),
            no_headers
        ));
    }

    #[test]
    fn a_percent_encoded_value_still_matches() {
        let id = identity(json!({ "company_id": "a b" }));
        assert!(bind("query.m", "identity.company_id").permits(&id, Some("m=a%20b"), no_headers));
    }

    #[test]
    fn an_omitted_parameter_is_refused_not_ignored() {
        let id = identity(json!({ "company_id": 11 }));
        let b = bind("query.merchantId", "identity.company_id");
        assert!(!b.permits(&id, Some("other=1"), no_headers));
        assert!(!b.permits(&id, None, no_headers));
    }

    #[test]
    fn a_caller_without_the_claim_is_refused() {
        // A staff user with no company must not fall through the check.
        let id = identity(json!({ "user_type": "S" }));
        assert!(!bind("query.merchantId", "identity.company_id").permits(
            &id,
            Some("merchantId=11"),
            no_headers
        ));
    }

    #[test]
    fn a_null_claim_is_refused() {
        let id = identity(json!({ "company_id": null }));
        assert!(!bind("query.m", "identity.company_id").permits(&id, Some("m=null"), no_headers));
    }

    #[test]
    fn a_structured_claim_is_not_comparable() {
        let id = identity(json!({ "company": { "id": 11 } }));
        assert!(!bind("query.m", "identity.company").permits(&id, Some("m=11"), no_headers));
        // The leaf of the same structure is.
        assert!(bind("query.m", "identity.company.id").permits(&id, Some("m=11"), no_headers));
    }

    #[test]
    fn a_non_numeric_value_does_not_match_a_numeric_claim() {
        let id = identity(json!({ "company_id": 11 }));
        assert!(!bind("query.m", "identity.company_id").permits(&id, Some("m=abc"), no_headers));
    }

    #[test]
    fn the_subject_can_be_bound() {
        let id = identity(json!({}));
        assert!(bind("query.userId", "identity.subject").permits(
            &id,
            Some("userId=4821"),
            no_headers
        ));
        assert!(!bind("query.userId", "identity.sub").permits(&id, Some("userId=9"), no_headers));
    }

    #[test]
    fn a_header_source_is_matched_case_insensitively() {
        let id = identity(json!({ "company_id": "11" }));
        let b = bind("header.X-Company-Id", "identity.company_id");
        assert_eq!(b.source, Source::Header("x-company-id".into()));
        assert!(b.permits(&id, None, |n| if n == "x-company-id" {
            Some("11")
        } else {
            None
        }));
    }

    #[test]
    fn claim_paths_tolerate_either_spelling() {
        let id = identity(json!({ "employer_company_id": 7 }));
        assert!(bind("query.m", "identity.employerCompanyId").permits(
            &id,
            Some("m=7"),
            no_headers
        ));
    }

    #[test]
    fn a_malformed_binding_is_a_parse_error_not_a_silent_pass() {
        assert!(Binding::parse("merchantId", "identity.company_id").is_err());
        assert!(Binding::parse("body.merchantId", "identity.company_id").is_err());
        assert!(Binding::parse("query.", "identity.company_id").is_err());
        assert!(Binding::parse("query.m", "company_id").is_err());
        assert!(Binding::parse("query.m", "identity.").is_err());
    }
}
