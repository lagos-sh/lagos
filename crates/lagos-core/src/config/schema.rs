//! Editor schemas for YAML input, without loading configuration or services.

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde_json::{Value, json};

use super::{ClaimDetails, GatewayConfig, UpstreamDetails, UpstreamTargetDetails};
use crate::routes::RouteGroups;

// These unions describe the visitors' accepted input, not normalized output.
#[derive(JsonSchema)]
#[schemars(untagged)]
#[allow(dead_code)]
pub(super) enum Upstream {
    Url(String),
    Detailed(UpstreamDetails),
}

#[derive(JsonSchema)]
#[schemars(untagged)]
#[allow(dead_code)]
pub(super) enum Target {
    Url(String),
    Detailed(UpstreamTargetDetails),
}

#[derive(JsonSchema)]
#[schemars(untagged)]
#[allow(dead_code)]
pub(super) enum Claim {
    Path(String),
    Detailed(ClaimDetails),
}

// Match the string selectors consumed by the custom deserializers.
macro_rules! selector {
    ($name:ident, $value:expr) => {
        pub(super) struct $name;

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                $value
            }
        }
    };
}

selector!(
    RetryFailure,
    schemars::json_schema!({
        "type": "string", "enum": ["connection_failure", "transport_error"]
    })
);
selector!(
    RateSelector,
    schemars::json_schema!({
        "type": "string", "pattern": "^(ip|identity|route|header\\..+)$",
        "examples": ["ip", "identity", "route", "header.x-tenant"]
    })
);
selector!(
    HashSelector,
    schemars::json_schema!({
        "type": "string", "pattern": "^(ip|identity|path|header\\..+)$",
        "examples": ["path", "ip", "identity", "header.x-tenant"]
    })
);

pub(super) fn byte_size(_: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0, "maximum": u64::MAX},
            {"type": "string", "pattern": "^\\s*[0-9]+\\s*([bB]|[kKmMgG]([bB]|[iI][bB])?)?\\s*$"}
        ],
        "examples": [52428800, "50mb", "8 MiB"]
    })
}

// Omission is inheritance, not the explicit null/empty value an editor might insert.
pub(crate) fn inherited_policy(schema: &mut Schema) {
    schema.remove("default");
}

pub(crate) fn one_or_many_hosts(_: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"anyOf": [
        {"type": "string"},
        {"type": "array", "items": {"type": "string"}}
    ]})
}

pub(super) fn upstream_source(schema: &mut Schema) {
    // `url` with an empty `targets` is accepted by the existing visitor.
    // `url: null` with nonempty targets is also accepted. Neither source, or
    // two nonempty sources, is an error rather than an editor suggestion.
    schema.insert(
        "anyOf".into(),
        json!([
            {"required": ["url"], "properties": {
                "url": {"type": "string"}, "targets": {"maxItems": 0}
            }},
            {"required": ["targets"], "properties": {
                "targets": {"minItems": 1}, "url": {"type": "null"}
            }}
        ]),
    );
}

/// Generate a gateway or standalone route-file schema. Output is deterministic
/// and depends only on compiled configuration types, never the environment.
pub fn document(routes: bool) -> Value {
    let generator = SchemaSettings::draft07().into_generator();
    let schema = if routes {
        generator.into_root_schema_for::<RouteGroups>()
    } else {
        generator.into_root_schema_for::<GatewayConfig>()
    };
    let mut value = schema.to_value();
    allow_interpolation(&mut value, false);
    value
}

/// Share this formatting between the CLI and committed-artifact checks.
pub fn formatted(routes: bool) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&document(routes))?
    ))
}

// Interpolation happens before YAML parsing: typed scalars and even entire
// lists/maps can be supplied by variables. Walk schema keywords only, never
// default values or examples, so schema metadata cannot become input schemas.
fn allow_interpolation(value: &mut Value, wrap: bool) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for keyword in ["properties", "definitions", "$defs", "patternProperties"] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                allow_interpolation(child, true);
            }
        }
    }
    for keyword in ["items", "additionalProperties", "not"] {
        if let Some(child) = object.get_mut(keyword) {
            allow_interpolation(child, true);
        }
    }
    for keyword in ["anyOf", "oneOf", "allOf"] {
        if let Some(children) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for child in children {
                // Constraints without a type/ref describe only one part of an
                // input, so do not independently turn them into alternatives.
                allow_interpolation(child, true);
            }
        }
    }
    let unrestricted_string = object.get("type") == Some(&json!("string"))
        && !object.contains_key("enum")
        && !object.contains_key("pattern");
    let typed = object.contains_key("type") || object.contains_key("$ref");
    if !wrap || !typed || unrestricted_string {
        return;
    }

    let mut metadata = serde_json::Map::new();
    for key in ["title", "description", "default", "examples", "deprecated"] {
        if let Some(item) = object.remove(key) {
            metadata.insert(key.into(), item);
        }
    }
    let original = std::mem::take(value);
    // A doubled dollar escapes expansion. Pairwise escapes can precede a real
    // expansion; names and defaults follow config::interpolate's grammar.
    metadata.insert("anyOf".into(), json!([original, {
        "type": "string",
        "pattern": "(^|[^$])(\\$\\$)*\\$\\{[ \\t]*[A-Za-z_][A-Za-z0-9_]*[ \\t]*(:-[^}\\r\\n]*)?\\}"
    }]));
    *value = Value::Object(metadata);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        serde_yaml_ng::from_str(text).unwrap()
    }

    fn validator(routes: bool) -> jsonschema::Validator {
        jsonschema::validator_for(&document(routes)).unwrap()
    }

    #[test]
    fn examples_and_templates_are_valid_editor_input() {
        let validator = validator(false);
        for text in [
            include_str!("../../../../examples/gateway.yml"),
            include_str!("../../../../examples/minimal/gateway.yml"),
            include_str!("../../../../examples/extension/gateway.yml"),
            include_str!("../../templates/minimal-gateway.yml"),
            include_str!("../../templates/docker-gateway.yml"),
            include_str!("../../templates/extension-gateway.yml"),
        ] {
            let value = yaml(text);
            let errors: Vec<_> = validator
                .iter_errors(&value)
                .map(|e| e.to_string())
                .collect();
            assert!(errors.is_empty(), "{errors:?}");
        }
    }

    #[test]
    fn custom_shapes_agree_with_deserialization() {
        let validator = validator(false);
        for text in [
            "defaults: {methods: [GET], retry: {attempts: 2}, rate_limit: {requests: 100}}",
            "defaults: {methods: [], retry: null, rate_limit: null}",
            "routes: {public: [{prefix: /users, upstream: u, methods: [], retry: null, rate_limit: null}]}",
            "upstreams: {u: 'http://svc:8080'}",
            "upstreams: {u: {url: 'svc:8080', targets: []}}",
            "upstreams: {u: {url: null, targets: ['svc:8080', {url: 'svc2:8080', weight: 3}], balance: consistent, hash_on: header.x-tenant, health_check: {timeout: 2s}}}",
            "identity: {claims: {x-id: sub, x-tenant: {claim: tenant, when_null: none}}}",
            "server: {shutdown_grace: null, graceful_shutdown: 25s}",
            "server: {shutdown_grace: 5s}",
            "limits: {max_body: '50 MiB', max_token: 8192}",
            "routes: {public: [{prefix: /users, upstream: u, host: api.example.com, retry: {attempts: 2, on: [transport_error]}, rate_limit: {requests: 10, key: header.x-tenant}}]}",
            "routes: {public: [{prefix: /users, upstream: u, host: [api.example.com, '*.example.com']}]}",
        ] {
            let value = yaml(text);
            assert!(validator.is_valid(&value), "editor rejected: {text}");
            assert!(
                serde_yaml_ng::from_str::<GatewayConfig>(text).is_ok(),
                "runtime rejected: {text}"
            );
        }
    }

    #[test]
    fn invalid_shapes_fail_in_editor_and_deserializer() {
        let validator = validator(false);
        for text in [
            "defaults: {methods: null}",
            "defaults: {cache: true}",
            "defaults: {retry: {on: [transport_error]}}",
            "defaults: {rate_limit: {interval: 60s}}",
            "routes: {public: [{prefix: /users, upstream: u, methods: null}]}",
            "servre: {}",
            "server: {unknown: true}",
            "server: {threads: -1}",
            "server: {graceful_shutdown: 25}",
            "server: {shutdown_grace: 5}",
            "upstreams: {u: {}}",
            "upstreams: {u: {targets: []}}",
            "upstreams: {u: {url: 'svc:8080', targets: ['svc2:8080']}}",
            "upstreams: {u: {targets: [{url: 'svc:8080', weigth: 2}]}}",
            "upstreams: {u: {url: 'svc:8080', balance: fastest}}",
            "upstreams: {u: {url: 'svc:8080', hash_on: header.}}",
            "identity: {claims: {x-id: {cliam: sub}}}",
            "forward: {mode: anything}",
            "limits: {max_body: '50 terabytes'}",
            "routes: {public: [{prefix: /users, upstream: u, host: 42}]}",
            "routes: {public: [{prefix: /users, upstream: u, auth: public}]}",
            "routes: {public: [{prefix: /users, upstream: u, retry: {attempts: 2, on: [502]}}]}",
            "routes: {public: [{prefix: /users, upstream: u, rate_limit: {requests: 10, key: arbitrary}}]}",
        ] {
            let value = yaml(text);
            assert!(!validator.is_valid(&value), "editor accepted: {text}");
            assert!(
                serde_yaml_ng::from_str::<GatewayConfig>(text).is_err(),
                "runtime accepted: {text}"
            );
        }
    }

    #[test]
    fn typed_interpolation_is_checkable_before_variables_are_set() {
        let validator = validator(false);
        for text in [
            "server: {threads: '${THREADS:-2}'}",
            "server: {threads: '${ THREADS }'}",
            "server: {threads: '${THREADS}00'}",
            "forward: {authorization: '${FORWARD_AUTH:-false}', mode: '${FORWARD_MODE}'}",
            "limits: {max_body: '${BODY_LIMIT:-50mb}'}",
            "server: {mounts: '${MOUNTS}'}",
            "auth: '${AUTH_CONFIG}'",
            "upstreams: {u: {targets: '${TARGETS}', balance: '${BALANCE}'}}",
            "routes: {public: [{prefix: /users, upstream: u, retry: {attempts: '${RETRIES}', on: ['${FAILURE}']}}]}",
        ] {
            assert!(
                validator.is_valid(&yaml(text)),
                "rejected interpolation: {text}"
            );
        }
        for value in [
            "${}",
            "${2THREADS}",
            "${THREADS-BAD}",
            "$${THREADS}",
            "${THREADS",
            "anything",
        ] {
            assert!(
                !validator.is_valid(&json!({"server": {"threads": value}})),
                "accepted: {value}"
            );
        }
    }

    #[test]
    fn standalone_routes_use_their_own_document_shape() {
        let validator = validator(true);
        let text = "internal: [/private]\npublic: [{prefix: /users, upstream: u, methods: [GET]}]";
        assert!(validator.is_valid(&yaml(text)));
        assert!(serde_yaml_ng::from_str::<RouteGroups>(text).is_ok());
        assert!(!validator.is_valid(&yaml("routes: {public: []}")));
        assert!(!validator.is_valid(&yaml("public: [{prefix: /users}]")));
    }

    #[test]
    fn defaults_are_input_values_and_runtime_fields_are_absent() {
        let doc = document(false);
        // Human-time serde still serializes actual Duration defaults, while
        // the schema override describes the accepted YAML string.
        assert_eq!(
            doc.pointer("/definitions/Timeouts/anyOf/0/properties/connect/default"),
            Some(&json!("5s"))
        );
        assert_eq!(
            doc.pointer("/definitions/ServerConfig/anyOf/0/properties/threads/default"),
            Some(&json!(2))
        );
        let fields = doc
            .pointer("/definitions/RouteConfig/anyOf/0/properties")
            .unwrap()
            .as_object()
            .unwrap();
        assert!(fields["methods"].get("default").is_none());
        assert!(fields["retry"].get("default").is_none());
        assert!(fields["rate_limit"].get("default").is_none());
        for name in [
            "auth",
            "hosts",
            "bindings",
            "retry_policy",
            "limiter",
            "policy_origins",
        ] {
            assert!(!fields.contains_key(name));
        }
    }

    #[test]
    fn committed_schemas_match_compiled_input_types() {
        assert_eq!(
            formatted(false).unwrap(),
            include_str!("../../../../schemas/gateway.schema.json")
        );
        assert_eq!(
            formatted(true).unwrap(),
            include_str!("../../../../schemas/routes.schema.json")
        );
        assert_eq!(formatted(false).unwrap(), formatted(false).unwrap());
    }
}
