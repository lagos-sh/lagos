#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
const CONFIG: &str = r#"
server:
  mounts: [/v1, /v1/nested]
  internal_listen: 127.0.0.1:9999
  health_path: /healthz
auth:
  machine:
    secret: machine-secret-fixture
inject:
  headers:
    x-public: public-secret-fixture
  machine:
    x-private: private-secret-fixture
upstreams:
  users: http://127.0.0.1:1
routes:
  internal: [/users/private]
  public:
    - id: api-get
      prefix: /users
      host: api.example.com
      methods: [GET]
      upstream: users
    - id: other-post
      prefix: /users
      host: other.example.com
      methods: [POST]
      upstream: users
    - id: wildcard-get
      prefix: /users
      host: '*.example.net'
      methods: [GET]
      upstream: users
    - id: any-method
      prefix: /any
      upstream: users
    - id: disabled
      prefix: /users
      enabled: false
      upstream: users
  authenticated:
    - id: secure
      prefix: /secure
      upstream: users
  machine:
    - id: machine-users
      prefix: /users
      methods: [GET]
      upstream: users
"#;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lagos-explain-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("gateway.yml"), CONFIG).unwrap();
        Self(path)
    }
    fn explain(&self, args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_lagos"))
            .current_dir(&self.0)
            .env_clear()
            .args(["explain", "--config", "gateway.yml"])
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("UNCHECKED: credentials"));
        assert!(text.contains("not a verified or proxied request"));
        for secret in [
            "machine-secret-fixture",
            "public-secret-fixture",
            "private-secret-fixture",
        ] {
            assert!(!text.contains(secret));
        }
        text
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn each_prefix_candidate_reports_all_failed_constraints() {
    let dir = Scratch::new();
    let text = dir.explain(&[
        "--path",
        "/v1/users/42",
        "--method",
        "PATCH",
        "--host",
        "wrong.example.org",
        "--why-not",
    ]);
    assert!(text.contains("api-get  /users  (group: public): host mismatch; requires api.example.com; method mismatch; allows GET"));
    assert!(text.contains("other-post  /users  (group: public): host mismatch; requires other.example.com; method mismatch; allows POST"));
    assert!(text.contains("wildcard-get  /users"));
    assert!(text.contains(
        "machine-users  /users  (group: machine): belongs to internal listener; method mismatch"
    ));
    assert!(text.contains("404 (not_allowlisted)"));
    assert!(!text.contains("disabled"));
    let missing = dir.explain(&["--path", "/v1/users", "--why-not"]);
    assert!(missing.contains("Host header missing; requires api.example.com"));
    assert!(!missing.contains("api-get  /users  (group: public): method mismatch"));
}

#[test]
fn host_normalization_wildcards_and_unrestricted_methods_select_routes() {
    let dir = Scratch::new();
    for (host, id) in [
        ("API.EXAMPLE.COM:443", "api-get"),
        ("a.example.net:8080", "wildcard-get"),
    ] {
        let text = dir.explain(&[
            "--path",
            "/v1/users",
            "--method",
            "get",
            "--host",
            host,
            "--why-not",
        ]);
        assert!(text.contains(&format!("✓ {id}  (group: public)")));
        assert!(!text.contains("Prefix candidates"));
    }
    let bare = dir.explain(&["--path", "/v1/users", "--host", "example.net", "--why-not"]);
    assert!(bare.contains("wildcard-get  /users  (group: public): host mismatch"));
    let any = dir.explain(&["--path", "/v1/any", "--method", "PATCH", "--why-not"]);
    assert!(any.contains("✓ any-method"));
}

#[test]
fn mounts_queries_and_canonical_paths_agree_with_selection() {
    let dir = Scratch::new();
    let text = dir.explain(&[
        "--path",
        "/v1/nested/%75sers/42?next=ignored",
        "--host",
        "api.example.com",
        "--why-not",
    ]);
    assert!(text.contains("✓ /v1/nested"));
    assert!(text.contains("canonicalized to `users/42`"));
    assert!(text.contains("✓ api-get"));
    let outside = dir.explain(&["--path", "/v1x/users", "--why-not"]);
    assert!(outside.contains("404 (outside_base_path)"));
    assert!(!outside.contains("Prefix candidates"));
    let unsafe_path = dir.explain(&["--path", "/v1/users/%2e%2e/admin", "--why-not"]);
    assert!(unsafe_path.contains("404 (unsafe_path)"));
    assert!(!unsafe_path.contains("Prefix candidates"));
    let boundary = dir.explain(&["--path", "/v1/users-admin", "--why-not"]);
    assert!(boundary.contains("no enabled route has a matching canonical prefix"));
}

#[test]
fn deny_rules_and_listener_partitioning_are_explained() {
    let dir = Scratch::new();
    let denied = dir.explain(&[
        "--path",
        "/v1/users/private",
        "--host",
        "api.example.com",
        "--why-not",
    ]);
    assert!(denied.contains("404 (deny_list)"));
    assert!(denied.contains("api-get  /users  (group: public): blocked by deny-list"));
    assert!(
        denied.contains("machine-users  /users  (group: machine): belongs to internal listener")
    );
    let machine = dir.explain(&[
        "--path",
        "/v1/users/private",
        "--listener",
        "internal",
        "--why-not",
    ]);
    assert!(machine.contains("✓ machine-users  (group: machine)"));
    assert!(machine.contains("shared credential on the internal listener only"));
    assert!(machine.contains("x-private: <redacted>"));
    assert!(!machine.contains("x-public:"));
    let wrong = dir.explain(&["--path", "/v1/any", "--listener", "internal", "--why-not"]);
    assert!(wrong.contains("any-method  /any  (group: public): belongs to public listener"));
}

#[test]
fn local_health_and_disabled_internal_listener_are_distinct_results() {
    let dir = Scratch::new();
    for listener in ["public", "internal"] {
        let health = dir.explain(&[
            "--path",
            "/healthz?ready=yes",
            "--listener",
            listener,
            "--why-not",
        ]);
        assert!(health.contains("200 (local_health)"));
        assert!(!health.contains("Prefix candidates"));
    }
    std::fs::write(dir.0.join("gateway.yml"), "upstreams:\n  users: http://127.0.0.1:1\nroutes:\n  public:\n    - prefix: /users\n      upstream: users\n").unwrap();
    let disabled = dir.explain(&["--path", "/users", "--listener", "internal", "--why-not"]);
    assert!(disabled.contains("listener unavailable: server.internal_listen is not configured"));
    assert!(!disabled.contains("404"));
}

#[test]
fn ordinary_explain_does_not_claim_host_failure_is_method_failure() {
    let dir = Scratch::new();
    let text = dir.explain(&["--path", "/v1/users", "--host", "wrong.example.org"]);
    assert!(text.contains("404 (not_allowlisted)"));
    assert!(!text.contains("allows only"));
    assert!(!text.contains("Prefix candidates"));
    let secure = dir.explain(&["--path", "/v1/secure", "--why-not"]);
    assert!(secure.contains("✓ secure  (group: authenticated)"));
    assert!(secure.contains("a valid token is required"));
}
