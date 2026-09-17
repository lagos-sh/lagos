#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
const BASE: &str = "upstreams:\n  users: http://127.0.0.1:1\nroutes:\n  public:\n    - prefix: /users\n      upstream: users\n";
const SECRET: &str = "effective-fixture-secret-do-not-print";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lagos-effective-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, file: &str, text: &str) {
        std::fs::write(self.0.join(file), text).unwrap();
    }
    fn run(&self, file: &str, environment: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lagos"))
            .current_dir(&self.0)
            .env_clear()
            .envs(environment.iter().copied())
            .args(["config", "--effective", file])
            .output()
            .unwrap()
    }
    fn view(&self, file: &str, environment: &[(&str, &str)]) -> Value {
        let output = self.run(file, environment);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn dedicated_view_hides_every_string_surface_and_keeps_typed_policy() {
    let dir = Scratch::new();
    let config = format!(
        r#"
server:
  service_name: {SECRET}
  internal_listen: 127.0.0.1:9999
  threads: 3
auth:
  machine:
    secret: {SECRET}
identity:
  claims:
    x-custom: {{claim: '{SECRET}', when_null: '{SECRET}'}}
  token:
    secret: {SECRET}
    audience: {SECRET}
inject:
  headers:
    x-{SECRET}: {SECRET}
  machine:
    x-machine: {SECRET}
forward:
  headers: [{SECRET}]
reject:
  client_headers: [{SECRET}]
observability:
  tracing:
    otlp:
      endpoint: http://127.0.0.1:1/{SECRET}
cors:
  origins: [https://{SECRET}.example.test]
upstreams:
  {SECRET}: http://user:{SECRET}@127.0.0.1:1/{SECRET}?credential={SECRET}
routes:
  public:
    - id: {SECRET}
      prefix: /{SECRET}
      host: {SECRET}.example.test
      upstream: {SECRET}
      methods: [GET, {SECRET}]
      retry: {{attempts: 2}}
      rate_limit: {{requests: 100, key: header.{SECRET}}}
      extensions: [{SECRET}]
  machine:
    - id: internal-{SECRET}
      prefix: /internal
      upstream: {SECRET}
"#
    );
    dir.write("gateway.yml", &config);
    let view = dir.view("gateway.yml", &[]);
    assert_eq!(view["diagnostic"], true);
    assert_eq!(view["suitable_for_deployment"], false);
    assert_eq!(view["is_running_snapshot"], false);
    assert_eq!(view["configuration"]["server"]["threads"]["value"], 3);
    assert_eq!(
        view["configuration"]["server"]["threads"]["origin"],
        "CONFIG.server.threads"
    );
    assert_eq!(
        view["configuration"]["timeouts"]["default"]["origin"],
        "built-in"
    );
    let public = view["configuration"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["group"] == "public")
        .unwrap();
    assert_eq!(
        public["methods"]["value"],
        serde_json::json!(["GET", "<redacted>"])
    );
    assert_eq!(public["retry"]["value"]["attempts"], 2);
    assert_eq!(public["rate_limit"]["value"]["requests"], 100);
    assert_eq!(public["extensions"]["status"], "unchecked");
    assert_eq!(public["upstream"]["value"], "upstream-1");
    assert!(
        lagos_core::config::GatewayConfig::parse_with("diagnostic.json", &view.to_string(), |_| {
            None
        })
        .is_err()
    );
}

#[test]
fn interpolation_and_secret_defaults_are_hidden_including_numeric_fields() {
    let dir = Scratch::new();
    dir.write("gateway.yml", &format!("server:\n  threads: ${{THREADS}}\n  service_name: ${{NAME:-{SECRET}}}\ntimeouts:\n  connect: ${{CONNECT:-987654321s}}\n{BASE}"));
    let output = dir.run("gateway.yml", &[("THREADS", "987654321")]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains(SECRET));
    assert!(!text.contains("987654321"));
    let view: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(view["configuration"]["server"]["threads"]["redacted"], true);
    assert_eq!(
        view["configuration"]["timeouts"]["connect"]["redacted"],
        true
    );
    assert_eq!(view["configuration"]["timeouts"]["default"]["value"], "30s");
}

#[test]
fn same_line_injected_fields_cannot_masquerade_as_built_in_defaults() {
    let dir = Scratch::new();
    dir.write(
        "gateway.yml",
        &format!("dns: {{cache_ttl: ${{TTL}}}}\n{BASE}"),
    );
    let view = dir.view("gateway.yml", &[("TTL", "30s, max_entries: 987654321")]);
    assert_eq!(
        view["configuration"]["dns"]["max_entries"]["value"],
        "<redacted>"
    );
    assert_eq!(
        view["configuration"]["dns"]["max_entries"]["origin"],
        "CONFIG.dns.max_entries"
    );
    assert!(!view.to_string().contains("987654321"));
}

#[test]
fn external_routes_use_their_own_snapshot_and_conservative_group_provenance() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.0.join("config")).unwrap();
    dir.write(
        "config/gateway.yml",
        "upstreams:\n  users: http://127.0.0.1:1\nroutes:\n  file: ${FILE}\n",
    );
    dir.write(&format!("config/{SECRET}.yml"), "public:\n  - id: user\n    prefix: /users\n    upstream: users\n    retry: {attempts: ${ATTEMPTS}}\n");
    let view = dir.view(
        "config/gateway.yml",
        &[
            ("FILE", &format!("{SECRET}.yml")),
            ("ATTEMPTS", "987654321"),
        ],
    );
    assert_eq!(view["sources"][1]["label"], "routes.file");
    assert_eq!(view["sources"][1]["path"], "<redacted>");
    assert_eq!(
        view["configuration"]["routes"][0]["retry"]["origin"],
        "routes.file.public"
    );
    assert_eq!(
        view["configuration"]["routes"][0]["retry"]["redacted"],
        true
    );
    assert!(!view.to_string().contains("987654321"));
}

#[test]
fn structure_substitutions_and_interpolated_keys_hide_child_policy_values() {
    let dir = Scratch::new();
    for (yaml, env) in [
        (
            "server: ${SERVER}\n",
            vec![("SERVER", "{threads: 987654321}")],
        ),
        (
            "${ROOT}\n",
            vec![(
                "ROOT",
                "{server: {threads: 987654321}, upstreams: {users: http://127.0.0.1:1}, routes: {public: [{prefix: /users, upstream: users}]}}",
            )],
        ),
        ("server:\n  ${KEY}: 987654321\n", vec![("KEY", "threads")]),
    ] {
        let yaml = if yaml.starts_with("${ROOT}") {
            yaml.to_string()
        } else {
            format!("{yaml}{BASE}")
        };
        dir.write("gateway.yml", &yaml);
        let view = dir.view("gateway.yml", &env);
        assert_eq!(view["configuration"]["server"]["threads"]["redacted"], true);
        assert!(!view.to_string().contains("987654321"));
    }
}

#[test]
fn failures_never_echo_config_paths_payloads_or_values() {
    let dir = Scratch::new();
    let file = format!("{SECRET}.yml");
    for (yaml, env) in [
        (format!("server: {{threads: {SECRET}}}\n"), vec![]),
        (format!("{SECRET}: forbidden\n"), vec![]),
        (format!("key: ${{{SECRET}}}\n"), vec![]),
        (
            format!("forward:\n  trusted_proxy_ips: [{SECRET}]\n{BASE}"),
            vec![],
        ),
        (format!("routes:\n  file: {SECRET}-missing.yml\n"), vec![]),
        (
            "server:\n  service_name: ${VALUE}\n".into(),
            vec![("VALUE", "effective-fixture-secret-do-not-print\nextra")],
        ),
        (
            format!("routes:\n  public:\n    - prefix: /users\n      upstream: {SECRET}\n"),
            vec![],
        ),
        ("server:\n  threads: ${MISSING}\n".into(), vec![]),
    ] {
        dir.write(&file, &yaml);
        let output = dir.run(&file, &env);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    }
    dir.write(&file, "routes:\n  file: routes.yml\n");
    dir.write("routes.yml", &format!("public:\n  - unknown: {SECRET}\n"));
    let output = dir.run(&file, &[]);
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}

#[test]
fn config_requires_effective_flag_and_has_no_raw_mode() {
    let dir = Scratch::new();
    for args in [vec!["config"], vec!["config", "--effective", "--raw"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_lagos"))
            .current_dir(&dir.0)
            .env_clear()
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
