#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const DEFAULTS: &str = "defaults:\n  methods: [GET]\n  retry: {attempts: 2, non_idempotent: true}\n  rate_limit: {requests: 100, interval: 120s, key: route}\n";
const UPSTREAMS: &str = "upstreams: {u: 'http://127.0.0.1:1'}\n";
const ROUTES: &str = "public:\n  - {id: inherited, prefix: /inherit, upstream: u}\n  - {id: disabled, prefix: /disable, upstream: u, methods: [], retry: null, rate_limit: null}\n  - {id: replaced, prefix: /replace, upstream: u, methods: [POST], retry: {attempts: 0}, rate_limit: {requests: 5}}\n";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lagos-defaults-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).unwrap();
    }
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lagos"))
            .current_dir(&self.0)
            .env_clear()
            .envs(env.iter().copied())
            .args(args)
            .output()
            .unwrap()
    }
    fn text(&self, args: &[&str]) -> String {
        let output = self.run(args, &[]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }
    fn view(&self, name: &str, env: &[(&str, &str)]) -> Value {
        let output = self.run(&["config", "--effective", name], env);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn config(&self, external: bool) {
        self.write("routes.yml", ROUTES);
        let routes = if external {
            "routes: {file: routes.yml}\n".to_string()
        } else {
            format!(
                "routes:\n{}",
                ROUTES
                    .lines()
                    .map(|line| format!("  {line}\n"))
                    .collect::<String>()
            )
        };
        self.write("gateway.yml", &format!("{DEFAULTS}{UPSTREAMS}{routes}"));
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn inline_and_external_tools_resolve_the_same_policies_and_origins() {
    let dir = Scratch::new();
    for external in [false, true] {
        dir.config(external);
        assert!(dir.text(&["validate", "gateway.yml"]).contains("valid"));
        let rows = dir.text(&["routes", "gateway.yml"]);
        assert!(rows.contains(
            "methods=global defaults, retry=global defaults, rate_limit=global defaults"
        ));
        assert!(rows.contains("methods=route, retry=route, rate_limit=route"));
        let inherited = dir.text(&["explain", "--config", "gateway.yml", "--path", "/inherit"]);
        assert!(inherited.contains("methods: global defaults"));
        assert!(inherited.contains("up to 2 after the first attempt"));
        let not_allowed = dir.text(&[
            "explain",
            "--config",
            "gateway.yml",
            "--path",
            "/inherit",
            "--method",
            "POST",
            "--why-not",
        ]);
        assert!(not_allowed.contains("method mismatch; allows GET"));
        let disabled = dir.text(&[
            "explain",
            "--config",
            "gateway.yml",
            "--path",
            "/disable",
            "--method",
            "PATCH",
        ]);
        assert!(disabled.contains("✓ disabled"));
        assert!(!disabled.contains("up to 2"));
        let view = dir.view("gateway.yml", &[]);
        let routes = view["configuration"]["routes"].as_array().unwrap();
        let inherited = routes
            .iter()
            .find(|route| route["retry"]["policy_origin"] == "global defaults")
            .unwrap();
        assert_eq!(inherited["methods"]["value"], serde_json::json!(["GET"]));
        assert_eq!(inherited["retry"]["value"]["attempts"], 2);
        assert_eq!(inherited["rate_limit"]["value"]["interval"], "120s");
        assert_eq!(inherited["retry"]["origin"], "CONFIG.defaults.retry");
        assert!(
            routes.iter().any(|route| route["retry"]["value"].is_null()
                && route["retry"]["policy_origin"] == "route")
        );
        let replaced = routes
            .iter()
            .find(|route| route["rate_limit"]["value"]["requests"] == 5)
            .unwrap();
        assert_eq!(replaced["retry"]["value"]["non_idempotent"], false);
        assert_eq!(replaced["rate_limit"]["value"]["interval"], "60s");
        dir.write("gateway.test.yml", "tests:\n  - name: inherited GET\n    request: {path: /inherit}\n    expect: {result: route, route: inherited}\n  - name: inherited method restriction\n    request: {path: /inherit, method: POST}\n    expect: {result: no_route}\n  - name: explicit any method\n    request: {path: /disable, method: PATCH}\n    expect: {result: route, route: disabled}\n");
        assert!(
            dir.text(&["test", "gateway.yml"])
                .contains("3 passed, 0 failed")
        );
    }
}

#[test]
fn defaults_only_diff_reports_effective_changes_and_restart_boundary() {
    let dir = Scratch::new();
    dir.config(true);
    let old = std::fs::read_to_string(dir.0.join("gateway.yml")).unwrap();
    dir.write(
        "next.yml",
        &old.replace("requests: 100", "requests: 200")
            .replace("attempts: 2", "attempts: 3")
            .replace("methods: [GET]", "methods: [GET, HEAD]"),
    );
    let diff = dir.text(&["diff", "gateway.yml", "next.yml"]);
    for field in ["methods", "retry", "rate_limit"] {
        assert!(diff.contains(&format!("~ route inherited: {field}:")));
    }
    assert!(!diff.contains("~ route disabled:"));
    assert!(!diff.contains("~ route replaced:"));
    assert!(diff.contains("Top-level defaults require restart"));
}

#[test]
fn invalid_defaults_and_invalid_replacements_fail_before_any_json_output() {
    let dir = Scratch::new();
    for defaults in [
        "defaults: {cache: true}\n",
        "defaults: {methods: null}\n",
        "defaults: {rate_limit: {requests: 0}}\n",
        "defaults: {retry: {non_idempotent: true}}\n",
    ] {
        dir.write(
            "gateway.yml",
            &format!(
                "{defaults}{UPSTREAMS}routes: {{public: [{{prefix: /items, upstream: u}}]}}\n"
            ),
        );
        for args in [
            vec!["validate", "gateway.yml"],
            vec!["config", "--effective", "gateway.yml"],
        ] {
            let output = dir.run(&args, &[]);
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
        }
    }
    for policy in [
        "methods: null",
        "retry: {non_idempotent: false}",
        "rate_limit: {interval: 5s}",
    ] {
        dir.write("gateway.yml", &format!("{DEFAULTS}{UPSTREAMS}routes: {{public: [{{prefix: /items, upstream: u, {policy}}}]}}\n"));
        assert!(!dir.run(&["validate", "gateway.yml"], &[]).status.success());
    }
}

#[test]
fn inherited_interpolated_values_stay_redacted_even_in_literal_external_routes() {
    let dir = Scratch::new();
    dir.config(true);
    let original = std::fs::read_to_string(dir.0.join("gateway.yml")).unwrap();
    for modified in [
        original.replace("requests: 100", "requests: ${QUOTA}"),
        original.replace(
            "{requests: 100, interval: 120s, key: route}",
            "${RATE_POLICY}",
        ),
    ] {
        dir.write("gateway.yml", &modified);
        let view = dir.view(
            "gateway.yml",
            &[
                ("QUOTA", "987654321"),
                (
                    "RATE_POLICY",
                    "{requests: 987654321, interval: 120s, key: route}",
                ),
            ],
        );
        assert!(!view.to_string().contains("987654321"));
        let route = view["configuration"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rate_limit"]["policy_origin"] == "global defaults")
            .unwrap();
        assert_eq!(route["rate_limit"]["value"], "<redacted>");
        assert_eq!(route["rate_limit"]["redacted"], true);
        assert!(
            view["configuration"]["routes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["rate_limit"]["value"]["requests"] == 5)
        );
    }
}
