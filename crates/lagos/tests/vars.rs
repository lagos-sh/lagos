#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);
const SECRET: &str = "inventory-secret-must-never-appear";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lagos-vars-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, file: &str, text: &str) {
        std::fs::write(self.0.join(file), text).unwrap();
    }
    fn run(&self, extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lagos"));
        command
            .current_dir(&self.0)
            .args(["vars", "gateway.yml"])
            .env_clear()
            .envs(extra.iter().copied());
        command.output().unwrap()
    }
    fn text(&self, extra: &[(&str, &str)]) -> String {
        let output = self.run(extra);
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(SECRET));
        text
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn inventory_preserves_each_reference_and_runtime_rules() {
    let dir = Scratch::new();
    dir.write(
        "gateway.yml",
        &format!(
            r#"# ${{COMMENT}}
upstreams:
  users: ${{SAME}}
  orders: ${{SAME:-{SECRET}}}
  carts: ${{SET:-{SECRET}}} # ${{IGNORED}}
  escaped: $${{ESCAPED}}
  empty: ${{BLANK:-}}
  spaces: ${{SPACES}}
  quoted: "literal # ${{QUOTED}}"
  block: |
    # ${{BLOCK}}
routes:
  public: []
"#
        ),
    );
    let text = dir.text(&[("SET", SECRET), ("BLANK", ""), ("SPACES", " \t ")]);
    assert!(text.contains("CONFIG:3:10\tSAME\trequired (unset)\tno"));
    assert!(text.contains("CONFIG:4:11\tSAME\tdefaulted\tyes"));
    assert!(text.contains("\tSET\tset\tyes"));
    assert!(text.contains("\tBLANK\tdefaulted\tyes"));
    for name in ["SPACES", "QUOTED", "BLOCK"] {
        assert!(text.contains(&format!("\t{name}\trequired (unset)\tno")));
    }
    for name in ["COMMENT", "IGNORED", "ESCAPED"] {
        assert!(!text.contains(name));
    }
    assert!(text.contains("Inventory complete"));
}

#[test]
fn external_file_is_relative_to_gateway_and_its_path_values_are_hidden() {
    let dir = Scratch::new();
    std::fs::create_dir(dir.0.join("config")).unwrap();
    dir.write(
        "config/gateway.yml",
        "upstreams:\n  users: ${URL}\nroutes:\n  file: ${ROUTE_FILE}\n",
    );
    dir.write(&format!("config/{SECRET}.yml"), &format!("public:\n  - prefix: /users\n    upstream: users\n    inject:\n      x-key: ${{KEY:-{SECRET}}}\n"));
    let output = Command::new(env!("CARGO_BIN_EXE_lagos"))
        .current_dir(&dir.0)
        .args(["vars", "config/gateway.yml"])
        .env_clear()
        .env("ROUTE_FILE", format!("{SECRET}.yml"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("routes.file:5:14\tKEY\tdefaulted\tyes"));
    assert!(text.contains("Inventory complete (CONFIG and routes.file)"));
    assert!(!text.contains(SECRET));
}

#[test]
fn unresolved_unreadable_and_opaque_route_sources_are_unchecked() {
    let dir = Scratch::new();
    for (yaml, env) in [
        ("routes:\n  file: ${PATH}\n", vec![]),
        ("routes:\n  file: ${PATH}\n", vec![("PATH", SECRET)]),
        ("routes: ${ROUTES}\n", vec![("ROUTES", SECRET)]),
        ("${ROOT}\n", vec![]),
        ("routes:\n  ${KEY}: source.yml\n", vec![]),
        ("broken: [\nroutes:\n  file: source.yml\n", vec![]),
    ] {
        dir.write("gateway.yml", yaml);
        let text = dir.text(&env);
        assert!(text.contains("UNCHECKED routes.file:"));
        assert!(text.contains("inventory incomplete"));
        assert!(!text.contains("Inventory complete"));
    }
}

#[test]
fn invalid_values_and_syntax_errors_do_not_echo_secret_fixtures() {
    let dir = Scratch::new();
    dir.write("gateway.yml", "upstreams:\n  users: ${URL}\n");
    let text = dir.text(&[("URL", &format!("{SECRET}\nextra"))]);
    assert!(text.contains("\tURL\tinvalid (control character)"));
    for yaml in [
        format!("key: ${{{SECRET}}}\n"),
        format!("key: ${{NAME:-{SECRET}\n"),
    ] {
        dir.write("gateway.yml", &yaml);
        let output = dir.run(&[]);
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains(SECRET));
        assert!(stderr.contains("CONFIG:line 1:"));
        assert!(output.stdout.is_empty());
    }
    dir.write("gateway.yml", &format!("routes:\n  file: {SECRET}.yml\n"));
    assert!(dir.text(&[]).contains("UNCHECKED"));
}

#[test]
fn escaped_file_reference_is_a_literal_filename() {
    let dir = Scratch::new();
    dir.write("gateway.yml", "routes:\n  file: $${FILE}.yml\n");
    dir.write("${FILE}.yml", "public: []\n");
    let text = dir.text(&[("FILE", SECRET)]);
    assert!(!text.contains("\tFILE\t"));
    assert!(text.contains("Inventory complete (CONFIG and routes.file)"));
}

#[test]
fn file_substitutions_are_decoded_by_yaml_like_runtime() {
    let dir = Scratch::new();
    dir.write("gateway.yml", "routes:\n  file: \"${FILE}\"\n");
    dir.write("routes.yml", "public: []\n");
    let text = dir.text(&[("FILE", r"routes\u002eyml")]);
    assert!(text.contains("Inventory complete (CONFIG and routes.file)"));
}
