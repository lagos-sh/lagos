#![allow(clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lagos-schema-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_lagos"))
            .current_dir(&self.0)
            .env("GATEWAY_CONFIG", "does-not-exist.yml")
            .env("INTERNAL_API_KEY", "schema-must-not-read-this-secret")
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn schema_stdout_is_independent_of_configuration() {
    let dir = Scratch::new();
    std::fs::write(dir.0.join("gateway.yml"), "not: valid: yaml:").unwrap();
    for (args, expected) in [
        (
            vec!["schema"],
            include_str!("../../../schemas/gateway.schema.json"),
        ),
        (
            vec!["schema", "--routes"],
            include_str!("../../../schemas/routes.schema.json"),
        ),
    ] {
        let output = dir.run(&args);
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn init_can_use_a_local_schema_without_creating_extra_files() {
    let dir = Scratch::new();
    let output = dir.run(&["init", "--docker", "--schema", "./gateway.schema.json"]);
    assert!(output.status.success(), "{:?}", output.stderr);
    let gateway = std::fs::read_to_string(dir.0.join("gateway.yml")).unwrap();
    assert!(gateway.starts_with("# yaml-language-server: $schema=./gateway.schema.json\n"));
    let dockerfile = std::fs::read_to_string(dir.0.join("Dockerfile")).unwrap();
    assert!(dockerfile.contains(env!("CARGO_PKG_VERSION")));
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 2);
    // Existing destinations remain protected even with an editor option.
    assert!(
        !dir.run(&["init", "--docker", "--schema", "other.json"])
            .status
            .success()
    );
    assert_eq!(
        std::fs::read_to_string(dir.0.join("gateway.yml")).unwrap(),
        gateway
    );
}
