//! Value-free environment inventory. Never attach raw YAML, parser errors,
//! interpolated filenames or selected values to diagnostics.

use std::io::Write;
use std::path::Path;

use crate::config::interpolate::{Inspection, VariableState, inspect};

pub(super) fn run(given: Option<String>) -> anyhow::Result<()> {
    let path = super::resolve_config_path(given)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("cannot read CONFIG as UTF-8"))?;
    let gateway = inspect_env(&text, "CONFIG")?;
    let mut output = String::from("SOURCE:LINE:COLUMN\tVARIABLE\tSTATE\tDEFAULT\tREQUIRED\n");
    append(&mut output, "CONFIG", &gateway);

    match route_source(&gateway) {
        RouteSource::Inline => output.push_str("Inventory complete (inline routes).\n"),
        RouteSource::Unchecked(reason) => {
            output.push_str(&format!(
                "UNCHECKED routes.file: {reason}; inventory incomplete.\n"
            ));
        }
        RouteSource::File => {
            // Substitutions precede YAML decoding at runtime. Re-read the
            // scalar through that pipeline so quotes and backslash escapes in
            // a selected filename have exactly the same meaning. Never print
            // the expanded document or its parser errors.
            let Some(file) = runtime_file(&text) else {
                output.push_str("UNCHECKED routes.file: cannot resolve path through runtime interpolation; inventory incomplete.\n");
                output.push_str("Values and default text are hidden. This inventory does not validate configuration.\n");
                std::io::stdout().lock().write_all(output.as_bytes())?;
                return Ok(());
            };
            let file = Path::new(&path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(file);
            match std::fs::read_to_string(file) {
                Ok(text) => {
                    let routes = inspect_env(&text, "routes.file")?;
                    append(&mut output, "routes.file", &routes);
                    output.push_str("Inventory complete (CONFIG and routes.file).\n");
                }
                Err(_) => output.push_str(
                    "UNCHECKED routes.file: cannot read file as UTF-8; inventory incomplete.\n",
                ),
            }
        }
    }
    output.push_str(
        "Values and default text are hidden. This inventory does not validate configuration.\n",
    );
    std::io::stdout().lock().write_all(output.as_bytes())?;
    Ok(())
}

fn inspect_env(text: &str, source: &str) -> anyhow::Result<Inspection> {
    inspect(text, |name| std::env::var(name).ok())
        .map_err(|error| super::diagnostics::interpolation(source, error))
}

fn append(output: &mut String, source: &str, inspection: &Inspection) {
    for reference in &inspection.references {
        let state = match reference.state {
            VariableState::Set => "set",
            VariableState::Defaulted => "defaulted",
            VariableState::Required => "required (unset)",
            VariableState::Invalid => "invalid (control character)",
        };
        output.push_str(&format!(
            "{source}:{}:{}\t{}\t{state}\t{}\t{}\n",
            reference.line,
            reference.column,
            reference.name,
            if reference.has_default { "yes" } else { "no" },
            if reference.has_default { "no" } else { "yes" },
        ));
    }
}

fn runtime_file(text: &str) -> Option<String> {
    let fallback = |_: &str| "lagos-vars-unset".to_string();
    let expanded =
        crate::config::interpolate::interpolate_env_with_fallback(text, Some(&fallback)).ok()?;
    let root: serde_yaml_ng::Value = serde_yaml_ng::from_str(&expanded.text).ok()?;
    root.get("routes")?
        .get("file")?
        .as_str()
        .map(str::to_string)
}

enum RouteSource {
    Inline,
    File,
    Unchecked(&'static str),
}

fn route_source(inspection: &Inspection) -> RouteSource {
    use serde_yaml_ng::Value;

    // Parse only masked text. Parser diagnostics may quote arbitrary secrets,
    // so failure is reported using a fixed message rather than the error.
    let Ok(Value::Mapping(root)) = serde_yaml_ng::from_str(&inspection.masked) else {
        return RouteSource::Unchecked("cannot identify routes in the masked YAML");
    };
    if root
        .keys()
        .any(|key| key.as_str().is_some_and(|s| inspection.contains_marker(s)))
    {
        return RouteSource::Unchecked("a variable supplies a configuration key");
    }
    let Some(routes) = root.get(Value::String("routes".into())) else {
        return RouteSource::Inline;
    };
    let Value::Mapping(routes) = routes else {
        return RouteSource::Unchecked("routes is not a literal mapping");
    };
    if routes
        .keys()
        .any(|key| key.as_str().is_some_and(|s| inspection.contains_marker(s)))
    {
        return RouteSource::Unchecked("a variable supplies a routes key");
    }
    match routes.get(Value::String("file".into())) {
        None | Some(Value::Null) => RouteSource::Inline,
        Some(Value::String(file)) => match inspection.resolve_scalar(file) {
            Some(_) => RouteSource::File,
            None => RouteSource::Unchecked("path depends on an unset or invalid variable"),
        },
        Some(_) => RouteSource::Unchecked("file path is not a string"),
    }
}
