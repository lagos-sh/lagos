//! Fixed diagnostics shared by commands that promise value-free output.
use crate::config::{ConfigError, InterpolateError};

pub(super) fn interpolation(source: &str, error: InterpolateError) -> anyhow::Error {
    // BadName carries arbitrary document text. Never format the raw error or
    // attach it as a cause: anyhow's error chain would expose that text.
    let (line, reason) = match error {
        InterpolateError::Unterminated { line } => (line, "unterminated variable reference"),
        InterpolateError::EmptyName { line } => (line, "empty variable name"),
        InterpolateError::BadName { line, .. } => (line, "invalid variable name"),
        InterpolateError::ControlCharacter { line, .. } => (line, "invalid substituted value"),
        InterpolateError::Unset { line, .. } => (line, "missing required variable"),
    };
    anyhow::anyhow!("{source}:line {line}: {reason}")
}

pub(super) fn configuration(source: &str, error: ConfigError) -> anyhow::Error {
    match error {
        ConfigError::Interpolate { error, .. } => interpolation(source, error),
        ConfigError::Read { .. } => anyhow::anyhow!("cannot read {source} as UTF-8"),
        ConfigError::Parse { .. } => anyhow::anyhow!("{source}: invalid configuration input"),
        ConfigError::Invalid(_) => {
            anyhow::anyhow!("{source}: configuration failed semantic validation")
        }
    }
}
