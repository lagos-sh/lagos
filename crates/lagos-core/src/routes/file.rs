//! Route provider backed by a YAML file, re-read when its mtime changes.

use super::{RouteGroups, RouteProvider, RouteTable};

pub struct FileRouteProvider {
    path: String,
}

impl FileRouteProvider {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[async_trait::async_trait]
impl RouteProvider for FileRouteProvider {
    async fn load(&self) -> anyhow::Result<RouteTable> {
        let text = tokio::fs::read_to_string(&self.path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read route file {}: {e}", self.path))?;

        // The route file gets the same `${VAR}` expansion as the main document,
        // so a rollout switch or a per-environment prefix works in either place.
        let expanded = crate::config::interpolate::interpolate_env(&text)
            .map_err(|e| anyhow::anyhow!("{}: {e}", self.path))?;

        let groups: RouteGroups = serde_yaml_ng::from_str(&expanded.text).map_err(|e| {
            let at = e
                .location()
                .map(|l| format!(":{}:{}", l.line(), l.column()))
                .unwrap_or_default();
            anyhow::anyhow!("{}{at}: {e}", self.path)
        })?;

        Ok(RouteTable::build(groups))
    }
}

/// A provider over a table that is already in memory — routes written inline in
/// the main document. Reloading is a no-op: the document that holds them is
/// only read at startup.
pub struct InlineRouteProvider {
    groups: RouteGroups,
}

impl InlineRouteProvider {
    pub fn new(groups: RouteGroups) -> Self {
        Self { groups }
    }
}

#[async_trait::async_trait]
impl RouteProvider for InlineRouteProvider {
    async fn load(&self) -> anyhow::Result<RouteTable> {
        Ok(RouteTable::build(self.groups.clone()))
    }
}
