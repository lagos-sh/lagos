//! Your application-specific policy. Route names refer to NAMES below.

use std::sync::Arc;

use lagos_core::{Extension, ExtensionContext, Rejection};

/// Names available during offline `validate --allow-unset`.
pub const NAMES: &[&str] = &["example-header"];

/// Constructors run on `run` and ordinary `validate`, with the real environment.
pub fn extensions() -> anyhow::Result<Vec<Arc<dyn Extension>>> {
    Ok(vec![Arc::new(ExampleHeader)])
}

struct ExampleHeader;

#[async_trait::async_trait]
impl Extension for ExampleHeader {
    fn name(&self) -> &'static str {
        "example-header"
    }

    async fn on_request(&self, cx: &mut ExtensionContext<'_>) -> Result<(), Rejection> {
        cx.plan.set("x-lagos-example", "custom".to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_names_match_runtime_extensions() {
        let registered = extensions().expect("build example extensions");
        let names: Vec<_> = registered.iter().map(|extension| extension.name()).collect();
        assert_eq!(names, NAMES);
    }
}
