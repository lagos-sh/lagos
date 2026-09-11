//! Structured logging.
//!
//! Emits one JSON object per line with the same field names the Node service
//! used, so existing log pipelines and dashboards keep working during a
//! migration.

/// Whether this process is narrating requests rather than logging them.
///
/// Set by `gateway dev` on the child it supervises. Reading it from the
/// environment rather than threading a flag through means the proxy, the
/// telemetry layer and the CLI all agree without a new constructor argument.
pub fn dev_mode() -> bool {
    std::env::var("LAGOS_DEV").as_deref() == Ok("1")
}

pub fn init(service_name: &str, deployment_env: &str) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    // Dev narrates each request itself, so the framework's own startup chatter
    // is noise between the blocks that matter. LOG_LEVEL still wins if set.
    let default = if dev_mode() {
        "warn,lagos_core=warn"
    } else {
        "info"
    };
    let filter = EnvFilter::try_from_env("LOG_LEVEL")
        .or_else(|_| EnvFilter::try_new(default))
        .unwrap_or_default();

    // Dev narrates each request itself; the structured line would double it.
    let json = !dev_mode() && std::env::var("NODE_ENV").as_deref() != Ok("development");

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(false),
            )
            .init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }

    if !dev_mode() {
        tracing::info!(
            service = service_name,
            deployment.environment = deployment_env,
            "logging initialized",
        );
    }
}
