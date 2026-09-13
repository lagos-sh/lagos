//! Lagos — an identity-aware HTTP gateway built on Pingora.
//!
//! The gateway verifies caller identity once at the edge and hands downstream
//! services a request they can trust, so those services need no knowledge of
//! the identity provider. What it routes, what it refuses, and what it injects
//! are entirely declarative; anything deployment-specific is an [`ext::Extension`].

// Test code asserts on known-good fixtures, where a panic *is* the failure
// report. The lints below stay on for everything that can see a request.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod accept;
pub mod auth;
pub mod binding;
pub mod breaker;
#[cfg(feature = "cache")]
pub mod cache;
pub mod cli;
pub mod config;
pub mod cors;
pub mod dns;
pub mod error;
pub mod ext;
pub mod headers;
pub mod identity;
pub mod metrics;
pub mod otel;
pub mod path;
pub mod proxy;
pub mod ratelimit;
pub mod retry;
pub mod routes;
pub mod runtime;
pub mod telemetry;
pub mod trace;
pub mod upstream;

pub use cli::Cli;
pub use config::{ConfigError, GatewayConfig, ResolvedConfig};
pub use error::Rejection;
pub use ext::{Extension, ExtensionContext, ExtensionRegistry};
pub use proxy::Gateway;
pub use routes::{AuthTier, RouteConfig, RouteGroups, RouteProvider, RouteTable, SharedRoutes};
pub use runtime::Runtime;
