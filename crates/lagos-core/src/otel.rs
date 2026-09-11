//! OTLP span export.
//!
//! ```yaml
//! observability:
//!   tracing:
//!     sample_ratio: 0.1
//!     otlp:
//!       endpoint: http://otel-collector:4318/v1/traces
//! ```
//!
//! # The request path never waits for a collector
//!
//! A finished span is handed to a **bounded** queue with a non-blocking send
//! and a background task does the exporting. If the queue is full the span is
//! dropped and counted.
//!
//! That is deliberate. An unbounded queue turns a slow or dead collector into
//! memory exhaustion, and blocking on the send turns it into an outage — the
//! gateway would stop serving traffic because a telemetry backend was down.
//! Losing visibility is the correct thing to lose.
//!
//! Ids come from [`crate::trace::TraceContext`], so the exported span is the
//! same one named in the `traceparent` sent upstream.

use std::time::SystemTime;

use crate::trace::TraceContext;

/// What the request path reports when a request finishes.
pub struct FinishedSpan {
    pub trace: TraceContext,
    pub name: String,
    pub route: String,
    pub upstream: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub retries: u32,
    pub start: SystemTime,
    pub end: SystemTime,
}

#[cfg(feature = "otel")]
mod exporter {
    use super::FinishedSpan;
    use std::borrow::Cow;
    use std::sync::OnceLock;
    use std::time::Duration;

    use opentelemetry::trace::{
        SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
    };
    use opentelemetry::{InstrumentationScope, KeyValue};
    use opentelemetry_sdk::trace::{SpanData, SpanEvents, SpanLinks};

    /// How many finished spans may wait to be exported.
    ///
    /// Sized to absorb a short collector stall without letting a long one grow
    /// the process: at a few thousand requests a second this is a second or so
    /// of buffer.
    const QUEUE_DEPTH: usize = 2048;
    /// Spans per OTLP request.
    const BATCH_SIZE: usize = 256;
    /// How long a partial batch waits before being sent anyway.
    const BATCH_INTERVAL: Duration = Duration::from_secs(2);

    static SENDER: OnceLock<tokio::sync::mpsc::Sender<FinishedSpan>> = OnceLock::new();

    /// The OTLP exporter's HTTP transport, over the `reqwest` this crate
    /// already uses to fetch signing keys.
    ///
    /// `opentelemetry-otlp` ships a client of its own behind `reqwest-client`,
    /// but it bundles a different major version of reqwest — enabling it puts
    /// two HTTP stacks, two TLS configurations and two connection pools in the
    /// binary to do the same job. The trait is three lines; the duplication is
    /// megabytes.
    #[derive(Debug)]
    struct ReqwestTransport(reqwest::Client);

    #[async_trait::async_trait]
    impl opentelemetry_http::HttpClient for ReqwestTransport {
        async fn send_bytes(
            &self,
            request: http::Request<bytes::Bytes>,
        ) -> Result<http::Response<bytes::Bytes>, opentelemetry_http::HttpError> {
            let (parts, body) = request.into_parts();
            let mut req = self
                .0
                .request(parts.method, parts.uri.to_string())
                .body(body);
            for (name, value) in parts.headers.iter() {
                req = req.header(name.as_str(), value.as_bytes());
            }

            let response = req.send().await?;
            let status = response.status();
            let body = response.bytes().await?;

            let mut out = http::Response::builder().status(status.as_u16());
            if let Some(headers) = out.headers_mut() {
                headers.reserve(4);
            }
            Ok(out.body(body)?)
        }
    }

    /// Start the background exporter. Called once at startup.
    pub fn init(endpoint: &str, service_name: &str) -> anyhow::Result<()> {
        use opentelemetry_otlp::WithExportConfig as _;
        use opentelemetry_otlp::WithHttpConfig as _;

        let transport = ReqwestTransport(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| anyhow::anyhow!("OTLP transport: {e}"))?,
        );

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(transport)
            .with_endpoint(endpoint)
            .with_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow::anyhow!("OTLP exporter: {e}"))?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<FinishedSpan>(QUEUE_DEPTH);
        if SENDER.set(tx).is_err() {
            anyhow::bail!("tracing exporter was initialized twice");
        }

        let scope = InstrumentationScope::builder("lagos")
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let service = service_name.to_string();

        tokio::spawn(async move {
            use opentelemetry_sdk::trace::SpanExporter as _;

            let mut batch: Vec<SpanData> = Vec::with_capacity(BATCH_SIZE);
            let mut ticker = tokio::time::interval(BATCH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                let flush = tokio::select! {
                    received = rx.recv() => match received {
                        Some(span) => {
                            batch.push(to_span_data(span, &scope, &service));
                            batch.len() >= BATCH_SIZE
                        }
                        // The gateway is shutting down; send what is left.
                        None => true,
                    },
                    _ = ticker.tick() => true,
                };

                if flush && !batch.is_empty() {
                    let to_send = std::mem::take(&mut batch);
                    if let Err(e) = exporter.export(to_send).await {
                        // A failing collector is not a reason to stop serving,
                        // or to stop trying.
                        tracing::warn!(error = %e, "OTLP export failed");
                    }
                }

                if rx.is_closed() && batch.is_empty() {
                    return;
                }
            }
        });

        Ok(())
    }

    /// Queue a finished span. Never blocks; drops when the queue is full.
    pub fn record(span: FinishedSpan) {
        let Some(tx) = SENDER.get() else {
            return;
        };
        if tx.try_send(span).is_err()
            && let Some(m) = crate::metrics::metrics()
        {
            m.record_span_dropped();
        }
    }

    fn to_span_data(s: FinishedSpan, scope: &InstrumentationScope, service: &str) -> SpanData {
        let span_context = SpanContext::new(
            TraceId::from_bytes(s.trace.trace_id),
            SpanId::from_bytes(s.trace.span_id),
            TraceFlags::new(s.trace.flags),
            // The parent arrived over the wire rather than being created here.
            true,
            TraceState::default(),
        );

        let mut attributes = vec![
            KeyValue::new("service.name", service.to_string()),
            KeyValue::new("http.request.method", s.method),
            KeyValue::new("url.path", s.path),
            KeyValue::new("http.response.status_code", i64::from(s.status)),
        ];
        if !s.route.is_empty() {
            attributes.push(KeyValue::new("lagos.route", s.route));
        }
        if !s.upstream.is_empty() {
            attributes.push(KeyValue::new("lagos.upstream", s.upstream));
        }
        if s.retries > 0 {
            attributes.push(KeyValue::new("lagos.retries", i64::from(s.retries)));
        }

        SpanData {
            span_context,
            parent_span_id: s
                .trace
                .parent_span_id
                .map_or(SpanId::INVALID, SpanId::from_bytes),
            parent_span_is_remote: s.trace.parent_span_id.is_some(),
            // The gateway answered a client, so it is the server of this span.
            span_kind: SpanKind::Server,
            name: Cow::Owned(s.name),
            start_time: s.start,
            end_time: s.end,
            attributes,
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: if s.status >= 500 {
                Status::error("upstream or gateway error")
            } else {
                Status::Unset
            },
            instrumentation_scope: scope.clone(),
        }
    }
}

#[cfg(not(feature = "otel"))]
mod exporter {
    use super::FinishedSpan;

    /// Tracing export is compiled out. Propagation still works — the gateway
    /// remains a correct hop in a trace, it just exports no spans of its own.
    pub fn init(_endpoint: &str, _service_name: &str) -> anyhow::Result<()> {
        anyhow::bail!(
            "this build has tracing export compiled out (`--no-default-features`); \
             remove `observability.tracing.otlp` or use a build with the `otel` feature"
        )
    }

    pub fn record(_span: FinishedSpan) {}
}

pub use exporter::{init, record};
