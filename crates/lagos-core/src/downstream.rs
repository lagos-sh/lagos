//! An absolute deadline for the request-header phase.
//!
//! Pingora reads headers before calling `ProxyHttp::early_request_filter`, so
//! setting a session read timeout there cannot bound a client that trickles an
//! incomplete header. Wrap each HTTP session until that filter reports that
//! parsing has completed; after that, normal body and response budgets apply.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::protocols::http::v2::server::H2Options;
use pingora::proxy::HttpProxy;
use pingora::server::ShutdownWatch;
use tokio::sync::Notify;

use crate::proxy::Gateway;

tokio::task_local! {
    static HEADER_PARSED: Arc<Notify>;
}

/// Called at the start of the first filter, after Pingora has read the header.
pub fn header_parsed() {
    let _ = HEADER_PARSED.try_with(|signal| signal.notify_one());
}

pub struct DeadlineProxy {
    inner: Arc<HttpProxy<Gateway>>,
    header_timeout: Duration,
}

impl DeadlineProxy {
    pub fn new(inner: HttpProxy<Gateway>, header_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(inner),
            header_timeout,
        }
    }
}

async fn wait_for_header<F, T>(future: F, signal: Arc<Notify>, deadline: Duration) -> Option<T>
where
    F: Future<Output = T>,
{
    let process = HEADER_PARSED.scope(signal.clone(), future);
    tokio::pin!(process);
    tokio::select! {
        biased;
        result = &mut process => Some(result),
        _ = signal.notified() => Some(process.await),
        _ = tokio::time::sleep(deadline) => None,
    }
}

#[async_trait::async_trait]
impl HttpServerApp for DeadlineProxy {
    async fn process_new_http(
        self: &Arc<Self>,
        session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        wait_for_header(
            self.inner.process_new_http(session, shutdown),
            Arc::new(Notify::new()),
            self.header_timeout,
        )
        .await
        .flatten()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        self.inner.server_options.as_ref()
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.inner.h2_options.clone()
    }

    async fn http_cleanup(&self) {
        self.inner.http_cleanup().await;
    }

    async fn process_custom_session(
        self: Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        self.inner
            .clone()
            .process_custom_session(stream, shutdown)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_header_is_cut_off_at_absolute_deadline() {
        let result = wait_for_header(
            async { tokio::time::sleep(Duration::from_secs(1)).await },
            Arc::new(Notify::new()),
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn completed_header_can_continue_past_header_deadline() {
        let result = wait_for_header(
            async {
                header_parsed();
                tokio::time::sleep(Duration::from_millis(30)).await;
                42
            },
            Arc::new(Notify::new()),
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(result, Some(42));
    }
}
