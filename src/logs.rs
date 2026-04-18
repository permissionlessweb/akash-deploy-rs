//! Provider log streaming for Akash deployments.
//!
//! Connects to a provider's WebSocket log endpoint and yields log lines
//! as an async stream. Requires the `log-streaming` feature.
//!
//! # Usage
//!
//! ```ignore
//! use akash_deploy_rs::{LogStreamConfig, AkashClient};
//!
//! let config = LogStreamConfig::new()
//!     .with_follow(true)
//!     .with_tail(100)
//!     .with_service("web");
//!
//! let mut stream = client.stream_logs(&provider_uri, &lease_id, &auth, &config).await?;
//! while let Some(line) = stream.next().await {
//!     println!("{}", line?);
//! }
//! ```

use crate::{error::DeployError, types::*};

/// Configuration for a log stream request.
#[derive(Debug, Clone)]
pub struct LogStreamConfig {
    /// Follow log output (like `tail -f`). Default: true.
    pub follow: bool,
    /// Number of lines to show from the end of the logs. Default: 100.
    pub tail: u64,
    /// Filter to a specific service name. None = all services.
    pub service: Option<String>,
}

impl Default for LogStreamConfig {
    fn default() -> Self {
        Self {
            follow: true,
            tail: 100,
            service: None,
        }
    }
}

impl LogStreamConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_follow(mut self, follow: bool) -> Self {
        self.follow = follow;
        self
    }

    pub fn with_tail(mut self, tail: u64) -> Self {
        self.tail = tail;
        self
    }

    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Build the WebSocket URL path for the provider's log endpoint.
    pub fn to_ws_url(&self, provider_uri: &str, lease: &LeaseId) -> String {
        let host = provider_uri.trim_end_matches('/');
        let ws_host = host
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        let mut url = format!(
            "{}/lease/{}/{}/{}/logs?follow={}&tail={}",
            ws_host, lease.dseq, lease.gseq, lease.oseq, self.follow, self.tail,
        );
        if let Some(ref svc) = self.service {
            url.push_str(&format!("&service={}", svc));
        }
        url
    }
}

/// A log line received from the provider.
#[derive(Debug, Clone)]
pub struct LogLine {
    /// The raw log text.
    pub message: String,
    /// Service name (if parsed from structured output).
    pub service: Option<String>,
}

impl std::fmt::Display for LogLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// ── WebSocket transport ───────────────────────────────────────────────────────

#[cfg(feature = "log-streaming")]
pub mod ws {
    use super::*;
    use futures_util::{Stream, StreamExt};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    /// An async stream of log lines from an Akash provider via WebSocket.
    pub struct WsLogStream {
        inner: Pin<
            Box<
                dyn Stream<Item = Result<LogLine, DeployError>> + Send,
            >,
        >,
    }

    impl WsLogStream {
        /// Connect to a provider's WebSocket log endpoint.
        ///
        /// `provider_uri` is the provider's host URI (e.g. `https://provider.example.com`).
        /// Auth is applied via the `Authorization: Bearer <token>` header for JWT,
        /// or via TLS client certificate for mTLS.
        pub async fn connect(
            provider_uri: &str,
            lease: &LeaseId,
            auth: &ProviderAuth,
            config: &LogStreamConfig,
        ) -> Result<Self, DeployError> {
            let url = config.to_ws_url(provider_uri, lease);

            let mut req = url
                .into_client_request()
                .map_err(|e| DeployError::LogStream(format!("invalid WebSocket URL: {}", e)))?;

            // Apply auth
            match auth {
                ProviderAuth::Jwt { token } => {
                    req.headers_mut().insert(
                        "Authorization",
                        format!("Bearer {}", token)
                            .parse()
                            .map_err(|e| {
                                DeployError::LogStream(format!("invalid auth header: {}", e))
                            })?,
                    );
                }
                ProviderAuth::Mtls { .. } => {
                    // mTLS is handled at the TLS layer, not via headers.
                    // For now, WebSocket log streaming only supports JWT auth.
                    return Err(DeployError::LogStream(
                        "mTLS auth not supported for WebSocket log streaming; use JWT".into(),
                    ));
                }
            }

            tracing::debug!("connecting to log stream: {}", req.uri());

            let (ws, _response) = tokio_tungstenite::connect_async(req)
                .await
                .map_err(|e| DeployError::LogStream(format!("WebSocket connect failed: {}", e)))?;

            let (_write, read) = ws.split();

            let stream = read.filter_map(|msg| async {
                match msg {
                    Ok(Message::Text(text)) => Some(Ok(LogLine {
                        message: text.to_string(),
                        service: None,
                    })),
                    Ok(Message::Close(_)) => None,
                    Ok(_) => None, // Ignore binary, ping, pong
                    Err(e) => Some(Err(DeployError::LogStream(format!(
                        "WebSocket error: {}",
                        e
                    )))),
                }
            });

            Ok(Self {
                inner: Box::pin(stream),
            })
        }
    }

    impl Stream for WsLogStream {
        type Item = Result<LogLine, DeployError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.inner.as_mut().poll_next(cx)
        }
    }
}
