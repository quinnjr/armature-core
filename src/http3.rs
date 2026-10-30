//! HTTP/3 (QUIC) Support
//!
//! This module provides HTTP/3 server capabilities for the Armature framework.
//! HTTP/3 is the latest HTTP protocol, using QUIC instead of TCP for transport.
//!
//! ## Key Benefits
//!
//! - **0-RTT Connection Establishment**: Faster initial connections
//! - **Multiplexing without Head-of-Line Blocking**: Streams are independent
//! - **Connection Migration**: Seamless network changes (WiFi → cellular)
//! - **Built-in Encryption**: TLS 1.3 integrated into QUIC
//! - **Improved Loss Recovery**: Better congestion control
//!
//! ## Requirements
//!
//! - Enable the `http3` feature in Cargo.toml
//! - Provide TLS certificates (QUIC always requires encryption)
//! - Open UDP port (not TCP!) on your firewall
//!
//! ## Usage
//!
//! ```rust,ignore
//! use armature_core::{Application, Http3Config, TlsConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let app = Application::new(container, router);
//! let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
//!
//! // Start HTTP/3 server on UDP port 443
//! app.listen_h3(443, tls).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Alt-Svc Header
//!
//! To advertise HTTP/3 support from your HTTP/1.1 or HTTP/2 server,
//! add the `Alt-Svc` header to responses:
//!
//! ```text
//! Alt-Svc: h3=":443"; ma=86400
//! ```
//!
//! This tells clients that HTTP/3 is available on UDP port 443.
//!
//! ## Browser Support
//!
//! As of 2024, HTTP/3 is supported by:
//! - Chrome 87+
//! - Firefox 88+
//! - Safari 14+
//! - Edge 87+
//!
//! ## Note on Port Numbers
//!
//! HTTP/3 typically runs on the same port number as HTTPS (443),
//! but uses UDP instead of TCP. This means you can run both
//! HTTP/2 (TCP) and HTTP/3 (UDP) on port 443 simultaneously.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(feature = "http3")]
use std::net::SocketAddr;
#[cfg(feature = "http3")]
use std::sync::atomic::AtomicBool;

/// HTTP/3 server configuration
///
/// Marked `#[non_exhaustive]`: construct it with [`Http3Config::default`],
/// one of the preset constructors, or [`Http3Config::builder`] rather than an
/// exhaustive struct literal, so that adding fields (like
/// `max_request_body_size`) stays backwards compatible for downstream crates.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http3Config {
    /// Maximum concurrent bidirectional streams per connection
    /// Default: 100 - same as HTTP/2
    pub max_concurrent_bidi_streams: u32,

    /// Maximum concurrent unidirectional streams per connection
    /// Default: 3 - for QPACK encoder/decoder and control stream
    pub max_concurrent_uni_streams: u32,

    /// Initial stream receive window size (bytes)
    /// Default: 1MB
    pub initial_stream_receive_window: u32,

    /// Initial connection receive window size (bytes)
    /// Default: 10MB
    pub initial_connection_receive_window: u32,

    /// Maximum idle timeout before closing connection
    /// Default: 30 seconds
    pub max_idle_timeout: Duration,

    /// Keep-alive interval (QUIC PING frames sent by the server)
    ///
    /// Default: `None`. A server that pings at an interval shorter than
    /// `max_idle_timeout` keeps every connection alive forever, including ones
    /// whose client has gone quiet and will never send another request — the
    /// idle timeout then never fires. Keep-alive is the client's call; set this
    /// only for a deployment that needs NAT bindings held open from the server
    /// side, and know that it makes idle connections permanent.
    pub keep_alive_interval: Option<Duration>,

    /// Enable 0-RTT (early data) for faster connection establishment
    ///
    /// **Security note**: 0-RTT data is replayable — anyone who captured it can
    /// send it again, and the server cannot tell. With this enabled, a request
    /// that arrives before the handshake is confirmed is served only if its
    /// method is safe (`GET`, `HEAD`, `OPTIONS`), and is marked with an
    /// `Early-Data: 1` request header (RFC 8470) so a handler can decline it;
    /// any other method is answered `425 Too Early`, which tells the client to
    /// retry once the handshake completes.
    ///
    /// Default: `false`, in every preset.
    pub enable_0rtt: bool,

    /// Maximum UDP payload size
    /// Default: 1350 bytes (safe for most networks)
    pub max_udp_payload_size: u16,

    /// Enable DATAGRAM extension (RFC 9221)
    /// Used for real-time/low-latency data
    /// Default: false
    pub enable_datagram: bool,

    /// QPACK max table capacity (bytes)
    /// Default: 4096
    pub qpack_max_table_capacity: u32,

    /// QPACK blocked streams
    /// Default: 16
    pub qpack_blocked_streams: u16,

    /// Maximum request body size (bytes)
    /// Requests with larger bodies are rejected with 413 Payload Too Large
    /// Default: 10MB
    pub max_request_body_size: usize,

    /// Largest request header section (bytes, as QPACK-decoded field lines)
    /// the server accepts; a larger one is refused before it is buffered.
    ///
    /// `h3`'s own default is unlimited, which lets one request make the
    /// server hold an arbitrarily large header block. Default: 16 KiB, the
    /// same as HTTP/2's `max_header_list_size` and `armature-h1`'s head cap.
    pub max_field_section_size: u64,
}

/// Default for [`Http3Config::max_field_section_size`].
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 3,
            initial_stream_receive_window: 1024 * 1024, // 1MB
            initial_connection_receive_window: 10 * 1024 * 1024, // 10MB
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: None,
            enable_0rtt: false,
            max_udp_payload_size: 1350,
            enable_datagram: false,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            max_request_body_size: 10 * 1024 * 1024, // 10MB
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
        }
    }
}

impl Http3Config {
    /// Create a new builder
    pub fn builder() -> Http3ConfigBuilder {
        Http3ConfigBuilder::default()
    }

    /// High-throughput configuration for large file transfers
    pub fn high_throughput() -> Self {
        Self {
            max_concurrent_bidi_streams: 250,
            max_concurrent_uni_streams: 10,
            initial_stream_receive_window: 4 * 1024 * 1024, // 4MB
            initial_connection_receive_window: 50 * 1024 * 1024, // 50MB
            max_idle_timeout: Duration::from_secs(60),
            // See the field docs: server-side pings make idle connections
            // permanent, and 0-RTT requests are replayable.
            keep_alive_interval: None,
            enable_0rtt: false,
            max_udp_payload_size: 1452, // Larger for better throughput
            enable_datagram: false,
            qpack_max_table_capacity: 16384,
            qpack_blocked_streams: 32,
            max_request_body_size: 50 * 1024 * 1024, // 50MB for large transfers
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
        }
    }

    /// Low-latency configuration for real-time applications
    pub fn low_latency() -> Self {
        Self {
            max_concurrent_bidi_streams: 50,
            max_concurrent_uni_streams: 3,
            initial_stream_receive_window: 256 * 1024, // 256KB
            initial_connection_receive_window: 2 * 1024 * 1024, // 2MB
            max_idle_timeout: Duration::from_secs(15),
            // See the field docs: server-side pings make idle connections
            // permanent, and 0-RTT requests are replayable.
            keep_alive_interval: None,
            enable_0rtt: false,
            max_udp_payload_size: 1200, // Smaller for faster delivery
            enable_datagram: true,      // For real-time data
            qpack_max_table_capacity: 2048,
            qpack_blocked_streams: 8,
            max_request_body_size: 10 * 1024 * 1024, // 10MB
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
        }
    }

    /// Mobile-optimized configuration
    /// Handles network changes and high latency gracefully
    pub fn mobile_optimized() -> Self {
        Self {
            max_concurrent_bidi_streams: 64,
            max_concurrent_uni_streams: 3,
            initial_stream_receive_window: 512 * 1024, // 512KB
            initial_connection_receive_window: 4 * 1024 * 1024, // 4MB
            max_idle_timeout: Duration::from_secs(120), // Longer for mobile networks
            // See the field docs: server-side pings make idle connections
            // permanent, and 0-RTT requests are replayable.
            keep_alive_interval: None,
            enable_0rtt: false,
            max_udp_payload_size: 1200, // Conservative for mobile networks
            enable_datagram: false,
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            max_request_body_size: 10 * 1024 * 1024, // 10MB
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
        }
    }
}

/// Builder for Http3Config
#[derive(Debug, Clone, Default)]
pub struct Http3ConfigBuilder {
    config: Http3Config,
}

impl Http3ConfigBuilder {
    /// Set maximum concurrent bidirectional streams
    pub fn max_concurrent_bidi_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_bidi_streams = max;
        self
    }

    /// Set maximum concurrent unidirectional streams
    pub fn max_concurrent_uni_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_uni_streams = max;
        self
    }

    /// Set initial stream receive window
    pub fn initial_stream_receive_window(mut self, size: u32) -> Self {
        self.config.initial_stream_receive_window = size;
        self
    }

    /// Set initial connection receive window
    pub fn initial_connection_receive_window(mut self, size: u32) -> Self {
        self.config.initial_connection_receive_window = size;
        self
    }

    /// Set maximum idle timeout
    pub fn max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.max_idle_timeout = timeout;
        self
    }

    /// Set keep-alive interval
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.config.keep_alive_interval = interval;
        self
    }

    /// Enable or disable 0-RTT early data
    ///
    /// **Security warning**: 0-RTT data is replayable. When enabled, requests
    /// arriving before the handshake is confirmed are limited to safe methods
    /// and marked `Early-Data: 1`; see [`Http3Config::enable_0rtt`].
    pub fn enable_0rtt(mut self, enable: bool) -> Self {
        self.config.enable_0rtt = enable;
        self
    }

    /// Set maximum UDP payload size
    pub fn max_udp_payload_size(mut self, size: u16) -> Self {
        self.config.max_udp_payload_size = size;
        self
    }

    /// Enable DATAGRAM extension
    pub fn enable_datagram(mut self, enable: bool) -> Self {
        self.config.enable_datagram = enable;
        self
    }

    /// Set maximum request body size in bytes
    pub fn max_request_body_size(mut self, size: usize) -> Self {
        self.config.max_request_body_size = size;
        self
    }

    /// Set the largest request header section accepted (see
    /// [`Http3Config::max_field_section_size`])
    pub fn max_field_section_size(mut self, bytes: u64) -> Self {
        self.config.max_field_section_size = bytes;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Http3Config {
        self.config
    }
}

// ============================================================================
// HTTP/3 Statistics
// ============================================================================

/// Statistics for HTTP/3 connections
#[derive(Debug, Default)]
pub struct Http3Stats {
    /// Active QUIC connections
    active_connections: AtomicUsize,
    /// Total QUIC connections
    total_connections: AtomicU64,
    /// Active HTTP/3 streams
    active_streams: AtomicUsize,
    /// Total HTTP/3 streams
    total_streams: AtomicU64,
    /// Total requests processed
    total_requests: AtomicU64,
    /// Requests served from 0-RTT early data
    zero_rtt_accepted: AtomicU64,
    /// Connection migrations (IP/port changes)
    connection_migrations: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
}

impl Http3Stats {
    /// Create new statistics tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record connection opened
    #[inline]
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed
    #[inline]
    pub fn connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record stream created
    #[inline]
    pub fn stream_created(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
        self.total_streams.fetch_add(1, Ordering::Relaxed);
    }

    /// Record stream closed
    #[inline]
    pub fn stream_closed(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record request processed
    #[inline]
    pub fn request_processed(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request served from 0-RTT early data (one that arrived
    /// before the handshake was confirmed and was not answered `425`).
    #[inline]
    pub fn zero_rtt_accepted(&self) {
        self.zero_rtt_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection migration
    #[inline]
    pub fn connection_migrated(&self) {
        self.connection_migrations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes transferred
    #[inline]
    pub fn record_transfer(&self, sent: u64, received: u64) {
        self.bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.bytes_received.fetch_add(received, Ordering::Relaxed);
    }

    /// Get active connections
    #[inline]
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total connections
    #[inline]
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get active streams
    #[inline]
    pub fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// Get total streams
    #[inline]
    pub fn total_streams(&self) -> u64 {
        self.total_streams.load(Ordering::Relaxed)
    }

    /// Get total requests
    #[inline]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get the number of requests served from 0-RTT early data.
    ///
    /// Counts requests, not handshakes: a server-side "0-RTT accepted"
    /// handshake result only says early data was *allowed*, and is reported
    /// for every confirmed handshake whether or not the client sent any.
    #[inline]
    pub fn total_zero_rtt_accepted(&self) -> u64 {
        self.zero_rtt_accepted.load(Ordering::Relaxed)
    }

    /// Get total connection migrations
    #[inline]
    pub fn total_connection_migrations(&self) -> u64 {
        self.connection_migrations.load(Ordering::Relaxed)
    }

    /// Get total bytes sent
    #[inline]
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[inline]
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

// ============================================================================
// HTTP/3 Server Implementation (feature-gated)
// ============================================================================

#[cfg(feature = "http3")]
mod server {
    use super::*;
    use crate::application::{ServeState, dispatch_via_h3};
    use crate::{Error, HttpRequest, route_cache::OptimizedRouter};
    use bytes::{Buf, Bytes};
    use h3_quinn::quinn;
    use http::Response;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::task::Poll;
    use tracing::{debug, info};

    /// HTTP/3 Server
    ///
    /// Every request goes through the same pipeline as the TCP transports —
    /// path canonicalization, global middleware and guards, route-scoped
    /// guards, CORS, body limits, the slow-body policy and exception filters —
    /// so serving a route over QUIC is never a way around its protection.
    pub struct Http3Server {
        config: Http3Config,
        stats: Arc<Http3Stats>,
        state: ServeState,
        /// Connections served at once; see [`Http3Server::listen`].
        max_connections: usize,
        /// How long one response write may stall; see
        /// [`with_write_timeout`](Self::with_write_timeout).
        write_timeout: Option<Duration>,
    }

    impl Http3Server {
        /// Create a standalone HTTP/3 server for `router`.
        ///
        /// Route-scoped guards and middleware bound to the router's routes are
        /// enforced; there are no global guards, middleware, CORS or filters.
        /// `Application::listen_h3` builds the server from the application's
        /// full serve state instead.
        pub fn new(config: Http3Config, router: Arc<OptimizedRouter>) -> Self {
            let state = ServeState::for_router(router, config.max_request_body_size);
            Self {
                config,
                stats: Arc::new(Http3Stats::new()),
                state,
                max_connections: crate::pipeline::DEFAULT_MAX_CONNECTIONS,
                write_timeout: crate::pipeline::PipelineConfig::default().write_timeout,
            }
        }

        /// A server sharing an application's serve state. The body cap is the
        /// smaller of the application's and `config.max_request_body_size`;
        /// `max_connections` is the application's TCP connection cap
        /// ([`PipelineConfig::max_connections`](crate::pipeline::PipelineConfig::max_connections)),
        /// so QUIC is not a way around it.
        pub(crate) fn from_state(
            config: Http3Config,
            state: ServeState,
            max_connections: usize,
        ) -> Self {
            let state = state.with_max_body_size_at_most(config.max_request_body_size);
            Self {
                config,
                stats: Arc::new(Http3Stats::new()),
                state,
                max_connections: max_connections.max(1),
                write_timeout: crate::pipeline::PipelineConfig::default().write_timeout,
            }
        }

        /// Bound how long one response write may stall, as
        /// [`PipelineConfig::write_timeout`](crate::pipeline::PipelineConfig::write_timeout)
        /// does for the TCP transports.
        ///
        /// QUIC has no socket to put a write deadline on: a response waits on
        /// the peer's flow-control credit (`MAX_STREAM_DATA`), and a peer that
        /// never grants any while answering PINGs would otherwise hold the
        /// stream, its connection and a connection slot forever. Each chunk of
        /// the response must be accepted within this; past it the stream is
        /// reset. `None` disables the bound.
        pub(crate) fn with_write_timeout(mut self, write_timeout: Option<Duration>) -> Self {
            self.write_timeout = write_timeout;
            self
        }

        /// Get statistics
        pub fn stats(&self) -> Arc<Http3Stats> {
            Arc::clone(&self.stats)
        }

        /// Configure QUIC server from TLS config
        ///
        /// The caller's `tls_config` is shared behind an `Arc` (the TCP
        /// listeners of a dual-stack server use the same one), so it is cloned
        /// before anything below changes it.
        pub fn configure_quinn(
            &self,
            tls_config: Arc<rustls::ServerConfig>,
        ) -> Result<quinn::ServerConfig, Error> {
            let mut tls = (*tls_config).clone();
            tls.alpn_protocols = h3_alpn(&tls_config);
            // 0-RTT (early data) is enabled by advertising a non-zero
            // `max_early_data_size`; QUIC requires exactly `u32::MAX` when
            // enabled. Off, it is set to zero explicitly rather than inherited:
            // the config is the caller's, and one built for TLS-over-TCP early
            // data must not silently turn on replayable 0-RTT over QUIC.
            tls.max_early_data_size = if self.config.enable_0rtt { u32::MAX } else { 0 };
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
                .map_err(|e| Error::Internal(format!("Failed to create QUIC crypto: {}", e)))?;

            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_config.transport_config(Arc::new(build_transport(&self.config)));
            // Bound the handshakes quinn will hold queued for `accept`, by the
            // same cap as established connections: past it, quinn refuses new
            // ones itself instead of buffering them.
            server_config.max_incoming(self.max_connections.min(1 << 16));

            Ok(server_config)
        }

        /// Start listening for HTTP/3 connections
        ///
        /// At most `max_connections` connections are served at once — the
        /// application's TCP cap when started from `Application`, otherwise
        /// [`DEFAULT_MAX_CONNECTIONS`](crate::pipeline::DEFAULT_MAX_CONNECTIONS).
        /// Unlike a TCP listener, which can stop accepting and let the
        /// kernel's backlog absorb a burst, a QUIC endpoint has no backlog to
        /// lean on, so a connection attempt over the cap is refused outright.
        pub async fn listen(
            self,
            addr: SocketAddr,
            tls_config: Arc<rustls::ServerConfig>,
        ) -> Result<(), Error> {
            let server_config = self.configure_quinn(tls_config)?;

            let endpoint = quinn::Endpoint::server(server_config, addr)
                .map_err(|e| Error::Internal(format!("Failed to bind QUIC endpoint: {}", e)))?;

            info!(address = %addr, "HTTP/3 server listening (QUIC/UDP)");

            self.serve_endpoint(endpoint).await;
            Ok(())
        }

        /// The accept loop behind [`listen`](Self::listen), over an already
        /// bound endpoint so tests can serve an ephemeral port.
        pub(crate) async fn serve_endpoint(self, endpoint: quinn::Endpoint) {
            let limit = Arc::new(tokio::sync::Semaphore::new(
                self.max_connections
                    .clamp(1, tokio::sync::Semaphore::MAX_PERMITS),
            ));
            let options = ConnectionOptions {
                enable_0rtt: self.config.enable_0rtt,
                idle_timeout: self.config.max_idle_timeout,
                max_field_section_size: self.config.max_field_section_size,
                write_timeout: self.write_timeout,
            };

            while let Some(incoming) = endpoint.accept().await {
                // Validate the client's address before it costs anything. An
                // Initial packet's source address is trivially spoofed, and
                // each one accepted took a connection slot for as long as the
                // handshake could take — a stream of forged Initials filled the
                // cap without the sender ever receiving a byte. A Retry is
                // stateless: only a client that can receive at its address
                // comes back, with a token that validates it.
                //
                // Always on, at the cost of one round trip on a client's first
                // connection: quinn hands out NEW_TOKEN tokens on every
                // connection, and a returning client that presents one is
                // already validated and skips the Retry — which is also the
                // only client that can have a 0-RTT ticket, so early data
                // keeps its zero-round-trip path.
                if !incoming.remote_address_validated() && incoming.may_retry() {
                    if let Err(e) = incoming.retry() {
                        e.into_incoming().refuse();
                    }
                    continue;
                }
                let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                    debug!(
                        client = %incoming.remote_address(),
                        "HTTP/3 connection refused: at the connection limit"
                    );
                    incoming.refuse();
                    continue;
                };
                let stats = Arc::clone(&self.stats);
                let state = self.state.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(incoming, state, stats, options).await {
                        // Handshake failures and timeouts are the peer's doing.
                        debug!(error = %e, "HTTP/3 connection error");
                    }
                });
            }
        }
    }

    /// The ALPN list the QUIC listener offers, whatever `tls` offers.
    ///
    /// QUIC refuses a handshake whose ALPN does not name the application
    /// protocol, and `TlsConfig` offers `h2` and `http/1.1` — the TCP
    /// protocols — so passing its list through made every HTTP/3 handshake
    /// fail. This listener speaks `h3` and nothing else.
    pub(super) fn h3_alpn(_tls: &rustls::ServerConfig) -> Vec<Vec<u8>> {
        vec![b"h3".to_vec()]
    }

    /// Per-connection settings [`handle_connection`] needs from the config.
    #[derive(Debug, Clone, Copy)]
    struct ConnectionOptions {
        enable_0rtt: bool,
        idle_timeout: std::time::Duration,
        max_field_section_size: u64,
        write_timeout: Option<Duration>,
    }

    impl ConnectionOptions {
        /// How long a handshake, or a request's HEADERS, may take to complete:
        /// the head deadline every TCP transport uses, or the idle timeout if
        /// that is shorter.
        fn handshake_timeout(&self) -> Duration {
            crate::pipeline::HEADER_READ_TIMEOUT.min(self.idle_timeout)
        }
    }

    /// The largest piece of a response body written under one
    /// [`ConnectionOptions::write_timeout`]: the deadline bounds a *stall*, as
    /// [`WriteDeadline`](crate::pipeline::WriteDeadline) does on TCP, not the
    /// whole transfer, so a large body to a slow but live client is not cut
    /// off.
    const RESPONSE_CHUNK: usize = 64 * 1024;

    /// Build the quinn transport config from an [`Http3Config`], applying every
    /// advertised knob (stream/connection flow-control windows, concurrency
    /// limits, idle timeout, keep-alive, and DATAGRAM buffers).
    ///
    /// Split out from [`Http3Server::configure_quinn`] so the mapping from
    /// config to transport parameters is unit-testable without a TLS
    /// certificate.
    pub(super) fn build_transport(config: &Http3Config) -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();

        transport
            .max_concurrent_bidi_streams(config.max_concurrent_bidi_streams.into())
            .max_concurrent_uni_streams(config.max_concurrent_uni_streams.into())
            // Apply the advertised flow-control windows so large transfers are
            // not throttled by quinn's conservative defaults.
            .stream_receive_window(config.initial_stream_receive_window.into())
            .receive_window(config.initial_connection_receive_window.into())
            .initial_mtu(config.max_udp_payload_size)
            .max_idle_timeout(Some(
                config
                    .max_idle_timeout
                    .try_into()
                    .unwrap_or(quinn::IdleTimeout::from(quinn::VarInt::from_u32(30_000))),
            ));

        // Explicitly `None` when unset rather than left at quinn's default, so
        // the "no server-side keep-alive" default cannot drift with quinn's.
        transport.keep_alive_interval(config.keep_alive_interval);

        if config.enable_datagram {
            transport.datagram_receive_buffer_size(Some(65536));
            transport.datagram_send_buffer_size(65536);
        }

        transport
    }

    /// Handle a single QUIC connection
    async fn handle_connection(
        incoming: quinn::Incoming,
        state: ServeState,
        stats: Arc<Http3Stats>,
        options: ConnectionOptions,
    ) -> Result<(), Error> {
        let connecting = incoming
            .accept()
            .map_err(|e| Error::Internal(format!("Accept failed: {}", e)))?;

        // Whether the handshake is confirmed — the client has proven it holds
        // the keys, so what it sends cannot be a replay of someone else's
        // packets. Requests that arrive before then are early data.
        let confirmed = Arc::new(AtomicBool::new(false));
        // The handshake holds a connection slot, so it runs under the head
        // deadline rather than QUIC's idle timeout alone: a peer that keeps
        // retransmitting a stalled handshake would otherwise reset that timer
        // indefinitely.
        let handshake_timeout = options.handshake_timeout();
        let handshake = |connecting: quinn::Connecting| async move {
            match tokio::time::timeout(handshake_timeout, connecting).await {
                Ok(Ok(conn)) => Ok(conn),
                Ok(Err(e)) => Err(Error::Internal(format!("Connection failed: {}", e))),
                Err(_) => Err(Error::Internal("QUIC handshake timed out".to_string())),
            }
        };
        let conn = if options.enable_0rtt {
            // `into_0rtt` always succeeds on the server, and its future
            // resolves when the handshake completes. Its `bool` is meaningless
            // here: on the server it is `true` for every confirmed handshake,
            // early data or not, so the statistic counts requests actually
            // served from early data instead (see `handle_request_resolver`).
            match connecting.into_0rtt() {
                Ok((conn, handshake_done)) => {
                    let confirmed = Arc::clone(&confirmed);
                    let watched = conn.clone();
                    tokio::spawn(async move {
                        match tokio::time::timeout(handshake_timeout, handshake_done).await {
                            // The future also resolves when the connection is
                            // lost mid-handshake. Only a connection that is
                            // still open has actually confirmed it; anything
                            // else must keep being treated as early data.
                            Ok(_) if watched.close_reason().is_none() => {
                                confirmed.store(true, Ordering::Release);
                            }
                            Ok(_) => {}
                            // Early data is being served on a connection
                            // whose handshake never finishes: end it.
                            Err(_) => {
                                watched.close(quinn::VarInt::from_u32(0x100), b"handshake timeout")
                            }
                        }
                    });
                    conn
                }
                Err(connecting) => {
                    let conn = handshake(connecting).await?;
                    confirmed.store(true, Ordering::Release);
                    conn
                }
            }
        } else {
            // No early data: wait for the full handshake before serving a
            // byte, so nothing below ever runs on an unconfirmed connection.
            let conn = handshake(connecting).await?;
            confirmed.store(true, Ordering::Release);
            conn
        };

        stats.connection_opened();
        let remote_addr = conn.remote_address();
        debug!(client = %remote_addr, "HTTP/3 connection established");
        // The body budget is per connection for the same reason HTTP/2's is:
        // up to `max_concurrent_bidi_streams` bodies may be buffering at once.
        // The peer is filled in per request, below.
        let state = state.with_default_body_budget();

        // QUIC's own idle timeout only fires when *no packets* flow, so a
        // client that keeps pinging holds a connection with zero streams
        // forever. Close one that has had no request in flight for the idle
        // timeout, or none at all within the first-request deadline — from a
        // watcher, so the accept loop below is never cancelled mid-poll.
        let tracker = Arc::new(crate::http2::StreamTracker::new());
        let watcher = {
            let tracker = Arc::clone(&tracker);
            let conn = conn.clone();
            tokio::spawn(async move {
                // The first request is due within the head deadline every TCP
                // transport uses, or the idle timeout if that is shorter.
                let mut deadline = tracker.started + options.handshake_timeout();
                loop {
                    tokio::select! {
                        _ = conn.closed() => return,
                        () = tokio::time::sleep_until(deadline) => {
                            match tracker.next_deadline(
                                tokio::time::Instant::now(),
                                options.idle_timeout,
                            ) {
                                Some(next) => deadline = next,
                                None => {
                                    // H3_NO_ERROR: a clean close, not a fault.
                                    conn.close(quinn::VarInt::from_u32(0x100), b"idle");
                                    return;
                                }
                            }
                        }
                    }
                }
            })
        };

        // Create HTTP/3 connection. `h3`'s default field-section limit is
        // unbounded; see `Http3Config::max_field_section_size`.
        let quic_conn = conn.clone();
        let mut h3_conn = h3::server::builder()
            .max_field_section_size(options.max_field_section_size)
            .build(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| Error::Internal(format!("H3 connection failed: {}", e)))?;

        // Every request task is owned by the connection, not detached: the
        // connection's slot in the cap is released when this function
        // returns, so a request still running then would be work the cap no
        // longer counts — a client could close connection after connection,
        // each leaving a slow handler behind, and run unbounded handlers
        // while holding a single slot. Dropping the set aborts them.
        let mut requests = tokio::task::JoinSet::new();
        let mut graceful = false;
        loop {
            // Reap finished requests so the set holds only live ones.
            while requests.try_join_next().is_some() {}
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let _stream = OpenStream::new(Arc::clone(&stats));
                    // The address now, not at the handshake: QUIC connections
                    // migrate, and a request must be attributed to where it
                    // actually came from.
                    let state = state.for_peer(quic_conn.remote_address());
                    let stats = Arc::clone(&stats);
                    let confirmed = Arc::clone(&confirmed);
                    let tracker = Arc::clone(&tracker);

                    requests.spawn(async move {
                        let _stream = _stream;
                        if let Err(e) = handle_request_resolver(
                            resolver, state, stats, &confirmed, &tracker, options,
                        )
                        .await
                        {
                            // A stream the peer reset, abandoned or starved
                            // is not a server fault, and a peer can produce
                            // these at will: keep them out of error logs.
                            debug!(error = %e, "HTTP/3 request error");
                        }
                    });
                }
                Ok(None) => {
                    // A graceful close (GOAWAY): no new requests, but those
                    // already accepted are still owed their responses.
                    graceful = true;
                    break;
                }
                Err(e) => {
                    debug!(error = %e, "HTTP/3 accept error");
                    break;
                }
            }
        }
        if graceful {
            // Bounded: every request is under the handler and write deadlines
            // and the minimum response rate; and the connection closing
            // outright ends the wait, aborting whatever is left.
            tokio::select! {
                () = async { while requests.join_next().await.is_some() {} } => {}
                _ = quic_conn.closed() => {}
            }
        }
        requests.abort_all();
        drop(requests);

        watcher.abort();
        stats.connection_closed();
        debug!(client = %remote_addr, "HTTP/3 connection closed");

        Ok(())
    }

    /// Convert a resolved HTTP/3 request into an Armature [`HttpRequest`],
    /// copying method, headers, and the full request target — query string
    /// included, so [`HttpRequest::query`] can parse it on demand (mirrors
    /// `application.rs::handle_request`'s hyper conversion).
    ///
    /// Split out from [`handle_request_resolver`] so the conversion is
    /// unit-testable without a live QUIC connection.
    ///
    /// The `:authority` pseudo-header is settled against `Host` the same way
    /// as on HTTP/2 (see `application::reconcile_authority`): a mismatch is
    /// the `Err` reason for a `400`, and an absent `Host` is filled in from it.
    pub(super) fn build_armature_request(
        request: &http::Request<()>,
        peer: Option<SocketAddr>,
    ) -> Result<HttpRequest, &'static str> {
        let host_from_authority = crate::application::reconcile_authority(
            // Every request on this path is HTTP/3, whatever the version field
            // says (`h3` sets it, a hand-built request may not).
            http::Version::HTTP_3,
            request.method() == http::Method::CONNECT,
            request.uri().authority().map(|a| a.as_str()),
            request
                .headers()
                .get_all(http::header::HOST)
                .iter()
                .map(|v| v.as_bytes()),
        )?;

        // `Method::from` matches the token against the well-known set, so the
        // common case is a unit variant rather than a per-request `String`.
        let method = crate::Method::from(request.method().as_str());
        // The full target, query included. Without the query, `?a=b` on a QUIC
        // request was silently dropped; carrying it in the target means the
        // router still matches on the path alone and a handler that asks for
        // the query gets it.
        let target = match request.uri().query() {
            Some(q) => format!("{}?{}", request.uri().path(), q),
            None => request.uri().path().to_string(),
        };
        let mut armature_req = HttpRequest::new(method, target).with_peer(peer);

        // Copy headers. One copy per value, because `HeaderValue` owns its own
        // buffer; the name goes in as a `&str`, so a well-known header name
        // costs nothing.
        //
        // `append`, not `insert`, for the reason `handle_request` gives: a
        // repeated field (`X-Forwarded-For`) must reach the policy above with
        // every occurrence, the same over QUIC as over TCP.
        for (name, value) in request.headers() {
            armature_req
                .headers
                .append(name.as_str(), Bytes::copy_from_slice(value.as_bytes()));
        }
        if let Some(host) = host_from_authority {
            armature_req
                .headers
                .append("host", Bytes::copy_from_slice(host.as_bytes()));
        }

        Ok(armature_req)
    }

    /// Whether a request may be served from early (0-RTT) data: only the
    /// methods RFC 9110 defines as safe, which a replay cannot turn into a
    /// second state change.
    pub(super) fn safe_for_early_data(method: &http::Method) -> bool {
        matches!(
            *method,
            http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
        )
    }

    /// A bodyless response with `status`.
    fn plain_response(status: u16) -> Response<http_body_util::Full<Bytes>> {
        let mut response = Response::new(http_body_util::Full::new(Bytes::new()));
        *response.status_mut() =
            http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_REQUEST);
        response
    }

    /// An [`HttpResponse`](crate::HttpResponse) rejection as a wire response,
    /// for the few answers given before the request reaches the pipeline.
    fn to_wire(response: crate::HttpResponse) -> Response<http_body_util::Full<Bytes>> {
        let mut wire = plain_response(response.status);
        if let Some(ct) = response.headers.get("Content-Type")
            && let Ok(value) = http::HeaderValue::from_str(ct)
        {
            wire.headers_mut().insert(http::header::CONTENT_TYPE, value);
        }
        *wire.body_mut() = http_body_util::Full::new(response.into_body_bytes());
        wire
    }

    /// Every byte of a received DATA chunk.
    ///
    /// A `Buf` may span several non-contiguous slices; `chunk()` returns only
    /// the first, so reading it alone silently truncated bodies — a signature
    /// computed by a proxy over the full body would then disagree with the
    /// bytes the handler saw.
    pub(super) fn buf_to_bytes(mut buf: impl Buf) -> Bytes {
        let remaining = buf.remaining();
        buf.copy_to_bytes(remaining)
    }

    /// One open request stream in [`Http3Stats`], closed when dropped — so the
    /// gauge comes back down however the stream ends (an error, a reset, a
    /// timeout), not only when its response was sent in full.
    struct OpenStream(Arc<Http3Stats>);

    impl OpenStream {
        fn new(stats: Arc<Http3Stats>) -> Self {
            stats.stream_created();
            Self(stats)
        }
    }

    impl Drop for OpenStream {
        fn drop(&mut self) {
            self.0.stream_closed();
        }
    }

    /// Handle a request using the RequestResolver API (h3 0.0.8+)
    async fn handle_request_resolver(
        resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
        state: ServeState,
        stats: Arc<Http3Stats>,
        confirmed: &AtomicBool,
        tracker: &Arc<crate::http2::StreamTracker>,
        options: ConnectionOptions,
    ) -> Result<(), Error> {
        // h3 hands over a stream as soon as the peer opens it, before any
        // HEADERS arrive. Waiting for them is bounded, and the stream does not
        // count as a request in flight until they have arrived: otherwise a
        // peer that opens a stream, sends nothing and keeps the connection
        // alive with PINGs would hold the connection (whose idle watcher sees
        // a request in flight) and its connection slot forever. On expiry the
        // stream is dropped, which stops both its directions.
        let (request, mut stream) =
            match tokio::time::timeout(options.handshake_timeout(), resolver.resolve_request())
                .await
            {
                Ok(resolved) => resolved
                    .map_err(|e| Error::Internal(format!("Failed to resolve request: {}", e)))?,
                Err(_) => {
                    return Err(Error::Internal(
                        "request HEADERS not received in time".to_string(),
                    ));
                }
            };
        let _active = tracker.begin();

        stats.request_processed();

        // Read once, here: a request is early data if the handshake was not
        // confirmed when its head arrived. A replayed copy of someone else's
        // 0-RTT packets never confirms, so it is always caught by this.
        let early = !confirmed.load(Ordering::Acquire);
        if early && safe_for_early_data(request.method()) {
            stats.zero_rtt_accepted();
        }

        let response = if early && !safe_for_early_data(request.method()) {
            // RFC 8470 §5.2: the client retries once the handshake completes.
            plain_response(425)
        } else {
            match build_armature_request(&request, state.peer()) {
                Err(reason) => {
                    debug!(reason, "Rejected an HTTP/3 request authority");
                    to_wire(Error::BadRequest(reason.to_string()).to_client_response())
                }
                Ok(mut armature_req) => {
                    if early {
                        // RFC 8470 §5.1: tell the application, which may
                        // still answer 425 itself.
                        armature_req
                            .headers
                            .insert("early-data", Bytes::from_static(b"1"));
                    }
                    // The shared pipeline: canonical path, preflight, declared
                    // length, early 404, body read under the cap and the
                    // slow-body policy, then middleware → guards → route, with
                    // the same response rules (CORS, fail-closed headers) as
                    // the TCP transports.
                    dispatch_via_h3(
                        armature_req,
                        |cx| match stream.poll_recv_data(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(Some(buf))) => Poll::Ready(Some(Ok(buf_to_bytes(buf)))),
                            Poll::Ready(Ok(None)) => Poll::Ready(None),
                            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                        },
                        &state,
                    )
                    .await
                }
            }
        };

        let (parts, body) = response.into_parts();
        let body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(never) => match never {},
        };
        let http_response: http::Response<()> = Response::from_parts(parts, ());

        // Every write waits on the peer's flow-control credit, so each is
        // bounded: see `Http3Server::with_write_timeout`. The response as a
        // whole is held to the policy's minimum rate as well.
        let sent = send_response(
            &mut stream,
            http_response,
            body,
            options.write_timeout,
            state.body_read(),
        )
        .await;
        if sent.is_err() {
            // Abandon the stream outright rather than leave a half-sent
            // response queued against credit that may never come.
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        sent
    }

    /// Write a response head, its body in [`RESPONSE_CHUNK`] pieces, and the
    /// end of the stream, each under `write_timeout` and the minimum rate of
    /// `rate` (see [`BodyReadPolicy`](crate::BodyReadPolicy)).
    ///
    /// The write timeout alone bounds a stall, not the transfer: a peer that
    /// grants one chunk of credit just inside every timeout never stalls, and
    /// would hold the stream — with the whole response buffered — for
    /// `size / RESPONSE_CHUNK × write_timeout`, on every stream it may open.
    /// So the write that completes with `n` bytes sent must also finish by
    /// the rate budget for `n` bytes, counted from the start of the response.
    async fn send_response<S>(
        stream: &mut h3::server::RequestStream<S, Bytes>,
        head: http::Response<()>,
        mut body: Bytes,
        write_timeout: Option<Duration>,
        rate: crate::BodyReadPolicy,
    ) -> Result<(), Error>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let started = tokio::time::Instant::now();
        // When the write that brings the total to `sent` bytes must finish.
        let deadline = |sent: usize| {
            let stall = write_timeout.map(|limit| tokio::time::Instant::now() + limit);
            let rate = rate.rate_budget(sent).map(|budget| started + budget);
            match (stall, rate) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            }
        };
        async fn bounded<T, E: std::fmt::Display>(
            deadline: Option<tokio::time::Instant>,
            what: &str,
            write: impl std::future::Future<Output = Result<T, E>>,
        ) -> Result<T, Error> {
            let written = match deadline {
                Some(at) => tokio::time::timeout_at(at, write)
                    .await
                    .map_err(|_| Error::Internal(format!("{what} timed out")))?,
                None => write.await,
            };
            written.map_err(|e| Error::Internal(format!("Failed to {what}: {e}")))
        }

        bounded(deadline(0), "send response", stream.send_response(head)).await?;
        let mut sent = 0usize;
        while !body.is_empty() {
            let chunk = body.split_to(body.len().min(RESPONSE_CHUNK));
            sent = sent.saturating_add(chunk.len());
            bounded(deadline(sent), "send body", stream.send_data(chunk)).await?;
        }
        bounded(deadline(sent), "finish stream", stream.finish()).await
    }
}

#[cfg(feature = "http3")]
pub use server::Http3Server;

// ============================================================================
// Alt-Svc Header Helper
// ============================================================================

/// Generate Alt-Svc header value for HTTP/3 advertisement
///
/// # Example
///
/// ```rust
/// use armature_core::http3::alt_svc_header;
///
/// // Advertise HTTP/3 on port 443
/// let header = alt_svc_header(443, 86400);
/// assert_eq!(header, "h3=\":443\"; ma=86400");
/// ```
pub fn alt_svc_header(port: u16, max_age_seconds: u32) -> String {
    format!("h3=\":{}\"; ma={}", port, max_age_seconds)
}

/// Generate Alt-Svc header for multiple protocols
///
/// # Example
///
/// ```rust
/// use armature_core::http3::alt_svc_header_full;
///
/// // Advertise h3 and h3-29 (draft) on port 443
/// let header = alt_svc_header_full(443, 86400, true);
/// ```
pub fn alt_svc_header_full(port: u16, max_age_seconds: u32, include_draft: bool) -> String {
    if include_draft {
        format!(
            "h3=\":{}\"; ma={}, h3-29=\":{}\"; ma={}",
            port, max_age_seconds, port, max_age_seconds
        )
    } else {
        alt_svc_header(port, max_age_seconds)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Http3Config::default();
        assert_eq!(config.max_concurrent_bidi_streams, 100);
        assert_eq!(config.max_concurrent_uni_streams, 3);
        assert!(!config.enable_0rtt);
        assert!(!config.enable_datagram);
    }

    #[test]
    fn test_high_throughput_config() {
        let config = Http3Config::high_throughput();
        assert_eq!(config.max_concurrent_bidi_streams, 250);
        assert!(!config.enable_0rtt);
        assert_eq!(config.initial_connection_receive_window, 50 * 1024 * 1024);
    }

    #[test]
    fn test_low_latency_config() {
        let config = Http3Config::low_latency();
        assert!(!config.enable_0rtt);
        assert!(config.enable_datagram);
        assert_eq!(config.max_udp_payload_size, 1200);
    }

    #[test]
    fn test_mobile_optimized_config() {
        let config = Http3Config::mobile_optimized();
        assert_eq!(config.max_idle_timeout, Duration::from_secs(120));
        assert!(!config.enable_0rtt);
    }

    #[test]
    fn test_config_builder() {
        let config = Http3Config::builder()
            .max_concurrent_bidi_streams(200)
            .enable_0rtt(true)
            .enable_datagram(true)
            .max_idle_timeout(Duration::from_secs(60))
            .build();

        assert_eq!(config.max_concurrent_bidi_streams, 200);
        assert!(config.enable_0rtt);
        assert!(config.enable_datagram);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_stats() {
        let stats = Http3Stats::new();

        stats.connection_opened();
        stats.connection_opened();
        assert_eq!(stats.active_connections(), 2);
        assert_eq!(stats.total_connections(), 2);

        stats.stream_created();
        stats.stream_created();
        stats.stream_created();
        assert_eq!(stats.active_streams(), 3);

        stats.request_processed();
        stats.request_processed();
        assert_eq!(stats.total_requests(), 2);

        stats.zero_rtt_accepted();
        assert_eq!(stats.total_zero_rtt_accepted(), 1);

        stats.connection_migrated();
        stats.connection_migrated();
        assert_eq!(stats.total_connection_migrations(), 2);

        stats.stream_closed();
        assert_eq!(stats.active_streams(), 2);

        stats.connection_closed();
        assert_eq!(stats.active_connections(), 1);
    }

    #[test]
    fn test_alt_svc_header() {
        let header = alt_svc_header(443, 86400);
        assert_eq!(header, "h3=\":443\"; ma=86400");

        let header = alt_svc_header(8443, 3600);
        assert_eq!(header, "h3=\":8443\"; ma=3600");
    }

    #[test]
    fn test_alt_svc_header_full() {
        let header = alt_svc_header_full(443, 86400, true);
        assert!(header.contains("h3=\":443\""));
        assert!(header.contains("h3-29=\":443\""));

        let header = alt_svc_header_full(443, 86400, false);
        assert!(!header.contains("h3-29"));
    }

    /// Regression: the advertised flow-control windows must actually be applied
    /// to the quinn transport config. Two configs that differ only in their
    /// stream/connection receive windows must produce different transport
    /// parameters; before the fix the knobs were dead and both were identical.
    #[cfg(feature = "http3")]
    #[test]
    fn test_configure_quinn_applies_flow_control_windows() {
        let base = Http3Config::default();
        // Same as `base` except for the two flow-control windows.
        let widened = Http3Config::builder()
            .initial_stream_receive_window(base.initial_stream_receive_window * 3 + 1)
            .initial_connection_receive_window(base.initial_connection_receive_window * 3 + 1)
            .build();

        let base_transport = format!("{:?}", super::server::build_transport(&base));
        let widened_transport = format!("{:?}", super::server::build_transport(&widened));

        assert_ne!(
            base_transport, widened_transport,
            "flow-control windows must be reflected in the quinn transport config"
        );
        assert!(
            widened_transport.contains(&widened.initial_stream_receive_window.to_string()),
            "stream receive window must appear in the applied transport config"
        );
        assert!(
            widened_transport.contains(&widened.initial_connection_receive_window.to_string()),
            "connection receive window must appear in the applied transport config"
        );
    }

    /// H2 regression: a DATA chunk spanning several slices is copied whole.
    /// Reading only `chunk()` (the first contiguous slice) truncated it.
    #[cfg(feature = "http3")]
    #[test]
    fn test_buf_to_bytes_copies_every_slice() {
        use bytes::{Buf, Bytes};
        let chained = Bytes::from_static(b"ab")
            .chain(Bytes::from_static(b"cd"))
            .chain(Bytes::from_static(b"ef"));
        assert_eq!(chained.chunk(), b"ab", "the premise: several slices");
        assert_eq!(&super::server::buf_to_bytes(chained)[..], b"abcdef");
    }

    /// Repeated header fields keep every occurrence over QUIC, as over TCP.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_keeps_repeated_headers() {
        let request = http::Request::builder()
            .uri("https://example.com/")
            .header("x-forwarded-for", "198.51.100.9")
            .header("x-forwarded-for", "203.0.113.7")
            .body(())
            .unwrap();
        let armature_req =
            super::server::build_armature_request(&request, None).expect("no authority conflict");
        assert_eq!(armature_req.headers.get_all("x-forwarded-for").len(), 2);
    }

    /// Regression: query strings must be parsed and percent-decoded on the
    /// HTTP/3 path, just like the hyper-based `application.rs::handle_request`.
    /// Before the fix, `handle_request_resolver` built the Armature request
    /// from `request.uri().path()` only and never touched `.query()`, so
    /// `?a=b` was silently dropped on every `listen_h3` / `listen_dual_stack`
    /// QUIC request.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_decodes_query_params() {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://example.com/search?a=b&name=hello%20world")
            .body(())
            .unwrap();

        let armature_req =
            super::server::build_armature_request(&request, None).expect("no authority conflict");

        assert_eq!(armature_req.method, "GET");
        assert_eq!(armature_req.path_only(), "/search");
        assert_eq!(armature_req.query_param("a"), Some("b"));
        assert_eq!(armature_req.query_param("name"), Some("hello world"));
    }

    /// Requests without a query string must yield an empty query view.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_without_query_string() {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://example.com/no-query")
            .body(())
            .unwrap();

        let armature_req =
            super::server::build_armature_request(&request, None).expect("no authority conflict");

        assert!(armature_req.query().is_empty());
        assert_eq!(armature_req.query_string(), None);
    }

    /// A URI ending in a bare `?` has a query string that is present but
    /// empty (`request.uri().query()` returns `Some("")`), distinct from no
    /// query string at all. `build_armature_request` must not panic and
    /// must produce an empty query view in this case.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_with_empty_query_string() {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://example.com/search?")
            .body(())
            .unwrap();

        assert_eq!(request.uri().query(), Some(""));

        let armature_req =
            super::server::build_armature_request(&request, None).expect("no authority conflict");

        assert_eq!(armature_req.path_only(), "/search");
        assert!(armature_req.query().is_empty());
    }

    /// Duplicate query keys are all preserved, in the order the client sent
    /// them; `get` answers with the first. The old `HashMap`-backed parse kept
    /// only the last.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_with_duplicate_query_keys() {
        let request = http::Request::builder()
            .method("GET")
            .uri("https://example.com/search?a=1&a=2")
            .body(())
            .unwrap();

        let armature_req =
            super::server::build_armature_request(&request, None).expect("no authority conflict");

        assert_eq!(armature_req.query().len(), 2);
        assert_eq!(armature_req.query_param("a"), Some("1"));
        assert_eq!(
            armature_req.query().get_all("a").collect::<Vec<_>>(),
            vec!["1", "2"]
        );
    }

    /// No preset turns on replayable 0-RTT or server-side keep-alive (which
    /// would hold idle connections open forever), and every one bounds the
    /// header section.
    #[test]
    fn test_presets_are_safe_by_default() {
        for (name, config) in [
            ("default", Http3Config::default()),
            ("high_throughput", Http3Config::high_throughput()),
            ("low_latency", Http3Config::low_latency()),
            ("mobile_optimized", Http3Config::mobile_optimized()),
        ] {
            assert!(!config.enable_0rtt, "{name}: 0-RTT is opt-in");
            assert_eq!(config.keep_alive_interval, None, "{name}");
            assert_eq!(
                config.max_field_section_size, DEFAULT_MAX_FIELD_SECTION_SIZE,
                "{name}"
            );
        }
        let config = Http3Config::builder().max_field_section_size(4096).build();
        assert_eq!(config.max_field_section_size, 4096);
    }

    /// Only safe methods may be answered from replayable early data.
    #[cfg(feature = "http3")]
    #[test]
    fn test_only_safe_methods_are_served_from_early_data() {
        use http::Method;
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(super::server::safe_for_early_data(&method), "{method}");
        }
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(!super::server::safe_for_early_data(&method), "{method}");
        }
    }

    /// `:authority` reaches the request as `Host`, and a contradicting `Host`
    /// is refused, exactly as over HTTP/2.
    #[cfg(feature = "http3")]
    #[test]
    fn test_build_armature_request_reconciles_authority_and_host() {
        let request = http::Request::builder()
            .version(http::Version::HTTP_3)
            .uri("https://tenant.example/")
            .body(())
            .unwrap();
        let armature_req = super::server::build_armature_request(&request, None).unwrap();
        assert_eq!(armature_req.headers.get("host"), Some("tenant.example"));

        let request = http::Request::builder()
            .version(http::Version::HTTP_3)
            .uri("https://tenant.example/")
            .header("host", "admin.example")
            .body(())
            .unwrap();
        assert!(super::server::build_armature_request(&request, None).is_err());
    }

    /// The QUIC listener negotiates `h3` whatever ALPN list the shared TLS
    /// config carries (it offers `h2`/`http/1.1` for the TCP listeners), and
    /// does so without touching the caller's config.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[test]
    fn test_configure_quinn_negotiates_h3_only() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = crate::TlsConfig::self_signed(&["localhost"]).expect("cert");
        let shared = tls.server_config.clone();
        let router = std::sync::Arc::new(crate::route_cache::OptimizedRouter::from_router(
            &crate::Router::new(),
        ));
        let server = Http3Server::new(Http3Config::default(), router);
        let _ = server
            .configure_quinn(tls.server_config)
            .expect("quinn config");
        assert!(
            shared.alpn_protocols.iter().all(|p| p.as_slice() != b"h3"),
            "the caller's TLS config must not be mutated"
        );
    }

    /// A cert, its TLS config for the server, and a QUIC client trusting it.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    fn quic_pair() -> (crate::TlsConfig, quinn::ClientConfig) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let tls =
            crate::TlsConfig::from_pem_bytes(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h3".to_vec()];
        let client = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap(),
        ));
        (tls, client)
    }

    /// Serve `config` for a router with `/hello` on an ephemeral UDP port.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    fn spawn_h3(config: Http3Config, tls: &crate::TlsConfig, max_connections: usize) -> SocketAddr {
        spawn_h3_with(config, tls, max_connections, Some(Duration::from_secs(300))).0
    }

    /// [`spawn_h3`] with a response write timeout; also serves `/big`, a 1 MiB
    /// body.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    fn spawn_h3_with(
        config: Http3Config,
        tls: &crate::TlsConfig,
        max_connections: usize,
        write_timeout: Option<Duration>,
    ) -> (SocketAddr, std::sync::Arc<Http3Stats>) {
        spawn_h3_policy(
            config,
            tls,
            max_connections,
            write_timeout,
            crate::BodyReadPolicy::default(),
        )
    }

    /// Handlers of `/hang` that have started, and that have been dropped.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    static HANG_STARTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    static HANG_DROPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// [`spawn_h3_with`] with a body-read policy (whose minimum rate also
    /// governs responses); also serves `/hang`, a handler that never returns
    /// and counts itself in [`HANG_STARTED`] / [`HANG_DROPPED`].
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    fn spawn_h3_policy(
        config: Http3Config,
        tls: &crate::TlsConfig,
        max_connections: usize,
        write_timeout: Option<Duration>,
        policy: crate::BodyReadPolicy,
    ) -> (SocketAddr, std::sync::Arc<Http3Stats>) {
        async fn hang(_req: crate::HttpRequest) -> Result<crate::HttpResponse, crate::Error> {
            struct Dropped;
            impl Drop for Dropped {
                fn drop(&mut self) {
                    HANG_DROPPED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _dropped = Dropped;
            HANG_STARTED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::pending::<()>().await;
            unreachable!()
        }
        async fn hello(req: crate::HttpRequest) -> Result<crate::HttpResponse, crate::Error> {
            let host = req.headers.get("host").unwrap_or_default().to_owned();
            Ok(crate::HttpResponse::ok().with_body(host.into_bytes()))
        }
        async fn big(_req: crate::HttpRequest) -> Result<crate::HttpResponse, crate::Error> {
            Ok(crate::HttpResponse::ok().with_body(vec![b'x'; 1 << 20]))
        }
        let mut router = crate::Router::new();
        router.get("/hello", hello);
        router.get("/big", big);
        router.get("/hang", hang);
        let state = crate::application::ServeState::for_test(
            std::sync::Arc::new(crate::route_cache::OptimizedRouter::from_router(&router)),
            crate::DEFAULT_MAX_BODY_SIZE,
        )
        .with_body_read_for_test(policy);
        let server = Http3Server::from_state(config, state, max_connections)
            .with_write_timeout(write_timeout);
        let stats = server.stats();
        let quinn_config = server.configure_quinn(tls.server_config.clone()).unwrap();
        let endpoint =
            quinn::Endpoint::server(quinn_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(server.serve_endpoint(endpoint));
        (addr, stats)
    }

    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    async fn connect(client: &quinn::ClientConfig, addr: SocketAddr) -> quinn::Connection {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client.clone());
        tokio::time::timeout(
            Duration::from_secs(5),
            endpoint.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("handshake in time")
        .expect("the QUIC handshake must succeed")
    }

    /// The ALPN regression end to end: a real QUIC client offering `h3` must
    /// complete the handshake against a `TlsConfig` that offers `h2` and
    /// `http/1.1`, and be served — with `:authority` reaching the handler as
    /// `Host`.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_a_real_h3_client_is_served() {
        use bytes::Buf;
        let (tls, client) = quic_pair();
        assert!(
            tls.server_config
                .alpn_protocols
                .iter()
                .all(|p| p.as_slice() != b"h3"),
            "the premise: the shared TLS config does not offer h3"
        );
        let addr = spawn_h3(Http3Config::default(), &tls, 16);
        let conn = connect(&client, addr).await;

        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = send
            .send_request(
                http::Request::get("https://localhost/hello")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.copy_to_bytes(n));
        }
        assert_eq!(&body[..], b"localhost");
    }

    /// QUIC connections count against the same cap as TCP ones; past it a
    /// connection attempt is refused rather than served.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_connections_are_capped() {
        let (tls, client) = quic_pair();
        let addr = spawn_h3(Http3Config::default(), &tls, 1);
        let _held = connect(&client, addr).await;

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client.clone());
        let second = tokio::time::timeout(
            Duration::from_secs(5),
            endpoint.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("refused promptly, not left hanging");
        assert!(second.is_err(), "a connection over the cap must be refused");
    }

    /// A QUIC connection that never opens a request stream is closed at the
    /// first-request deadline even though QUIC itself would keep it alive
    /// (here: client keep-alive pings well inside the idle timeout).
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_idle_connection_is_closed() {
        let (tls, mut client) = quic_pair();
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(100)));
        client.transport_config(std::sync::Arc::new(transport));
        let config = Http3Config::builder()
            .max_idle_timeout(Duration::from_secs(1))
            .build();
        let addr = spawn_h3(config, &tls, 16);
        let conn = connect(&client, addr).await;
        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("an idle connection must be closed by the server");
        assert!(
            matches!(reason, quinn::ConnectionError::ApplicationClosed(_)),
            "{reason:?}"
        );
    }

    /// A client whose transport keeps the connection alive with PINGs.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    fn pinging(mut client: quinn::ClientConfig, stream_window: Option<u32>) -> quinn::ClientConfig {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(100)));
        if let Some(window) = stream_window {
            transport.stream_receive_window(window.into());
        }
        client.transport_config(std::sync::Arc::new(transport));
        client
    }

    /// The finding: h3 hands a stream to the server as soon as it is opened,
    /// before any HEADERS, and counting it as a request in flight from then
    /// on meant a peer that opens one, sends nothing and keeps pinging held
    /// the connection forever. The stream now has the head deadline to send
    /// HEADERS, and only counts once it has.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_stream_without_headers_does_not_hold_the_connection() {
        let (tls, client) = quic_pair();
        let config = Http3Config::builder()
            .max_idle_timeout(Duration::from_secs(1))
            .build();
        let (addr, stats) = spawn_h3_with(config, &tls, 16, Some(Duration::from_secs(300)));
        let conn = connect(&pinging(client, None), addr).await;

        // Open a request stream and send one byte of a HEADERS frame (its
        // type), never the rest: the server sees the stream, but no request.
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0x01]).await.unwrap();

        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("a stream that never sends HEADERS must not keep the connection");
        assert!(
            matches!(reason, quinn::ConnectionError::ApplicationClosed(_)),
            "{reason:?}"
        );
        // The abandoned stream is not left counted as open.
        tokio::time::timeout(Duration::from_secs(5), async {
            while stats.active_streams() != 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the open-stream gauge must come back to zero");
    }

    /// The finding: a response waits on the peer's flow-control credit, and
    /// nothing bounded that wait — a client that grants none (here: a small
    /// stream window it never drains) while pinging held the stream, the
    /// connection and its slot forever. The stalled write now times out, the
    /// stream is reset, and the then-idle connection is closed.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_response_stalled_on_flow_control_times_out() {
        let (tls, client) = quic_pair();
        let config = Http3Config::builder()
            .max_idle_timeout(Duration::from_secs(1))
            .build();
        let (addr, _) = spawn_h3_with(config, &tls, 16, Some(Duration::from_millis(300)));
        let conn = connect(&pinging(client, Some(4096)), addr).await;

        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = send
            .send_request(
                http::Request::get("https://localhost/big")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Never read the response: the 1 MiB body stalls on the 4 KiB window.

        let reason = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("a response the client never accepts must not hold the connection");
        assert!(
            matches!(reason, quinn::ConnectionError::ApplicationClosed(_)),
            "{reason:?}"
        );
        drop(stream);
    }

    /// The finding: request tasks were detached, so closing a connection
    /// released its slot in the cap while its handlers ran on — a client could
    /// keep unbounded handlers running from one slot. They are now owned by
    /// the connection and cancelled with it.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_handlers_are_cancelled_when_the_connection_closes() {
        use std::sync::atomic::Ordering::SeqCst;
        let (tls, client) = quic_pair();
        let addr = spawn_h3(Http3Config::default(), &tls, 16);
        let conn = connect(&client, addr).await;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let dropped_before = HANG_DROPPED.load(SeqCst);
        let started_before = HANG_STARTED.load(SeqCst);
        let mut stream = send
            .send_request(
                http::Request::get("https://localhost/hang")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while HANG_STARTED.load(SeqCst) == started_before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the handler started");

        conn.close(quinn::VarInt::from_u32(0), b"bye");
        tokio::time::timeout(Duration::from_secs(5), async {
            while HANG_DROPPED.load(SeqCst) == dropped_before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the in-flight handler must be cancelled with its connection");
        drop(stream);
    }

    /// Read `/big` over a 16 KiB stream window, pausing `pause` after every
    /// chunk, from a server with a `min_rate` floor (after a 200 ms grace) and
    /// a write timeout far longer than any pause. Returns the bytes received
    /// and whether the body ended cleanly.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    async fn read_h3_big_at(pause: Duration, min_rate: u64) -> (usize, bool) {
        use bytes::Buf;
        let (tls, client) = quic_pair();
        let policy = crate::BodyReadPolicy {
            idle_timeout: Duration::from_millis(200),
            min_bytes_per_sec: min_rate,
        };
        let (addr, _) = spawn_h3_policy(
            Http3Config::default(),
            &tls,
            16,
            Some(Duration::from_secs(5)),
            policy,
        );
        let conn = connect(&pinging(client, Some(16 * 1024)), addr).await;
        let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = send
            .send_request(
                http::Request::get("https://localhost/big")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let mut received = 0usize;
        let Ok(response) = stream.recv_response().await else {
            return (0, false);
        };
        assert_eq!(response.status(), 200);
        loop {
            match stream.recv_data().await {
                Ok(None) => return (received, true),
                Err(_) => return (received, false),
                Ok(Some(chunk)) => received += chunk.remaining(),
            }
            tokio::time::sleep(pause).await;
        }
    }

    /// The finding: each write needed only to finish within the write
    /// timeout, so a peer granting a little credit at a time held a stream and
    /// its buffered response for hours. A response accepted below the minimum
    /// rate now has its stream reset.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_response_below_the_minimum_rate_is_reset() {
        // At most ~160 KiB/s against a 512 KiB/s floor.
        let (received, complete) = tokio::time::timeout(
            Duration::from_secs(5),
            read_h3_big_at(Duration::from_millis(100), 512 * 1024),
        )
        .await
        .expect("a below-rate response must be cut off, not trickled out");
        assert!(!complete && received < 1 << 20, "received {received}");
    }

    /// A reader above the floor is served in full.
    #[cfg(all(feature = "http3", feature = "self-signed-certs"))]
    #[tokio::test]
    async fn test_h3_response_above_the_minimum_rate_completes() {
        let (received, complete) = tokio::time::timeout(
            Duration::from_secs(10),
            read_h3_big_at(Duration::from_millis(2), 64 * 1024),
        )
        .await
        .expect("served in time");
        assert!(complete);
        assert_eq!(received, 1 << 20);
    }
}
