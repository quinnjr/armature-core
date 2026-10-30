//! HTTP/2 Support
//!
//! This module provides HTTP/2 server capabilities for the Armature framework.
//! HTTP/2 offers significant performance improvements over HTTP/1.1:
//!
//! - **Multiplexing**: Multiple requests over a single connection
//! - **Header Compression**: HPACK compression reduces overhead
//! - **Server Push**: Proactively send resources (optional)
//! - **Binary Protocol**: More efficient parsing than text-based HTTP/1.1
//! - **Flow Control**: Per-stream and connection-level flow control
//!
//! ## Usage
//!
//! ```rust,ignore
//! use armature_core::{Application, Http2Config};
//!
//! // HTTP/2 over TLS (recommended)
//! let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?
//!     .with_alpn_protocols(vec!["h2", "http/1.1"]);
//! app.listen_https_h2(443, tls).await?;
//!
//! // HTTP/2 cleartext (h2c) - for development/internal use
//! app.listen_h2c(8080).await?;
//! ```
//!
//! ## ALPN Negotiation
//!
//! When using HTTPS, the server automatically negotiates the best protocol:
//! 1. If client supports HTTP/2 and advertises "h2", use HTTP/2
//! 2. Otherwise, fall back to HTTP/1.1
//!
//! ## Performance Considerations
//!
//! - HTTP/2 excels with many concurrent requests
//! - Single large file transfers may not see improvement
//! - Header compression benefits repeated similar requests
//! - Flow control prevents fast senders from overwhelming slow receivers

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// HTTP/2 server configuration
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http2Config {
    /// Initial connection-level flow control window size (bytes)
    /// Default: 65535 (64KB) - HTTP/2 spec default
    /// Increase for high-bandwidth connections
    pub initial_connection_window_size: u32,

    /// Initial stream-level flow control window size (bytes)
    /// Default: 65535 (64KB) - HTTP/2 spec default
    pub initial_stream_window_size: u32,

    /// Maximum concurrent streams per connection
    /// Default: 100 - balance between parallelism and resource usage
    ///
    /// Kept at the RFC 9113 recommended minimum rather than lowered: what made
    /// a high stream count dangerous was each stream buffering a whole body,
    /// and that is bounded per connection by
    /// [`max_buffered_body_bytes`](Self::max_buffered_body_bytes) instead.
    pub max_concurrent_streams: u32,

    /// Maximum frame size (bytes)
    /// Default: 16384 (16KB) - HTTP/2 spec default
    /// Max: 16777215 (16MB)
    pub max_frame_size: u32,

    /// Maximum header list size (bytes)
    /// Default: 16384 (16KB)
    pub max_header_list_size: u32,

    /// Enable the HTTP/2 extended CONNECT protocol (RFC 8441)
    /// Required for WebSockets over HTTP/2
    /// Default: false
    pub enable_connect_protocol: bool,

    /// Keep-alive interval for PING frames
    /// Default: 20 seconds
    pub keep_alive_interval: Option<Duration>,

    /// Keep-alive timeout (how long to wait for PING response)
    /// Default: 10 seconds
    pub keep_alive_timeout: Duration,

    /// Maximum send buffer size per stream (bytes)
    /// Default: 1MB
    pub max_send_buffer_size: usize,

    /// Enable adaptive flow control window sizing
    /// Default: true
    pub adaptive_window: bool,

    /// Most request-body bytes one connection may hold buffered at once,
    /// summed across all of its concurrent streams; `None` (the default) means
    /// twice the application's body cap
    /// ([`Application::with_max_body_size`](crate::Application::with_max_body_size)).
    ///
    /// Every request body is buffered whole before its handler runs, so
    /// without this an HTTP/2 connection could hold `max_concurrent_streams`
    /// bodies of up to the body cap each — a gigabyte per connection at the
    /// defaults — where an HTTP/1.1 connection holds one. A stream whose body
    /// would push the connection past the budget is answered `503` and the
    /// bytes it had buffered are released; the client may retry it once its
    /// other uploads finish.
    pub max_buffered_body_bytes: Option<usize>,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            initial_connection_window_size: 65535,
            initial_stream_window_size: 65535,
            max_concurrent_streams: 100,
            max_frame_size: 16384,
            max_header_list_size: 16384,
            enable_connect_protocol: false,
            keep_alive_interval: Some(Duration::from_secs(20)),
            keep_alive_timeout: Duration::from_secs(10),
            max_send_buffer_size: 1024 * 1024, // 1MB
            adaptive_window: true,
            max_buffered_body_bytes: None,
        }
    }
}

impl Http2Config {
    /// Create a new builder
    pub fn builder() -> Http2ConfigBuilder {
        Http2ConfigBuilder::default()
    }

    /// High-throughput configuration for bandwidth-intensive workloads
    pub fn high_throughput() -> Self {
        Self {
            initial_connection_window_size: 1024 * 1024, // 1MB
            initial_stream_window_size: 512 * 1024,      // 512KB
            max_concurrent_streams: 250,
            max_frame_size: 65536, // 64KB
            max_header_list_size: 32768,
            enable_connect_protocol: false,
            keep_alive_interval: Some(Duration::from_secs(30)),
            keep_alive_timeout: Duration::from_secs(15),
            max_send_buffer_size: 4 * 1024 * 1024, // 4MB
            adaptive_window: true,
            max_buffered_body_bytes: None,
        }
    }

    /// Low-latency configuration for request/response workloads
    pub fn low_latency() -> Self {
        Self {
            initial_connection_window_size: 65535,
            initial_stream_window_size: 32768,
            max_concurrent_streams: 50,
            max_frame_size: 16384,
            max_header_list_size: 8192,
            enable_connect_protocol: false,
            keep_alive_interval: Some(Duration::from_secs(10)),
            keep_alive_timeout: Duration::from_secs(5),
            max_send_buffer_size: 256 * 1024, // 256KB
            adaptive_window: false,
            max_buffered_body_bytes: None,
        }
    }

    /// Memory-efficient configuration for resource-constrained environments
    pub fn memory_efficient() -> Self {
        Self {
            initial_connection_window_size: 32768,
            initial_stream_window_size: 16384,
            max_concurrent_streams: 25,
            max_frame_size: 16384,
            max_header_list_size: 8192,
            enable_connect_protocol: false,
            keep_alive_interval: Some(Duration::from_secs(60)),
            keep_alive_timeout: Duration::from_secs(20),
            max_send_buffer_size: 128 * 1024, // 128KB
            adaptive_window: false,
            max_buffered_body_bytes: None,
        }
    }
}

/// Builder for Http2Config
#[derive(Debug, Clone, Default)]
pub struct Http2ConfigBuilder {
    config: Http2Config,
}

impl Http2ConfigBuilder {
    /// Set initial connection window size
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.config.initial_connection_window_size = size;
        self
    }

    /// Set initial stream window size
    pub fn initial_stream_window_size(mut self, size: u32) -> Self {
        self.config.initial_stream_window_size = size;
        self
    }

    /// Set maximum concurrent streams
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    /// Set maximum frame size
    pub fn max_frame_size(mut self, size: u32) -> Self {
        self.config.max_frame_size = size.min(16777215); // HTTP/2 max
        self
    }

    /// Set maximum header list size
    pub fn max_header_list_size(mut self, size: u32) -> Self {
        self.config.max_header_list_size = size;
        self
    }

    /// Enable or disable the extended CONNECT protocol (RFC 8441)
    pub fn enable_connect_protocol(mut self, enable: bool) -> Self {
        self.config.enable_connect_protocol = enable;
        self
    }

    /// Set keep-alive interval
    pub fn keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.config.keep_alive_interval = interval;
        self
    }

    /// Set keep-alive timeout
    pub fn keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.config.keep_alive_timeout = timeout;
        self
    }

    /// Set maximum send buffer size
    pub fn max_send_buffer_size(mut self, size: usize) -> Self {
        self.config.max_send_buffer_size = size;
        self
    }

    /// Enable or disable adaptive window sizing
    pub fn adaptive_window(mut self, enable: bool) -> Self {
        self.config.adaptive_window = enable;
        self
    }

    /// Set the per-connection budget for buffered request bodies (see
    /// [`Http2Config::max_buffered_body_bytes`]).
    pub fn max_buffered_body_bytes(mut self, bytes: Option<usize>) -> Self {
        self.config.max_buffered_body_bytes = bytes;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Http2Config {
        self.config
    }
}

// ============================================================================
// HTTP/2 Statistics
// ============================================================================

/// Statistics for HTTP/2 connections
#[derive(Debug, Default)]
pub struct Http2Stats {
    /// Active HTTP/2 connections
    active_connections: AtomicUsize,
    /// Total HTTP/2 connections
    total_connections: AtomicU64,
    /// Total streams created
    total_streams: AtomicU64,
    /// Active streams
    active_streams: AtomicUsize,
    /// Total requests processed
    total_requests: AtomicU64,
    /// GOAWAY frames sent (graceful shutdown)
    goaway_sent: AtomicU64,
    /// RST_STREAM frames sent (stream reset)
    rst_stream_sent: AtomicU64,
}

impl Http2Stats {
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

    /// Record a GOAWAY frame sent (graceful shutdown)
    #[inline]
    pub fn goaway_sent(&self) {
        self.goaway_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total GOAWAY frames sent
    #[inline]
    pub fn total_goaway_sent(&self) -> u64 {
        self.goaway_sent.load(Ordering::Relaxed)
    }

    /// Record an RST_STREAM frame sent
    #[inline]
    pub fn rst_stream_sent(&self) {
        self.rst_stream_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total RST_STREAM frames sent
    #[inline]
    pub fn total_rst_stream_sent(&self) -> u64 {
        self.rst_stream_sent.load(Ordering::Relaxed)
    }
}

// ============================================================================
// HTTP/2 Connection Builder
// ============================================================================

/// Builder for configuring HTTP/2 connections
pub struct Http2Builder {
    config: Http2Config,
    stats: Arc<Http2Stats>,
}

impl Http2Builder {
    /// Create a new HTTP/2 builder with default config
    pub fn new() -> Self {
        Self {
            config: Http2Config::default(),
            stats: Arc::new(Http2Stats::new()),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: Http2Config) -> Self {
        Self {
            config,
            stats: Arc::new(Http2Stats::new()),
        }
    }

    /// Create with shared statistics
    pub fn with_stats(config: Http2Config, stats: Arc<Http2Stats>) -> Self {
        Self { config, stats }
    }

    /// Get the configuration
    pub fn config(&self) -> &Http2Config {
        &self.config
    }

    /// Get shared statistics
    pub fn stats(&self) -> Arc<Http2Stats> {
        Arc::clone(&self.stats)
    }

    /// Configure a Hyper http2::Builder
    #[inline]
    pub fn configure_hyper_builder(
        &self,
    ) -> hyper::server::conn::http2::Builder<hyper_util::rt::TokioExecutor> {
        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());

        // A timer is not optional: every `Http2Config` preset sets
        // `keep_alive_interval`, and hyper panics ("You must supply a timer.")
        // on the first connection that arms a keep-alive ping without one.
        // It is set unconditionally so a config without keep-alive cannot
        // reintroduce that by later gaining one.
        builder.timer(hyper_util::rt::TokioTimer::new());

        builder
            .initial_connection_window_size(self.config.initial_connection_window_size)
            .initial_stream_window_size(self.config.initial_stream_window_size)
            .max_concurrent_streams(self.config.max_concurrent_streams)
            .max_frame_size(self.config.max_frame_size)
            .max_header_list_size(self.config.max_header_list_size)
            .max_send_buf_size(self.config.max_send_buffer_size)
            .adaptive_window(self.config.adaptive_window);

        if self.config.enable_connect_protocol {
            builder.enable_connect_protocol();
        }

        if let Some(interval) = self.config.keep_alive_interval {
            builder.keep_alive_interval(interval);
            builder.keep_alive_timeout(self.config.keep_alive_timeout);
        }

        builder
    }
}

impl Default for Http2Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Builder {
    /// Everything needed to serve one connection with this builder's tuning
    /// and the connection-lifetime deadlines below.
    ///
    /// `pipeline` supplies the two deadlines HTTP/2 shares with HTTP/1.1 —
    /// `keep_alive_timeout` (how long a connection may sit with no request in
    /// flight) and `write_timeout` (how long one write may stall) — so a
    /// deployment configures idleness once for every TCP listener.
    /// `max_body_size` is the application's body cap, from which the
    /// per-connection body budget defaults.
    pub(crate) fn connection_server(
        &self,
        pipeline: &crate::pipeline::PipelineConfig,
        max_body_size: usize,
    ) -> H2ConnectionServer {
        H2ConnectionServer {
            builder: self.configure_hyper_builder(),
            stats: Arc::clone(&self.stats),
            limits: H2ConnectionLimits {
                handshake_timeout: crate::pipeline::HEADER_READ_TIMEOUT,
                idle_timeout: pipeline.keep_alive_timeout,
                shutdown_grace: crate::pipeline::HEADER_READ_TIMEOUT,
                write_timeout: pipeline.write_timeout,
                body_budget: self
                    .config
                    .max_buffered_body_bytes
                    .unwrap_or_else(|| max_body_size.saturating_mul(2))
                    // At least one maximal body must fit, or a lone upload the
                    // application accepts over HTTP/1.1 is refused here.
                    .max(max_body_size),
            },
        }
    }
}

// ============================================================================
// Bounded connection serving
// ============================================================================

/// The deadlines and budgets one hyper-served HTTP/2 connection runs under.
///
/// hyper's HTTP/2 driver has none of its own: no deadline for the client
/// preface, and no idle timeout — its keep-alive PINGs only detect a *dead*
/// peer, and a live one that answers them while opening no streams holds the
/// connection, its slot in the accept loop's connection limit (or in an
/// `armature-h1` worker's), and its buffers forever. A few thousand of those
/// exhaust the limit and the server stops accepting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct H2ConnectionLimits {
    /// From accept to the first request: covers the client preface, the
    /// SETTINGS exchange and the first HEADERS frame.
    pub(crate) handshake_timeout: Duration,
    /// How long the connection may have no stream in flight before it is
    /// closed (`GOAWAY`, then a close once the peer acknowledges).
    pub(crate) idle_timeout: Duration,
    /// How long a graceful shutdown may take before the connection is simply
    /// dropped: a peer that never answers the `GOAWAY` handshake must not turn
    /// "closing" into a new way to hold a slot.
    pub(crate) shutdown_grace: Duration,
    /// How long one socket write may stall (see
    /// [`WriteDeadline`](crate::pipeline::WriteDeadline)), and how long one
    /// stream's response body may make no progress (see [`TrackedBody`]).
    pub(crate) write_timeout: Option<Duration>,
    /// Request-body bytes the connection may buffer at once across streams.
    pub(crate) body_budget: usize,
}

/// Serves HTTP/2 connections through hyper under [`H2ConnectionLimits`].
///
/// The one place every hyper HTTP/2 connection is driven — `listen_h2c`, the
/// hyper `listen_https_h2`, and the `armature-h1` ALPN fallback — so the
/// deadlines cannot be present on one listener and missing on another.
#[derive(Clone)]
pub(crate) struct H2ConnectionServer {
    builder: hyper::server::conn::http2::Builder<hyper_util::rt::TokioExecutor>,
    stats: Arc<Http2Stats>,
    limits: H2ConnectionLimits,
}

impl H2ConnectionServer {
    /// The limits this server applies.
    #[cfg(test)]
    pub(crate) fn limits(&self) -> H2ConnectionLimits {
        self.limits
    }

    /// The same server with different limits, for tests that need deadlines
    /// short enough to wait out.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: H2ConnectionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Serve `io` as one HTTP/2 connection with `state`, until the peer closes
    /// it, it fails, or a deadline closes it.
    ///
    /// Not `Send`-bounded on `io`: the `armature-h1` fallback hands over a
    /// `Box<dyn Transport>` on a `current_thread` worker, and the accept loops
    /// that do spawn this onto a multi-threaded runtime pass a `Send` stream,
    /// which makes the future `Send` for them.
    pub(crate) async fn serve<T>(
        &self,
        io: T,
        state: crate::application::ServeState,
    ) -> Result<(), hyper::Error>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    {
        use hyper::body::Incoming as IncomingBody;
        use hyper::service::service_fn;

        let limits = self.limits;
        let tracker = Arc::new(StreamTracker::new());
        // One budget per connection, shared by its streams through the state
        // every one of them is served with.
        let state = state.with_body_budget(limits.body_budget);
        let stats = Arc::clone(&self.stats);
        stats.connection_opened();

        let service =
            {
                let tracker = Arc::clone(&tracker);
                let stats = Arc::clone(&stats);
                service_fn(move |req: hyper::Request<IncomingBody>| {
                    // Taken before the handler future exists and handed on to the
                    // response body, so it is released only once the response has
                    // been sent in full or the stream is gone (a reset, the
                    // connection closing): the idle clock runs only while nothing
                    // is in flight. Releasing it when the handler returned left a
                    // response still waiting on the peer's flow-control window
                    // uncounted, and a peer that never opens the window could pin
                    // a stream's worth of response per stream, indefinitely.
                    let active = tracker.begin();
                    stats.request_processed();
                    let state = state.clone();
                    let tracker = Arc::clone(&tracker);
                    async move {
                        let response = crate::application::handle_request(req, state).await?;
                        Ok::<_, hyper::Error>(response.map(|body| {
                            TrackedBody::new(body, active, &tracker, limits.write_timeout)
                        }))
                    }
                })
            };

        let io = hyper_util::rt::TokioIo::new(crate::pipeline::WriteDeadline::new(
            io,
            limits.write_timeout,
        ));
        let conn = self.builder.serve_connection(io, service);
        let mut conn = std::pin::pin!(conn);

        let mut deadline = tracker.started + limits.handshake_timeout;
        let served = loop {
            tokio::select! {
                served = conn.as_mut() => break Some(served),
                () = tokio::time::sleep_until(deadline) => {
                    let now = tokio::time::Instant::now();
                    let Some(next) = tracker.next_deadline(now, limits.idle_timeout) else {
                        break None;
                    };
                    // hyper cannot reset one stream from out here, so a
                    // response the peer has stopped accepting closes the
                    // connection, the way a stalled write does on HTTP/1.1.
                    match limits
                        .write_timeout
                        .map(|limit| tracker.next_stall_deadline(now, limit))
                    {
                        Some(Err(Stalled)) => break None,
                        Some(Ok(Some(stall))) => deadline = next.min(stall),
                        _ => deadline = next,
                    }
                }
            }
        };

        let served = match served {
            Some(served) => served,
            None => {
                crate::logging::debug!(
                    seen_request = tracker.seen(),
                    "closing an HTTP/2 connection that is idle past its deadline"
                );
                stats.goaway_sent();
                // `GOAWAY` and let in-flight work (there is none) finish; a
                // connection still mid-handshake is closed as soon as the
                // handshake completes, which for a silent peer is never — so
                // the grace bound below is what actually ends it.
                conn.as_mut().graceful_shutdown();
                tokio::time::timeout(limits.shutdown_grace, conn.as_mut())
                    .await
                    .unwrap_or(Ok(()))
            }
        };
        stats.connection_closed();
        served
    }
}

/// Counts a connection's in-flight streams and remembers when it last went
/// idle, so a watcher can tell an idle connection from a busy one without
/// being woken per request. Shared by [`H2ConnectionServer::serve`] and the
/// HTTP/3 server, which has the same problem: a peer that keeps a connection
/// alive at the transport level (PING frames) while opening no streams.
///
/// The watcher sleeps until the earliest moment the connection *could* be
/// over its deadline, then asks [`next_deadline`](Self::next_deadline): one
/// timer per idle period rather than one per request, and two atomic updates
/// on the request path.
pub(crate) struct StreamTracker {
    /// When the connection was accepted; the first-request deadline counts
    /// from here.
    pub(crate) started: tokio::time::Instant,
    active: AtomicUsize,
    /// Streams ever begun; non-zero once the handshake deadline is satisfied.
    begun: AtomicU64,
    /// When `active` last fell to zero, as nanoseconds since `started`.
    idle_since_nanos: AtomicU64,
    /// The response bodies still being sent, each as the moment (nanoseconds
    /// since `started`) it last made progress. Weak, so a finished body drops
    /// out by itself; the watcher sweeps the dead entries.
    responses: std::sync::Mutex<Vec<std::sync::Weak<AtomicU64>>>,
}

/// A response body made no progress within the write timeout.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stalled;

impl StreamTracker {
    pub(crate) fn new() -> Self {
        Self {
            started: tokio::time::Instant::now(),
            active: AtomicUsize::new(0),
            begun: AtomicU64::new(0),
            idle_since_nanos: AtomicU64::new(0),
            responses: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Nanoseconds from `started` to `at`.
    fn nanos_at(&self, at: tokio::time::Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.started).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Start watching a response body for progress; the body stamps the
    /// returned clock each time it is polled.
    fn watch_response(&self) -> Arc<AtomicU64> {
        let clock = Arc::new(AtomicU64::new(self.nanos_at(tokio::time::Instant::now())));
        if let Ok(mut responses) = self.responses.lock() {
            // Sweep here as well as in the watcher, so a busy connection whose
            // watcher rarely runs does not accumulate finished entries.
            if responses.len() >= 64 {
                responses.retain(|r| r.strong_count() > 0);
            }
            responses.push(Arc::downgrade(&clock));
        }
        clock
    }

    /// When a response body next could have stalled past `write_timeout`,
    /// `Ok(None)` if none is being sent, or [`Stalled`] if one already has.
    pub(crate) fn next_stall_deadline(
        &self,
        now: tokio::time::Instant,
        write_timeout: Duration,
    ) -> Result<Option<tokio::time::Instant>, Stalled> {
        let Ok(mut responses) = self.responses.lock() else {
            return Ok(None);
        };
        let mut oldest: Option<u64> = None;
        responses.retain(|r| match r.upgrade() {
            Some(clock) => {
                let at = clock.load(Ordering::Acquire);
                oldest = Some(oldest.map_or(at, |o| o.min(at)));
                true
            }
            None => false,
        });
        let Some(oldest) = oldest else {
            return Ok(None);
        };
        let expires = self.started + Duration::from_nanos(oldest) + write_timeout;
        if expires <= now {
            Err(Stalled)
        } else {
            Ok(Some(expires))
        }
    }

    /// Whether any stream has begun.
    pub(crate) fn seen(&self) -> bool {
        self.begun.load(Ordering::Acquire) > 0
    }

    /// Count one stream in flight until the returned guard drops.
    pub(crate) fn begin(self: &Arc<Self>) -> ActiveStream {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.begun.fetch_add(1, Ordering::AcqRel);
        ActiveStream(Arc::clone(self))
    }

    /// When the watcher should look again, or `None` to close the connection.
    ///
    /// Called when the previous deadline fires; the first one is `started`
    /// plus the first-request timeout, so a connection that has never begun a
    /// stream by then is closed.
    pub(crate) fn next_deadline(
        &self,
        now: tokio::time::Instant,
        idle_timeout: Duration,
    ) -> Option<tokio::time::Instant> {
        if !self.seen() {
            // The first-request deadline has passed without a single request.
            return None;
        }
        if self.active.load(Ordering::Acquire) > 0 {
            return Some(now + idle_timeout);
        }
        let idle_since =
            self.started + Duration::from_nanos(self.idle_since_nanos.load(Ordering::Acquire));
        let expires = idle_since + idle_timeout;
        (expires > now).then_some(expires)
    }
}

/// The largest piece of a response body handed to hyper at once. hyper polls
/// the body for its next piece only once the previous one has been queued
/// against the peer's flow-control window, so each poll is a sign of
/// progress; one whole-body frame would show none until the very end.
const RESPONSE_CHUNK: usize = 16 * 1024;

/// A response body that keeps its stream counted as in flight until it has
/// been sent (or the stream is gone), and reports its progress to the
/// connection's watcher, which closes the connection when one stops making
/// any for the write timeout.
///
/// A peer can stop a response dead without stalling the socket: advertise a
/// zero (or never-replenished) stream window and the body waits on credit
/// while every socket write succeeds, so the
/// [`WriteDeadline`](crate::pipeline::WriteDeadline) never arms. Without this,
/// such a stream was not even counted as in flight, so the connection could
/// also go on serving cheap requests, resetting its idle clock, while up to
/// `max_concurrent_streams` large responses sat pinned in memory.
pub(crate) struct TrackedBody {
    /// Bytes not yet handed to hyper.
    pending: bytes::Bytes,
    inner: http_body_util::Full<bytes::Bytes>,
    /// Stamped on every poll; `None` without a write timeout.
    progress: Option<Arc<AtomicU64>>,
    tracker: Arc<StreamTracker>,
    _active: ActiveStream,
}

impl TrackedBody {
    fn new(
        inner: http_body_util::Full<bytes::Bytes>,
        active: ActiveStream,
        tracker: &Arc<StreamTracker>,
        write_timeout: Option<Duration>,
    ) -> Self {
        use hyper::body::Body as _;
        // A body with nothing to send is never polled: hyper ends the stream
        // with the headers.
        let progress =
            (write_timeout.is_some() && !inner.is_end_stream()).then(|| tracker.watch_response());
        Self {
            pending: bytes::Bytes::new(),
            inner,
            progress,
            tracker: Arc::clone(tracker),
            _active: active,
        }
    }
}

impl hyper::body::Body for TrackedBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        let this = &mut *self;
        if let Some(progress) = &this.progress {
            progress.store(
                this.tracker.nanos_at(tokio::time::Instant::now()),
                Ordering::Release,
            );
        }
        if this.pending.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.pending = data,
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                other => return other,
            }
        }
        let n = this.pending.len().min(RESPONSE_CHUNK);
        Poll::Ready(Some(Ok(hyper::body::Frame::data(this.pending.split_to(n)))))
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = self.inner.size_hint();
        let pending = self.pending.len() as u64;
        hint.set_lower(hint.lower() + pending);
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper + pending);
        }
        hint
    }
}

/// One in-flight stream; dropping it may start the connection's idle clock.
pub(crate) struct ActiveStream(Arc<StreamTracker>);

impl Drop for ActiveStream {
    fn drop(&mut self) {
        let tracker = &self.0;
        // Stamp before decrementing, so a watcher that sees `active == 0` also
        // sees an idle-since no older than the moment it became true.
        let since = tokio::time::Instant::now().saturating_duration_since(tracker.started);
        tracker.idle_since_nanos.store(
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        tracker.active.fetch_sub(1, Ordering::AcqRel);
    }
}

// ============================================================================
// Protocol Detection
// ============================================================================

/// HTTP protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpProtocol {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    H2,
    /// HTTP/2 over cleartext (h2c)
    H2c,
}

impl HttpProtocol {
    /// Check if this is HTTP/2
    #[inline]
    pub fn is_h2(&self) -> bool {
        matches!(self, Self::H2 | Self::H2c)
    }

    /// Get ALPN protocol identifier
    pub fn alpn_id(&self) -> &'static [u8] {
        match self {
            Self::Http10 | Self::Http11 => b"http/1.1",
            Self::H2 | Self::H2c => b"h2",
        }
    }
}

/// ALPN protocols for HTTP/2 with HTTP/1.1 fallback
pub const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];

/// ALPN protocols for HTTP/2 only
pub const ALPN_H2_ONLY: &[&[u8]] = &[b"h2"];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Http2Config::default();
        assert_eq!(config.initial_connection_window_size, 65535);
        assert_eq!(config.max_concurrent_streams, 100);
        assert_eq!(config.max_frame_size, 16384);
    }

    #[test]
    fn test_high_throughput_config() {
        let config = Http2Config::high_throughput();
        assert_eq!(config.initial_connection_window_size, 1024 * 1024);
        assert_eq!(config.max_concurrent_streams, 250);
    }

    #[test]
    fn test_enable_connect_protocol_builder() {
        let config = Http2Config::builder().enable_connect_protocol(true).build();
        assert!(config.enable_connect_protocol);

        // Ensure the hyper builder can be constructed with it enabled
        let builder = Http2Builder::with_config(config);
        let _ = builder.configure_hyper_builder();
    }

    #[test]
    fn test_config_builder() {
        let config = Http2Config::builder()
            .max_concurrent_streams(200)
            .max_frame_size(32768)
            .adaptive_window(false)
            .build();

        assert_eq!(config.max_concurrent_streams, 200);
        assert_eq!(config.max_frame_size, 32768);
        assert!(!config.adaptive_window);
    }

    #[test]
    fn test_stats() {
        let stats = Http2Stats::new();

        stats.connection_opened();
        stats.connection_opened();
        assert_eq!(stats.active_connections(), 2);
        assert_eq!(stats.total_connections(), 2);

        stats.stream_created();
        stats.stream_created();
        stats.stream_created();
        assert_eq!(stats.active_streams(), 3);

        stats.stream_closed();
        assert_eq!(stats.active_streams(), 2);

        stats.connection_closed();
        assert_eq!(stats.active_connections(), 1);
    }

    #[test]
    fn test_protocol_detection() {
        assert!(HttpProtocol::H2.is_h2());
        assert!(HttpProtocol::H2c.is_h2());
        assert!(!HttpProtocol::Http11.is_h2());

        assert_eq!(HttpProtocol::H2.alpn_id(), b"h2");
        assert_eq!(HttpProtocol::Http11.alpn_id(), b"http/1.1");
    }

    #[test]
    fn test_builder() {
        let config = Http2Config::high_throughput();
        let builder = Http2Builder::with_config(config.clone());

        assert_eq!(
            builder.config().max_concurrent_streams,
            config.max_concurrent_streams
        );
        assert_eq!(builder.stats().active_connections(), 0);
    }

    // ---- Connection deadlines -------------------------------------------

    use crate::application::ServeState;
    use crate::route_cache::OptimizedRouter;
    use crate::{Error, HttpRequest, HttpResponse, Router};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use std::time::Instant;

    async fn hello(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::ok().with_body(b"hello".to_vec()))
    }

    async fn slow(_req: HttpRequest) -> Result<HttpResponse, Error> {
        tokio::time::sleep(Duration::from_millis(600)).await;
        Ok(HttpResponse::ok().with_body(b"slow".to_vec()))
    }

    async fn big(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::ok().with_body(vec![b'x'; 1 << 20]))
    }

    async fn empty(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::new(204))
    }

    fn state() -> ServeState {
        let mut router = Router::new();
        router.get("/hello", hello);
        router.get("/slow", slow);
        router.get("/big", big);
        router.get("/empty", empty);
        ServeState::for_test(
            Arc::new(OptimizedRouter::from_router(&router)),
            crate::DEFAULT_MAX_BODY_SIZE,
        )
    }

    /// Deadlines short enough for a test to wait out.
    fn short(stats: Arc<Http2Stats>) -> H2ConnectionServer {
        let limits = H2ConnectionLimits {
            handshake_timeout: Duration::from_millis(200),
            idle_timeout: Duration::from_millis(300),
            shutdown_grace: Duration::from_millis(200),
            write_timeout: Some(Duration::from_secs(5)),
            body_budget: 1024,
        };
        Http2Builder::with_stats(Http2Config::default(), stats)
            .connection_server(&crate::pipeline::PipelineConfig::default(), 1024)
            .with_limits(limits)
    }

    /// Serve one connection on a fresh loopback socket; returns the client end
    /// and a handle that resolves when the server lets the connection go.
    async fn serve_one(
        server: H2ConnectionServer,
    ) -> (tokio::net::TcpStream, tokio::task::JoinHandle<Instant>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let done = tokio::spawn(async move {
            let _ = server.serve(stream, state()).await;
            Instant::now()
        });
        (client, done)
    }

    #[test]
    fn connection_server_takes_its_limits_from_the_pipeline_config() {
        let pipeline = crate::pipeline::PipelineConfig {
            keep_alive_timeout: Duration::from_secs(7),
            write_timeout: Some(Duration::from_secs(9)),
            ..crate::pipeline::PipelineConfig::default()
        };
        let limits = Http2Builder::new()
            .connection_server(&pipeline, 1000)
            .limits();
        assert_eq!(limits.idle_timeout, Duration::from_secs(7));
        assert_eq!(limits.write_timeout, Some(Duration::from_secs(9)));
        assert_eq!(
            limits.handshake_timeout,
            crate::pipeline::HEADER_READ_TIMEOUT
        );
        assert_eq!(limits.body_budget, 2000, "twice the body cap by default");

        // An explicit budget is honoured, but never below one maximal body.
        let config = Http2Config::builder()
            .max_buffered_body_bytes(Some(10))
            .build();
        let limits = Http2Builder::with_config(config)
            .connection_server(&pipeline, 1000)
            .limits();
        assert_eq!(limits.body_budget, 1000);
    }

    /// The finding: a peer that connects and sends nothing — not even the
    /// preface — used to hold the connection forever.
    #[tokio::test]
    async fn a_silent_peer_is_dropped_after_the_handshake_deadline() {
        let stats = Arc::new(Http2Stats::new());
        let started = Instant::now();
        let (_client, done) = serve_one(short(Arc::clone(&stats))).await;
        let ended = tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .expect("a silent connection must not be held past its deadlines")
            .unwrap();
        // Handshake deadline plus the shutdown grace, with slack.
        assert!(ended - started < Duration::from_secs(2));
        assert_eq!(stats.active_connections(), 0);
        assert_eq!(stats.total_goaway_sent(), 1);
    }

    /// A peer that completes the handshake and keeps the connection alive at
    /// the transport level (answering PINGs) but never opens a stream is
    /// closed at the first-request deadline.
    #[tokio::test]
    async fn a_handshake_with_no_request_is_closed() {
        let (client, done) = serve_one(short(Arc::new(Http2Stats::new()))).await;
        let mut builder =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(Duration::from_millis(50))
            .keep_alive_while_idle(true);
        let (_sender, conn) = builder
            .handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("h2 handshake");
        let client_conn = tokio::spawn(conn);

        tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .expect("a pinging-but-idle connection must still be closed")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), client_conn)
            .await
            .expect("the client sees the close")
            .unwrap()
            .ok();
    }

    /// After serving requests, a connection with nothing in flight for the
    /// idle timeout is closed with a GOAWAY; a request still running is not
    /// cut off by it.
    #[tokio::test]
    async fn an_idle_connection_is_closed_but_an_in_flight_request_is_not() {
        let (client, done) = serve_one(short(Arc::new(Http2Stats::new()))).await;
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(client),
        )
        .await
        .expect("h2 handshake");
        tokio::spawn(conn);

        // Outlasts both the handshake and the idle deadline while in flight.
        let request = hyper::Request::get("http://localhost/slow")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.expect("served");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"slow");

        let request = hyper::Request::get("http://localhost/hello")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(sender.send_request(request).await.unwrap().status(), 200);

        let idle_from = Instant::now();
        let ended = tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .expect("an idle connection must be closed")
            .unwrap();
        assert!(ended - idle_from >= Duration::from_millis(250));
    }

    /// The finding: a peer that advertises a zero stream window stops a
    /// response dead while every socket write succeeds, so the write deadline
    /// never arms; and the stream stopped counting as in flight when its
    /// handler returned, so a trickle of cheap requests kept the connection
    /// "busy" while large responses sat pinned. The stalled body now holds
    /// the stream in flight and, after the write timeout without progress,
    /// gets the connection closed.
    #[tokio::test]
    async fn a_response_starved_of_flow_control_closes_the_connection() {
        let limits = H2ConnectionLimits {
            handshake_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_millis(300),
            shutdown_grace: Duration::from_millis(200),
            write_timeout: Some(Duration::from_millis(400)),
            body_budget: 1024,
        };
        let server = Http2Builder::new()
            .connection_server(&crate::pipeline::PipelineConfig::default(), 1024)
            .with_limits(limits);
        let (client, done) = serve_one(server).await;
        let mut builder =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder.initial_stream_window_size(0).adaptive_window(false);
        let (mut sender, conn) = builder
            .handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("h2 handshake");
        tokio::spawn(conn);

        let request = hyper::Request::get("http://localhost/big")
            .body(Empty::<Bytes>::new())
            .unwrap();
        // The head is not flow-controlled; the body never gets a byte of
        // window.
        let pinned = sender.send_request(request).await.expect("head served");
        assert_eq!(pinned.status(), 200);

        // Keep the connection looking busy with requests that need no window.
        let trickle = tokio::spawn(async move {
            loop {
                let request = hyper::Request::get("http://localhost/empty")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                if sender.send_request(request).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .expect("a starved response must not hold the connection open")
            .unwrap();
        trickle.abort();
        drop(pinned);
    }

    /// A slow reader that keeps granting window is not mistaken for a stalled
    /// one: progress, not total time, is what the write timeout bounds.
    #[tokio::test]
    async fn a_slow_but_progressing_response_is_not_cut_off() {
        let limits = H2ConnectionLimits {
            handshake_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_millis(300),
            shutdown_grace: Duration::from_millis(200),
            write_timeout: Some(Duration::from_millis(400)),
            body_budget: 1024,
        };
        let server = Http2Builder::new()
            .connection_server(&crate::pipeline::PipelineConfig::default(), 1024)
            .with_limits(limits);
        let (client, _done) = serve_one(server).await;
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(client),
        )
        .await
        .expect("h2 handshake");
        tokio::spawn(conn);

        let request = hyper::Request::get("http://localhost/big")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.expect("served");
        let mut body = response.into_body();
        let mut received = 0usize;
        let started = Instant::now();
        // Drain slowly: well past the write timeout in total, never stalled
        // for anything like it.
        while let Some(frame) = body.frame().await {
            received += frame
                .expect("not cut off")
                .into_data()
                .map_or(0, |d| d.len());
            if started.elapsed() < Duration::from_millis(900) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        assert_eq!(received, 1 << 20);
        assert!(started.elapsed() >= Duration::from_millis(400));
    }

    #[tokio::test]
    async fn the_tracker_reports_a_stalled_response() {
        let tracker = Arc::new(StreamTracker::new());
        let limit = Duration::from_millis(100);
        let now = tokio::time::Instant::now();
        assert_eq!(tracker.next_stall_deadline(now, limit), Ok(None));
        let clock = tracker.watch_response();
        let expires = tracker
            .next_stall_deadline(now, limit)
            .unwrap()
            .expect("one response pending");
        assert_eq!(tracker.next_stall_deadline(expires, limit), Err(Stalled));
        drop(clock);
        assert_eq!(tracker.next_stall_deadline(expires, limit), Ok(None));
    }

    #[tokio::test]
    async fn the_tracker_reports_idle_only_with_nothing_in_flight() {
        let tracker = Arc::new(StreamTracker::new());
        let idle = Duration::from_secs(10);
        let now = tokio::time::Instant::now();
        assert_eq!(tracker.next_deadline(now, idle), None, "no request yet");

        let active = tracker.begin();
        assert_eq!(tracker.next_deadline(now, idle), Some(now + idle));
        drop(active);
        let next = tracker.next_deadline(now, idle).expect("not idle long yet");
        assert!(next > now);
        assert_eq!(tracker.next_deadline(next, idle), None);
    }
}
