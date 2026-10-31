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
            max_streams: self.config.max_concurrent_streams,
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
    /// The `max_concurrent_streams` the connection advertises, which bounds
    /// its [`WireStreams`] bookkeeping.
    max_streams: u32,
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
        let wire = Arc::new(WireStreams::new(self.max_streams));
        let rate = state.body_read();
        // One budget per connection, shared by its streams through the state
        // every one of them is served with.
        let state = state.with_body_budget(limits.body_budget);
        let stats = Arc::clone(&self.stats);
        stats.connection_opened();

        let service = {
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
                    let rate = state.body_read();
                    let response = crate::application::handle_request(req, state).await?;
                    Ok::<_, hyper::Error>(response.map(|body| {
                        TrackedBody::new(body, active, &tracker, limits.write_timeout, rate)
                    }))
                }
            })
        };

        let io = hyper_util::rt::TokioIo::new(WireWatch::new(
            crate::pipeline::WriteDeadline::new(io, limits.write_timeout).with_min_rate(rate),
            Arc::clone(&wire),
        ));
        let conn = self.builder.serve_connection(io, service);
        let mut conn = std::pin::pin!(conn);

        // A response stream can open on the wire between two looks, and the
        // next look may otherwise be a whole idle timeout away; no stream's
        // first deadline is sooner than this, so looking at least this often
        // catches a stalled one within twice its budget.
        let look_every = match (limits.write_timeout, rate.rate_budget(0)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let mut deadline = tracker.started + limits.handshake_timeout;
        let served = loop {
            tokio::select! {
                served = conn.as_mut() => break Some(served),
                () = tokio::time::sleep_until(deadline) => {
                    let now = tokio::time::Instant::now();
                    let Some(mut next) = tracker.next_deadline(now, limits.idle_timeout) else {
                        break None;
                    };
                    // hyper cannot reset one stream from out here, so a
                    // response the peer has stopped accepting (or accepts too
                    // slowly) closes the connection, the way a stalled write
                    // does on HTTP/1.1. Checked twice: while hyper still holds
                    // the body (`TrackedBody`), and on the wire, which also
                    // covers the tail `h2` keeps after hyper has let go.
                    let mut stalled = false;
                    for stall in [
                        tracker.next_stall_deadline(now),
                        wire.next_stall_deadline(now, limits.write_timeout, rate),
                    ] {
                        match stall {
                            Err(Stalled) => stalled = true,
                            Ok(Some(stall)) => next = next.min(stall),
                            Ok(None) => {}
                        }
                    }
                    if stalled {
                        break None;
                    }
                    if let Some(every) = look_every {
                        next = next.min(deadline_after(now, every));
                    }
                    deadline = next;
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

/// `at + after`, saturating at a moment far enough out to mean "never".
///
/// `Duration::MAX` (or anything close) is how a configuration says "no
/// deadline", and `Instant + Duration` panics past the platform's range — in
/// a connection watcher, that panic ends the watcher and with it every bound
/// it enforced. Thirty years is what tokio itself uses for "far future".
///
/// Should even that not fit (an `at` already near the end of the clock's
/// range), the step is halved until it does, so the result is the furthest
/// representable moment rather than `at` itself — which would turn "never"
/// into "already expired". Only an `at` at the very end of the range, with
/// no room left at all, comes back unchanged.
pub(crate) fn deadline_after(at: tokio::time::Instant, after: Duration) -> tokio::time::Instant {
    const FAR_FUTURE: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);
    let mut step = after.min(FAR_FUTURE);
    loop {
        if let Some(deadline) = at.checked_add(step) {
            return deadline;
        }
        if step.is_zero() {
            return at;
        }
        step /= 2;
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
    /// since `started`) by which it must next make progress. Weak, so a
    /// finished body drops out by itself; the watcher sweeps the dead entries.
    responses: std::sync::Mutex<Responses>,
}

/// [`StreamTracker`]'s watched response bodies.
struct Responses {
    list: Vec<std::sync::Weak<AtomicU64>>,
    /// Sweep on push once the list is this long: twice what was live at the
    /// last sweep, so each sweep is paid for by as many pushes as it scans.
    sweep_at: usize,
    #[cfg(test)]
    sweeps: usize,
}

impl Responses {
    /// The fewest entries worth sweeping for.
    const MIN_SWEEP: usize = 64;

    fn sweep(&mut self) {
        self.list.retain(|r| r.strong_count() > 0);
        self.swept();
    }

    /// Set the next sweep point from what is live now.
    fn swept(&mut self) {
        self.sweep_at = self.list.len().saturating_mul(2).max(Self::MIN_SWEEP);
        #[cfg(test)]
        {
            self.sweeps += 1;
        }
    }
}

/// A response body missed its progress deadline: no progress within the write
/// timeout, or below the minimum rate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stalled;

impl StreamTracker {
    pub(crate) fn new() -> Self {
        Self {
            started: tokio::time::Instant::now(),
            active: AtomicUsize::new(0),
            begun: AtomicU64::new(0),
            idle_since_nanos: AtomicU64::new(0),
            responses: std::sync::Mutex::new(Responses {
                list: Vec::new(),
                sweep_at: Responses::MIN_SWEEP,
                #[cfg(test)]
                sweeps: 0,
            }),
        }
    }

    /// Nanoseconds from `started` to `at`.
    fn nanos_at(&self, at: tokio::time::Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.started).as_nanos()).unwrap_or(u64::MAX)
    }

    /// Start watching a response body that must first make progress by
    /// `deadline`; the body moves the returned deadline each time it is
    /// polled.
    fn watch_response(&self, deadline: tokio::time::Instant) -> Arc<AtomicU64> {
        let clock = Arc::new(AtomicU64::new(self.nanos_at(deadline)));
        if let Ok(mut responses) = self.responses.lock() {
            // Sweep here as well as in the watcher, so a busy connection whose
            // watcher rarely runs does not accumulate finished entries — but
            // only once the list has doubled since the last sweep: sweeping
            // at a fixed length scanned every live entry on every push once
            // that many were in flight, O(n²) at a large
            // `max_concurrent_streams`.
            if responses.list.len() >= responses.sweep_at {
                responses.sweep();
            }
            responses.list.push(Arc::downgrade(&clock));
        }
        clock
    }

    /// The earliest progress deadline of the response bodies being sent,
    /// `Ok(None)` if none is, or [`Stalled`] if one has already passed.
    pub(crate) fn next_stall_deadline(
        &self,
        now: tokio::time::Instant,
    ) -> Result<Option<tokio::time::Instant>, Stalled> {
        let Ok(mut responses) = self.responses.lock() else {
            return Ok(None);
        };
        let mut oldest: Option<u64> = None;
        responses.list.retain(|r| match r.upgrade() {
            Some(clock) => {
                let at = clock.load(Ordering::Acquire);
                oldest = Some(oldest.map_or(at, |o| o.min(at)));
                true
            }
            None => false,
        });
        responses.swept();
        let Some(oldest) = oldest else {
            return Ok(None);
        };
        let expires = deadline_after(self.started, Duration::from_nanos(oldest));
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
            return Some(deadline_after(now, idle_timeout));
        }
        let idle_since = deadline_after(
            self.started,
            Duration::from_nanos(self.idle_since_nanos.load(Ordering::Acquire)),
        );
        let expires = deadline_after(idle_since, idle_timeout);
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
/// any for the write timeout, or falls below the minimum rate of the
/// [`BodyReadPolicy`](crate::BodyReadPolicy).
///
/// A peer can stop a response dead without stalling the socket: advertise a
/// zero (or never-replenished) stream window and the body waits on credit
/// while every socket write succeeds, so the
/// [`WriteDeadline`](crate::pipeline::WriteDeadline) never arms. Without this,
/// such a stream was not even counted as in flight, so the connection could
/// also go on serving cheap requests, resetting its idle clock, while up to
/// `max_concurrent_streams` large responses sat pinned in memory.
///
/// Progress alone is not enough either: a peer that grants one chunk's worth
/// of window just inside every write timeout never stalls, yet holds the
/// stream (and its buffered response) for `size / chunk × write_timeout` —
/// hours, for a large body. So the body must also keep to the policy's
/// minimum rate: chunk `k` must be accepted by `grace + bytes_before_k /
/// min_bytes_per_sec` after the response started.
///
/// Its watch ends when hyper drops the body, which can be well before the
/// peer has been sent all of it; [`WireStreams`] watches the rest.
pub(crate) struct TrackedBody {
    /// Bytes not yet handed to hyper.
    pending: bytes::Bytes,
    inner: http_body_util::Full<bytes::Bytes>,
    /// The deadline for the next poll, moved on every poll; `None` with
    /// neither a write timeout nor a rate rule.
    progress: Option<Arc<AtomicU64>>,
    tracker: Arc<StreamTracker>,
    write_timeout: Option<Duration>,
    rate: crate::BodyReadPolicy,
    started: tokio::time::Instant,
    /// Bytes handed to hyper so far.
    sent: usize,
    _active: ActiveStream,
}

impl TrackedBody {
    fn new(
        inner: http_body_util::Full<bytes::Bytes>,
        active: ActiveStream,
        tracker: &Arc<StreamTracker>,
        write_timeout: Option<Duration>,
        rate: crate::BodyReadPolicy,
    ) -> Self {
        use hyper::body::Body as _;
        let started = tokio::time::Instant::now();
        let mut body = Self {
            pending: bytes::Bytes::new(),
            inner,
            progress: None,
            tracker: Arc::clone(tracker),
            write_timeout,
            rate,
            started,
            sent: 0,
            _active: active,
        };
        // A body with nothing to send is never polled: hyper ends the stream
        // with the headers.
        if !body.inner.is_end_stream()
            && let Some(deadline) = body.next_deadline(started)
        {
            body.progress = Some(tracker.watch_response(deadline));
        }
        body
    }

    /// When the next poll is due, having sent `self.sent` bytes by `now`: the
    /// sooner of the stall bound and the minimum-rate bound.
    fn next_deadline(&self, now: tokio::time::Instant) -> Option<tokio::time::Instant> {
        let stall = self.write_timeout.map(|limit| deadline_after(now, limit));
        let rate = self
            .rate
            .rate_budget(self.sent)
            .map(|budget| deadline_after(self.started, budget));
        match (stall, rate) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
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
        // hyper polls again only once this chunk is queued against the peer's
        // window, so the next poll is due by when the bytes handed out so far
        // (this chunk included) would meet the minimum rate.
        this.sent = this.sent.saturating_add(n);
        if let Some(progress) = &this.progress
            && let Some(deadline) = this.next_deadline(tokio::time::Instant::now())
        {
            progress.store(this.tracker.nanos_at(deadline), Ordering::Release);
        }
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

/// The response streams a connection has started on the wire and not yet
/// finished, as the bytes actually written to the socket show them.
///
/// [`TrackedBody`] can only watch a response while hyper holds its body, and
/// hyper lets go early: once a stream has a single byte of window it hands
/// `h2` the whole next chunk, and after the last one it ends the body, drops
/// it and is done — while `h2` may still be holding most of that chunk,
/// waiting on credit the peer need never grant. A peer with a one-byte stream
/// window pinned up to a chunk per stream that way, indefinitely, with no
/// stream counted in flight and nothing watching.
///
/// So the socket is watched too ([`WireWatch`]): a response stream opens when
/// its `HEADERS` (without `END_STREAM`) are written, makes progress with each
/// `DATA` frame written for it, and ends with `END_STREAM` or an
/// `RST_STREAM` in either direction — a peer that cancels a download leaves
/// `h2` nothing more to send, which must not read as a stall. Every open one
/// must meet the same rules as [`TrackedBody`]: progress within the write
/// timeout, and the minimum rate counted from its headers.
pub(crate) struct WireStreams {
    state: std::sync::Mutex<WireState>,
}

/// What [`WireStreams`] knows, under one lock.
struct WireState {
    open: std::collections::HashMap<u32, WireStream>,
    /// Streams the peer has reset, so `HEADERS` for one that reach the
    /// socket only afterwards do not open it. Under write backpressure `h2`
    /// can have a response's `HEADERS` encoded but unflushed when the peer's
    /// `RST_STREAM` for it is read; recorded in the order the bytes moved,
    /// the reset found nothing to remove and the late `HEADERS` then opened a
    /// stream nothing would ever close — judged stalled a write timeout
    /// later, closing the connection and every other stream on it. Stream
    /// ids are never reused on a connection, so remembering one cannot
    /// mistake a later stream for it.
    reset: std::collections::HashSet<u32>,
    /// `reset`'s ids oldest first, so the oldest is forgotten once
    /// `reset_cap` are remembered. Ids the server has since closed stay here
    /// until they age out; they only make the memory a little shorter.
    reset_order: std::collections::VecDeque<u32>,
    reset_cap: usize,
    /// More open streams than this is not something a peer kept to
    /// `max_concurrent_streams` can cause.
    open_cap: usize,
    /// A stream was refused for `open_cap`: the connection is closed at the
    /// watcher's next look.
    overflowed: bool,
}

/// One response stream open on the wire.
#[derive(Debug, Clone, Copy)]
struct WireStream {
    /// When its `HEADERS` were written: the rate rule counts from here.
    opened: tokio::time::Instant,
    /// When the last `DATA` for it was written (or `opened`).
    progressed: tokio::time::Instant,
    /// `DATA` payload bytes written for it.
    sent: u64,
}

impl WireStreams {
    /// Bookkeeping for a connection that allows `max_concurrent_streams`
    /// peer-initiated streams at once.
    ///
    /// Both bounds are twice that (with a floor, for tiny settings): the
    /// wire view lags `h2`'s by whatever is buffered, so a few more open or
    /// reset streams than the setting allows are legitimate, but not twice
    /// as many.
    pub(crate) fn new(max_concurrent_streams: u32) -> Self {
        let cap = usize::try_from(max_concurrent_streams)
            .unwrap_or(usize::MAX)
            .saturating_mul(2)
            .max(32);
        Self {
            state: std::sync::Mutex::new(WireState {
                open: std::collections::HashMap::new(),
                reset: std::collections::HashSet::new(),
                reset_order: std::collections::VecDeque::new(),
                reset_cap: cap,
                open_cap: cap,
                overflowed: false,
            }),
        }
    }

    /// The earliest moment an open response stream must next make progress,
    /// `Ok(None)` if none is open (or no rule applies), or [`Stalled`] if one
    /// is already past it.
    pub(crate) fn next_stall_deadline(
        &self,
        now: tokio::time::Instant,
        write_timeout: Option<Duration>,
        rate: crate::BodyReadPolicy,
    ) -> Result<Option<tokio::time::Instant>, Stalled> {
        let Ok(state) = self.state.lock() else {
            return Ok(None);
        };
        // Past `open_cap` streams stopped being watched, so the connection
        // cannot be vouched for; it closes rather than run unwatched (or grow
        // the map without bound, as it could with no rule to judge by).
        if state.overflowed {
            return Err(Stalled);
        }
        let mut earliest: Option<tokio::time::Instant> = None;
        for stream in state.open.values() {
            let stall = write_timeout.map(|limit| deadline_after(stream.progressed, limit));
            let slow = rate
                .rate_budget(usize::try_from(stream.sent).unwrap_or(usize::MAX))
                .map(|budget| deadline_after(stream.opened, budget));
            let due = match (stall, slow) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => continue,
            };
            if due <= now {
                return Err(Stalled);
            }
            earliest = Some(earliest.map_or(due, |e| e.min(due)));
        }
        Ok(earliest)
    }

    /// Apply the frames one side of the connection has just carried.
    fn record(&self, frames: &[FrameHead], outbound: bool) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let now = tokio::time::Instant::now();
        for frame in frames {
            let end_stream = frame.flags & FLAG_END_STREAM != 0;
            match (frame.kind, outbound) {
                // The peer cancelled: the stream is over, and whatever `h2`
                // already had queued for it must not reopen it. Remembered
                // even for an open stream — an informational response may be
                // out with the final one still queued.
                (FRAME_RST_STREAM, false) => {
                    state.open.remove(&frame.stream);
                    state.remember_reset(frame.stream);
                }
                // Nothing more goes out for this stream after either.
                (FRAME_RST_STREAM, true) => state.close(frame.stream),
                (FRAME_HEADERS | FRAME_DATA, true) if end_stream => state.close(frame.stream),
                (FRAME_HEADERS, true) => {
                    if state.reset.contains(&frame.stream) {
                        continue;
                    }
                    if state.open.len() >= state.open_cap && !state.open.contains_key(&frame.stream)
                    {
                        state.overflowed = true;
                        continue;
                    }
                    state.open.entry(frame.stream).or_insert(WireStream {
                        opened: now,
                        progressed: now,
                        sent: 0,
                    });
                }
                (FRAME_DATA, true) => {
                    if let Some(stream) = state.open.get_mut(&frame.stream)
                        && frame.len > 0
                    {
                        stream.sent = stream.sent.saturating_add(u64::from(frame.len));
                        stream.progressed = now;
                    }
                }
                _ => {}
            }
        }
    }
}

impl WireState {
    /// The server is done sending on `stream`.
    fn close(&mut self, stream: u32) {
        self.open.remove(&stream);
        self.reset.remove(&stream);
    }

    /// Remember that the peer reset `stream`, forgetting the oldest reset
    /// once `reset_cap` are remembered.
    fn remember_reset(&mut self, stream: u32) {
        if !self.reset.insert(stream) {
            return;
        }
        while self.reset_order.len() >= self.reset_cap {
            if let Some(oldest) = self.reset_order.pop_front() {
                self.reset.remove(&oldest);
            }
        }
        self.reset_order.push_back(stream);
    }
}

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FLAG_END_STREAM: u8 = 0x1;
/// The client connection preface (RFC 9113 §3.4), which precedes the first
/// frame a client sends.
const CLIENT_PREFACE_LEN: usize = 24;

/// The fields of an HTTP/2 frame header (RFC 9113 §4.1) [`WireStreams`]
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHead {
    len: u32,
    kind: u8,
    flags: u8,
    stream: u32,
}

/// Finds the frame headers in one direction of a connection's byte stream,
/// fed in whatever pieces the socket moves it in. Only the nine-byte headers
/// are looked at; payloads are skipped by length.
struct FrameScanner {
    /// Bytes to pass over before the next frame header: a payload, or the
    /// client preface.
    skip: usize,
    head: [u8; 9],
    filled: usize,
}

impl FrameScanner {
    fn new(skip: usize) -> Self {
        Self {
            skip,
            head: [0; 9],
            filled: 0,
        }
    }

    /// Scan `bytes`, collecting the headers of the frames that matter to
    /// [`WireStreams`] into `out`.
    fn feed(&mut self, mut bytes: &[u8], out: &mut smallvec::SmallVec<[FrameHead; 4]>) {
        while !bytes.is_empty() {
            if self.skip > 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (9 - self.filled).min(bytes.len());
            self.head[self.filled..self.filled + n].copy_from_slice(&bytes[..n]);
            self.filled += n;
            bytes = &bytes[n..];
            if self.filled == 9 {
                self.filled = 0;
                let h = &self.head;
                let frame = FrameHead {
                    len: u32::from_be_bytes([0, h[0], h[1], h[2]]),
                    kind: h[3],
                    flags: h[4],
                    stream: u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff,
                };
                self.skip = frame.len as usize;
                if matches!(frame.kind, FRAME_DATA | FRAME_HEADERS | FRAME_RST_STREAM) {
                    out.push(frame);
                }
            }
        }
    }
}

/// The transport an HTTP/2 connection is served over, reporting the frames
/// it carries to the connection's [`WireStreams`].
///
/// Cheap on the hot path: the scan touches nine bytes per frame and skips
/// payloads by length, and the shared state is locked once per read or write
/// that carried a frame it cares about, not per byte or per frame.
pub(crate) struct WireWatch<T> {
    inner: T,
    wire: Arc<WireStreams>,
    outbound: FrameScanner,
    inbound: FrameScanner,
}

impl<T> WireWatch<T> {
    pub(crate) fn new(inner: T, wire: Arc<WireStreams>) -> Self {
        Self {
            inner,
            wire,
            // The server's first bytes are its SETTINGS frame; the client's
            // are the connection preface, then frames.
            outbound: FrameScanner::new(0),
            inbound: FrameScanner::new(CLIENT_PREFACE_LEN),
        }
    }

    fn wrote<'a>(&mut self, written: usize, bufs: impl IntoIterator<Item = &'a [u8]>) {
        let mut frames = smallvec::SmallVec::new();
        let mut left = written;
        for buf in bufs {
            if left == 0 {
                break;
            }
            let n = left.min(buf.len());
            self.outbound.feed(&buf[..n], &mut frames);
            left -= n;
        }
        if !frames.is_empty() {
            self.wire.record(&frames, true);
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WireWatch<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = polled
            && buf.filled().len() > before
        {
            let mut frames = smallvec::SmallVec::new();
            self.inbound.feed(&buf.filled()[before..], &mut frames);
            // Of what the peer sends only a reset ends a response; skipping the
            // rest keeps request heads and bodies from taking the lock.
            frames.retain(|f: &mut FrameHead| f.kind == FRAME_RST_STREAM);
            if !frames.is_empty() {
                self.wire.record(&frames, false);
            }
        }
        polled
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WireWatch<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = polled {
            self.wrote(n, [buf]);
        }
        polled
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let std::task::Poll::Ready(Ok(n)) = polled {
            self.wrote(n, bufs.iter().map(|b| &**b));
        }
        polled
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

    /// One response chunk's worth: hyper hands it to `h2` whole, so its tail
    /// outlives the response body.
    async fn medium(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Ok(HttpResponse::ok().with_body(vec![b'x'; 8 * 1024]))
    }

    fn state() -> ServeState {
        let mut router = Router::new();
        router.get("/hello", hello);
        router.get("/slow", slow);
        router.get("/big", big);
        router.get("/empty", empty);
        router.get("/medium", medium);
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
        serve_one_with(server, state()).await
    }

    /// [`serve_one`] with a given state.
    async fn serve_one_with(
        server: H2ConnectionServer,
        state: ServeState,
    ) -> (tokio::net::TcpStream, tokio::task::JoinHandle<Instant>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let done = tokio::spawn(async move {
            let _ = server.serve(stream, state).await;
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

    /// The finding: hyper hands `h2` a whole body chunk as soon as the stream
    /// has a single byte of window, and on the last chunk drops the body —
    /// and with it the in-flight count and the progress clock — while `h2`
    /// still holds the bytes it could not send. A peer advertising a one-byte
    /// stream window pinned that tail on every stream it opened, for as long
    /// as a cheap request now and then kept the connection from going idle.
    /// What the peer has actually been sent is now watched on the wire, so a
    /// tail it never takes closes the connection like any other stalled
    /// response.
    #[tokio::test]
    async fn a_response_tail_left_in_h2_closes_the_connection() {
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
        builder.initial_stream_window_size(1).adaptive_window(false);
        let (mut sender, conn) = builder
            .handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("h2 handshake");
        tokio::spawn(conn);

        // Each response is one chunk: hyper passes it to h2 on the first byte
        // of window and is done with it. Hold the responses unread, so the
        // window is never replenished.
        let mut pinned = Vec::new();
        for _ in 0..4 {
            let request = hyper::Request::get("http://localhost/medium")
                .body(Empty::<Bytes>::new())
                .unwrap();
            pinned.push(sender.send_request(request).await.expect("head served"));
        }

        // Keep the idle clock fresh with requests that need no window.
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
            .expect("a response tail the peer never takes must not hold the connection")
            .unwrap();
        trickle.abort();
        drop(pinned);
    }

    /// A client that cancels a download (`RST_STREAM`) leaves the server
    /// nothing more to send on that stream: the bytes `h2` was holding for it
    /// are discarded, not stalled, and the connection goes on serving.
    #[tokio::test]
    async fn a_cancelled_response_is_not_mistaken_for_a_stalled_one() {
        let limits = H2ConnectionLimits {
            handshake_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_millis(200),
            write_timeout: Some(Duration::from_millis(300)),
            body_budget: 1024,
        };
        let server = Http2Builder::new()
            .connection_server(&crate::pipeline::PipelineConfig::default(), 1024)
            .with_limits(limits);
        let (client, done) = serve_one(server).await;
        let mut builder =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .initial_stream_window_size(16 * 1024)
            .adaptive_window(false);
        let (mut sender, conn) = builder
            .handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("h2 handshake");
        tokio::spawn(conn);

        for target in ["http://localhost/big", "http://localhost/medium"] {
            let request = hyper::Request::get(target)
                .body(Empty::<Bytes>::new())
                .unwrap();
            let mut body = sender.send_request(request).await.unwrap().into_body();
            body.frame().await.expect("a first frame").expect("data");
            // Dropping the body resets the stream.
            drop(body);
        }

        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            let request = hyper::Request::get("http://localhost/hello")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let response = sender
                .send_request(request)
                .await
                .expect("the connection must survive a cancelled download");
            assert_eq!(response.status(), 200);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!done.is_finished());
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

    /// Read `/big` with a 16 KiB stream window, pausing `pause` after every
    /// frame, from a server whose minimum response rate is `min_rate` (after
    /// a 200 ms grace) and whose write timeout is far longer than any pause.
    /// Returns the bytes received and whether the body ended cleanly.
    async fn read_big_at(pause: Duration, min_rate: u64) -> (usize, bool) {
        let limits = H2ConnectionLimits {
            handshake_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_millis(300),
            shutdown_grace: Duration::from_millis(200),
            write_timeout: Some(Duration::from_secs(5)),
            body_budget: 1024,
        };
        let server = Http2Builder::new()
            .connection_server(&crate::pipeline::PipelineConfig::default(), 1024)
            .with_limits(limits);
        let policy = crate::BodyReadPolicy {
            idle_timeout: Duration::from_millis(200),
            min_bytes_per_sec: min_rate,
        };
        let (client, _done) = serve_one_with(server, state().with_body_read_for_test(policy)).await;
        let mut builder =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .initial_stream_window_size(16 * 1024)
            .adaptive_window(false);
        let (mut sender, conn) = builder
            .handshake::<_, Empty<Bytes>>(hyper_util::rt::TokioIo::new(client))
            .await
            .expect("h2 handshake");
        tokio::spawn(conn);

        let request = hyper::Request::get("http://localhost/big")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.expect("head served");
        let mut body = response.into_body();
        let mut received = 0usize;
        loop {
            match body.frame().await {
                None => return (received, true),
                Some(Err(_)) => return (received, false),
                Some(Ok(frame)) => received += frame.into_data().map_or(0, |d| d.len()),
            }
            tokio::time::sleep(pause).await;
        }
    }

    /// The finding: the stall check only asked for *some* progress per write
    /// timeout, so a peer granting one chunk of window just inside it held a
    /// stream (and its whole buffered response) for hours. A response
    /// accepted below the minimum rate now gets the connection closed.
    #[tokio::test]
    async fn a_response_accepted_below_the_minimum_rate_closes_the_connection() {
        // ~160 KiB/s against a 256 KiB/s floor; 1 MiB would take ~6.4 s.
        let (received, complete) = tokio::time::timeout(
            Duration::from_secs(3),
            read_big_at(Duration::from_millis(100), 256 * 1024),
        )
        .await
        .expect("a below-rate response must be cut off, not trickled out");
        assert!(!complete && received < 1 << 20, "received {received}");
    }

    /// A reader slower than the network but above the floor is served in full.
    #[tokio::test]
    async fn a_response_accepted_above_the_minimum_rate_completes() {
        // ~800 KiB/s against a 64 KiB/s floor.
        let (received, complete) = tokio::time::timeout(
            Duration::from_secs(10),
            read_big_at(Duration::from_millis(20), 64 * 1024),
        )
        .await
        .expect("served in time");
        assert!(complete);
        assert_eq!(received, 1 << 20);
    }

    /// Frame headers are found however the socket splits the bytes, and
    /// payloads — which may look like anything — are skipped by length.
    #[test]
    fn the_frame_scanner_survives_any_split() {
        fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
            let len = (payload.len() as u32).to_be_bytes();
            let mut out = vec![len[1], len[2], len[3], kind, flags];
            out.extend_from_slice(&stream.to_be_bytes());
            out.extend_from_slice(payload);
            out
        }
        let mut wire = frame(0x4, 0, 0, &[0; 6]); // SETTINGS
        wire.extend(frame(FRAME_HEADERS, 0x4, 1, &[0x88]));
        // A payload that happens to look like a frame header.
        wire.extend(frame(FRAME_DATA, 0, 1, &frame(FRAME_RST_STREAM, 0, 9, &[])));
        wire.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, b"tail"));
        let expected = vec![
            FrameHead {
                len: 1,
                kind: FRAME_HEADERS,
                flags: 0x4,
                stream: 1,
            },
            FrameHead {
                len: 9,
                kind: FRAME_DATA,
                flags: 0,
                stream: 1,
            },
            FrameHead {
                len: 4,
                kind: FRAME_DATA,
                flags: FLAG_END_STREAM,
                stream: 1,
            },
        ];
        for piece in [1, 2, 7, 9, 10, wire.len()] {
            let mut scanner = FrameScanner::new(0);
            let mut frames = smallvec::SmallVec::new();
            for chunk in wire.chunks(piece) {
                scanner.feed(chunk, &mut frames);
            }
            assert_eq!(frames.to_vec(), expected, "split into {piece}-byte pieces");
        }
    }

    /// A response stream is watched from its headers to its end, and one the
    /// peer resets is let go rather than counted as stalled.
    #[tokio::test]
    async fn wire_streams_follow_a_response_to_its_end() {
        let wire = WireStreams::new(100);
        let timeout = Some(Duration::from_millis(100));
        let rate = crate::BodyReadPolicy {
            idle_timeout: Duration::from_secs(60),
            min_bytes_per_sec: 0,
        };
        let head = |kind, flags, stream| FrameHead {
            len: 4,
            kind,
            flags,
            stream,
        };
        let now = tokio::time::Instant::now();
        wire.record(
            &[head(FRAME_HEADERS, 0x4, 1), head(FRAME_HEADERS, 0x4, 3)],
            true,
        );
        let due = wire
            .next_stall_deadline(now, timeout, rate)
            .unwrap()
            .expect("two responses open");
        assert_eq!(
            wire.next_stall_deadline(due, timeout, rate),
            Err(Stalled),
            "no DATA within the write timeout"
        );
        wire.record(&[head(FRAME_DATA, FLAG_END_STREAM, 1)], true);
        wire.record(&[head(FRAME_RST_STREAM, 0, 3)], false);
        assert_eq!(wire.next_stall_deadline(due, timeout, rate), Ok(None));
    }

    fn rst_test_head(kind: u8, flags: u8, stream: u32) -> FrameHead {
        FrameHead {
            len: 4,
            kind,
            flags,
            stream,
        }
    }

    /// The finding: under write backpressure `h2` can have a stream's
    /// `HEADERS` encoded but not yet on the socket when the peer's
    /// `RST_STREAM` for it is read. The reset found nothing to remove, the
    /// late `HEADERS` then opened the stream, and nothing ever closed it: the
    /// connection was judged stalled a write timeout later and closed, taking
    /// every other stream on it along.
    #[tokio::test]
    async fn a_reset_read_before_its_headers_are_written_still_ends_the_stream() {
        let wire = WireStreams::new(100);
        let timeout = Some(Duration::from_millis(100));
        let rate = crate::BodyReadPolicy {
            idle_timeout: Duration::from_secs(60),
            min_bytes_per_sec: 0,
        };
        let later = tokio::time::Instant::now() + Duration::from_secs(10);

        wire.record(&[rst_test_head(FRAME_RST_STREAM, 0, 1)], false);
        wire.record(&[rst_test_head(FRAME_HEADERS, 0x4, 1)], true);
        assert_eq!(wire.next_stall_deadline(later, timeout, rate), Ok(None));

        // An informational response already out, the reset, then the final
        // response's headers that were queued behind it.
        wire.record(&[rst_test_head(FRAME_HEADERS, 0x4, 3)], true);
        wire.record(&[rst_test_head(FRAME_RST_STREAM, 0, 3)], false);
        wire.record(&[rst_test_head(FRAME_HEADERS, 0x4, 3)], true);
        assert_eq!(wire.next_stall_deadline(later, timeout, rate), Ok(None));

        // Other streams are still watched.
        wire.record(&[rst_test_head(FRAME_HEADERS, 0x4, 5)], true);
        assert_eq!(wire.next_stall_deadline(later, timeout, rate), Err(Stalled));
    }

    /// Neither the remembered resets nor the open streams grow without bound:
    /// resets age out oldest first, and more open streams than the
    /// connection could legitimately have closes it — even with no write
    /// timeout or rate rule to otherwise judge them by.
    #[tokio::test]
    async fn wire_stream_bookkeeping_is_bounded() {
        let wire = WireStreams::new(10);
        let no_rules = crate::BodyReadPolicy {
            idle_timeout: Duration::from_secs(60),
            min_bytes_per_sec: 0,
        };
        let now = tokio::time::Instant::now();
        for id in (1..10_000u32).step_by(2) {
            wire.record(&[rst_test_head(FRAME_RST_STREAM, 0, id)], false);
        }
        {
            let state = wire.state.lock().unwrap();
            assert!(
                state.reset.len() <= state.reset_cap,
                "{}",
                state.reset.len()
            );
            assert!(state.reset_order.len() <= state.reset_cap);
        }
        assert_eq!(wire.next_stall_deadline(now, None, no_rules), Ok(None));

        let cap = wire.state.lock().unwrap().open_cap;
        let fresh = 20_001u32;
        for i in 0..u32::try_from(cap).unwrap() {
            wire.record(&[rst_test_head(FRAME_HEADERS, 0x4, fresh + 2 * i)], true);
        }
        assert_eq!(wire.next_stall_deadline(now, None, no_rules), Ok(None));
        wire.record(
            &[rst_test_head(
                FRAME_HEADERS,
                0x4,
                fresh + 2 * u32::try_from(cap).unwrap(),
            )],
            true,
        );
        assert_eq!(wire.state.lock().unwrap().open.len(), cap);
        assert_eq!(wire.next_stall_deadline(now, None, no_rules), Err(Stalled));
    }

    /// `deadline_after` promised "never" on overflow but returned `at` —
    /// now — which turns "no deadline" into "already expired".
    #[tokio::test]
    async fn a_deadline_near_the_end_of_the_clock_is_still_in_the_future() {
        // Walk an instant out to within a couple of hours of the clock's end.
        let mut edge = tokio::time::Instant::now();
        let mut step = Duration::from_secs(u64::MAX >> 1);
        while step >= Duration::from_secs(3600) {
            match edge.checked_add(step) {
                Some(next) => edge = next,
                None => step /= 2,
            }
        }
        let near = edge.checked_sub(Duration::from_secs(3600)).unwrap();
        assert!(
            near.checked_add(Duration::from_secs(30 * 365 * 24 * 3600))
                .is_none()
        );
        assert!(deadline_after(near, Duration::MAX) > near);
    }

    /// Every push used to sweep the whole list once it held 64 entries, so a
    /// connection with many long responses in flight paid O(n) per response.
    /// The sweep is amortized now, and finished entries still do not pile up.
    #[tokio::test]
    async fn the_response_list_is_swept_amortized() {
        let tracker = StreamTracker::new();
        let far = tokio::time::Instant::now() + Duration::from_secs(60);
        let live: Vec<_> = (0..500).map(|_| tracker.watch_response(far)).collect();
        let sweeps_before = tracker.responses.lock().unwrap().sweeps;
        let more: Vec<_> = (0..500).map(|_| tracker.watch_response(far)).collect();
        let sweeps = tracker.responses.lock().unwrap().sweeps - sweeps_before;
        assert!(sweeps <= 2, "{sweeps} sweeps for 500 live pushes");
        drop(more);
        for _ in 0..10_000 {
            drop(tracker.watch_response(far));
        }
        let len = tracker.responses.lock().unwrap().list.len();
        assert!(
            len <= 2 * live.len() + 64,
            "{len} entries for {} live",
            live.len()
        );
    }

    #[tokio::test]
    async fn the_tracker_reports_a_stalled_response() {
        let tracker = Arc::new(StreamTracker::new());
        let now = tokio::time::Instant::now();
        assert_eq!(tracker.next_stall_deadline(now), Ok(None));
        let clock = tracker.watch_response(now + Duration::from_millis(100));
        let expires = tracker
            .next_stall_deadline(now)
            .unwrap()
            .expect("one response pending");
        assert_eq!(expires, now + Duration::from_millis(100));
        assert_eq!(tracker.next_stall_deadline(expires), Err(Stalled));
        drop(clock);
        assert_eq!(tracker.next_stall_deadline(expires), Ok(None));
    }

    /// `Duration::MAX` is how a configuration says "never": every deadline
    /// derived from one must saturate rather than overflow `Instant + Duration`,
    /// which panics — and a panic in the HTTP/3 watcher ended it, so the
    /// connection it guarded was never closed for idleness again.
    #[tokio::test]
    async fn deadlines_from_unbounded_durations_do_not_overflow() {
        let tracker = Arc::new(StreamTracker::new());
        let now = tokio::time::Instant::now();
        let active = tracker.begin();
        let next = tracker
            .next_deadline(now, Duration::MAX)
            .expect("in flight");
        assert!(next > now + Duration::from_secs(365 * 24 * 60 * 60));
        drop(active);
        assert!(tracker.next_deadline(now, Duration::MAX).is_some());

        let _clock = tracker.watch_response(deadline_after(now, Duration::MAX));
        let stall = tracker.next_stall_deadline(now).unwrap().expect("watched");
        assert!(stall > now);

        let body = TrackedBody::new(
            http_body_util::Full::new(bytes::Bytes::from_static(b"x")),
            tracker.begin(),
            &tracker,
            Some(Duration::MAX),
            crate::BodyReadPolicy {
                idle_timeout: Duration::MAX,
                min_bytes_per_sec: 1,
            },
        );
        assert!(body.next_deadline(now).is_some_and(|at| at > now));
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
