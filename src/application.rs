// Application bootstrapper and HTTP server

use crate::epoll_tuning::EpollConfig;
use crate::exception_filter::{ExceptionFilter, ExceptionFilterChain};
use crate::guard::{Guard, GuardContext};
use crate::http2::{Http2Builder, Http2Config, Http2Stats};
use crate::http3::{Http3Config, Http3Stats};
use crate::logging::{debug, error, info, trace, warn};
use crate::pipeline::{PipelineConfig, PipelineStats};
use crate::route_cache::OptimizedRouter;
use crate::{
    Container, Error, HttpRequest, HttpResponse, HttpsConfig, LifecycleManager, Module, Router,
    TlsConfig,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, body::Incoming as IncomingBody};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

// Only the hyper serve path builds HTTP/1.1 connections and terminates TLS in
// this process; with `h1-backend` on, `armature-h1` does both and these two
// have no remaining use here.
#[cfg(not(feature = "h1-backend"))]
use crate::pipeline::PipelinedHttp1Builder;
#[cfg(not(feature = "h1-backend"))]
use tokio_rustls::TlsAcceptor;

/// The main application struct
pub struct Application {
    pub container: Container,
    pub router: Arc<Router>,
    pub lifecycle: Arc<LifecycleManager>,
    /// HTTP/1.1 pipelining configuration
    pipeline_config: PipelineConfig,
    /// Shared pipeline statistics
    pipeline_stats: Arc<PipelineStats>,
    /// HTTP/2 configuration
    http2_config: Http2Config,
    /// Shared HTTP/2 statistics
    http2_stats: Arc<Http2Stats>,
    /// HTTP/3 (QUIC) configuration
    http3_config: Http3Config,
    /// Shared HTTP/3 statistics
    http3_stats: Arc<Http3Stats>,
    /// Optional CORS configuration applied to every response
    cors_config: Option<Arc<CorsConfig>>,
    /// Guards evaluated before routing. Each is scoped to a URL path prefix:
    /// module guards to their declaring module's controller base paths, and
    /// manually-added guards (via [`Application::with_guard`]) to the empty
    /// (all-matching) prefix. See [`ScopedGuard`].
    guards: Vec<ScopedGuard>,
    /// Maximum request body size in bytes; larger bodies are rejected with 413
    max_body_size: usize,
    /// Optional socket tuning applied to listener and accepted sockets
    #[cfg_attr(not(unix), allow(dead_code))]
    epoll_config: Option<EpollConfig>,
    /// Optional global exception filter chain (see [`Application::use_global_filter`]).
    /// When unset, errors are converted via [`Error::to_client_response`]
    /// exactly as before this field existed.
    filter_chain: Option<ExceptionFilterChain>,
}

/// Default maximum request body size (10 MB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// A guard paired with the URL path prefix it applies to.
///
/// Module guards are *not* global: a guard declared by a module is scoped to
/// the base paths of the controllers registered by that **same** module (see
/// [`Application::register_module`]), so it runs only for requests whose path
/// falls under one of those base paths. Guards added manually via
/// [`Application::with_guard`] use an empty prefix and therefore run for every
/// request (a genuinely global guard).
#[derive(Clone)]
struct ScopedGuard {
    /// URL path prefix this guard applies to. An empty prefix (or `"/"`)
    /// matches every request path.
    prefix: String,
    /// The guard to evaluate for matching requests.
    guard: Arc<dyn Guard>,
}

impl ScopedGuard {
    /// Returns `true` if this guard should run for the given request path.
    ///
    /// Matching is path-segment aware: prefix `/admin` matches `/admin` and
    /// `/admin/...` but **not** `/administrators`. An empty or `/` prefix
    /// matches every path (a global guard).
    fn matches(&self, path: &str) -> bool {
        let prefix = self.prefix.trim_end_matches('/');
        if prefix.is_empty() {
            return true;
        }
        path == prefix || path.starts_with(&format!("{}/", prefix))
    }
}

/// Shared state captured by every connection's request handler.
///
/// Routing dispatches through the O(1) [`OptimizedRouter`] (static-HashMap fast
/// path + compiled patterns + LRU cache), compiled once from the fully
/// populated linear [`Router`] at server startup (see
/// [`Application::serve_state`]). The linear router remains the registration
/// target; only per-request dispatch is accelerated.
#[derive(Clone)]
pub(crate) struct ServeState {
    router: Arc<OptimizedRouter>,
    cors: Option<Arc<CorsConfig>>,
    guards: Arc<[ScopedGuard]>,
    max_body_size: usize,
    /// Global exception filter chain (see [`Application::use_global_filter`]).
    /// `None` preserves the original behavior: errors go straight to
    /// [`Error::to_client_response`] via [`error_response`].
    filter_chain: Option<Arc<ExceptionFilterChain>>,
    /// The peer of the connection this state is serving, stamped onto every
    /// request that arrives on it (see [`HttpRequest::peer`]).
    ///
    /// Carried here rather than passed to `handle_request` because the state is
    /// already cloned once per connection, which is exactly the scope a peer
    /// address has: it is a property of the connection, not of the request.
    /// `None` on a path that does not know the address.
    peer: Option<SocketAddr>,
}

impl ServeState {
    /// A state with only a router and a body cap, for tests.
    ///
    /// The serve path's own tests need a `ServeState` without an `Application`
    /// behind it; every other field takes the value it has when nothing is
    /// configured, which is what those tests want to hold constant.
    #[cfg(all(test, feature = "h1-backend"))]
    pub(crate) fn for_test(router: Arc<OptimizedRouter>, max_body_size: usize) -> Self {
        Self {
            router,
            cors: None,
            guards: Vec::new().into(),
            max_body_size,
            filter_chain: None,
            peer: None,
        }
    }

    /// Serve with CORS configured, for tests.
    #[cfg(all(test, feature = "h1-backend"))]
    pub(crate) fn with_cors_for_test(mut self, cors: CorsConfig) -> Self {
        self.cors = Some(Arc::new(cors));
        self
    }

    /// Serve with one globally-scoped guard, for tests.
    ///
    /// An empty prefix, matching [`Application::with_guard`], so the guard runs
    /// for every request path.
    #[cfg(all(test, feature = "h1-backend"))]
    pub(crate) fn with_guard_for_test(mut self, guard: Arc<dyn Guard>) -> Self {
        self.guards = vec![ScopedGuard {
            prefix: String::new(),
            guard,
        }]
        .into();
        self
    }

    /// Serve with a global exception filter chain, for tests.
    ///
    /// The only live-socket filter tests drive [`handle_request`], so the final
    /// hop the `armature-h1` path takes — `dispatch_request` →
    /// `respond_to_error` → `to_h1_response` — was asserted nowhere. A filter
    /// response losing its status or its body in that hop is invisible without
    /// a way to put a chain on a `ServeState` the serve tests build.
    #[cfg(all(test, feature = "h1-backend"))]
    pub(crate) fn with_filter_chain_for_test(mut self, chain: ExceptionFilterChain) -> Self {
        self.filter_chain = Some(Arc::new(chain));
        self
    }

    /// The same state, serving one connection whose peer is known.
    pub(crate) fn for_peer(&self, peer: SocketAddr) -> Self {
        Self {
            peer: Some(peer),
            ..self.clone()
        }
    }
}

/// CORS configuration for the application.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allow_origin: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub allow_credentials: bool,
    pub max_age: u32,
}

impl CorsConfig {
    pub fn new(origin: impl Into<String>) -> Self {
        Self {
            allow_origin: origin.into(),
            allow_methods: "GET, POST, PUT, DELETE, OPTIONS, PATCH".to_string(),
            allow_headers: "Content-Type, Authorization, Accept, X-Requested-With".to_string(),
            allow_credentials: false,
            max_age: 86400,
        }
    }

    pub fn with_credentials(mut self) -> Self {
        self.allow_credentials = true;
        self
    }

    pub fn allow_headers(mut self, headers: impl Into<String>) -> Self {
        self.allow_headers = headers.into();
        self
    }
}

impl Application {
    /// Create an application with a container and router
    pub fn new(container: Container, router: Router) -> Self {
        Self {
            container,
            router: Arc::new(router),
            lifecycle: Arc::new(LifecycleManager::new()),
            pipeline_config: PipelineConfig::default(),
            pipeline_stats: Arc::new(PipelineStats::new()),
            http2_config: Http2Config::default(),
            http2_stats: Arc::new(Http2Stats::new()),
            http3_config: Http3Config::default(),
            http3_stats: Arc::new(Http3Stats::new()),
            cors_config: None,
            guards: Vec::new(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            epoll_config: None,
            filter_chain: None,
        }
    }

    /// Register a global exception filter.
    ///
    /// Filters run in priority order (highest first); the first filter
    /// whose `catch()` returns `Some(response)` wins and its response is
    /// returned to the client. Wired into every HTTP/1.1 and HTTP/2 request
    /// path: every `service_fn` closure across [`Application::listen`],
    /// [`Application::listen_on`], HTTP/2 cleartext, and HTTPS/TLS+ALPN
    /// listeners funnels through the same shared `handle_request`, so both
    /// the guard-rejection error path and the routing/handler error path try
    /// the filter chain before falling back to
    /// [`Error::to_client_response`]. HTTP/3 ([`Application::listen_h3`] /
    /// [`Application::listen_dual_stack`]'s QUIC side) does **not** yet go
    /// through the filter chain -- it's served by a separate `Http3Server`
    /// code path (see `http3.rs`) that doesn't call `handle_request`.
    ///
    /// A registered filter's `catch()` runs with panic and timeout
    /// isolation (see `respond_to_error`): a panicking or hanging filter
    /// falls back to the same response [`Error::to_client_response`] would
    /// have produced, rather than taking down the request or connection.
    ///
    /// Calling this repeatedly adds more filters to the same chain. Errors
    /// not claimed by any filter fall back to the chain's own default
    /// transformer (production-mode [`crate::error_transform::ErrorTransformer`]),
    /// *not* [`Error::to_client_response`] -- this matches
    /// [`crate::exception_filter::ExceptionFilterChain`]'s own documented
    /// behavior. Without any call to this method, errors are converted via
    /// [`Error::to_client_response`] exactly as before this method existed.
    ///
    /// # Example
    ///
    /// ```
    /// use armature_core::{Application, Container, Router};
    /// use armature_core::exception_filter::AllExceptionsFilter;
    ///
    /// let app = Application::new(Container::new(), Router::new())
    ///     .use_global_filter(AllExceptionsFilter::new());
    /// # let _ = app;
    /// ```
    pub fn use_global_filter<F: ExceptionFilter>(mut self, filter: F) -> Self {
        let chain = self.filter_chain.take().unwrap_or_default();
        self.filter_chain = Some(chain.add_filter(filter));
        self
    }

    /// Configure CORS for the application. Handles preflight OPTIONS
    /// requests automatically and adds CORS headers to every response.
    ///
    /// # Interaction with registered OPTIONS routes
    ///
    /// Only an actual CORS preflight is intercepted: an `OPTIONS` request that
    /// carries `Access-Control-Request-Method`, which is what a browser sends
    /// and what the Fetch standard defines a preflight to be. It is answered
    /// with `204` before the router is consulted, deliberately without checking
    /// whether a route exists — a preflight names a path the browser is *about*
    /// to call with some other method, so requiring an `OPTIONS` route for it
    /// would mean registering one beside every CORS-reachable handler.
    ///
    /// Any other `OPTIONS` request routes normally. RFC 9110 section 9.3.7
    /// gives `OPTIONS` a meaning of its own — ask what a resource supports —
    /// and a handler registered with `Router::options` keeps serving it.
    ///
    /// This applies to **every** listener. Before `0.9`, only
    /// [`listen_on`](Self::listen_on) consulted this configuration and every
    /// TLS listener silently ignored it, so an HTTPS server got no CORS headers
    /// at all.
    pub fn with_cors(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(Arc::new(config));
        self
    }

    /// Add a **global** guard evaluated for every request before routing.
    ///
    /// Manually-added guards use an empty (all-matching) path prefix, so they
    /// run for every request path regardless of which controller handles it.
    /// This is different from guards declared by a module, which are scoped to
    /// the base paths of that module's own controllers (see
    /// [`Application::register_module`]). Module guards are registered
    /// automatically during [`Application::create`]; use this to add global
    /// guards manually.
    pub fn with_guard(mut self, guard: Arc<dyn Guard>) -> Self {
        self.guards.push(ScopedGuard {
            prefix: String::new(),
            guard,
        });
        self
    }

    /// Set the maximum request body size in bytes.
    ///
    /// Requests with larger bodies are rejected with `413 Payload Too Large`
    /// before the body is buffered in memory. Defaults to
    /// [`DEFAULT_MAX_BODY_SIZE`] (10 MB).
    pub fn with_max_body_size(mut self, bytes: usize) -> Self {
        self.max_body_size = bytes;
        self
    }

    /// Apply low-level socket tuning to server sockets.
    ///
    /// When set, [`crate::epoll_tuning::configure_socket`] is applied to
    /// every accepted connection socket (TCP_NODELAY, TCP_QUICKACK, buffer
    /// sizes, keepalive) before the connection is served, and to the
    /// listener socket right after binding. Failures are logged as warnings
    /// and never abort the accept loop.
    ///
    /// # Limitations
    ///
    /// The server binds its listener via `TcpListener::bind`, so options
    /// that must be set *before* bind to have any effect — notably
    /// `SO_REUSEPORT` and `SO_REUSEADDR` — are applied too late to influence
    /// binding semantics. Setting them here succeeds but is effectively a
    /// no-op at the listener level; only options that still matter post-bind
    /// (e.g. buffer sizes, which accepted sockets inherit) take effect
    /// there. To use `SO_REUSEPORT` for multi-worker load balancing, create
    /// and bind the socket yourself with the option set before binding.
    ///
    /// Only effective on Unix platforms; the full option set requires Linux.
    /// The epoll flag settings in the config (`edge_triggered`, `oneshot`,
    /// `exclusive`) are advisory and are not applied by the built-in server
    /// (tokio owns its epoll registration).
    ///
    /// **With the default `h1-backend` feature this applies only to
    /// [`listen_h2c`](Self::listen_h2c).** Every other listener hands binding
    /// and accepting to `armature-h1`, so there is no listener fd in this
    /// process to configure and no accept loop to configure accepted sockets
    /// from. `armature-h1`'s own `TcpConfig` covers the part that survives
    /// — `TCP_NODELAY`, backlog, and `SO_REUSEPORT` (which it sets *before*
    /// bind, so it actually works there). Build with `default-features = false`
    /// to get the hyper serve path and this method's full effect back.
    ///
    /// See also [`crate::connection_tuning::TcpConfig`] for the related
    /// per-workload TCP tuning API.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, epoll_tuning::EpollConfig};
    ///
    /// let app = Application::new(container, router)
    ///     .with_socket_tuning(EpollConfig::low_latency());
    /// ```
    pub fn with_socket_tuning(mut self, config: EpollConfig) -> Self {
        self.epoll_config = Some(config);
        self
    }

    /// Build the shared per-connection serving state.
    ///
    /// The linear [`Router`] is compiled once into an [`OptimizedRouter`] here,
    /// after all modules have registered their routes, so per-request routing
    /// uses the O(1) fast path instead of an O(n) linear scan. Called once per
    /// `listen*` entry point (server startup), so the compilation cost is paid
    /// a single time.
    ///
    /// The CORS configuration is read from `self` here rather than passed in by
    /// each listener, and that is deliberate. It used to be a parameter, and
    /// every TLS listener passed `None` — so `with_cors` was a builder method
    /// that accepted configuration and dropped it on the floor for anything but
    /// plaintext. Fixing the call sites one by one leaves the mechanism intact:
    /// the next `listen_*` method to be written can pass `None` again and
    /// silently disable CORS a second time, and nothing would catch it. With no
    /// parameter there is nothing to get wrong.
    fn serve_state(&self) -> ServeState {
        ServeState {
            router: Arc::new(OptimizedRouter::from_router(&self.router)),
            cors: self.cors_config.clone(),
            guards: self.guards.clone().into(),
            max_body_size: self.max_body_size,
            filter_chain: self.filter_chain.clone().map(Arc::new),
            // Set per connection by the accept loops; this is the template.
            peer: None,
        }
    }

    /// Set the pipeline configuration for HTTP/1.1 pipelining
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, pipeline::{PipelineConfig, PipelineMode}};
    ///
    /// let app = Application::new(container, router)
    ///     .with_pipeline_config(PipelineConfig::high_performance());
    /// ```
    pub fn with_pipeline_config(mut self, config: PipelineConfig) -> Self {
        self.pipeline_config = config;
        self
    }

    /// Get the pipeline statistics
    ///
    /// Use this to monitor pipeline performance at runtime.
    ///
    /// **With the default `h1-backend` feature every counter here stays at
    /// zero.** The counters were incremented from the hyper accept loop;
    /// `armature-h1` owns that loop now and exposes no hook into it. Nothing
    /// about request handling changed — but a dashboard reading these will read
    /// flat, which is a healthy-looking idle system rather than an obvious
    /// failure. Build with `default-features = false` to get them back, or read
    /// HTTP/1.1 traffic from your own middleware.
    pub fn pipeline_stats(&self) -> Arc<PipelineStats> {
        Arc::clone(&self.pipeline_stats)
    }

    /// Get the pipeline configuration
    pub fn pipeline_config(&self) -> &PipelineConfig {
        &self.pipeline_config
    }

    /// Set the HTTP/2 configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, Http2Config};
    ///
    /// let app = Application::new(container, router)
    ///     .with_http2_config(Http2Config::high_throughput());
    /// ```
    pub fn with_http2_config(mut self, config: Http2Config) -> Self {
        self.http2_config = config;
        self
    }

    /// Get the HTTP/2 statistics
    ///
    /// Use this to monitor HTTP/2 connection and stream metrics at runtime.
    ///
    /// These keep counting with the default `h1-backend` feature: HTTP/2 is
    /// still served by hyper on both [`listen_h2c`](Self::listen_h2c) and the
    /// `h2`-negotiating half of [`listen_https_h2`](Self::listen_https_h2), and
    /// only those connections were ever counted here. Its HTTP/1.1 companion
    /// [`pipeline_stats`](Self::pipeline_stats) does *not* — see there.
    pub fn http2_stats(&self) -> Arc<Http2Stats> {
        Arc::clone(&self.http2_stats)
    }

    /// Get the HTTP/2 configuration
    pub fn http2_config(&self) -> &Http2Config {
        &self.http2_config
    }

    /// Set the HTTP/3 (QUIC) configuration
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, Http3Config};
    ///
    /// let app = Application::new(container, router)
    ///     .with_http3_config(Http3Config::low_latency());
    /// ```
    pub fn with_http3_config(mut self, config: Http3Config) -> Self {
        self.http3_config = config;
        self
    }

    /// Get the HTTP/3 (QUIC) statistics
    ///
    /// Use this to monitor HTTP/3 connection, stream, and transfer metrics.
    pub fn http3_stats(&self) -> Arc<Http3Stats> {
        Arc::clone(&self.http3_stats)
    }

    /// Get the HTTP/3 (QUIC) configuration
    pub fn http3_config(&self) -> &Http3Config {
        &self.http3_config
    }

    /// Create a new application from a root module with lifecycle support
    ///
    /// # Lifecycle hook failures are fail-open
    ///
    /// `OnModuleInit` and `OnApplicationBootstrap` hooks run automatically as
    /// part of bootstrap (see below). If one or more hooks return an `Err`,
    /// this is **not** fatal: the failures are logged (`warn!`/`error!`) and
    /// startup continues to completion, returning a fully constructed
    /// `Application` regardless. This is an intentional, documented design
    /// choice -- not a bug -- so a single misbehaving provider's init hook
    /// can't unconditionally prevent the process from starting. Callers that
    /// need boot to abort on hook failure should inspect
    /// [`LifecycleManager::call_module_init_hooks`]/
    /// [`LifecycleManager::call_bootstrap_hooks`] results themselves (e.g. by
    /// driving lifecycle manually instead of via `create`) or check logs/
    /// metrics for hook failures after `create` returns.
    pub async fn create<M: Module + Default>() -> Self {
        info!("Bootstrapping Armature application");
        debug!(
            module_type = std::any::type_name::<M>(),
            "Creating application from root module"
        );

        let container = Container::new();
        debug!("DI container initialized");

        let mut router = Router::new();
        debug!("Router initialized");

        let lifecycle = Arc::new(LifecycleManager::new());
        debug!("Lifecycle manager initialized");

        // Attach the lifecycle manager to the container *before* any
        // provider is registered: the provider registration path (see
        // `Container::attach_lifecycle`) probes each provider instance for
        // lifecycle hook trait implementations at the moment it's
        // registered, so this must happen before `register_module` below.
        container.attach_lifecycle(&lifecycle);

        // Initialize the root module
        let root_module = M::default();
        debug!("Root module instantiated");

        info!("Registering modules and dependencies");

        // Register all providers and controllers from the module tree
        let mut guards: Vec<ScopedGuard> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        Self::register_module(
            &container,
            &mut router,
            &mut guards,
            &mut visited,
            &root_module,
        );

        info!("Executing lifecycle hooks");

        // Fail-open: hook errors below are logged, not propagated. See the
        // "Lifecycle hook failures are fail-open" section on this method's
        // doc comment.

        // Call module init hooks
        debug!("Calling OnModuleInit hooks");
        if let Err(errors) = lifecycle.call_module_init_hooks().await {
            warn!(error_count = errors.len(), "Some module init hooks failed");
            for (name, error) in errors {
                error!(hook_name = %name, error = %error, "Module init hook failed");
            }
        } else {
            debug!("All OnModuleInit hooks completed successfully");
        }

        // Call bootstrap hooks
        debug!("Calling OnApplicationBootstrap hooks");
        if let Err(errors) = lifecycle.call_bootstrap_hooks().await {
            warn!(error_count = errors.len(), "Some bootstrap hooks failed");
            for (name, error) in errors {
                error!(hook_name = %name, error = %error, "Bootstrap hook failed");
            }
        } else {
            debug!("All OnApplicationBootstrap hooks completed successfully");
        }

        info!("Application bootstrap complete");

        Self {
            container,
            router: Arc::new(router),
            lifecycle,
            pipeline_config: PipelineConfig::default(),
            pipeline_stats: Arc::new(PipelineStats::new()),
            http2_config: Http2Config::default(),
            http2_stats: Arc::new(Http2Stats::new()),
            http3_config: Http3Config::default(),
            http3_stats: Arc::new(Http3Stats::new()),
            cors_config: None,
            guards,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            epoll_config: None,
            filter_chain: None,
        }
    }

    /// Get a reference to the lifecycle manager
    pub fn lifecycle(&self) -> &Arc<LifecycleManager> {
        &self.lifecycle
    }

    /// Gracefully shutdown the application
    pub async fn shutdown(
        &self,
        signal: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(signal = ?signal, "Gracefully shutting down application");

        // Call before shutdown hooks
        debug!("Calling BeforeApplicationShutdown hooks");
        if let Err(errors) = self
            .lifecycle
            .call_before_shutdown_hooks(signal.clone())
            .await
        {
            warn!(
                error_count = errors.len(),
                "Some before shutdown hooks failed"
            );
            for (name, error) in errors {
                error!(hook_name = %name, error = %error, "Before shutdown hook failed");
            }
        } else {
            debug!("All BeforeApplicationShutdown hooks completed successfully");
        }

        // Call shutdown hooks
        debug!("Calling OnApplicationShutdown hooks");
        if let Err(errors) = self.lifecycle.call_shutdown_hooks(signal.clone()).await {
            warn!(error_count = errors.len(), "Some shutdown hooks failed");
            for (name, error) in errors {
                error!(hook_name = %name, error = %error, "Shutdown hook failed");
            }
        } else {
            debug!("All OnApplicationShutdown hooks completed successfully");
        }

        // Call module destroy hooks
        debug!("Calling OnModuleDestroy hooks");
        if let Err(errors) = self.lifecycle.call_module_destroy_hooks().await {
            warn!(
                error_count = errors.len(),
                "Some module destroy hooks failed"
            );
            for (name, error) in errors {
                error!(hook_name = %name, error = %error, "Module destroy hook failed");
            }
        } else {
            debug!("All OnModuleDestroy hooks completed successfully");
        }

        info!("Application shutdown complete");
        Ok(())
    }

    /// Initialize logging with default configuration
    ///
    /// This is a convenience method that initializes JSON logging to STDOUT.
    /// For more control, use `LogConfig` directly.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::Application;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let _guard = Application::init_logging();
    ///     // Application code...
    /// }
    /// ```
    pub fn init_logging() -> Option<crate::logging::tracing_appender::non_blocking::WorkerGuard> {
        crate::logging::LogConfig::default().init()
    }

    /// Initialize logging with custom configuration
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use armature_core::{Application, LogConfig, LogLevel, LogFormat};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let config = LogConfig::new()
    ///         .level(LogLevel::Debug)
    ///         .format(LogFormat::Pretty);
    ///
    ///     let _guard = Application::init_logging_with_config(config);
    ///     // Application code...
    /// }
    /// ```
    pub fn init_logging_with_config(
        config: crate::logging::LogConfig,
    ) -> Option<crate::logging::tracing_appender::non_blocking::WorkerGuard> {
        config.init()
    }

    /// Register a module and its imports recursively.
    ///
    /// # Guard scoping
    ///
    /// Guards declared by a module are **not** application-global. Each
    /// module's guards are scoped to the base paths of the controllers that the
    /// **same** module registers (via `module.controllers()`): a guard `G` in a
    /// module whose controllers have base paths `[P1, P2]` is stored once per
    /// base path and runs only for requests whose path falls under `P1` or
    /// `P2`. Recursion does not widen this: an imported or child module's guards
    /// scope to that child's own controllers, never to the parent's. A module
    /// that declares guards but registers no controllers has nothing to scope
    /// to, so its guards are inert (a warning is emitted). Manually-added guards
    /// (see [`Application::with_guard`]) use an empty prefix and stay global.
    fn register_module(
        container: &Container,
        router: &mut Router,
        guards: &mut Vec<ScopedGuard>,
        visited: &mut std::collections::HashSet<std::any::TypeId>,
        module: &dyn Module,
    ) {
        // Dedup by the *concrete* module's `TypeId` (`Module::module_type_id`),
        // not `std::any::type_name_of_val(module)`. The latter resolves its
        // type parameter from the *static* type of the `module: &dyn Module`
        // parameter, so it always evaluates to the trait object's own type
        // name (the same string for every module) rather than the concrete
        // type behind the vtable. Keyed that way, the very first module
        // `register_module` ever touches (the root) claims the one shared
        // key, and every module reached afterwards — any import, re-export,
        // or sibling, not just true diamond re-imports — collides with it
        // and is silently skipped.
        let module_id = module.module_type_id();
        let module_type = module.module_type_name();

        // Each module registers once: diamond imports must not duplicate
        // providers/routes, and cyclic imports must not recurse forever.
        if !visited.insert(module_id) {
            debug!(
                module_type = module_type,
                "Module already registered, skipping"
            );
            return;
        }
        debug!(module_type = module_type, "Registering module");

        // First, recursively register imported modules
        let imports = module.imports();
        if !imports.is_empty() {
            debug!(
                module_type = module_type,
                import_count = imports.len(),
                "Registering imported modules"
            );
            for imported_module in imports {
                Self::register_module(container, router, guards, visited, imported_module.as_ref());
            }
        }

        // Register re-exported modules (they need to be registered too)
        let re_exports = module.re_exports();
        if !re_exports.is_empty() {
            debug!(
                module_type = module_type,
                re_export_count = re_exports.len(),
                "Registering re-exported modules"
            );
            for re_exported_module in re_exports {
                Self::register_module(
                    container,
                    router,
                    guards,
                    visited,
                    re_exported_module.as_ref(),
                );
            }
        }

        // Register all providers
        let providers = module.providers();
        debug!(
            module_type = module_type,
            provider_count = providers.len(),
            "Registering providers"
        );
        for provider_reg in providers {
            // Call the registration function which will register the provider in the container
            (provider_reg.register_fn)(container);
            debug!(
                module_type = module_type,
                provider = provider_reg.type_name,
                "Provider registered"
            );
        }

        // Register all guards.
        //
        // Module guards are scoped to the base paths of the controllers that
        // THIS SAME module registers, so a guard runs only for requests to its
        // own module's controllers — not for every request, and not for
        // controllers belonging to imported/child modules. A module that
        // declares guards but has no controllers has nothing to scope to, so
        // those guards are inert and a warning is emitted.
        let guard_regs = module.guards();
        if !guard_regs.is_empty() {
            // Base paths of this module's own controllers to scope guards to.
            let controller_paths: Vec<&'static str> =
                module.controllers().iter().map(|c| c.base_path).collect();
            debug!(
                module_type = module_type,
                guard_count = guard_regs.len(),
                controller_count = controller_paths.len(),
                "Registering guards"
            );
            for guard_reg in guard_regs {
                match (guard_reg.factory)(container) {
                    Ok(guard) => {
                        if controller_paths.is_empty() {
                            warn!(
                                module_type = module_type,
                                guard = guard_reg.type_name,
                                "Module declares a guard but registers no controllers; \
                                 the guard is inert and will not run for any request"
                            );
                        } else {
                            for base_path in &controller_paths {
                                guards.push(ScopedGuard {
                                    prefix: base_path.to_string(),
                                    guard: guard.clone(),
                                });
                            }
                            debug!(
                                module_type = module_type,
                                guard = guard_reg.type_name,
                                scoped_to = ?controller_paths,
                                "Guard registered (scoped to module's controller base paths)"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            module_type = module_type,
                            guard = guard_reg.type_name,
                            error = %e,
                            "Failed to instantiate guard"
                        );
                    }
                }
            }
        }

        // Register all controllers
        let controllers = module.controllers();
        debug!(
            module_type = module_type,
            controller_count = controllers.len(),
            "Registering controllers"
        );
        for controller_reg in controllers {
            // Instantiate controller with DI
            match (controller_reg.factory)(container) {
                Ok(controller_instance) => {
                    // Register routes for this controller
                    if let Err(e) =
                        (controller_reg.route_registrar)(container, router, controller_instance)
                    {
                        error!(
                            module_type = module_type,
                            controller = controller_reg.type_name,
                            error = %e,
                            "Failed to register routes for controller"
                        );
                    } else {
                        debug!(
                            module_type = module_type,
                            controller = controller_reg.type_name,
                            base_path = controller_reg.base_path,
                            "Controller registered"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        module_type = module_type,
                        controller = controller_reg.type_name,
                        error = %e,
                        "Failed to instantiate controller"
                    );
                }
            }
        }

        debug!(module_type = module_type, "Module registration complete");
    }

    /// Start the HTTP server on the specified port
    ///
    /// Configure HTTP/1.1 connection behavior with `with_pipeline_config()`
    /// before calling this method.
    ///
    /// # Pipelining
    ///
    /// With the default `h1-backend` feature, requests arriving on one
    /// connection are served **one at a time**: `armature-h1` reads no further
    /// than a single head and does not read again until that response has been
    /// written. A client may still pipeline — the extra requests simply wait in
    /// the socket buffer — but the throughput win of overlapping them is not
    /// available, and a slow handler holds up everything queued behind it on
    /// the same connection. Build with `default-features = false` for the hyper
    /// serve path, which does overlap pipelined requests.
    ///
    /// See [`listen_on`](Self::listen_on) for the rest of what the default
    /// backend changes: parser strictness, the blocking-handler hazard, the
    /// flat statistics, and the inert `epoll_config`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, pipeline::PipelineConfig};
    ///
    /// let app = Application::new(container, router)
    ///     .with_pipeline_config(PipelineConfig::high_performance());
    ///
    /// app.listen(8080).await?;
    /// ```
    ///
    /// This binds to all interfaces (`0.0.0.0`) on the given port. To bind to a
    /// specific address (e.g. loopback only, or an ephemeral `:0` port), use
    /// [`Application::listen_on`].
    pub async fn listen(self, port: u16) -> Result<(), Error> {
        self.listen_on((std::net::Ipv4Addr::UNSPECIFIED, port))
            .await
    }

    /// Start the HTTP server on the specified socket address.
    ///
    /// This is the address-accepting counterpart to [`Application::listen`],
    /// which binds to all interfaces on a port. `listen_on` accepts anything
    /// convertible into a [`SocketAddr`], allowing binds to a specific
    /// interface, IPv6, or an OS-assigned ephemeral port (`:0`).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::Application;
    /// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    ///
    /// # async fn example(app: Application) -> Result<(), Box<dyn std::error::Error>> {
    /// // Loopback only, port 8080
    /// app.listen_on(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # With the default `h1-backend` feature
    ///
    /// HTTP/1.1 is served by the sibling crate `armature-h1` rather than by
    /// hyper. It is the same framework above the transport — same routing, same
    /// guards, same filters — but the transport itself behaves differently in
    /// four ways a deployment can notice. All four apply to every HTTP/1.1
    /// listener on this type, not only this one. Build with
    /// `default-features = false` to get the hyper serve path back.
    ///
    /// **The parser is stricter.** `armature-h1` prescans the request head for
    /// strict CRLF framing before tokenizing it, and rejects a bare CR, a bare
    /// LF as a line terminator, obs-fold, whitespace before a field-name colon,
    /// a non-token field name, a non-UTF-8 or otherwise invalid request target,
    /// and any version other than HTTP/1.0 or HTTP/1.1. RFC 9112 permits some
    /// of that leniency; this backend declines it, because leniency that
    /// differs from a proxy's in front of it is a request-smuggling vector. A
    /// client or test harness that was getting away with a malformed head under
    /// hyper now gets a `400` and a closed connection.
    ///
    /// **A blocking handler stalls its whole worker.** `armature-h1` runs N
    /// pinned OS threads, each with a `current_thread` tokio runtime serving
    /// every connection assigned to it. A handler that blocks the thread —
    /// synchronous file or database I/O, a `std` mutex held across work, a long
    /// CPU loop — freezes every *other* connection on that core, not just its
    /// own, and no work-stealing rescues them. Under a multi-threaded runtime
    /// the same handler merely occupied one of many workers. Wrap blocking work
    /// in `tokio::task::spawn_blocking`.
    ///
    /// **[`pipeline_stats`](Self::pipeline_stats) stays at zero, and
    /// [`http2_stats`](Self::http2_stats) counts only HTTP/2.** The counters
    /// were incremented from the accept loop; `armature-h1` owns that loop and
    /// exposes no hook. This is observability, not behavior — but a dashboard
    /// reading connection or request counts goes flat and reads as a healthy
    /// idle system, which is worth knowing before the upgrade rather than after.
    ///
    /// **[`with_socket_tuning`](Self::with_socket_tuning) does nothing here.**
    /// It reaches for the raw fd of a listener this process no longer owns. The
    /// part that matters — `TCP_NODELAY`, backlog, `SO_REUSEPORT` — is covered
    /// by `armature-h1`'s own `TcpConfig`, which sets `SO_REUSEPORT` *before*
    /// bind and so actually gets the load balancing this method could never
    /// deliver. Only [`listen_h2c`](Self::listen_h2c) still applies it.
    pub async fn listen_on(self, addr: impl Into<SocketAddr>) -> Result<(), Error> {
        let addr = addr.into();

        // Which backend serves HTTP/1.1 is a compile-time choice, so it is made
        // with a `cfg`-selected binding rather than a branch: exactly one of
        // these two lines exists in any given build.
        //
        // The binding-then-`served` shape is not a redundant rebind waiting to
        // be simplified away: an attribute may not decorate a tail expression,
        // and `return` on the tail is `clippy::needless_return`. Every
        // `listen_*` method here repeats it for the same reason.
        #[cfg(feature = "h1-backend")]
        let served = self.listen_on_h1(addr).await;
        #[cfg(not(feature = "h1-backend"))]
        let served = self.listen_on_hyper(addr).await;
        served
    }

    /// `listen_on` over `armature-h1`'s thread-per-core server.
    ///
    /// Binding, accepting, TLS, and the per-connection loop all move into
    /// `armature-h1`, so the hyper version's accept loop has no counterpart
    /// here: what is left is configuration.
    ///
    /// Note what is *not* carried over. `PipelineStats` counted connections and
    /// requests from inside the accept loop; `armature-h1` owns that loop and
    /// exposes no hook, so those counters stay at zero on this path. They were
    /// observability, not behaviour — but a dashboard reading them will go flat,
    /// which is worth knowing before the upgrade rather than after.
    ///
    /// The `epoll_config` socket tuning is likewise not applied: it reaches for
    /// the raw fd of a listener this process no longer owns. `armature-h1`'s
    /// own `TcpConfig` covers the part that matters (`nodelay`, backlog,
    /// `SO_REUSEPORT`).
    #[cfg(feature = "h1-backend")]
    async fn listen_on_h1(self, addr: SocketAddr) -> Result<(), Error> {
        let state = self.serve_state();
        let cfg = crate::h1_backend::h1_config(addr, &self.pipeline_config, None);
        crate::h1_backend::serve(cfg, state, None).await
    }

    /// `listen_on` over `hyper::server::conn::http1`.
    ///
    /// The path taken with the `h1-backend` feature off, unchanged from before
    /// that feature existed.
    #[cfg(not(feature = "h1-backend"))]
    async fn listen_on_hyper(self, addr: SocketAddr) -> Result<(), Error> {
        debug!(address = %addr, "Binding to address");
        let listener = TcpListener::bind(addr).await?;

        #[cfg(unix)]
        let socket_tuning = self.epoll_config.clone();
        #[cfg(unix)]
        if let Some(ref tuning) = socket_tuning {
            use std::os::unix::io::AsRawFd;
            apply_socket_tuning(listener.as_raw_fd(), tuning, "listener");
        }

        info!(
            address = %addr,
            pipeline_mode = ?self.pipeline_config.mode,
            pipeline_flush = self.pipeline_config.pipeline_flush,
            max_concurrent = self.pipeline_config.max_concurrent,
            "HTTP server listening with pipelining enabled"
        );

        let state = self.serve_state();
        let pipeline_builder = PipelinedHttp1Builder::with_stats(
            self.pipeline_config.clone(),
            Arc::clone(&self.pipeline_stats),
        );
        let pipeline_stats = Arc::clone(&self.pipeline_stats);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            trace!(client_address = %client_addr, "Connection accepted");

            // Apply TCP_NODELAY if configured
            if pipeline_builder.config().tcp_nodelay
                && let Err(e) = stream.set_nodelay(true)
            {
                trace!(error = %e, "Failed to set TCP_NODELAY");
            }

            // Apply opt-in socket tuning to the accepted socket
            #[cfg(unix)]
            if let Some(ref tuning) = socket_tuning {
                use std::os::unix::io::AsRawFd;
                apply_socket_tuning(stream.as_raw_fd(), tuning, "accepted connection");
            }

            let io = TokioIo::new(stream);
            let state = state.for_peer(client_addr);
            let http_builder = pipeline_builder.configure_hyper_builder();
            let stats = Arc::clone(&pipeline_stats);

            // Track connection
            stats.connection_opened();

            tokio::spawn(async move {
                let stats_for_close = Arc::clone(&stats);
                let service = service_fn(move |req: Request<IncomingBody>| {
                    let state = state.clone();
                    let stats = Arc::clone(&stats);
                    async move {
                        stats.request_processed();
                        handle_request(req, state).await
                    }
                });

                if let Err(err) = http_builder.serve_connection(io, service).await {
                    error!(error = %err, client = %client_addr, "Error serving connection");
                }

                // Track connection close
                stats_for_close.connection_closed();
            });
        }
    }

    /// Start the HTTPS server with TLS
    ///
    /// # Example
    ///
    /// ```ignore
    /// use armature_core::{Application, TlsConfig, Module};
    ///
    /// #[derive(Clone)]
    /// struct AppModule;
    /// impl Module for AppModule {
    ///     fn name(&self) -> &str { "AppModule" }
    ///     fn controllers(&self) -> Vec<Box<dyn Controller>> { vec![] }
    /// }
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut app = Application::new();
    /// let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
    /// app.listen_https(443, tls).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This listener serves HTTP/1.1 only, so it advertises only `http/1.1`
    /// over ALPN even though [`TlsConfig`] offers `h2` as well; use
    /// [`listen_https_h2`](Self::listen_https_h2) for HTTP/2. See
    /// [`listen_on`](Self::listen_on) for what the default `h1-backend` feature
    /// changes about every HTTP/1.1 listener on this type.
    pub async fn listen_https(self, port: u16, tls_config: TlsConfig) -> Result<(), Error> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        // See `listen_on` for why this is a `cfg`-selected binding and not a
        // branch, and why the trailing `served` is not a redundant rebind.
        #[cfg(feature = "h1-backend")]
        let served = self.listen_https_h1(addr, tls_config, false).await;
        #[cfg(not(feature = "h1-backend"))]
        let served = self.listen_https_hyper(addr, tls_config).await;
        served
    }

    /// The `armature-h1` implementation behind [`listen_https`](Self::listen_https)
    /// and [`listen_https_h2`](Self::listen_https_h2).
    ///
    /// `armature-h1`'s dispatch does the ALPN check itself: it hands a
    /// connection that negotiated `h2` to the fallback and serves everything
    /// else as HTTP/1.1. `with_h2` decides whether that fallback is hyper's
    /// HTTP/2 driver or a close — which is the entire difference between the
    /// two public methods, since `listen_https` promises HTTP/1.1 only.
    ///
    /// See [`listen_on_h1`](Self::listen_on_h1) for what this path drops
    /// (pipeline/HTTP-2 connection counters, `epoll_config` socket tuning).
    #[cfg(feature = "h1-backend")]
    async fn listen_https_h1(
        self,
        addr: SocketAddr,
        tls_config: TlsConfig,
        with_h2: bool,
    ) -> Result<(), Error> {
        let state = self.serve_state();
        // The ALPN offer has to match what the fallback will actually do with
        // an `h2` connection: when it closes them, offering `h2` is a promise
        // the listener then breaks mid-handshake.
        let tls = if with_h2 {
            tls_config.server_config
        } else {
            without_h2_alpn(tls_config.server_config)
        };
        let cfg = crate::h1_backend::h1_config(addr, &self.pipeline_config, None).with_tls(tls);
        let h2 = with_h2.then(|| {
            Http2Builder::with_stats(self.http2_config.clone(), Arc::clone(&self.http2_stats))
                .configure_hyper_builder()
        });
        crate::h1_backend::serve(cfg, state, h2).await
    }

    /// `listen_https` over `hyper::server::conn::http1`.
    #[cfg(not(feature = "h1-backend"))]
    async fn listen_https_hyper(
        self,
        addr: SocketAddr,
        tls_config: TlsConfig,
    ) -> Result<(), Error> {
        debug!(address = %addr, "Binding to address (HTTPS)");
        let listener = TcpListener::bind(addr).await?;

        #[cfg(unix)]
        let socket_tuning = self.epoll_config.clone();
        #[cfg(unix)]
        if let Some(ref tuning) = socket_tuning {
            use std::os::unix::io::AsRawFd;
            apply_socket_tuning(listener.as_raw_fd(), tuning, "listener");
        }

        info!(
            address = %addr,
            pipeline_mode = ?self.pipeline_config.mode,
            pipeline_flush = self.pipeline_config.pipeline_flush,
            "HTTPS server listening with pipelining enabled"
        );

        // HTTP/1.1 only, so `h2` comes back out of the ALPN offer: hyper's
        // `http1` server rejects the h2 preface, and a protocol negotiated only
        // to be refused is worse than one never offered. See `without_h2_alpn`.
        let acceptor = TlsAcceptor::from(without_h2_alpn(tls_config.server_config));
        let state = self.serve_state();
        let pipeline_builder = PipelinedHttp1Builder::with_stats(
            self.pipeline_config.clone(),
            Arc::clone(&self.pipeline_stats),
        );
        let pipeline_stats = Arc::clone(&self.pipeline_stats);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            trace!(client_address = %client_addr, "HTTPS connection accepted");

            // Apply TCP_NODELAY if configured
            if pipeline_builder.config().tcp_nodelay
                && let Err(e) = stream.set_nodelay(true)
            {
                trace!(error = %e, "Failed to set TCP_NODELAY");
            }

            // Apply opt-in socket tuning to the accepted socket
            #[cfg(unix)]
            if let Some(ref tuning) = socket_tuning {
                use std::os::unix::io::AsRawFd;
                apply_socket_tuning(stream.as_raw_fd(), tuning, "accepted connection");
            }

            let acceptor = acceptor.clone();
            let state = state.for_peer(client_addr);
            let http_builder = pipeline_builder.configure_hyper_builder();
            let stats = Arc::clone(&pipeline_stats);

            // Track connection
            stats.connection_opened();

            tokio::spawn(async move {
                let stats_for_close = Arc::clone(&stats);
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        debug!(client = %client_addr, "TLS handshake successful");
                        let io = TokioIo::new(tls_stream);

                        let service = service_fn(move |req: Request<IncomingBody>| {
                            let state = state.clone();
                            let stats = Arc::clone(&stats);
                            async move {
                                stats.request_processed();
                                handle_request(req, state).await
                            }
                        });

                        if let Err(err) = http_builder.serve_connection(io, service).await {
                            error!(error = %err, client = %client_addr, "Error serving HTTPS connection");
                        }
                    }
                    Err(err) => {
                        error!(error = %err, client = %client_addr, "TLS handshake failed");
                    }
                }

                // Track connection close
                stats_for_close.connection_closed();
            });
        }
    }

    /// Start HTTPS server with optional HTTP to HTTPS redirect
    ///
    /// This method starts both an HTTPS server and optionally an HTTP server that redirects
    /// all traffic to HTTPS.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use armature_core::{Application, HttpsConfig, TlsConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut app = Application::new();
    /// let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
    /// let https_config = HttpsConfig::new("0.0.0.0:443", tls)
    ///     .with_http_redirect("0.0.0.0:80");
    /// app.listen_with_config(https_config).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The HTTPS listener serves HTTP/1.1 only, so it advertises only
    /// `http/1.1` over ALPN even though [`TlsConfig`] offers `h2` as well. See
    /// [`listen_on`](Self::listen_on) for what the default `h1-backend` feature
    /// changes about every HTTP/1.1 listener on this type.
    pub async fn listen_with_config(self, config: HttpsConfig) -> Result<(), Error> {
        let state = self.serve_state();

        // Start HTTP redirect server if configured
        if let Some(ref http_addr) = config.http_redirect_addr {
            let https_port = config
                .https_addr
                .split(':')
                .next_back()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(443);

            let http_addr = http_addr.clone();
            tokio::spawn(async move {
                if let Err(e) = start_http_redirect_server(&http_addr, https_port).await {
                    eprintln!("HTTP redirect server failed: {}", e);
                }
            });
        }

        // Parse HTTPS address
        let https_addr: SocketAddr = config
            .https_addr
            .parse()
            .map_err(|e| Error::Internal(format!("Invalid HTTPS address: {}", e)))?;

        // See `listen_on` for why this is a `cfg`-selected binding and not a
        // branch, and why the trailing `served` is not a redundant rebind.
        #[cfg(feature = "h1-backend")]
        let served = self.listen_with_config_h1(https_addr, config, state).await;
        #[cfg(not(feature = "h1-backend"))]
        let served = self
            .listen_with_config_hyper(https_addr, config, state)
            .await;
        served
    }

    /// The `armature-h1` half of [`listen_with_config`](Self::listen_with_config).
    ///
    /// The HTTP-to-HTTPS redirect server is already spawned by the caller and
    /// keeps running on the caller's runtime; only the HTTPS listener moves
    /// onto `armature-h1`.
    ///
    /// HTTP/2 is deliberately not offered here. The hyper version of this
    /// method served HTTP/1.1 only, with a bare `http1::Builder`, so routing an
    /// ALPN `h2` negotiation to hyper would add a protocol this listener never
    /// had — a behaviour change smuggled in under a backend swap. So `h2` is
    /// withdrawn from the ALPN offer instead of being negotiated and then
    /// refused; see [`without_h2_alpn`].
    #[cfg(feature = "h1-backend")]
    async fn listen_with_config_h1(
        self,
        https_addr: SocketAddr,
        config: HttpsConfig,
        state: ServeState,
    ) -> Result<(), Error> {
        let redirecting = config.http_redirect_addr.is_some();
        let cfg = crate::h1_backend::h1_config(https_addr, &self.pipeline_config, None)
            .with_tls(without_h2_alpn(config.tls.server_config));
        // Announced from `on_bound`, which runs once the listener exists.
        // Printing before the bind means a port conflict shows the operator
        // "listening on https://…" and then the error that says it never
        // listened — and the address printed would be the requested one rather
        // than the resolved one, which differ whenever the port is 0.
        crate::h1_backend::serve::serve_bound(cfg, state, None, move |addr, _| {
            println!("🔒 HTTPS Server listening on https://{}", addr);
            if redirecting {
                println!("↪️  HTTP redirect server enabled");
            }
        })
        .await
    }

    /// The hyper half of [`listen_with_config`](Self::listen_with_config).
    #[cfg(not(feature = "h1-backend"))]
    async fn listen_with_config_hyper(
        self,
        https_addr: SocketAddr,
        config: HttpsConfig,
        state: ServeState,
    ) -> Result<(), Error> {
        let listener = TcpListener::bind(https_addr).await?;

        #[cfg(unix)]
        let socket_tuning = self.epoll_config.clone();
        #[cfg(unix)]
        if let Some(ref tuning) = socket_tuning {
            use std::os::unix::io::AsRawFd;
            apply_socket_tuning(listener.as_raw_fd(), tuning, "listener");
        }

        println!("🔒 HTTPS Server listening on https://{}", https_addr);
        if config.http_redirect_addr.is_some() {
            println!("↪️  HTTP redirect server enabled");
        }

        // HTTP/1.1 only here too — see `without_h2_alpn`, and
        // `listen_with_config_h1` for why this listener does not gain HTTP/2.
        let acceptor = TlsAcceptor::from(without_h2_alpn(config.tls.server_config));

        loop {
            let (stream, client_addr) = listener.accept().await?;
            trace!(client_address = %client_addr, "TLS connection accepted");

            // Apply opt-in socket tuning to the accepted socket
            #[cfg(unix)]
            if let Some(ref tuning) = socket_tuning {
                use std::os::unix::io::AsRawFd;
                apply_socket_tuning(stream.as_raw_fd(), tuning, "accepted connection");
            }

            let acceptor = acceptor.clone();
            let state = state.for_peer(client_addr);

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);

                        let service = service_fn(move |req: Request<IncomingBody>| {
                            let state = state.clone();
                            async move { handle_request(req, state).await }
                        });

                        if let Err(err) = http1::Builder::new().serve_connection(io, service).await
                        {
                            eprintln!("Error serving HTTPS connection: {:?}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("TLS handshake failed: {:?}", err);
                    }
                }
            });
        }
    }

    /// Start HTTP/2 cleartext server (h2c)
    ///
    /// **Warning**: HTTP/2 cleartext (h2c) is not recommended for production.
    /// Use `listen_https_h2` for TLS-secured HTTP/2.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::Application;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let app = Application::new(container, router);
    /// app.listen_h2c(8080).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn listen_h2c(self, port: u16) -> Result<(), Error> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        debug!(address = %addr, "Binding to address (HTTP/2 cleartext)");
        let listener = TcpListener::bind(addr).await?;

        #[cfg(unix)]
        let socket_tuning = self.epoll_config.clone();
        #[cfg(unix)]
        if let Some(ref tuning) = socket_tuning {
            use std::os::unix::io::AsRawFd;
            apply_socket_tuning(listener.as_raw_fd(), tuning, "listener");
        }

        info!(
            address = %addr,
            max_concurrent_streams = self.http2_config.max_concurrent_streams,
            "HTTP/2 cleartext server listening (h2c)"
        );
        warn!("HTTP/2 cleartext (h2c) is not recommended for production. Use HTTPS.");

        let state = self.serve_state();
        let h2_builder =
            Http2Builder::with_stats(self.http2_config.clone(), Arc::clone(&self.http2_stats));
        let h2_stats = Arc::clone(&self.http2_stats);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            trace!(client_address = %client_addr, "HTTP/2 connection accepted");

            // Apply opt-in socket tuning to the accepted socket
            #[cfg(unix)]
            if let Some(ref tuning) = socket_tuning {
                use std::os::unix::io::AsRawFd;
                apply_socket_tuning(stream.as_raw_fd(), tuning, "accepted connection");
            }

            let io = TokioIo::new(stream);
            let state = state.for_peer(client_addr);
            let http_builder = h2_builder.configure_hyper_builder();
            let stats = Arc::clone(&h2_stats);

            // Track connection
            stats.connection_opened();

            tokio::spawn(async move {
                let stats_for_close = Arc::clone(&stats);
                let service = service_fn(move |req: Request<IncomingBody>| {
                    let state = state.clone();
                    let stats = Arc::clone(&stats);
                    async move {
                        stats.request_processed();
                        handle_request(req, state).await
                    }
                });

                if let Err(err) = http_builder.serve_connection(io, service).await {
                    error!(error = %err, client = %client_addr, "Error serving HTTP/2 connection");
                }

                // Track connection close
                stats_for_close.connection_closed();
            });
        }
    }

    /// Start HTTPS server with HTTP/2 support (ALPN negotiation)
    ///
    /// This method automatically negotiates the best protocol:
    /// - If client supports HTTP/2 and advertises "h2" via ALPN, use HTTP/2
    /// - Otherwise, fall back to HTTP/1.1
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, TlsConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let app = Application::new(container, router);
    /// let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
    /// app.listen_https_h2(443, tls).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [`listen_on`](Self::listen_on) for what the default `h1-backend`
    /// feature changes about the HTTP/1.1 half of this listener; the HTTP/2
    /// half is hyper's either way, so [`http2_stats`](Self::http2_stats) keeps
    /// counting here.
    pub async fn listen_https_h2(self, port: u16, tls_config: TlsConfig) -> Result<(), Error> {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        // `true`: connections that negotiate `h2` over ALPN go to hyper's
        // HTTP/2 driver rather than being closed.
        //
        // See `listen_on` for why this is a `cfg`-selected binding and not a
        // branch, and why the trailing `served` is not a redundant rebind.
        #[cfg(feature = "h1-backend")]
        let served = self.listen_https_h1(addr, tls_config, true).await;
        #[cfg(not(feature = "h1-backend"))]
        let served = self.listen_https_h2_hyper(addr, tls_config).await;
        served
    }

    /// `listen_https_h2` with both protocols served by hyper.
    #[cfg(not(feature = "h1-backend"))]
    async fn listen_https_h2_hyper(
        self,
        addr: SocketAddr,
        tls_config: TlsConfig,
    ) -> Result<(), Error> {
        debug!(address = %addr, "Binding to address (HTTPS with HTTP/2)");
        let listener = TcpListener::bind(addr).await?;

        #[cfg(unix)]
        let socket_tuning = self.epoll_config.clone();
        #[cfg(unix)]
        if let Some(ref tuning) = socket_tuning {
            use std::os::unix::io::AsRawFd;
            apply_socket_tuning(listener.as_raw_fd(), tuning, "listener");
        }

        info!(
            address = %addr,
            max_concurrent_streams = self.http2_config.max_concurrent_streams,
            pipeline_mode = ?self.pipeline_config.mode,
            "HTTPS server listening with HTTP/2 and HTTP/1.1 (ALPN)"
        );

        let acceptor = TlsAcceptor::from(tls_config.server_config);
        let state = self.serve_state();
        let h1_builder = PipelinedHttp1Builder::with_stats(
            self.pipeline_config.clone(),
            Arc::clone(&self.pipeline_stats),
        );
        let h2_builder =
            Http2Builder::with_stats(self.http2_config.clone(), Arc::clone(&self.http2_stats));
        let h1_stats = Arc::clone(&self.pipeline_stats);
        let h2_stats = Arc::clone(&self.http2_stats);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            trace!(client_address = %client_addr, "Connection accepted, starting TLS handshake");

            // Apply opt-in socket tuning to the accepted socket
            #[cfg(unix)]
            if let Some(ref tuning) = socket_tuning {
                use std::os::unix::io::AsRawFd;
                apply_socket_tuning(stream.as_raw_fd(), tuning, "accepted connection");
            }

            let acceptor = acceptor.clone();
            let state = state.for_peer(client_addr);
            let h1_builder_ref = h1_builder.configure_hyper_builder();
            let h2_builder_ref = h2_builder.configure_hyper_builder();
            let h1_stats = Arc::clone(&h1_stats);
            let h2_stats = Arc::clone(&h2_stats);

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        // Check negotiated ALPN protocol
                        let (_, session) = tls_stream.get_ref();
                        let protocol = session.alpn_protocol();

                        let is_h2 = protocol.map(|p| p == b"h2").unwrap_or(false);

                        if is_h2 {
                            debug!(client = %client_addr, "Using HTTP/2 (ALPN negotiated h2)");
                            h2_stats.connection_opened();

                            let io = TokioIo::new(tls_stream);
                            let stats = Arc::clone(&h2_stats);

                            let service = service_fn(move |req: Request<IncomingBody>| {
                                let state = state.clone();
                                let stats = Arc::clone(&stats);
                                async move {
                                    stats.request_processed();
                                    handle_request(req, state).await
                                }
                            });

                            if let Err(err) = h2_builder_ref.serve_connection(io, service).await {
                                error!(error = %err, client = %client_addr, "Error serving HTTP/2 connection");
                            }

                            h2_stats.connection_closed();
                        } else {
                            debug!(client = %client_addr, "Using HTTP/1.1 (ALPN fallback)");
                            h1_stats.connection_opened();

                            let io = TokioIo::new(tls_stream);
                            let stats = Arc::clone(&h1_stats);

                            let service = service_fn(move |req: Request<IncomingBody>| {
                                let state = state.clone();
                                let stats = Arc::clone(&stats);
                                async move {
                                    stats.request_processed();
                                    handle_request(req, state).await
                                }
                            });

                            if let Err(err) = h1_builder_ref.serve_connection(io, service).await {
                                error!(error = %err, client = %client_addr, "Error serving HTTP/1.1 connection");
                            }

                            h1_stats.connection_closed();
                        }
                    }
                    Err(err) => {
                        error!(error = %err, client = %client_addr, "TLS handshake failed");
                    }
                }
            });
        }
    }

    /// Start HTTP/3 (QUIC) server
    ///
    /// HTTP/3 uses QUIC (UDP) instead of TCP, providing:
    /// - 0-RTT connection establishment
    /// - No head-of-line blocking
    /// - Connection migration (mobile-friendly)
    /// - Built-in encryption (TLS 1.3)
    ///
    /// **Note**: Requires the `http3` feature to be enabled.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, TlsConfig, Http3Config};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let app = Application::new(container, router)
    ///     .with_http3_config(Http3Config::low_latency());
    ///
    /// let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
    /// app.listen_h3(443, tls).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "http3")]
    pub async fn listen_h3(self, port: u16, tls_config: TlsConfig) -> Result<(), Error> {
        use crate::http3::Http3Server;

        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        info!(
            address = %addr,
            max_concurrent_streams = self.http3_config.max_concurrent_bidi_streams,
            enable_0rtt = self.http3_config.enable_0rtt,
            "Starting HTTP/3 (QUIC) server"
        );

        // Compile the linear router into the O(1) optimized router once,
        // matching the TCP serve paths.
        let optimized = Arc::new(crate::route_cache::OptimizedRouter::from_router(
            &self.router,
        ));
        let server = Http3Server::new(self.http3_config.clone(), optimized);

        server.listen(addr, tls_config.server_config).await
    }

    /// Start dual-stack server: HTTP/3 (QUIC/UDP) + HTTPS (TCP)
    ///
    /// This runs both servers on the same port number (different protocols):
    /// - HTTP/3 on UDP port (for modern clients)
    /// - HTTPS with HTTP/2/HTTP/1.1 on TCP port (for compatibility)
    ///
    /// Add `Alt-Svc` header to responses to advertise HTTP/3:
    /// ```text
    /// Alt-Svc: h3=":443"; ma=86400
    /// ```
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use armature_core::{Application, TlsConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let app = Application::new(container, router);
    /// let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
    ///
    /// // Runs both HTTP/3 (UDP) and HTTPS (TCP) on port 443
    /// app.listen_dual_stack(443, tls).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "http3")]
    pub async fn listen_dual_stack(self, port: u16, tls_config: TlsConfig) -> Result<(), Error> {
        use crate::http3::Http3Server;

        let addr = SocketAddr::from(([0, 0, 0, 0], port));

        info!(
            address = %addr,
            "Starting dual-stack server (HTTP/3 + HTTPS)"
        );

        // Clone for the two servers
        let tls_config_h3 = tls_config.clone();
        let router_h3 = Arc::new(crate::route_cache::OptimizedRouter::from_router(
            &self.router,
        ));
        let http3_config = self.http3_config.clone();

        // Start HTTP/3 server (UDP)
        let h3_handle = tokio::spawn(async move {
            let server = Http3Server::new(http3_config, router_h3);
            if let Err(e) = server.listen(addr, tls_config_h3.server_config).await {
                error!(error = %e, "HTTP/3 server error");
            }
        });

        // Start HTTPS server with HTTP/2 (TCP)
        let https_handle = tokio::spawn(async move {
            if let Err(e) = self.listen_https_h2(port, tls_config).await {
                error!(error = %e, "HTTPS server error");
            }
        });

        // Wait for either to finish (usually they run forever)
        tokio::select! {
            _ = h3_handle => {
                warn!("HTTP/3 server stopped");
            }
            _ = https_handle => {
                warn!("HTTPS server stopped");
            }
        }

        Ok(())
    }

    /// Get a reference to the DI container
    pub fn container(&self) -> &Container {
        &self.container
    }
}

/// The same rustls configuration with `h2` withdrawn from its ALPN offer.
///
/// [`TlsConfig`] unconditionally advertises `["h2", "http/1.1"]`, so a listener
/// that serves HTTP/1.1 only would negotiate `h2` with every modern browser and
/// then drop the connection without a byte of HTTP ever crossing it — the client
/// is told the server speaks a protocol the server immediately refuses. That is
/// not new to the `armature-h1` backend (hyper's `http1` server rejects the h2
/// preface too), which is precisely why it needs fixing at the offer rather than
/// left as inherited parity: the failure is invisible from the server side and
/// looks like a network fault from the client's.
///
/// Returns the input untouched when `h2` was not offered, so the common case
/// costs a scan of a two-element list rather than a clone of the config.
///
/// Applied on both serve paths, because both need it: hyper's `http1` server
/// rejects the h2 preface exactly as `armature-h1`'s `CloseH2` does.
fn without_h2_alpn(tls: Arc<rustls::ServerConfig>) -> Arc<rustls::ServerConfig> {
    if !tls.alpn_protocols.iter().any(|p| p.as_slice() == b"h2") {
        return tls;
    }
    let mut stripped = (*tls).clone();
    stripped.alpn_protocols.retain(|p| p.as_slice() != b"h2");
    Arc::new(stripped)
}

/// Apply the configured socket tuning options to a raw fd, logging a
/// warning on failure. Never fails the caller.
#[cfg(unix)]
fn apply_socket_tuning(fd: std::os::unix::io::RawFd, config: &EpollConfig, socket: &'static str) {
    if let Err(e) = crate::epoll_tuning::configure_socket(fd, config) {
        warn!(error = %e, socket, "Failed to apply socket tuning");
    }
}

/// Start HTTP server that redirects all requests to HTTPS
async fn start_http_redirect_server(addr: &str, https_port: u16) -> Result<(), Error> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| Error::Internal(format!("Invalid HTTP redirect address: {}", e)))?;

    let listener = TcpListener::bind(addr).await?;

    println!("↪️  HTTP redirect server listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<IncomingBody>| async move {
                // Redirect to HTTPS
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("localhost");

                // Remove port from host if present
                let host_without_port = host.split(':').next().unwrap_or(host);

                let location = if https_port == 443 {
                    format!("https://{}{}", host_without_port, req.uri().path())
                } else {
                    format!(
                        "https://{}:{}{}",
                        host_without_port,
                        https_port,
                        req.uri().path()
                    )
                };

                let response = Response::builder()
                    .status(301)
                    .header("Location", location)
                    .body(Full::new(bytes::Bytes::from("Redirecting to HTTPS...")))
                    .unwrap();

                Ok::<_, hyper::Error>(response)
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving HTTP redirect: {:?}", err);
            }
        });
    }
}

/// Handle an incoming HTTP request
pub(crate) async fn handle_request(
    req: Request<IncomingBody>,
    state: ServeState,
) -> Result<Response<Full<bytes::Bytes>>, hyper::Error> {
    use std::time::Instant;

    let start = Instant::now();

    // Convert hyper request to our HttpRequest
    let method = crate::Method::from(req.method().as_str());
    // The full target, query included, taken whole rather than reassembled:
    // `HttpRequest` splits and parses it on demand, so a handler that ignores
    // the query never pays for it.
    let target = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), |pq| pq.as_str().to_owned());

    let mut armature_req = HttpRequest::new(method.clone(), target).with_peer(state.peer);

    // Guards and routing each consume `armature_req` by value, so the target
    // has to be kept separately for logging and guard-scope prefix matching.
    // A `ByteStr` clone is a refcount bump, not a second copy of the target,
    // and `path_only` trims the query off it without allocating.
    let target_handle = armature_req.path.clone();
    let path = target_handle
        .split_once('?')
        .map_or(target_handle.as_str(), |(p, _)| p);

    if let Some(preflight) = cors_preflight(
        &method,
        || req.headers().contains_key("access-control-request-method"),
        &state,
    ) {
        return Ok(to_hyper_response_raw(preflight, &method, path));
    }

    // Copy headers. One copy per value, because hyper's `HeaderValue` owns its
    // own buffer and cannot be projected into our `Bytes`; the name goes in as
    // a `&str`, so it costs nothing for a well-known header.
    //
    // `append`, not `insert`. hyper's iterator yields each occurrence of a
    // repeated field separately, and `insert` would replace — collapsing a
    // field the wire sent twice to its last occurrence, while the h1 adapter
    // keeps all of them. That divergence is not cosmetic: `client_address`
    // reads `get_all("X-Forwarded-For")` and joins the lines per RFC 9110
    // §5.3, so a collapsing adapter hands it one line where the other hands it
    // all of them, and the same request resolves to a different client over
    // HTTP/2 (served here) than over HTTP/1.1. Both adapters must present the
    // same shape to `dispatch_request` or the policy above it is not shared at
    // all.
    for (name, value) in req.headers() {
        armature_req.headers.append(
            name.as_str(),
            bytes::Bytes::copy_from_slice(value.as_bytes()),
        );
    }

    // Fast-path rejection, before any body byte is buffered. The streaming
    // `Limited` wrapper below still enforces the limit for chunked or
    // undeclared bodies.
    let declared_len = declared_content_length(armature_req.headers.get("content-length"));
    if let Some(rejection) = declared_length_rejection(declared_len, &method, path, &state) {
        return Ok(to_hyper_response(
            rejection,
            state.cors.as_deref(),
            &method,
            path,
        ));
    }

    // Read body into Bytes (zero-copy after this point), enforcing the
    // configured size limit before the body is buffered in memory.
    let limited = Limited::new(req.into_body(), state.max_body_size);
    let body_bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) if err.is::<http_body_util::LengthLimitError>() => {
            warn!(
                method = %method,
                path = %path,
                limit = state.max_body_size,
                "Request body exceeds configured limit"
            );
            return Ok(to_hyper_response(
                payload_too_large_response(),
                state.cors.as_deref(),
                &method,
                path,
            ));
        }
        Err(err) => match err.downcast::<hyper::Error>() {
            Ok(hyper_err) => return Err(*hyper_err),
            Err(other) => {
                warn!(method = %method, path = %path, error = %other, "Failed to read request body");
                return Ok(to_hyper_response(
                    HttpResponse::new(400),
                    state.cors.as_deref(),
                    &method,
                    path,
                ));
            }
        },
    };
    let body_size = body_bytes.len();

    // Use zero-copy body storage
    if body_size > 0 {
        armature_req.set_body_bytes(body_bytes);
        trace!(body_size = body_size, "Request body received (zero-copy)");
    }

    Ok(to_hyper_response(
        dispatch_request(armature_req, &state, start).await,
        state.cors.as_deref(),
        &method,
        path,
    ))
}

/// Serve one request that arrived over `armature-h1`.
///
/// The counterpart to [`handle_request`], and deliberately the same shape: both
/// build an [`HttpRequest`], answer a CORS preflight before touching the body,
/// enforce the body limit, and then hand off to [`dispatch_request`], which is
/// where all the actual policy lives. Only the transport-facing edges differ.
///
/// Returns an `armature_h1::Response` rather than a `Result`, because there is
/// no error to report to: `armature-h1` owns the connection and every failure
/// this function can encounter has a status code that belongs on the wire.
#[cfg(feature = "h1-backend")]
pub(crate) async fn dispatch_via_h1(
    req: armature_h1::Request,
    state: ServeState,
) -> armature_h1::Response {
    use crate::h1_backend::bridge::{request_from_head, to_h1_response};
    use std::time::Instant;

    let start = Instant::now();
    let armature_h1::Request {
        head,
        mut body,
        peer,
    } = req;
    let method = head.method.clone();

    if let Some(preflight) = cors_preflight(
        &method,
        || {
            // `Access-Control-Request-Method` is outside armature-h1's
            // well-known table, so this compares names rather than interning a
            // needle. It runs only for an `OPTIONS` request on a
            // CORS-configured server.
            head.headers
                .iter()
                .any(|(id, _)| id.as_str() == "access-control-request-method")
        },
        &state,
    ) {
        // No CORS argument: the preflight answer already carries the full
        // preflight header set, and appending the per-response origin pair on
        // top of it would duplicate `Access-Control-Allow-Origin`.
        return to_h1_response(preflight, None, &method, head.path());
    }

    // Fast-path rejection, before any body byte is buffered — the same check
    // the hyper path makes, through the same helper. `armature-h1`
    // independently caps the body at `Limits::max_body_bytes`, but that cap
    // produces a bare 413 from the connection loop; going through
    // `payload_too_large_response` here keeps the body this framework's other
    // transports return.
    let declared_len = declared_content_length(head.get_str(&armature_h1::HeaderId::ContentLength));
    if let Some(rejection) = declared_length_rejection(declared_len, &method, head.path(), &state) {
        return to_h1_response(rejection, state.cors.as_deref(), &method, head.path());
    }

    // `collect` enforces the cap while reading rather than after, so an
    // undeclared or chunked body over the limit is refused mid-stream instead
    // of being buffered whole first.
    let body_bytes = match body.collect(state.max_body_size as u64).await {
        Ok(b) => b,
        Err(err) => {
            let status = err.status();
            warn!(
                method = %method,
                path = head.path(),
                error = %err,
                status,
                "Failed to read request body"
            );
            let response = if status == 413 {
                payload_too_large_response()
            } else {
                HttpResponse::new(status)
            };
            return to_h1_response(response, state.cors.as_deref(), &method, head.path());
        }
    };

    let mut armature_req = request_from_head(head, peer);
    if !body_bytes.is_empty() {
        let body_size = body_bytes.len();
        armature_req.set_body_bytes(body_bytes);
        trace!(body_size = body_size, "Request body received (zero-copy)");
    }

    // `head` is gone into the request by now, so the target is kept the way the
    // hyper path keeps it: a `ByteStr` clone is a refcount bump on the read
    // buffer, and `split_once` trims the query off it without allocating.
    let target_handle = armature_req.path.clone();
    let path = target_handle
        .split_once('?')
        .map_or(target_handle.as_str(), |(p, _)| p);

    to_h1_response(
        dispatch_request(armature_req, &state, start).await,
        state.cors.as_deref(),
        &method,
        path,
    )
}

/// The CORS preflight answer for this request, if one is owed.
///
/// Split out of [`handle_request`] because both serve paths owe it, and both owe
/// it at the same point: before the body is read. Moving it after the read would
/// have an `OPTIONS` carrying a body pay for that body before being answered
/// with a response that never looks at it.
fn cors_preflight(
    method: &crate::Method,
    is_preflight: impl FnOnce() -> bool,
    state: &ServeState,
) -> Option<HttpResponse> {
    let cors = state.cors.as_deref()?;
    if method != "OPTIONS" {
        return None;
    }
    // `OPTIONS` alone does not make it a preflight. RFC 9110 section 9.3.7
    // gives `OPTIONS` its own meaning — ask what a resource supports, answered
    // with `Allow` — and that request has nothing to do with CORS. A preflight
    // is the narrower thing the Fetch standard defines: `OPTIONS` carrying
    // `Access-Control-Request-Method`, which a browser sends and nothing else
    // does.
    //
    // Answering both here would make a registered `OPTIONS` route unreachable
    // the moment CORS is configured, which is a routing decision taken by a
    // header the caller sets. The closure is invoked only once the two cheap
    // checks above pass, so a non-`OPTIONS` request never pays for the lookup.
    if !is_preflight() {
        return None;
    }
    let mut response = HttpResponse::new(204);
    response.headers.insert(
        "Access-Control-Allow-Origin".into(),
        cors.allow_origin.clone(),
    );
    response.headers.insert(
        "Access-Control-Allow-Methods".into(),
        cors.allow_methods.clone(),
    );
    response.headers.insert(
        "Access-Control-Allow-Headers".into(),
        cors.allow_headers.clone(),
    );
    response
        .headers
        .insert("Access-Control-Max-Age".into(), cors.max_age.to_string());
    // Through the same decision the per-response path uses, because the
    // preflight is a response too and the wildcard rule does not care which one
    // it is. Its result reaches the adapters with `cors = None` — it carries the
    // full preflight set already — so this is the only place the guard can run
    // for it, and without it a wildcard-plus-credentials configuration went out
    // as the invalid pair on the preflight while being correctly suppressed on
    // every response that followed.
    if response_wire::cors_additions(None, cors).credentials {
        response.headers.insert(
            "Access-Control-Allow-Credentials".into(),
            "true".to_string(),
        );
    }
    Some(response)
}

/// The body length a request declares, in bytes, or `None` if it declares none
/// this framework will act on.
///
/// Only the first comma-separated element is parsed. `Content-Length: 100, 100`
/// is a legal spelling of a 100-byte body — RFC 9112 §6.3 accepts a list whose
/// elements all agree, and `armature-h1`'s framing does too — but a bare
/// `parse::<usize>()` fails on it and reports no declared length at all, which
/// silently skips the fast-path rejection below for exactly the request most
/// likely to be probing for one. The size cap is not lost when that happens (the
/// streaming read still enforces it), but the early refusal and the operator's
/// `warn!` line are, and the framing this parse must agree with is the
/// connection's, not the strictest reading available.
fn declared_content_length(raw: Option<&str>) -> Option<usize> {
    raw?.split(',').next()?.trim().parse::<usize>().ok()
}

/// The `413` answer owed to a request whose declared body already exceeds the
/// configured cap, if one is owed.
///
/// Sibling to [`cors_preflight`], split out for the same reason: both serve
/// paths owe this check and both owe it at the same moment — after the preflight
/// answer, before a single body byte is buffered. Left inline it was policy
/// living in two adapters whose whole arrangement is that only their
/// transport-facing edges differ, and the two copies had already begun to: they
/// extracted the declared length by different rules.
///
/// `None` for `declared_len` means the request declares no length; the streaming
/// read caps those instead.
fn declared_length_rejection(
    declared_len: Option<usize>,
    method: &crate::Method,
    path: &str,
    state: &ServeState,
) -> Option<HttpResponse> {
    let declared_len = declared_len?;
    if body_within_limit(declared_len, state.max_body_size) {
        return None;
    }
    warn!(
        method = %method,
        path = %path,
        limit = state.max_body_size,
        declared_len,
        "Request Content-Length exceeds configured limit"
    );
    Some(payload_too_large_response())
}

/// Guards, routing, and error mapping for a fully-formed request.
///
/// Everything between "an [`HttpRequest`] exists, body included" and "an
/// [`HttpResponse`] is ready", with no transport type in the signature. Both
/// serve paths — hyper and `armature-h1` — funnel through here, so the guard
/// ordering, the filter-chain snapshot, and the error mapping have exactly one
/// implementation rather than two that drift.
///
/// `start` is passed in rather than taken here because the duration that
/// matters is measured from the point the transport handed the request over,
/// which is upstream of this call.
async fn dispatch_request(
    mut armature_req: HttpRequest,
    state: &ServeState,
    start: std::time::Instant,
) -> HttpResponse {
    let method = armature_req.method.clone();
    let target_handle = armature_req.path.clone();
    let path = target_handle
        .split_once('?')
        .map_or(target_handle.as_str(), |(p, _)| p);

    // The arrival record, emitted here rather than in each adapter so both
    // transports produce it. It was previously written only by the hyper
    // adapter, so moving the serve path onto `armature-h1` silently removed
    // every per-request trace for HTTP/1.1 — the first record for a request
    // became "Routing request", which is emitted after body handling and never
    // at all for one rejected before that.
    trace!(
        method = %method,
        path = %path,
        header_count = armature_req.headers.len(),
        "Incoming request"
    );

    // Only needed when a global exception filter chain is configured: a
    // filter's `catch()` receives the original request for context (path,
    // headers, request id, ...), matching `ExceptionContext::from_request`.
    // Guard evaluation and routing below each consume `armature_req` by
    // value, so it must be captured before either runs.
    //
    // Limitation (documented, not confirmed to be a bug): because this clone
    // is taken *before* guards run and *before* routing populates path
    // params, `ExceptionContext::request` as seen by a filter's `catch()` is
    // a pre-guard/pre-routing snapshot. Guard-added request extensions and
    // resolved route/path params are therefore never visible to a filter --
    // only headers, method, path, and body as they arrived on the wire.
    let filter_ctx_request = state.filter_chain.as_ref().map(|_| armature_req.clone());

    // Evaluate guards before routing.
    //
    // Only guards whose scope prefix matches this request path are evaluated:
    // module guards are scoped to the base paths of the declaring module's own
    // controllers, while guards added via `Application::with_guard` use an empty
    // prefix and match every path. Guards always run before routing.
    if !state.guards.is_empty() {
        match evaluate_scoped_guards(&state.guards, path, armature_req).await {
            Ok(req) => armature_req = req,
            Err(GuardRejection::Reject) => {
                warn!(method = %method, path = %path, "Request rejected by guard");
                let body = serde_json::json!({
                    "error": "Forbidden",
                    "status": 403,
                });
                return HttpResponse::new(403)
                    .with_json(&body)
                    .unwrap_or_else(|_| HttpResponse::new(403));
            }
            Err(GuardRejection::Error(err)) => {
                warn!(method = %method, path = %path, error = %err, "Guard returned an error");
                return respond_to_error(err, filter_ctx_request, state.filter_chain.clone()).await;
            }
        }
    }

    // Route the request
    debug!(method = %method, path = %path, "Routing request");
    let response = match state.router.route(armature_req).await {
        Ok(resp) => {
            debug!(method = %method, path = %path, status = resp.status, "Request handled successfully");
            resp
        }
        Err(err) => {
            warn!(method = %method, path = %path, error = %err, "Request handling failed");
            respond_to_error(err, filter_ctx_request, state.filter_chain.clone()).await
        }
    };

    let duration = start.elapsed();
    debug!(
        method = %method,
        path = %path,
        status = response.status,
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    response
}

/// Convert a handler error into a client-safe HTTP response.
///
/// Thin wrapper over [`Error::to_client_response`], the single canonical
/// error-to-response mapping shared by every server transport: 4xx errors keep
/// their message; 5xx messages are redacted to a generic body so internal
/// details never reach the client. The full error is logged at the call site.
fn error_response(err: &Error) -> HttpResponse {
    err.to_client_response()
}

/// Default upper bound on how long a single global exception filter chain
/// invocation is allowed to run before `respond_to_error` gives up on it and
/// falls back to [`error_response`]. Chosen to comfortably cover any
/// reasonable filter (a synchronous transform, at most a quick lookup) while
/// still bounding worst-case added latency per request; mirrors the 5s
/// safety-net convention already used for socket reads elsewhere in this
/// file's test harness (see `micro.rs`'s `send_raw_request`).
const DEFAULT_EXCEPTION_FILTER_TIMEOUT: Duration = Duration::from_secs(5);

/// Convert a handler/guard error into an `HttpResponse`, trying the
/// application's global exception filter chain first (see
/// [`Application::use_global_filter`]) before falling back to
/// [`error_response`].
///
/// Both `filter_chain` and `ctx_request` are `None` unless a filter has
/// actually been registered (see `handle_request`'s `filter_ctx_request`),
/// so the fallback path is exercised for every request when no filter is
/// configured -- identical to this framework's behavior before
/// `use_global_filter` existed.
///
/// Thin wrapper over [`respond_to_error_with_timeout`] using
/// [`DEFAULT_EXCEPTION_FILTER_TIMEOUT`]; see that function for the
/// panic/timeout isolation guarantees around the filter chain invocation.
async fn respond_to_error(
    err: Error,
    ctx_request: Option<HttpRequest>,
    filter_chain: Option<Arc<ExceptionFilterChain>>,
) -> HttpResponse {
    respond_to_error_with_timeout(
        err,
        ctx_request,
        filter_chain,
        DEFAULT_EXCEPTION_FILTER_TIMEOUT,
    )
    .await
}

/// Same as [`respond_to_error`], but with an explicit filter-chain timeout
/// (split out so tests can exercise the timeout path without an actual
/// multi-second wait).
///
/// A registered exception filter runs arbitrary, user-supplied code
/// (`ExceptionFilter::catch()`). Without isolation, a filter implementation
/// that panics would unwind the request task and one that hangs would stall
/// the connection forever -- either way taking down request handling for a
/// bug in third-party filter code, on the error path no less, which is
/// exactly when the server should be at its most robust. To prevent that,
/// the filter chain call runs on its own `tokio::spawn`ed task:
///
/// - A panic inside `catch()` unwinds only that spawned task; it surfaces
///   here as `Err(JoinError)` rather than propagating into the caller, and
///   is treated the same as a timeout.
/// - `tokio::time::timeout` bounds how long the task is waited on; if it
///   fires, the still-running task is aborted so it doesn't leak.
///
/// In both failure modes, `err`'s fallback response ([`error_response`],
/// identical to what would be returned with no filter chain configured at
/// all) is used -- the filter is treated as if it had declined to handle the
/// error (returned `None`), not as if the request itself had failed.
async fn respond_to_error_with_timeout(
    err: Error,
    ctx_request: Option<HttpRequest>,
    filter_chain: Option<Arc<ExceptionFilterChain>>,
    filter_timeout: Duration,
) -> HttpResponse {
    match (filter_chain, ctx_request) {
        (Some(chain), Some(request)) => {
            // Computed before `err` is moved into the isolated task below,
            // so it's available as the fallback on either a panic or a
            // timeout without requiring `Error` to be `Clone`.
            let fallback = error_response(&err);

            let task = tokio::spawn(async move { chain.handle(&err, &request).await });
            let abort_handle = task.abort_handle();

            match tokio::time::timeout(filter_timeout, task).await {
                Ok(Ok(response)) => response,
                Ok(Err(join_err)) => {
                    error!(
                        error = %join_err,
                        "Exception filter task panicked; falling back to the default error response"
                    );
                    fallback
                }
                Err(_elapsed) => {
                    // The task is still running (or about to start); stop it
                    // so a hanging filter doesn't keep burning resources
                    // forever in the background.
                    abort_handle.abort();
                    warn!(
                        timeout_secs = filter_timeout.as_secs_f64(),
                        "Exception filter chain timed out; falling back to the default error response"
                    );
                    fallback
                }
            }
        }
        _ => {
            // No filter chain configured, or (defensively) no context
            // request captured for it -- identical to the no-filter
            // fallback.
            error_response(&err)
        }
    }
}

/// Returns `true` if a request body of `len` bytes is within the configured
/// `max` limit.
///
/// Bodies exactly at the limit are accepted; anything larger is rejected with
/// `413 Payload Too Large`. Extracted as a pure function so the boundary is
/// unit-testable independent of the HTTP server.
fn body_within_limit(len: usize, max: usize) -> bool {
    len <= max
}

/// Build the `413 Payload Too Large` response with a JSON body matching the
/// canonical `{"error", "status"}` shape.
fn payload_too_large_response() -> HttpResponse {
    let body = serde_json::json!({
        "error": "Payload Too Large",
        "status": 413,
    });
    HttpResponse::new(413)
        .with_json(&body)
        .unwrap_or_else(|_| HttpResponse::new(413))
}

/// Reason a request was rejected while evaluating scoped guards.
enum GuardRejection {
    /// A guard rejected the request (`Ok(false)`) — respond with 403.
    Reject,
    /// A guard returned an error — respond with the error's client response.
    Error(Error),
}

/// Evaluate the guards whose scope prefix matches `path`, in order.
///
/// Module guards are scoped to the base paths of the declaring module's own
/// controllers (see [`Application::register_module`]); guards added via
/// [`Application::with_guard`] use an empty prefix and match every path. Guards
/// that do not match `path` are skipped entirely. Evaluation stops at the first
/// guard that rejects or errors.
///
/// On success returns the (possibly guard-mutated) request so routing can
/// continue; on rejection returns why the request was denied.
async fn evaluate_scoped_guards(
    guards: &[ScopedGuard],
    path: &str,
    request: HttpRequest,
) -> Result<HttpRequest, GuardRejection> {
    let matching: Vec<&ScopedGuard> = guards.iter().filter(|g| g.matches(path)).collect();
    if matching.is_empty() {
        return Ok(request);
    }
    let context = GuardContext::new(request);
    for scoped in matching {
        match scoped.guard.can_activate(&context).await {
            Ok(true) => {}
            Ok(false) => return Err(GuardRejection::Reject),
            Err(err) => return Err(GuardRejection::Error(err)),
        }
    }
    Ok(context.request)
}

/// The tests and decisions every response adapter owes, whichever transport it
/// writes to.
///
/// This crate has two response adapters — [`to_hyper_response`] here and
/// `to_h1_response` in the `armature-h1` bridge — and the shipped default build
/// runs both: `armature-h1` serves HTTP/1.1 and hyper serves every HTTP/2
/// stream through the fallback. Anything that decides what may go on the wire
/// therefore has to live somewhere both can reach, or one transport enforces it
/// and the other does not — which is not a smaller version of the same policy
/// but a hole in it, reachable by asking for the protocol that skips the check.
///
/// It lives here rather than in the bridge because the bridge is compiled only
/// with the `h1-backend` feature, while this module is compiled always: helpers
/// kept there would vanish from the `--no-default-features` build that still
/// serves every request through hyper. Nothing in here names a transport type;
/// the inputs are a field name, a field value, and the CORS configuration.
pub(crate) mod response_wire {
    use super::{CorsConfig, HttpResponse};
    use crate::logging::{debug, warn};

    /// Whether a field name is a token, as RFC 9110 section 5.6.2 defines one.
    pub(crate) fn name_is_token(name: &str) -> bool {
        !name.is_empty()
            && name.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    }

    /// Whether a field value carries nothing that would terminate the field
    /// early.
    ///
    /// `armature-h1`'s writer runs the same test and answers it by dropping the
    /// offending field and serving the rest of the response. That is the wrong
    /// side to err on for a *response*: response splitting is prevented either
    /// way, but the field that gets dropped is as likely to be a
    /// `Content-Security-Policy`, an `X-Frame-Options`, or a `Set-Cookie`
    /// carrying `Secure`/`HttpOnly` as it is to be decoration, and a page served
    /// with its protections silently missing is worse than a page not served at
    /// all. So both adapters ask the question first, where the whole response
    /// can still be abandoned.
    ///
    /// The two transports do not reject the *same set*: `armature_h1`'s writer
    /// permits control bytes other than CR, LF, and NUL, where hyper's
    /// `HeaderValue` refuses every control byte
    /// (`armature-h1/BACKENDS.md` records the difference). What they share is
    /// the *outcome* this test buys — a field this returns `false` for never
    /// reaches the wire under either, and the response carrying it is abandoned
    /// rather than quietly stripped. Values in the gap between the two sets are
    /// still handled: on the hyper side they fail when the builder refuses them,
    /// and the same 500 is served.
    pub(crate) fn value_is_emittable(value: &[u8]) -> bool {
        !value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0))
    }

    /// A field the transport decides rather than the handler.
    pub(crate) enum TransportField {
        /// A hop-by-hop field, or one that steers how the body is framed.
        Framing,
        /// `Content-Length`, which the writer computes from the bytes it
        /// actually writes.
        ContentLength,
    }

    /// Whether this field is the transport's to decide rather than the
    /// handler's.
    ///
    /// The hop-by-hop set is RFC 9110 section 7.6.1's, plus `Content-Length`:
    /// that one is not hop-by-hop, but both serve paths frame the body
    /// themselves, and a handler-supplied length that disagrees with the bytes
    /// actually written is a desync a pooling proxy reads as the start of the
    /// next response.
    ///
    /// Matched on the name rather than on either transport's interned field
    /// enum, so the two adapters cannot answer this differently.
    pub(crate) fn transport_field(name: &str) -> Option<TransportField> {
        const FRAMING: [&str; 8] = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ];
        if name.eq_ignore_ascii_case("content-length") {
            return Some(TransportField::ContentLength);
        }
        FRAMING
            .iter()
            .any(|known| name.eq_ignore_ascii_case(known))
            .then_some(TransportField::Framing)
    }

    /// Report a field dropped because it belongs to the transport.
    ///
    /// Two levels, because the two cases say different things about the
    /// handler. Setting `Content-Length` on a response is a common and harmless
    /// habit — the writer computes the true length regardless — and warning
    /// about it once per request buries the lines that matter. A `Connection`,
    /// `Upgrade`, or `Transfer-Encoding` is a handler reaching for framing the
    /// connection loop decides knowing things the handler does not: whether the
    /// body was consumed, whether the connection is about to close. A response
    /// that carried its own `Connection` would win over that decision —
    /// `armature-h1`'s writer suppresses its own field when one was supplied —
    /// so a handler reflecting a request's `connection: keep-alive` could talk
    /// the server out of the `close` it is about to act on regardless, and a
    /// pooling proxy would then keep a socket the server has already hung up.
    ///
    /// The name is safe to log here: it reached this point only by passing
    /// [`name_is_token`].
    pub(crate) fn report_transport_field(field: &TransportField, name: &str) {
        match field {
            TransportField::ContentLength => {
                debug!(field = %name, "Dropping a handler-supplied Content-Length; the writer computes it");
            }
            TransportField::Framing => {
                warn!(field = %name, "Dropping a hop-by-hop or framing header supplied by a handler");
            }
        }
    }

    /// Report the field that made a response unemittable, and why.
    ///
    /// Deliberately without the name or the value. The name is checked here too,
    /// so a failing field may be failing *because* its name carries CR or LF —
    /// and interpolating it would carry that injection straight into whatever
    /// reads the log, forging log lines from the same bytes that were denied the
    /// wire. Lengths and which half failed are enough to find the handler;
    /// `method` and `path` say which request to look at.
    pub(crate) fn report_unemittable(
        name: &str,
        value: &[u8],
        method: &crate::Method,
        path: &str,
        what: &str,
    ) {
        warn!(
            method = %method,
            path = %path,
            what,
            name_ok = name_is_token(name),
            name_len = name.len(),
            value_len = value.len(),
            "Handler produced an unwritable header; failing the response closed"
        );
    }

    /// The `500` served in place of a response a handler made unemittable.
    ///
    /// The framework's own error envelope rather than an empty body, for the
    /// reason the `max_body_bytes` note in `h1_backend::serve` gives for the 413
    /// path: a bare status with no `Content-Type` and no CORS headers reaches a
    /// browser doing a credentialed fetch as an opaque CORS failure, so the one
    /// audience that can act on it is told nothing. Both adapters attach the
    /// configured CORS pair to it as they would to any other response.
    ///
    /// The handler's own body is not carried over — it was written alongside a
    /// field that cannot go on the wire, and that field may well be what the
    /// body needed for protection.
    pub(crate) fn internal_error_envelope() -> HttpResponse {
        let body = serde_json::json!({
            "error": "Internal Server Error",
            "status": 500,
        });
        HttpResponse::new(500)
            .with_json(&body)
            .unwrap_or_else(|_| HttpResponse::new(500))
    }

    /// What the configured CORS policy adds to a response the handler has
    /// already had its say on.
    pub(crate) struct CorsAdditions {
        /// The `Access-Control-Allow-Origin` to add, or `None` when the handler
        /// supplied one and adding a second would make the browser reject the
        /// response outright.
        pub(crate) origin: Option<String>,
        /// Whether to add `Access-Control-Allow-Credentials: true`.
        pub(crate) credentials: bool,
        /// Whether to add `Vary: Origin`.
        pub(crate) vary_origin: bool,
    }

    /// Decide what the configured CORS policy adds, given whatever origin the
    /// handler already set.
    ///
    /// One function for both adapters because this is a policy decision with no
    /// transport in it, and written twice it had already drifted — one copy
    /// compared origins case-insensitively, the other compared an exact
    /// lowercase string.
    ///
    /// Three rules, in the order they bite:
    ///
    /// A handler that sets `Access-Control-Allow-Origin` itself has answered
    /// more precisely than a static config can, and the configured value is not
    /// added next to it: two `Allow-Origin` fields make a browser discard the
    /// whole response, so the result would be worse than either answer alone.
    /// Because the response then depends on the request's `Origin`, it also
    /// earns `Vary: Origin` — without it a shared cache can serve one origin's
    /// answer to another.
    ///
    /// Credentials are attached only when the origin actually going out is one
    /// the configuration authorised — the configured origin itself, or no
    /// handler origin at all. A handler that reflects the request's `Origin`
    /// unchecked is the classic CORS mistake, and pairing that reflection with
    /// `Allow-Credentials: true` turns it into a full credentialed cross-origin
    /// read of the response for *any* site that asks. This crate is the last
    /// place that can tell the difference, because only it knows which origin
    /// the operator configured.
    ///
    /// And `*` never carries credentials: the pair is invalid, a browser
    /// discards the response rather than downgrading it, so emitting both turns
    /// a misconfiguration into a silently failing request.
    pub(crate) fn cors_additions(handler_origin: Option<&str>, cors: &CorsConfig) -> CorsAdditions {
        let effective_origin = handler_origin.unwrap_or(cors.allow_origin.as_str());
        let authorised = match handler_origin {
            None => true,
            Some(origin) => origin.eq_ignore_ascii_case(&cors.allow_origin),
        };
        let credentials = if !cors.allow_credentials {
            false
        } else if !authorised {
            warn!(
                "Access-Control-Allow-Credentials withheld: the handler set an \
                 Access-Control-Allow-Origin the CORS configuration does not \
                 authorise, and credentials against an unvalidated origin would \
                 allow any site to read this response"
            );
            false
        } else if effective_origin == "*" {
            warn!(
                "Access-Control-Allow-Credentials withheld: it is invalid \
                 alongside a wildcard origin, and a browser rejects the pair"
            );
            false
        } else {
            true
        };
        CorsAdditions {
            origin: handler_origin.is_none().then(|| cors.allow_origin.clone()),
            credentials,
            vary_origin: handler_origin.is_some(),
        }
    }
}

/// Convert our HttpResponse to a hyper Response, adding no CORS headers.
///
/// For a response that already carries every header it should — the CORS
/// preflight answer, which sets the full preflight set itself and must not have
/// the per-response `Allow-Origin` pair appended on top.
fn to_hyper_response_raw(
    response: HttpResponse,
    method: &crate::Method,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
    to_hyper_response(response, None, method, path)
}

/// Convert our HttpResponse to a hyper Response, applying CORS headers.
///
/// `method` and `path` are carried only so the fail-closed 500 below can name
/// the request that produced it; nothing else here reads them.
fn to_hyper_response(
    response: HttpResponse,
    cors: Option<&CorsConfig>,
    method: &crate::Method,
    path: &str,
) -> Response<Full<bytes::Bytes>> {
    use response_wire::{
        cors_additions, name_is_token, report_transport_field, report_unemittable, transport_field,
        value_is_emittable,
    };

    let mut builder = Response::builder().status(response.status);

    for (key, value) in &response.headers {
        // The same two tests, in the same order, as the `armature-h1` bridge —
        // out of the same module, so this transport cannot end up enforcing a
        // narrower rule than the other. Before they were shared, a handler that
        // set `Content-Length: 999` on a five-byte body had it stripped over
        // HTTP/1.1 and passed straight through here, which is a response desync
        // reachable by asking for HTTP/2.
        if !name_is_token(key) || !value_is_emittable(value.as_bytes()) {
            report_unemittable(key, value.as_bytes(), method, path, "header");
            return unemittable_hyper_response(cors);
        }
        if let Some(field) = transport_field(key) {
            report_transport_field(&field, key);
            continue;
        }
        builder = builder.header(key, value);
    }
    for cookie_value in &response.cookies {
        // The name is the literal `set-cookie`, so only the value is in
        // question here.
        if !value_is_emittable(cookie_value.as_bytes()) {
            report_unemittable(
                "set-cookie",
                cookie_value.as_bytes(),
                method,
                path,
                "set-cookie",
            );
            return unemittable_hyper_response(cors);
        }
        builder = builder.header("Set-Cookie", cookie_value);
    }
    if let Some(cors) = cors {
        let handler_origin = response
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("access-control-allow-origin"))
            .map(|(_, value)| value.as_str());
        let additions = cors_additions(handler_origin, cors);
        if let Some(origin) = &additions.origin {
            builder = builder.header("Access-Control-Allow-Origin", origin);
        }
        if additions.credentials {
            builder = builder.header("Access-Control-Allow-Credentials", "true");
        }
        if additions.vary_origin {
            builder = builder.header("Vary", "Origin");
        }
    }

    // Zero-copy body passthrough to Hyper
    let body = Full::new(response.into_body_bytes());
    builder.body(body).unwrap_or_else(|_| {
        // A field in the gap between the two writers' rules: hyper refuses
        // every control byte, where the checks above refuse only the three that
        // terminate a field. Same outcome, one step later.
        warn!(
            method = %method,
            path = %path,
            "hyper refused a handler header; failing the response closed"
        );
        unemittable_hyper_response(cors)
    })
}

/// The hyper form of the fail-closed 500, CORS included.
///
/// Built field by field rather than by handing the envelope back to
/// [`to_hyper_response`]: that would be a recursion whose base case depends on
/// the configured origin being emittable, and a configuration is not a thing
/// this function gets to assume anything about.
fn unemittable_hyper_response(cors: Option<&CorsConfig>) -> Response<Full<bytes::Bytes>> {
    let envelope = response_wire::internal_error_envelope();
    let mut builder = Response::builder().status(envelope.status);
    for (key, value) in &envelope.headers {
        builder = builder.header(key, value);
    }
    if let Some(cors) = cors {
        // No handler origin: this response is the framework's, not the
        // handler's, so the configured pair applies unconditionally.
        let additions = response_wire::cors_additions(None, cors);
        if let Some(origin) = &additions.origin {
            builder = builder.header("Access-Control-Allow-Origin", origin);
        }
        if additions.credentials {
            builder = builder.header("Access-Control-Allow-Credentials", "true");
        }
    }
    builder
        .body(Full::new(envelope.into_body_bytes()))
        .unwrap_or_else(|_| {
            // Only reachable from a configured origin hyper refuses, which is
            // a misconfiguration rather than a request-shaped input. The status
            // still has to reach the client.
            let mut fallback = Response::new(Full::new(bytes::Bytes::new()));
            *fallback.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_socket_tuning_stores_config() {
        let app = Application::new(Container::new(), Router::new())
            .with_socket_tuning(EpollConfig::low_latency());

        let config = app
            .epoll_config
            .as_ref()
            .expect("with_socket_tuning should store the config");
        assert_eq!(config.max_events, 256);
        assert!(config.tcp_nodelay);

        // Default is opt-out: no tuning unless requested.
        let plain = Application::new(Container::new(), Router::new());
        assert!(plain.epoll_config.is_none());
    }

    #[test]
    fn test_error_response_redacts_5xx_messages() {
        let err = Error::Internal("db password auth failed for user 'app'".to_string());
        let response = error_response(&err);
        assert_eq!(response.status, 500);
        let body = String::from_utf8(response.into_body_bytes().to_vec()).unwrap();
        assert!(!body.contains("db password"));
        assert!(body.contains("Internal Server Error"));
    }

    #[test]
    fn test_error_response_keeps_4xx_messages() {
        let err = Error::NotFound("User not found".to_string());
        let response = error_response(&err);
        assert_eq!(response.status, 404);
        let body = String::from_utf8(response.into_body_bytes().to_vec()).unwrap();
        assert!(body.contains("User not found"));
    }

    /// Every conversion below answers the same nominal request. The method and
    /// path reach the logs and nothing else, so one pair serves for all of them.
    fn convert(response: HttpResponse, cors: Option<&CorsConfig>) -> Response<Full<bytes::Bytes>> {
        to_hyper_response(response, cors, &crate::Method::Get, "/t")
    }

    /// Parity with `to_h1_response`. `builder.header` appends, so a handler
    /// that reflects `Origin` would otherwise get two of them and the browser
    /// rejects the response — turning a working credentialed-CORS handler into
    /// a broken one purely by configuring CORS.
    #[test]
    fn to_hyper_response_does_not_duplicate_a_handler_supplied_cors_origin() {
        let mut response = HttpResponse::new(200);
        response.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://reflected.test".to_string(),
        );
        let cors = CorsConfig::new("https://configured.test");

        let out = convert(response, Some(&cors));

        let origins: Vec<_> = out
            .headers()
            .get_all("access-control-allow-origin")
            .iter()
            .map(|v| v.to_str().expect("ascii"))
            .collect();
        assert_eq!(
            origins,
            vec!["https://reflected.test"],
            "the handler's reflected origin must stand alone; a second field \
             makes the browser reject a response that was correct"
        );
        assert_eq!(
            out.headers()
                .get("vary")
                .map(|v| v.to_str().expect("ascii")),
            Some("Origin"),
            "the origin came from the handler, so the response varies by it"
        );
    }

    /// `*` with `Allow-Credentials: true` is an invalid pair browsers reject,
    /// so emitting it turns a misconfiguration into a silently broken control.
    #[test]
    fn to_hyper_response_withholds_credentials_from_a_wildcard_origin() {
        let cors = CorsConfig::new("*").with_credentials();

        let out = convert(HttpResponse::new(200), Some(&cors));

        assert!(
            out.headers()
                .get("access-control-allow-credentials")
                .is_none(),
            "credentials must be withheld alongside a wildcard origin rather \
             than emitted as a pair no browser will honour"
        );
    }

    /// The security half of the reflection fix: not duplicating the handler's
    /// origin is only correct if the credentials flag is then judged against
    /// *that* origin. A handler reflecting `Origin` unchecked, plus
    /// `Allow-Credentials: true`, is a credentialed cross-origin read granted to
    /// whoever asked.
    #[test]
    fn to_hyper_response_withholds_credentials_from_an_unauthorised_reflected_origin() {
        let mut response = HttpResponse::new(200);
        response.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://evil.test".to_string(),
        );
        let cors = CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(response, Some(&cors));

        assert_eq!(
            out.headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().expect("ascii")),
            Some("https://evil.test")
        );
        assert!(
            out.headers()
                .get("access-control-allow-credentials")
                .is_none(),
            "credentials belong only to an origin the configuration authorised"
        );
    }

    /// The origin the configuration *did* authorise still gets them.
    #[test]
    fn to_hyper_response_keeps_credentials_for_the_configured_origin() {
        let mut response = HttpResponse::new(200);
        response.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://configured.test".to_string(),
        );
        let cors = CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(response, Some(&cors));

        assert_eq!(
            out.headers()
                .get("access-control-allow-credentials")
                .map(|v| v.to_str().expect("ascii")),
            Some("true")
        );
    }

    /// The mirror of the bridge's
    /// `a_handler_cannot_override_the_connection_loops_framing`. Both adapters
    /// ship in the default build — hyper serves every HTTP/2 stream — so a
    /// filter enforced on one of them is a hole reachable by choosing the other
    /// protocol.
    #[test]
    fn to_hyper_response_drops_handler_supplied_framing_headers() {
        let mut response = HttpResponse::new(413);
        response
            .headers
            .insert("Connection".to_string(), "keep-alive".to_string());
        response
            .headers
            .insert("Transfer-Encoding".to_string(), "chunked".to_string());
        response
            .headers
            .insert("Upgrade".to_string(), "websocket".to_string());
        response
            .headers
            .insert("Content-Length".to_string(), "999".to_string());
        response
            .headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        let out = convert(response, None);

        for field in [
            "connection",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ] {
            assert!(
                out.headers().get(field).is_none(),
                "{field} is the transport's to decide, not the handler's — and \
                 a handler-supplied Content-Length over a body of another \
                 length is a desync a pooling proxy reads as the next response"
            );
        }
        assert_eq!(
            out.headers()
                .get("content-type")
                .map(|v| v.to_str().expect("ascii")),
            Some("text/plain"),
            "only the transport's own fields go; the rest survives"
        );
    }

    /// Same fail-closed rule as the bridge, for the same reason: the field that
    /// would be dropped is as likely to be a `Content-Security-Policy` as it is
    /// to be decoration.
    #[test]
    fn to_hyper_response_fails_a_response_closed_on_an_unwritable_field() {
        for (name, value) in [
            ("X-Bad", "a\r\nx-injected: 1"),
            ("X-Bad", "a\nb"),
            ("X-Bad", "a\0b"),
            ("X Bad", "fine"),
            ("bad:name", "fine"),
        ] {
            let mut response = HttpResponse::new(200);
            response.headers.insert(
                "Content-Security-Policy".to_string(),
                "default-src 'none'".to_string(),
            );
            response.headers.insert(name.to_string(), value.to_string());

            let out = convert(response, None);

            assert_eq!(
                out.status(),
                500,
                "{name}: {value:?} must fail the whole response closed"
            );
            assert!(out.headers().get("content-security-policy").is_none());
            assert_eq!(
                out.headers()
                    .get("content-type")
                    .map(|v| v.to_str().expect("ascii")),
                Some("application/json"),
                "an envelope, not a bare status: a credentialed fetch has to be \
                 able to tell a 500 from a network failure"
            );
        }
    }

    #[test]
    fn the_hyper_fail_closed_500_carries_the_configured_cors_headers() {
        let mut response = HttpResponse::new(200);
        response
            .headers
            .insert("X Bad".to_string(), "fine".to_string());
        let cors = CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(response, Some(&cors));

        assert_eq!(out.status(), 500);
        assert_eq!(
            out.headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().expect("ascii")),
            Some("https://configured.test")
        );
        assert_eq!(
            out.headers()
                .get("access-control-allow-credentials")
                .map(|v| v.to_str().expect("ascii")),
            Some("true")
        );
    }

    /// The preflight answer reaches the adapters with `cors = None`, so the
    /// wildcard guard cannot run on it there — it has to run where the answer is
    /// built, or a wildcard-plus-credentials configuration goes out as the
    /// invalid pair on the preflight and is correctly suppressed on every
    /// response after it.
    #[test]
    fn a_preflight_withholds_credentials_from_a_wildcard_origin() {
        let state = Application::new(Container::new(), Router::new())
            .with_cors(CorsConfig::new("*").with_credentials())
            .serve_state();

        let preflight = cors_preflight(&crate::Method::Options, || true, &state)
            .expect("a preflight answer is owed");

        assert_eq!(preflight.status, 204);
        assert!(
            preflight
                .headers
                .get("Access-Control-Allow-Credentials")
                .is_none(),
            "the pair is invalid, so a browser discards the preflight entirely"
        );
    }

    #[test]
    fn a_preflight_keeps_credentials_for_a_named_origin() {
        let state = Application::new(Container::new(), Router::new())
            .with_cors(CorsConfig::new("https://configured.test").with_credentials())
            .serve_state();

        let preflight = cors_preflight(&crate::Method::Options, || true, &state)
            .expect("a preflight answer is owed");

        assert_eq!(
            preflight
                .headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn test_to_hyper_response_sets_headers_cookies_and_cors() {
        let response = HttpResponse::ok()
            .content_type("application/json")
            .cookie("session", "abc; HttpOnly")
            .with_body(b"{}".to_vec());
        let cors = CorsConfig::new("https://example.com").with_credentials();

        let hyper_resp = convert(response, Some(&cors));
        assert_eq!(hyper_resp.status(), 200);
        assert_eq!(
            hyper_resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            hyper_resp.headers().get("Set-Cookie").unwrap(),
            "session=abc; HttpOnly"
        );
        assert_eq!(
            hyper_resp
                .headers()
                .get("Access-Control-Allow-Origin")
                .unwrap(),
            "https://example.com"
        );
        assert_eq!(
            hyper_resp
                .headers()
                .get("Access-Control-Allow-Credentials")
                .unwrap(),
            "true"
        );
    }

    // ---- Body-limit boundary (fix #4) --------------------------------------

    #[test]
    fn test_body_within_limit_boundary() {
        // Exactly at the limit is accepted; one byte over is rejected.
        assert!(body_within_limit(0, 10));
        assert!(body_within_limit(10, 10));
        assert!(!body_within_limit(11, 10));

        let max = DEFAULT_MAX_BODY_SIZE;
        assert!(body_within_limit(max, max));
        assert!(!body_within_limit(max + 1, max));
    }

    #[test]
    fn test_declared_content_length_accepts_a_comma_list() {
        assert_eq!(declared_content_length(Some("100")), Some(100));
        assert_eq!(declared_content_length(Some(" 100 ")), Some(100));
        // RFC 9112 §6.3: a list whose elements agree frames a body of that
        // length, and `armature-h1` reads it that way. A bare `parse` does not,
        // and reporting `None` here would skip the pre-buffer 413 entirely.
        assert_eq!(declared_content_length(Some("100, 100")), Some(100));
        assert_eq!(declared_content_length(Some("100,100")), Some(100));

        assert_eq!(declared_content_length(None), None);
        assert_eq!(declared_content_length(Some("")), None);
        assert_eq!(declared_content_length(Some("banana")), None);
        assert_eq!(declared_content_length(Some("-1")), None);
    }

    #[test]
    fn test_without_h2_alpn_strips_only_h2() {
        use rustls::ServerConfig;

        // Named explicitly, matching `TlsConfig`: rustls refuses to pick a
        // process-level provider on its own.
        let base =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(NoCertResolver));

        let mut offering_h2 = base.clone();
        offering_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let stripped = without_h2_alpn(Arc::new(offering_h2));
        assert_eq!(
            stripped.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "a listener that closes h2 connections must not advertise h2"
        );

        // Nothing to strip: returned as-is rather than cloned.
        let mut h1_only = base;
        h1_only.alpn_protocols = vec![b"http/1.1".to_vec()];
        let untouched = Arc::new(h1_only);
        let same = without_h2_alpn(Arc::clone(&untouched));
        assert!(Arc::ptr_eq(&untouched, &same));
    }

    /// A resolver that never resolves, for building a `ServerConfig` whose
    /// certificate is irrelevant because no handshake is ever performed.
    #[derive(Debug)]
    struct NoCertResolver;

    impl rustls::server::ResolvesServerCert for NoCertResolver {
        fn resolve(
            &self,
            _hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    #[test]
    fn test_payload_too_large_response_path() {
        let resp = payload_too_large_response();
        assert_eq!(resp.status, 413);
        let body = String::from_utf8(resp.into_body_bytes().to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["status"], 413);
        assert_eq!(parsed["error"], "Payload Too Large");
    }

    // ---- Scoped guards (fix #3) --------------------------------------------

    struct AllowGuard;
    #[async_trait::async_trait]
    impl Guard for AllowGuard {
        async fn can_activate(&self, _ctx: &GuardContext) -> Result<bool, Error> {
            Ok(true)
        }
    }

    struct RecordingGuard {
        ran: Arc<std::sync::atomic::AtomicBool>,
    }
    #[async_trait::async_trait]
    impl Guard for RecordingGuard {
        async fn can_activate(&self, _ctx: &GuardContext) -> Result<bool, Error> {
            self.ran.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
    }

    #[test]
    fn test_scoped_guard_matches_is_segment_aware() {
        let g = ScopedGuard {
            prefix: "/admin".to_string(),
            guard: Arc::new(AllowGuard),
        };
        assert!(g.matches("/admin"));
        assert!(g.matches("/admin/users"));
        // Segment-aware: /administrators must NOT match /admin.
        assert!(!g.matches("/administrators"));
        assert!(!g.matches("/public"));

        // Empty prefix is a genuinely global guard.
        let global = ScopedGuard {
            prefix: String::new(),
            guard: Arc::new(AllowGuard),
        };
        assert!(global.matches("/anything"));
        assert!(global.matches("/"));

        // A "/" prefix is also global.
        let root = ScopedGuard {
            prefix: "/".to_string(),
            guard: Arc::new(AllowGuard),
        };
        assert!(root.matches("/anything"));
    }

    #[tokio::test]
    async fn test_scoped_guard_runs_only_for_its_controller_path() {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guards = vec![ScopedGuard {
            prefix: "/admin".to_string(),
            guard: Arc::new(RecordingGuard { ran: ran.clone() }),
        }];

        // Matches /admin/x → guard runs.
        let req = HttpRequest::new("GET", "/admin/x".to_string());
        let decision = evaluate_scoped_guards(&guards, "/admin/x", req).await;
        assert!(decision.is_ok());
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));

        // Does NOT match /public/y → guard is not evaluated.
        ran.store(false, std::sync::atomic::Ordering::SeqCst);
        let req = HttpRequest::new("GET", "/public/y".to_string());
        let decision = evaluate_scoped_guards(&guards, "/public/y", req).await;
        assert!(decision.is_ok());
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));

        // /administrators must NOT match /admin → guard not evaluated.
        ran.store(false, std::sync::atomic::Ordering::SeqCst);
        let req = HttpRequest::new("GET", "/administrators".to_string());
        let _ = evaluate_scoped_guards(&guards, "/administrators", req).await;
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    fn admin_guard_registration() -> crate::module::GuardRegistration {
        crate::module::GuardRegistration {
            type_id: std::any::TypeId::of::<AllowGuard>(),
            type_name: "AllowGuard",
            factory: |_c| Ok(Arc::new(AllowGuard) as Arc<dyn Guard>),
        }
    }

    fn controller_registration(base_path: &'static str) -> crate::ControllerRegistration {
        crate::ControllerRegistration {
            type_id: std::any::TypeId::of::<()>(),
            type_name: "TestController",
            base_path,
            factory: |_c| Ok(Box::new(()) as Box<dyn std::any::Any + Send + Sync>),
            route_registrar: |_c, _r, _b| Ok(()),
        }
    }

    /// Module with a guard and a controller at `/admin`.
    struct AdminModule;
    impl Module for AdminModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![controller_registration("/admin")]
        }
        fn guards(&self) -> Vec<crate::module::GuardRegistration> {
            vec![admin_guard_registration()]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    /// Module that declares a guard but registers no controllers.
    struct GuardOnlyModule;
    impl Module for GuardOnlyModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn guards(&self) -> Vec<crate::module::GuardRegistration> {
            vec![admin_guard_registration()]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[test]
    fn test_register_module_scopes_guard_to_controller_base_path() {
        let container = Container::new();
        let mut router = Router::new();
        let mut guards: Vec<ScopedGuard> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        Application::register_module(
            &container,
            &mut router,
            &mut guards,
            &mut visited,
            &AdminModule,
        );

        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].prefix, "/admin");
        assert!(guards[0].matches("/admin/users"));
        assert!(!guards[0].matches("/public"));
    }

    #[test]
    fn test_register_module_guard_without_controllers_is_inert() {
        let container = Container::new();
        let mut router = Router::new();
        let mut guards: Vec<ScopedGuard> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        Application::register_module(
            &container,
            &mut router,
            &mut guards,
            &mut visited,
            &GuardOnlyModule,
        );

        // No controllers to scope to → guard registers nothing.
        assert!(guards.is_empty());
    }

    // ---- register_module dedups by concrete module type, not the erased
    // trait-object type (regression: T4b) ------------------------------
    //
    // `std::any::type_name_of_val(module: &dyn Module)` always evaluates to
    // the trait object's own type name ("dyn Module"), the same string for
    // every concrete module, because its type parameter is resolved from
    // the *static* type of the reference, not the concrete type behind the
    // vtable. A visited-set keyed on that string treats every module after
    // the first one touched as a duplicate and silently drops it.

    struct DistinctProviderA;
    struct DistinctProviderB;

    async fn distinct_handler_a(
        _req: crate::HttpRequest,
    ) -> Result<crate::HttpResponse, crate::Error> {
        Ok(crate::HttpResponse::ok())
    }

    async fn distinct_handler_b(
        _req: crate::HttpRequest,
    ) -> Result<crate::HttpResponse, crate::Error> {
        Ok(crate::HttpResponse::ok())
    }

    fn distinct_controller_registration_a() -> crate::ControllerRegistration {
        crate::ControllerRegistration {
            type_id: std::any::TypeId::of::<()>(),
            type_name: "DistinctControllerA",
            base_path: "/distinct-a",
            factory: |_c| Ok(Box::new(()) as Box<dyn std::any::Any + Send + Sync>),
            route_registrar: |_c, r, _b| {
                r.get("/distinct-a", distinct_handler_a);
                Ok(())
            },
        }
    }

    fn distinct_controller_registration_b() -> crate::ControllerRegistration {
        crate::ControllerRegistration {
            type_id: std::any::TypeId::of::<()>(),
            type_name: "DistinctControllerB",
            base_path: "/distinct-b",
            factory: |_c| Ok(Box::new(()) as Box<dyn std::any::Any + Send + Sync>),
            route_registrar: |_c, r, _b| {
                r.get("/distinct-b", distinct_handler_b);
                Ok(())
            },
        }
    }

    /// Imported module A: registers `DistinctProviderA` and a controller at
    /// `/distinct-a`.
    struct DistinctModuleA;
    impl Module for DistinctModuleA {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![crate::ProviderRegistration {
                type_id: std::any::TypeId::of::<DistinctProviderA>(),
                type_name: "DistinctProviderA",
                register_fn: |c| c.register(DistinctProviderA),
            }]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![distinct_controller_registration_a()]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    /// Imported module B: a concrete type distinct from `DistinctModuleA`;
    /// registers `DistinctProviderB` and a controller at `/distinct-b`.
    struct DistinctModuleB;
    impl Module for DistinctModuleB {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![crate::ProviderRegistration {
                type_id: std::any::TypeId::of::<DistinctProviderB>(),
                type_name: "DistinctProviderB",
                register_fn: |c| c.register(DistinctProviderB),
            }]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![distinct_controller_registration_b()]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    /// Root module with no providers/controllers of its own; everything
    /// observable comes from its two distinct imports.
    struct DistinctRootModule;
    impl Module for DistinctRootModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(DistinctModuleA), Box::new(DistinctModuleB)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[test]
    fn test_register_module_registers_all_distinct_imported_modules() {
        let container = Container::new();
        let mut router = Router::new();
        let mut guards: Vec<ScopedGuard> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        Application::register_module(
            &container,
            &mut router,
            &mut guards,
            &mut visited,
            &DistinctRootModule,
        );

        assert!(
            container.has::<DistinctProviderA>(),
            "first imported module's provider must be registered"
        );
        assert!(
            container.has::<DistinctProviderB>(),
            "second imported module's provider must be registered (must not \
             be dropped as a false-positive duplicate of the first)"
        );
        assert!(
            router.routes.iter().any(|r| r.path == "/distinct-a"),
            "first imported module's controller route must be registered"
        );
        assert!(
            router.routes.iter().any(|r| r.path == "/distinct-b"),
            "second imported module's controller route must be registered"
        );
    }

    // ---- true diamond import: the same concrete module reached via two
    // different parents must still register exactly once -----------------

    struct SharedDiamondProvider;

    static DIAMOND_PROVIDER_INIT_COUNT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct SharedDiamondModule;
    impl Module for SharedDiamondModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![crate::ProviderRegistration {
                type_id: std::any::TypeId::of::<SharedDiamondProvider>(),
                type_name: "SharedDiamondProvider",
                register_fn: |c| {
                    DIAMOND_PROVIDER_INIT_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    c.register(SharedDiamondProvider);
                },
            }]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    struct DiamondLeftModule;
    impl Module for DiamondLeftModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(SharedDiamondModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    struct DiamondRightModule;
    impl Module for DiamondRightModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(SharedDiamondModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    struct DiamondRootModule;
    impl Module for DiamondRootModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(DiamondLeftModule), Box::new(DiamondRightModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[test]
    fn test_register_module_diamond_import_registers_shared_module_once() {
        let container = Container::new();
        let mut router = Router::new();
        let mut guards: Vec<ScopedGuard> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        Application::register_module(
            &container,
            &mut router,
            &mut guards,
            &mut visited,
            &DiamondRootModule,
        );

        assert!(
            container.has::<SharedDiamondProvider>(),
            "shared module reachable via a diamond must still register"
        );
        assert_eq!(
            DIAMOND_PROVIDER_INIT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "diamond-imported module (reached via two different parents) \
             must register exactly once, not zero (dropped) or two \
             (duplicated)"
        );
    }

    // ---- Application::create() dedups diamond/cyclic imports end-to-end --
    //
    // `test_register_module_diamond_import_registers_shared_module_once`
    // above exercises `register_module` directly. These exercise the exact
    // same dedup logic through the full public `Application::create()`
    // entrypoint -- the actual bootstrap path real applications use -- and
    // additionally cover a genuinely cyclic import graph (X imports Y
    // imports X), which nothing above tests.

    static CREATE_DIAMOND_PROVIDER_INIT_COUNT: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    struct CreateDiamondSharedProvider;

    async fn create_diamond_shared_handler(
        _req: crate::HttpRequest,
    ) -> Result<crate::HttpResponse, crate::Error> {
        Ok(crate::HttpResponse::ok())
    }

    fn create_diamond_shared_controller_registration() -> crate::ControllerRegistration {
        crate::ControllerRegistration {
            type_id: std::any::TypeId::of::<()>(),
            type_name: "CreateDiamondSharedController",
            base_path: "/create-diamond-shared",
            factory: |_c| Ok(Box::new(()) as Box<dyn std::any::Any + Send + Sync>),
            route_registrar: |_c, r, _b| {
                r.get("/create-diamond-shared", create_diamond_shared_handler);
                Ok(())
            },
        }
    }

    /// The shared module reached via both `CreateDiamondLeftModule` and
    /// `CreateDiamondRightModule` below (the "diamond").
    #[derive(Default)]
    struct CreateDiamondSharedModule;
    impl Module for CreateDiamondSharedModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![crate::ProviderRegistration {
                type_id: std::any::TypeId::of::<CreateDiamondSharedProvider>(),
                type_name: "CreateDiamondSharedProvider",
                register_fn: |c| {
                    CREATE_DIAMOND_PROVIDER_INIT_COUNT
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    c.register(CreateDiamondSharedProvider);
                },
            }]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![create_diamond_shared_controller_registration()]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[derive(Default)]
    struct CreateDiamondLeftModule;
    impl Module for CreateDiamondLeftModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(CreateDiamondSharedModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[derive(Default)]
    struct CreateDiamondRightModule;
    impl Module for CreateDiamondRightModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(CreateDiamondSharedModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[derive(Default)]
    struct CreateDiamondRootModule;
    impl Module for CreateDiamondRootModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![
                Box::new(CreateDiamondLeftModule),
                Box::new(CreateDiamondRightModule),
            ]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[tokio::test]
    async fn test_application_create_dedups_diamond_imported_module() {
        CREATE_DIAMOND_PROVIDER_INIT_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);

        let app = Application::create::<CreateDiamondRootModule>().await;

        assert!(
            app.container.has::<CreateDiamondSharedProvider>(),
            "shared module reachable via a diamond (through two different \
             parent modules) must still register"
        );
        assert_eq!(
            CREATE_DIAMOND_PROVIDER_INIT_COUNT.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "diamond-imported module's provider must register exactly once \
             through Application::create, not zero (dropped) or two \
             (duplicated)"
        );

        let route_count = app
            .router
            .routes
            .iter()
            .filter(|r| r.path == "/create-diamond-shared")
            .count();
        assert_eq!(
            route_count, 1,
            "diamond-imported module's controller route must register \
             exactly once through Application::create"
        );
    }

    #[derive(Default)]
    struct CyclicImportXModule;
    impl Module for CyclicImportXModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![Box::new(CyclicImportYModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    struct CyclicImportYModule;
    impl Module for CyclicImportYModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            vec![]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            // Cycle: Y imports X, and X (above) imports Y. Each `imports()`
            // call fabricates a *fresh* instance of the other module type on
            // demand -- there's no literal infinitely-sized value here --
            // but `register_module`'s TypeId-keyed `visited` set must still
            // stop the recursion the second time either concrete type is
            // reached, or this would recurse forever and blow the stack.
            vec![Box::new(CyclicImportXModule)]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[tokio::test]
    async fn test_application_create_terminates_on_cyclic_imports() {
        // A generous bound: if the dedup guard in `register_module` ever
        // regresses to unconditional recursion, this fails fast with a
        // clear "timed out" failure instead of hanging the whole test
        // binary. (A true regression could also manifest as a stack
        // overflow, which no timeout can catch -- but a loud process abort
        // is at least as diagnosable as a silent hang.)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Application::create::<CyclicImportXModule>(),
        )
        .await;

        assert!(
            result.is_ok(),
            "Application::create must terminate for a cyclic module import \
             graph, not hang"
        );
    }

    #[test]
    fn test_with_guard_registers_global_prefix() {
        let app =
            Application::new(Container::new(), Router::new()).with_guard(Arc::new(AllowGuard));
        assert_eq!(app.guards.len(), 1);
        assert!(app.guards[0].prefix.is_empty());
        assert!(app.guards[0].matches("/any/path"));
    }

    // ---- Application::create wires lifecycle hooks (Finding 1) ------------

    static LIFECYCLE_PROBE_INIT_CALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static LIFECYCLE_PROBE_BOOTSTRAP_CALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    /// Records the order hooks actually ran in, so the test below can assert
    /// the documented `OnModuleInit` -> `OnApplicationBootstrap` ordering
    /// contract, not just that both eventually fired.
    static LIFECYCLE_PROBE_ORDER: std::sync::Mutex<Vec<&'static str>> =
        std::sync::Mutex::new(Vec::new());

    #[derive(Clone, Default)]
    struct LifecycleProbeProvider;

    #[async_trait::async_trait]
    impl crate::lifecycle::OnModuleInit for LifecycleProbeProvider {
        async fn on_module_init(&self) -> crate::lifecycle::LifecycleResult {
            LIFECYCLE_PROBE_INIT_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
            LIFECYCLE_PROBE_ORDER.lock().unwrap().push("init");
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl crate::lifecycle::OnApplicationBootstrap for LifecycleProbeProvider {
        async fn on_application_bootstrap(&self) -> crate::lifecycle::LifecycleResult {
            LIFECYCLE_PROBE_BOOTSTRAP_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
            LIFECYCLE_PROBE_ORDER.lock().unwrap().push("bootstrap");
            Ok(())
        }
    }

    #[derive(Default)]
    struct LifecycleProbeModule;
    impl Module for LifecycleProbeModule {
        fn providers(&self) -> Vec<crate::ProviderRegistration> {
            // Exercises the real `provider_registration!` macro path (the
            // same one `armature_proc_macro`'s `#[module(...)]` codegen
            // mirrors), not a hand-rolled `ProviderRegistration`.
            vec![crate::provider_registration!(
                LifecycleProbeProvider,
                LifecycleProbeProvider
            )]
        }
        fn controllers(&self) -> Vec<crate::ControllerRegistration> {
            vec![]
        }
        fn imports(&self) -> Vec<Box<dyn Module>> {
            vec![]
        }
        fn exports(&self) -> Vec<std::any::TypeId> {
            vec![]
        }
    }

    #[tokio::test]
    async fn test_application_create_fires_on_module_init_and_bootstrap_hooks() {
        LIFECYCLE_PROBE_INIT_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
        LIFECYCLE_PROBE_BOOTSTRAP_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
        LIFECYCLE_PROBE_ORDER.lock().unwrap().clear();

        let app = Application::create::<LifecycleProbeModule>().await;

        assert!(
            LIFECYCLE_PROBE_INIT_CALLED.load(std::sync::atomic::Ordering::SeqCst),
            "OnModuleInit must fire automatically during Application::create"
        );
        assert!(
            LIFECYCLE_PROBE_BOOTSTRAP_CALLED.load(std::sync::atomic::Ordering::SeqCst),
            "OnApplicationBootstrap must fire automatically during Application::create"
        );
        assert!(app.container.has::<LifecycleProbeProvider>());

        // Documented ordering contract: OnModuleInit must run to completion
        // before OnApplicationBootstrap starts, not just "both eventually
        // fired in some order".
        let order = LIFECYCLE_PROBE_ORDER.lock().unwrap().clone();
        assert_eq!(
            order,
            vec!["init", "bootstrap"],
            "OnModuleInit must run before OnApplicationBootstrap"
        );
    }

    // ---- Application::use_global_filter wiring (Finding 3) ----------------

    struct AlwaysNotFoundGuard;
    #[async_trait::async_trait]
    impl Guard for AlwaysNotFoundGuard {
        async fn can_activate(&self, _ctx: &GuardContext) -> Result<bool, Error> {
            Err(Error::NotFound("boom".to_string()))
        }
    }

    struct RecordingCatchAllFilter {
        called: Arc<std::sync::atomic::AtomicBool>,
    }
    #[async_trait::async_trait]
    impl crate::exception_filter::ExceptionFilter for RecordingCatchAllFilter {
        async fn catch(
            &self,
            error: &Error,
            _ctx: &crate::exception_filter::ExceptionContext,
        ) -> Option<HttpResponse> {
            if let Error::NotFound(_) = error {
                self.called.store(true, std::sync::atomic::Ordering::SeqCst);
                Some(
                    HttpResponse::new(599)
                        .with_json(&serde_json::json!({"caught_by": "RecordingCatchAllFilter"}))
                        .unwrap(),
                )
            } else {
                None
            }
        }
    }

    #[test]
    fn test_use_global_filter_populates_serve_state() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let app = Application::new(Container::new(), Router::new()).use_global_filter(
            RecordingCatchAllFilter {
                called: called.clone(),
            },
        );

        assert!(app.filter_chain.is_some());
        let state = app.serve_state();
        assert!(
            state.filter_chain.is_some(),
            "serve_state must carry the configured filter chain through to ServeState"
        );
    }

    #[test]
    fn test_no_filter_configured_leaves_serve_state_filter_chain_none() {
        let app = Application::new(Container::new(), Router::new());
        let state = app.serve_state();
        assert!(
            state.filter_chain.is_none(),
            "without use_global_filter, ServeState must carry no filter chain, \
             preserving the original error_response fallback behavior"
        );
    }

    /// Live end-to-end test: binds a real TCP listener, serves exactly one
    /// connection through the real `handle_request` function (the same one
    /// `Application::listen`/`listen_on` use), sends a raw HTTP request that
    /// triggers a guard error, and asserts the response actually returned
    /// over the wire is the one produced by the registered global filter --
    /// not `error_response`'s default `to_client_response()` output.
    #[tokio::test]
    async fn test_use_global_filter_transforms_error_in_live_handle_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let filter_chain = Arc::new(
            crate::exception_filter::ExceptionFilterChain::new().add_filter(
                RecordingCatchAllFilter {
                    called: called.clone(),
                },
            ),
        );

        let state = ServeState {
            router: Arc::new(OptimizedRouter::from_router(&Router::new())),
            cors: None,
            guards: vec![ScopedGuard {
                prefix: String::new(),
                guard: Arc::new(AlwaysNotFoundGuard),
            }]
            .into(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            filter_chain: Some(filter_chain),
            peer: None,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<IncomingBody>| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /anything HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        // Bounded the same way as micro.rs's `send_raw_request` test helper:
        // relies on `Connection: close` above to unblock `read_to_end` once
        // the server replies, with a safety timeout in case that path ever
        // regresses and the connection is left open.
        let mut raw_response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut raw_response),
        )
        .await;
        let raw_response = String::from_utf8_lossy(&raw_response);

        assert!(
            raw_response.starts_with("HTTP/1.1 599"),
            "expected the filter's custom 599 status, got: {raw_response}"
        );
        assert!(
            raw_response.contains("RecordingCatchAllFilter"),
            "expected the filter's custom body, got: {raw_response}"
        );
        assert!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            "the registered filter's catch() must actually have run"
        );
    }

    /// Handler that unconditionally returns an error, used to exercise the
    /// routing/handler-error branch of `respond_to_error` (as opposed to the
    /// guard-rejection branch `AlwaysNotFoundGuard` exercises above) end to
    /// end through a real socket.
    async fn always_erroring_handler(_req: HttpRequest) -> Result<HttpResponse, Error> {
        Err(Error::NotFound("handler boom".to_string()))
    }

    /// Live end-to-end test, sibling of
    /// `test_use_global_filter_transforms_error_in_live_handle_request`
    /// above: no guard is involved at all here. A real route is registered
    /// whose handler itself returns `Err(...)`, so this exercises the
    /// *routing/handler-error* branch of `respond_to_error` (the guard test
    /// above only ever exercises the guard-rejection branch, since its guard
    /// rejects every request before routing is ever reached).
    #[tokio::test]
    async fn test_use_global_filter_transforms_handler_error_in_live_handle_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let filter_chain = Arc::new(
            crate::exception_filter::ExceptionFilterChain::new().add_filter(
                RecordingCatchAllFilter {
                    called: called.clone(),
                },
            ),
        );

        let mut router = Router::new();
        router.get("/broken", always_erroring_handler);

        let state = ServeState {
            router: Arc::new(OptimizedRouter::from_router(&router)),
            cors: None,
            // No guards at all: this response must come from the router's
            // handler-error path, not guard rejection.
            guards: Vec::new().into(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            filter_chain: Some(filter_chain),
            peer: None,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<IncomingBody>| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /broken HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut raw_response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut raw_response),
        )
        .await;
        let raw_response = String::from_utf8_lossy(&raw_response);

        assert!(
            raw_response.starts_with("HTTP/1.1 599"),
            "expected the filter's custom 599 status, got: {raw_response}"
        );
        assert!(
            raw_response.contains("RecordingCatchAllFilter"),
            "expected the filter's custom body, got: {raw_response}"
        );
        assert!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            "the registered filter's catch() must actually have run for a \
             real handler error, not just a guard rejection"
        );
    }

    // ---- respond_to_error isolates panicking/hanging filters (Finding 2) --

    struct PanickingFilter;
    #[async_trait::async_trait]
    impl crate::exception_filter::ExceptionFilter for PanickingFilter {
        async fn catch(
            &self,
            _error: &Error,
            _ctx: &crate::exception_filter::ExceptionContext,
        ) -> Option<HttpResponse> {
            panic!("PanickingFilter deliberately panics for test coverage");
        }
    }

    struct HangingFilter;
    #[async_trait::async_trait]
    impl crate::exception_filter::ExceptionFilter for HangingFilter {
        async fn catch(
            &self,
            _error: &Error,
            _ctx: &crate::exception_filter::ExceptionContext,
        ) -> Option<HttpResponse> {
            // Deliberately sleeps far longer than the timeout used in the
            // test below, so it never actually completes -- exercising the
            // "hanging filter" isolation path.
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            None
        }
    }

    #[tokio::test]
    async fn test_respond_to_error_falls_back_when_filter_panics() {
        let chain = Arc::new(
            crate::exception_filter::ExceptionFilterChain::new().add_filter(PanickingFilter),
        );
        let req = HttpRequest::new("GET", "/panics".to_string());
        let err = Error::Internal("boom".to_string());

        // Must fall back to exactly what `error_response(&err)` (i.e. no
        // filter at all) would have produced: a panicking filter is treated
        // as though it declined to handle the error, not as a crashed
        // request/connection.
        let response = respond_to_error_with_timeout(
            err,
            Some(req),
            Some(chain),
            std::time::Duration::from_secs(5),
        )
        .await;

        assert_eq!(response.status, 500);
        let body = String::from_utf8(response.into_body_bytes().to_vec()).unwrap();
        assert!(
            body.contains("Internal Server Error"),
            "a panicking filter must fall back to the redacted default 5xx \
             body, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_respond_to_error_falls_back_when_filter_hangs() {
        let chain = Arc::new(
            crate::exception_filter::ExceptionFilterChain::new().add_filter(HangingFilter),
        );
        let req = HttpRequest::new("GET", "/hangs".to_string());
        let err = Error::Internal("boom".to_string());

        // A short timeout (rather than the 5s production default) keeps this
        // test fast; what's under test is the fallback behavior on timeout,
        // not the exact default duration (that's `DEFAULT_EXCEPTION_FILTER_TIMEOUT`,
        // exercised indirectly via `respond_to_error`).
        let start = std::time::Instant::now();
        let response = respond_to_error_with_timeout(
            err,
            Some(req),
            Some(chain),
            std::time::Duration::from_millis(50),
        )
        .await;
        let elapsed = start.elapsed();

        assert_eq!(response.status, 500);
        let body = String::from_utf8(response.into_body_bytes().to_vec()).unwrap();
        assert!(
            body.contains("Internal Server Error"),
            "a hanging filter must fall back to the redacted default 5xx \
             body, got: {body}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "a hanging filter must not block the caller past the configured \
             timeout, took {elapsed:?}"
        );
    }
}
