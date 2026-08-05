//! Driving `armature-h1`'s thread-per-core server from `Application`.
//!
//! # The threading model, and why `listen_*` still looks async
//!
//! [`armature_h1::Server::serve`] blocks its caller and spawns its own worker
//! threads, each running a `current_thread` runtime with its own
//! `SO_REUSEPORT` listener. That is the point of it: a connection never
//! migrates cores, so per-core state — the `Date` cache, route caches — needs
//! no synchronization, and handler futures need not be `Send`.
//!
//! Blocking is exactly what must not happen on the multi-threaded runtime the
//! caller is already inside, so [`serve`] hands the whole server to
//! `spawn_blocking` and awaits the join handle. `Application::listen_on` keeps
//! its `async fn` signature and its behaviour of running until shutdown; the
//! thread it would have occupied is a blocking-pool thread instead of a
//! runtime worker.
//!
//! # What the service factory has to satisfy
//!
//! Note the bound asymmetry `armature-h1` requires: the *factory* is `Send +
//! Clone`, because it crosses into each worker thread at startup; the service
//! it produces is not, because it never does. [`ServeState`] is `Arc`-based and
//! therefore `Send`, so one is cloned per worker and the per-request path is
//! unchanged.

use crate::application::{ServeState, dispatch_via_h1};
use crate::h1_backend::h2_fallback::HyperH2;
use crate::logging::{error, info};
use crate::pipeline::PipelineConfig;
use armature_h1::{Config, Limits, Server, ServerHandle, TcpConfig};
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;

/// Signals shutdown when dropped.
///
/// The bridge between two ownership models. Tokio's is that dropping a future
/// releases everything it was doing; `armature-h1`'s is that the server owns OS
/// threads which no future's drop can reach. Held inside the serve future, this
/// makes the first imply the second — so a cancelled `listen_on` closes the
/// listener rather than leaving a bound socket and a runtime that hangs at drop
/// waiting on a blocking task nothing will ever end.
///
/// Dropping it after a clean exit signals a server that has already stopped,
/// which [`ServerHandle::shutdown`] treats as the no-op it is.
struct ShutdownOnDrop(ServerHandle);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

/// Build `armature-h1`'s server configuration from this application's.
///
/// Seven of `PipelineConfig`'s fields document themselves as "not currently
/// wired" because hyper's H1 builder has no knob for them. Two of those become
/// wired here, because `armature-h1` does:
///
/// - `keep_alive_timeout` → [`Limits::idle_timeout`], the deadline for the next
///   request to begin on an idle keep-alive connection.
/// - `max_header_size` → [`Limits::max_head_bytes`], a byte cap on the request
///   line plus header section, which is what the field always meant. Under
///   hyper it could only have been mapped onto `max_headers`, a *count*.
///
/// `max_concurrent`, `max_buffered_requests` and `max_requests_per_connection`
/// stay unwired, and for a reason that is now structural rather than
/// incidental: `armature-h1` reads no further than one complete head and does
/// not read again until that request's response is written, so there is never
/// more than one request in flight per connection to limit. `mode` and
/// `write_buffer_size` likewise have nothing to attach to.
///
/// It takes no body-size argument, deliberately: armature-core enforces that
/// cap itself, for the reason spelled out on `max_body_bytes` below.
///
/// Two fields go the other way, and `PipelineConfig` does not warn about them
/// because under hyper there was nothing to warn about: `pipeline_flush` and
/// `read_buffer_size` are wired to hyper's `pipeline_flush` and `max_buf_size`
/// and are silently dropped here. `armature-h1` writes each response as it is
/// produced and grows its read buffer from a fixed chunk size, so it exposes no
/// knob for either. With the `h1-backend` feature on — the default — both are
/// honoured only on connections hyper still serves, which is HTTP/2.
pub(crate) fn h1_config(
    addr: SocketAddr,
    pipeline: &PipelineConfig,
    workers: Option<usize>,
) -> Config {
    let limits = Limits {
        max_head_bytes: pipeline.max_header_size,
        // Unbounded here on purpose: armature-core is the sole enforcer of the
        // body cap on this path, and it has to be.
        //
        // `armature-h1` evaluates `max_body_bytes` in `framing::decide`, before
        // the service is ever called, and answers a bare status-line 413 — no
        // body, no CORS headers, connection closed. Configuring it with the
        // framework's own cap therefore made `dispatch_via_h1`'s check
        // unreachable for any declared `Content-Length`, and with it this
        // framework's `{"error":"Payload Too Large","status":413}` envelope,
        // which every other transport returns. A browser doing a CORS upload
        // over the limit saw an opaque CORS failure rather than a 413. Nor does
        // a headroom constant fix it: whatever the margin, a declaration past it
        // trips armature-h1 first.
        //
        // Nothing is unprotected as a result. `dispatch_via_h1` rejects an
        // over-limit declared length before a body byte is buffered, and reads
        // the body through `Body::collect(max_body_size)`, which fails mid-read
        // on an undeclared or chunked body that runs past the cap. Both answer
        // with the envelope.
        max_body_bytes: u64::MAX,
        idle_timeout: pipeline.keep_alive_timeout,
        ..Limits::default()
    };

    let mut cfg = Config::new(addr).limits(limits);
    cfg.tcp = TcpConfig {
        nodelay: pipeline.tcp_nodelay,
        ..TcpConfig::default()
    };
    if let Some(n) = workers {
        cfg = cfg.workers(n);
    }
    cfg
}

/// Serve `cfg` with `state` until shutdown, without blocking the caller's
/// runtime.
///
/// `h2` is the HTTP/2 builder for connections `armature-h1` classifies as
/// HTTP/2 — reached via ALPN when TLS is configured on `cfg`, or via the h2c
/// preface when `cfg.detect_h2c` is set. Pass `None` to close them instead,
/// which is what a plain HTTP/1 listener wants.
///
/// Dropping this future stops the server. That is worth stating because it is
/// not what cancelling a future normally achieves here: `armature-h1`'s workers
/// are OS threads it owns, not tasks, and the future being dropped is only
/// awaiting the blocking-pool thread they were launched from — cancelling it
/// reaches none of them. So the future carries a guard that signals shutdown on
/// drop, which is what makes the idiom every caller already writes
/// (`select! { _ = app.listen_on(addr) => {}, _ = ctrl_c() => {} }`) actually
/// close the listener instead of leaving it bound and the workers serving.
pub(crate) async fn serve(
    cfg: Config,
    state: ServeState,
    h2: Option<hyper::server::conn::http2::Builder<TokioExecutor>>,
) -> Result<(), crate::Error> {
    serve_bound(cfg, state, h2, |_, _| {}).await
}

/// [`serve`], reporting the bound address and a shutdown handle before it
/// starts serving.
///
/// `on_bound` runs once, after the listener exists and before the first accept.
/// Both of its arguments are unobtainable at any later moment: `Server::bind`
/// resolves `:0` to a real port here, and this function does not return until
/// the server stops — so without the [`ServerHandle`] there is nothing a caller
/// could ever stop it *deliberately* with. Dropping this future stops it too,
/// via [`ShutdownOnDrop`]; see [`serve`] for why that needs arranging.
pub(crate) async fn serve_bound(
    cfg: Config,
    state: ServeState,
    h2: Option<hyper::server::conn::http2::Builder<TokioExecutor>>,
    on_bound: impl FnOnce(SocketAddr, ServerHandle),
) -> Result<(), crate::Error> {
    let server = Server::bind(cfg).map_err(crate::Error::from)?;
    let addr = server.local_addr();
    info!(address = %addr, "HTTP server listening (armature-h1 backend)");
    on_bound(addr, server.handle());

    // Held across the await below, which is the whole point: it is the drop of
    // this local that turns "the caller stopped caring about this future" into
    // "the workers stop accepting". Taken before `server` moves into the
    // closure, and safe even in the window before serving begins.
    let _stop = ShutdownOnDrop(server.handle());

    // The whole server, threads and all, moves onto a blocking-pool thread:
    // `Server::serve` blocks until shutdown, and blocking a runtime worker
    // would stall every other task the caller has running.
    let joined = tokio::task::spawn_blocking(move || match h2 {
        Some(builder) => server.serve_with_fallback(
            {
                let state = state.clone();
                move || {
                    let state = state.clone();
                    move |req| dispatch_via_h1(req, state.clone())
                }
            },
            move || HyperH2::new(state.clone(), builder.clone()),
        ),
        None => server.serve({
            let state = state.clone();
            move || {
                let state = state.clone();
                move |req| dispatch_via_h1(req, state.clone())
            }
        }),
    })
    .await;

    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(crate::Error::from(e)),
        Err(join) => {
            error!(error = %join, "the armature-h1 server thread did not exit cleanly");
            Err(crate::Error::Internal(format!(
                "armature-h1 server thread panicked: {join}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn addr() -> SocketAddr {
        "127.0.0.1:0".parse().expect("addr")
    }

    #[test]
    fn the_two_previously_unwired_pipeline_fields_reach_the_limits() {
        let pipeline = PipelineConfig {
            keep_alive_timeout: Duration::from_secs(7),
            max_header_size: 4096,
            tcp_nodelay: false,
            ..PipelineConfig::default()
        };
        let cfg = h1_config(addr(), &pipeline, Some(2));

        assert_eq!(
            cfg.limits.idle_timeout,
            Duration::from_secs(7),
            "keep_alive_timeout has an idle-timeout knob under armature-h1"
        );
        assert_eq!(
            cfg.limits.max_head_bytes, 4096,
            "max_header_size is a byte cap and armature-h1 takes one"
        );
        assert_eq!(
            cfg.limits.max_body_bytes,
            u64::MAX,
            "armature-core enforces the body cap on this path, so armature-h1 \
             must not reject first with its bare status line and cost the \
             client the framework's JSON envelope"
        );
        assert!(!cfg.tcp.nodelay);
        assert_eq!(cfg.workers, 2);
    }

    #[test]
    fn an_over_ceiling_header_count_is_clamped_by_config() {
        // `Config::limits` clamps `max_headers` to the parser's scratch-array
        // ceiling. Going through it (rather than setting `cfg.limits`
        // directly) is what makes that clamp apply, so this pins that
        // `h1_config` uses the builder.
        let cfg = h1_config(addr(), &PipelineConfig::default(), None);
        assert!(cfg.limits.max_headers <= armature_h1::limits::MAX_HEADERS_CEILING);
    }
}
