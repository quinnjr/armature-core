//! End-to-end tests for the `armature-h1` serve path.
//!
//! These drive a real `armature_h1::Server` on a real socket with a real
//! `ServeState` — routes, guards, CORS, body limits — and assert on raw
//! response bytes. Every other test in this module tree exercises one of the
//! bridge's halves in isolation, which cannot catch a wiring mistake between
//! them: a `ServeState` never reaching the workers, a body never being read, a
//! response never being framed.
//!
//! They live in-crate rather than under `tests/` because
//! [`serve_bound`](super::serve::serve_bound) and [`ServeState`] are
//! crate-private, and the point is to test the actual serve path rather than a
//! reconstruction of it.

use crate::application::ServeState;
use crate::h1_backend::serve::{h1_config, serve_bound};
use crate::http::{HttpRequest, HttpResponse};
use crate::pipeline::PipelineConfig;
use crate::route_cache::OptimizedRouter;
use crate::routing::{Route, Router};
use crate::traits::HttpMethod;
use crate::{Error, application::DEFAULT_MAX_BODY_SIZE};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Echoes back what the serve path produced, so one request can assert on
/// several things at once: the method, the target with its query intact, a
/// header value, the peer address, and the body.
async fn echo(req: HttpRequest) -> Result<HttpResponse, Error> {
    let body = format!(
        "method={} path={} trace={} peer={} body={}",
        req.method,
        req.path,
        req.headers.get("x-trace-id").unwrap_or("-"),
        req.peer.map_or("-".to_string(), |p| p.to_string()),
        String::from_utf8_lossy(&req.body),
    );
    Ok(HttpResponse::ok().with_body(body.into_bytes()))
}

fn test_state(max_body_size: usize) -> ServeState {
    let mut router = Router::new();
    router.add_route(Route::new(HttpMethod::GET, "/echo", echo));
    router.add_route(Route::new(HttpMethod::POST, "/echo", echo));
    ServeState::for_test(
        Arc::new(OptimizedRouter::from_router(&router)),
        max_body_size,
    )
}

/// Start a server on an ephemeral port, run `body` against it, then shut down.
///
/// The address comes back through `serve_bound`'s callback because
/// `armature-h1` resolves `:0` at bind time and then never returns until
/// shutdown — so there is no later moment to ask.
async fn with_server<F, Fut, T>(state: ServeState, body: F) -> T
where
    F: FnOnce(std::net::SocketAddr) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send,
    T: Send + 'static,
{
    let cfg = h1_config(
        "127.0.0.1:0".parse().expect("addr"),
        &PipelineConfig::default(),
        // One worker: the test asserts on responses, not on load balancing, and
        // a worker per core would open N listeners for no added coverage.
        Some(1),
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = serve_bound(cfg, state, None, move |addr, handle| {
            let _ = tx.take().expect("bound once").send((addr, handle));
        })
        .await;
    });

    let (addr, handle) = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("server bound within 5s")
        .expect("bind address");
    let out = body(addr).await;

    // Shut down rather than abort. The workers are OS threads owned by
    // `armature-h1`, so aborting the task awaiting them leaves them running —
    // and the runtime's own drop then blocks forever waiting on the
    // `spawn_blocking` that holds them. `shutdown` is the only thing that ends
    // them, which is why `serve_bound` hands the handle out at all.
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    out
}

/// Write `request` and read until the peer closes, bounded so a hang fails
/// rather than stalls the suite.
async fn roundtrip(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    stream.write_all(request).await.expect("write request");

    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn a_routed_request_is_served_end_to_end() {
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"GET /echo?q=1 HTTP/1.1\r\nHost: a\r\nX-Trace-Id: abc\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "expected a 200: {response:?}"
    );
    assert!(
        response.contains("method=GET"),
        "the method must survive the bridge: {response:?}"
    );
    assert!(
        response.contains("path=/echo?q=1"),
        "the target must arrive whole, query included: {response:?}"
    );
    assert!(
        response.contains("trace=abc"),
        "a custom header must reach the handler: {response:?}"
    );
    assert!(
        response.contains("peer=127.0.0.1:"),
        "the peer address must be stamped onto the request, or every \
         rate-limit and audit decision keyed on it silently loses the client: \
         {response:?}"
    );
}

#[tokio::test]
async fn a_request_body_reaches_the_handler() {
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
    })
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    assert!(
        response.contains("body=hello"),
        "the body must be read and handed over: {response:?}"
    );
}

#[tokio::test]
async fn a_chunked_body_reaches_the_handler() {
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    assert!(
        response.contains("body=hello"),
        "a chunked body must be decoded, not handed over as frames: {response:?}"
    );
}

#[tokio::test]
async fn keep_alive_serves_a_second_request_on_one_connection() {
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"GET /echo?first HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .expect("write first");

        // Read only the first response, then send the second on the same
        // connection: a read_to_end here would wait for a close that keep-alive
        // is specifically not going to do.
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("first response within 5s")
            .expect("read");
        let first = String::from_utf8_lossy(&buf[..n]).into_owned();

        stream
            .write_all(b"GET /echo?second HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            .await
            .expect("write second");
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
        (first, String::from_utf8_lossy(&rest).into_owned())
    })
    .await;

    let (first, second) = response;
    assert!(
        first.contains("path=/echo?first"),
        "first response: {first:?}"
    );
    assert!(
        second.contains("path=/echo?second"),
        "the connection must be reused rather than closed after one request: \
         {second:?}"
    );
}

#[tokio::test]
async fn an_unrouted_path_is_a_404_not_a_dropped_connection() {
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"GET /nope HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "an unrouted path must produce this framework's 404, which means the \
         router was actually consulted: {response:?}"
    );
}

#[tokio::test]
async fn a_declared_content_length_over_the_limit_is_refused_before_the_body() {
    // A 16-byte cap with a 100-byte declaration: the rejection must come from
    // the declared length, without the body being read at all.
    let response = with_server(test_state(16), |addr| async move {
        roundtrip(
            addr,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 413"),
        "an over-limit declaration must be refused with 413: {response:?}"
    );
    // The status line alone does not distinguish the producers: `armature-h1`
    // answers a bare 413 from `framing::decide` before the service runs, and
    // armature-core answers one with this envelope. `h1_config` gives its cap a
    // byte of headroom precisely so the framework's answer wins, and asserting
    // the body is what pins that — otherwise the two are indistinguishable and
    // a regression is invisible.
    assert!(
        response.contains("\"status\":413"),
        "the framework's own 413 envelope must reach the client, not \
         armature-h1's bare status line: {response:?}"
    );
}

#[tokio::test]
async fn an_undeclared_over_limit_body_is_refused_while_being_read() {
    // Chunked, so there is no `Content-Length` to check up front: the cap has
    // to be enforced during the read or not at all.
    let mut request =
        b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            .to_vec();
    request.extend_from_slice(format!("{:x}\r\n", 100).as_bytes());
    request.extend_from_slice(&[b'x'; 100]);
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    let response = with_server(test_state(16), move |addr| async move {
        roundtrip(addr, &request).await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 413"),
        "a chunked body over the cap must still be refused: {response:?}"
    );
}

#[tokio::test]
async fn a_smuggling_shaped_request_is_rejected_rather_than_served() {
    // Both `Content-Length` and `Transfer-Encoding` — the canonical request
    // smuggling setup, which hyper's H1 stack also rejects. Asserting it here
    // pins that this framework inherits `armature-h1`'s framing decisions
    // rather than routing the request anyway.
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\
              Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 400"),
        "Content-Length together with Transfer-Encoding must be refused: \
         {response:?}"
    );
}

// ---------------------------------------------------------------------------
// Guards, CORS, routing semantics, and response framing.
//
// The module doc above claims this suite drives "routes, guards, CORS, body
// limits". Until `ServeState` grew test builders it could only ever drive the
// first and last of those, so everything below was asserted nowhere on the
// serve path — including two things AGENTS.md names explicitly: that guards
// fail closed, and that routing semantics (param extraction, unknown-method →
// 404) are preserved exactly.
// ---------------------------------------------------------------------------

use crate::guard::{Guard, GuardContext};

/// Reports the path parameter it was routed with, so extraction is observable
/// from the wire rather than inferred.
async fn echo_param(req: HttpRequest) -> Result<HttpResponse, Error> {
    use crate::http::RouteParamsExt;
    let id = req.path_params.get_str("id").unwrap_or("-").to_string();
    Ok(HttpResponse::ok().with_body(format!("id={id}").into_bytes()))
}

/// A 200 with no body at all, for the framing assertions.
async fn empty_ok(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::ok())
}

/// A 204, which must not carry a `Content-Length` at all.
async fn no_content(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::new(204))
}

fn routed_state() -> ServeState {
    let mut router = Router::new();
    router.add_route(Route::new(HttpMethod::GET, "/echo", echo));
    router.add_route(Route::new(HttpMethod::POST, "/echo", echo));
    router.add_route(Route::new(HttpMethod::GET, "/u/:id", echo_param));
    router.add_route(Route::new(HttpMethod::GET, "/empty", empty_ok));
    router.add_route(Route::new(HttpMethod::GET, "/nothing", no_content));
    router.add_route(Route::new(HttpMethod::HEAD, "/head", echo));
    ServeState::for_test(
        Arc::new(OptimizedRouter::from_router(&router)),
        DEFAULT_MAX_BODY_SIZE,
    )
}

/// Refuses everything, to prove a guard's verdict reaches the wire.
struct DenyAll;

#[async_trait::async_trait]
impl Guard for DenyAll {
    async fn can_activate(&self, _ctx: &GuardContext) -> Result<bool, Error> {
        Ok(false)
    }
}

/// Fails rather than refusing — a different path through `dispatch_request`,
/// which maps the error rather than emitting the canned 403.
struct ExplodingGuard;

#[async_trait::async_trait]
impl Guard for ExplodingGuard {
    async fn can_activate(&self, _ctx: &GuardContext) -> Result<bool, Error> {
        Err(Error::Unauthorized("no credentials".to_string()))
    }
}

/// How many times `name` appears as a header field in a raw response.
///
/// Counted rather than merely detected: the response path adds the CORS origin
/// in `to_h1_response` while the preflight path builds its own complete set, so
/// the failure worth guarding against is two of them, not zero.
fn header_count(response: &str, name: &str) -> usize {
    let head = response.split("\r\n\r\n").next().unwrap_or(response);
    head.lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        })
        .count()
}

#[tokio::test]
async fn a_cors_configured_response_carries_exactly_one_allow_origin() {
    let state = routed_state().with_cors_for_test(crate::CorsConfig::new("https://example.test"));

    let response = with_server(state, |addr| async move {
        roundtrip(
            addr,
            b"GET /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    assert_eq!(
        header_count(&response, "access-control-allow-origin"),
        1,
        "exactly one origin header — zero means CORS never reached the serve \
         path, two means both the response path and something upstream added \
         it: {response:?}"
    );
}

#[tokio::test]
async fn an_options_preflight_is_answered_before_routing() {
    let state = routed_state().with_cors_for_test(crate::CorsConfig::new("https://example.test"));

    let response = with_server(state, |addr| async move {
        // A path with no registered OPTIONS route: a preflight is sent for a
        // path the browser is about to call with some other method, so it must
        // be answered without consulting the router.
        roundtrip(
            addr,
            b"OPTIONS /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 204"),
        "a preflight is answered with 204, not routed: {response:?}"
    );
    assert_eq!(
        header_count(&response, "access-control-allow-origin"),
        1,
        "the preflight builds its own complete header set, so adding the \
         per-response origin on top would duplicate it: {response:?}"
    );
    assert!(
        response
            .to_ascii_lowercase()
            .contains("access-control-allow-methods"),
        "the preflight set must be complete: {response:?}"
    );
}

#[tokio::test]
async fn a_denying_guard_produces_the_frameworks_403() {
    let state = routed_state().with_guard_for_test(Arc::new(DenyAll));

    let response = with_server(state, |addr| async move {
        roundtrip(
            addr,
            b"GET /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "guards fail closed, so a refusal must reach the wire as a 403 rather \
         than the handler running: {response:?}"
    );
    assert!(
        response.contains("\"status\":403"),
        "the framework's own 403 envelope, not a bare status line: {response:?}"
    );
}

#[tokio::test]
async fn a_guard_returning_an_error_maps_to_its_status() {
    let state = routed_state().with_guard_for_test(Arc::new(ExplodingGuard));

    let response = with_server(state, |addr| async move {
        roundtrip(
            addr,
            b"GET /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 401"),
        "a guard's error maps through the error path, which is distinct from \
         the canned 403 a refusal produces: {response:?}"
    );
}

#[tokio::test]
async fn a_path_parameter_is_extracted_and_reaches_the_handler() {
    let response = with_server(routed_state(), |addr| async move {
        roundtrip(
            addr,
            b"GET /u/42 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    assert!(
        response.ends_with("id=42"),
        "param extraction is a routing semantic that must survive the backend \
         swap: {response:?}"
    );
}

#[tokio::test]
async fn a_known_path_with_an_unregistered_method_is_a_404() {
    let response = with_server(routed_state(), |addr| async move {
        // `/u/:id` exists for GET only. AGENTS.md names unknown-method → 404
        // as a routing semantic to preserve exactly, and it is distinct from
        // the unrouted-path case: the path matches, the method does not.
        roundtrip(
            addr,
            b"DELETE /u/42 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "a known path with an unregistered method is a 404, not a 405 and not \
         a match: {response:?}"
    );
}

#[tokio::test]
async fn a_head_response_reports_a_length_but_sends_no_body_bytes() {
    let response = with_server(routed_state(), |addr| async move {
        roundtrip(
            addr,
            b"HEAD /head HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    let (head, body) = response
        .split_once("\r\n\r\n")
        .expect("a complete response head");
    assert!(
        head.to_ascii_lowercase().contains("content-length:"),
        "HEAD reports the length a GET would have sent, or a client cannot use \
         it to size a fetch: {head:?}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("content-length: 0"),
        "the reported length is the body a GET would produce, not zero: {head:?}"
    );
    assert!(
        body.is_empty(),
        "…but none of those bytes go on the wire: {body:?}"
    );
}

/// Not a swap regression — the router is shared by both backends — but worth
/// pinning, because the framing test above would otherwise look like proof
/// that `HEAD` works generally when it only works for an explicitly registered
/// route. RFC 9110 §9.3.2 makes `HEAD` identical to `GET` bar the body, and
/// this framework does not derive one from the other.
#[tokio::test]
async fn head_is_not_derived_from_a_registered_get_route() {
    let response = with_server(routed_state(), |addr| async move {
        roundtrip(
            addr,
            b"HEAD /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 404"),
        "a GET-only route does not answer HEAD; if this ever starts passing as \
         a 200, the router gained auto-derivation and this test should become \
         the assertion that it did: {response:?}"
    );
}

#[tokio::test]
async fn an_empty_200_is_framed_with_content_length_zero_but_a_204_is_not() {
    let empty_200 = with_server(routed_state(), |addr| async move {
        roundtrip(
            addr,
            b"GET /empty HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(empty_200.starts_with("HTTP/1.1 200 OK"), "{empty_200:?}");
    assert!(
        empty_200.to_ascii_lowercase().contains("content-length: 0"),
        "a 200 with an empty body still needs an explicit zero length, or the \
         client cannot tell the body ended: {empty_200:?}"
    );

    let no_content = with_server(routed_state(), |addr| async move {
        roundtrip(
            addr,
            b"GET /nothing HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(no_content.starts_with("HTTP/1.1 204"), "{no_content:?}");
    assert!(
        !no_content.to_ascii_lowercase().contains("content-length"),
        "a 204 must carry no body framing at all — this is the distinction a \
         type-level assertion on ResponseBody cannot make, because it never \
         reaches the writer: {no_content:?}"
    );
}
