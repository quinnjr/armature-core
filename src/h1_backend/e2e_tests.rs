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
    // Both layers are checked rather than discarded. A server that will not
    // stop is not a slow test: its worker threads are still held by the
    // `spawn_blocking` inside `serve_bound`, so the runtime's own drop blocks
    // on them and the suite hangs with no test named as the one that failed.
    // Failing here names it.
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect(
            "the server did not stop within 10s of being told to; its worker \
             threads are still held, and the runtime will block at drop",
        )
        .expect("the task running the server panicked");
    out
}

/// Write `request`, read until the peer closes, and report whether it actually
/// did — bounded so a hang fails rather than stalls the suite.
///
/// The second half of the tuple is the point. Reading to the end of a stream
/// the server never closes returns whatever arrived before the deadline, which
/// is indistinguishable from a clean close by inspecting the bytes: a server
/// that writes a complete response head and then leaks the connection produces
/// exactly the same `String` as one that writes it and hangs up. Closing on
/// every framing rejection is the strictness this backend was chosen for, so
/// whether the close happened has to be observable.
async fn roundtrip_closed(addr: std::net::SocketAddr, request: &[u8]) -> (String, bool) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    stream.write_all(request).await.expect("write request");

    let mut out = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .is_ok_and(|read| read.is_ok());
    (String::from_utf8_lossy(&out).into_owned(), closed)
}

/// [`roundtrip_closed`] for the requests that ask the connection to close.
///
/// Every call site below sends `Connection: close` or is a framing rejection,
/// so the close is part of the contract in all of them and asserting it here
/// gives each one the check without restating it.
async fn roundtrip(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let (response, closed) = roundtrip_closed(addr, request).await;
    assert!(
        closed,
        "the server answered but never closed the connection, so the response \
         below is only what arrived before the read deadline — a leaked \
         connection reads exactly like a served one otherwise: {response:?}"
    );
    response
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
    let (response, closed) = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip_closed(
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
    // The half this test is named for. A status line proves the router ran; it
    // says nothing about the connection, and "not a dropped connection" is
    // equally violated by one that is never let go of.
    assert!(
        closed,
        "the 404 arrived but the connection stayed open past the read \
         deadline, which is the leak this test is named for: {response:?}"
    );
}

#[tokio::test]
async fn a_declared_content_length_over_the_limit_is_refused_before_the_body() {
    // A 16-byte cap with a 100-byte declaration: the rejection must come from
    // the declared length, without the body being read at all.
    let (response, closed) = with_server(test_state(16), |addr| async move {
        roundtrip_closed(
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
    // 100 bytes were declared and none sent. Anything that kept this
    // connection would be waiting for a body it just refused, holding a socket
    // per probe — which is the cheapest denial of service there is.
    assert!(
        closed,
        "a refusal before the body must close the connection rather than wait \
         for the body it declined to read: {response:?}"
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

    let (response, closed) = with_server(test_state(16), move |addr| async move {
        roundtrip_closed(addr, &request).await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 413"),
        "a chunked body over the cap must still be refused: {response:?}"
    );
    // The same reason the declared-length test above asserts the body: on this
    // path `dispatch_via_h1` picks between `payload_too_large_response()` and a
    // bare `HttpResponse::new(status)` on the read error's status, and both
    // spell the status line "413". Asserting only the line passes either way,
    // so the branch that costs the client the envelope every other transport
    // returns would be invisible.
    assert!(
        response.contains("\"status\":413"),
        "a mid-read refusal must produce the same envelope the declared-length \
         refusal does, not a bare status line: {response:?}"
    );
    assert!(
        closed,
        "the read was abandoned mid-body, so the connection is out of sync \
         with the sender and must not be reused: {response:?}"
    );
}

/// Companion to the test above. `dispatch_via_h1` answers *every* body-read
/// failure from one match on `err.status()`, and only the 413 arm is meant to
/// wear the payload envelope. Without this, widening that arm — or defaulting
/// it — would dress a malformed-framing 400 as a size refusal, and the size
/// test above would keep passing.
#[tokio::test]
async fn a_body_error_that_is_not_a_413_is_not_dressed_as_one() {
    // `zz` is not a hexadecimal chunk size, so the read fails on framing rather
    // than on length — well under the 16-byte cap, so size cannot be the cause.
    let mut request =
        b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            .to_vec();
    request.extend_from_slice(b"zz\r\nhello\r\n0\r\n\r\n");

    let (response, closed) = with_server(test_state(16), move |addr| async move {
        roundtrip_closed(addr, &request).await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 400"),
        "an unparseable chunk size is a framing error, so it keeps the status \
         armature-h1 assigned it rather than being mapped to something else: \
         {response:?}"
    );
    assert!(
        !response.contains("Payload Too Large"),
        "a body this far under the cap was not refused for its size, and \
         telling the client it was sends them to shrink a request that was \
         never too big: {response:?}"
    );
    assert!(
        closed,
        "the framing is unrecoverable, so nothing further on this connection \
         can be trusted to be a request boundary: {response:?}"
    );
}

#[tokio::test]
async fn a_smuggling_shaped_request_is_rejected_rather_than_served() {
    // Both `Content-Length` and `Transfer-Encoding` — the canonical request
    // smuggling setup, which hyper's H1 stack also rejects. Asserting it here
    // pins that this framework inherits `armature-h1`'s framing decisions
    // rather than routing the request anyway.
    let (response, closed) = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip_closed(
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
    // Refusing and then continuing to read is the smuggle: the two framings
    // disagree about where this request ends, so whatever arrives next would be
    // interpreted as a request boundary by this server and as body bytes by
    // whatever sits in front of it. Closing is what makes the refusal mean
    // something.
    assert!(
        closed,
        "a request whose two framings disagree must take the connection with \
         it; keeping it open is the smuggle the 400 was supposed to prevent: \
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
    router.add_route(Route::new(HttpMethod::OPTIONS, "/echo", echo));
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
            b"OPTIONS /echo HTTP/1.1\r\nHost: a\r\nOrigin: https://example.test\r\n\
              Access-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
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

/// `OPTIONS` has a meaning of its own (RFC 9110 §9.3.7 — ask what a resource
/// supports), and a CORS preflight is the narrower thing the Fetch standard
/// defines: `OPTIONS` carrying `Access-Control-Request-Method`. Intercepting
/// both made `Router::options` unreachable the moment CORS was configured —
/// a routing decision taken by a header the caller sets.
#[tokio::test]
async fn a_plain_options_request_routes_even_with_cors_configured() {
    let state = routed_state().with_cors_for_test(crate::CorsConfig::new("https://example.test"));

    let response = with_server(state, |addr| async move {
        // No `Access-Control-Request-Method`: not a preflight, so the
        // registered OPTIONS handler must answer it.
        roundtrip(
            addr,
            b"OPTIONS /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "a non-preflight OPTIONS must reach its route, not the canned 204: \
         {response:?}"
    );
    assert!(
        response.contains("method=OPTIONS"),
        "the handler must actually have run: {response:?}"
    );
}

/// The companion to the above: an `Origin` header alone does not make a
/// preflight either. A browser sends `Origin` on plenty of requests that are
/// not preflights, so gating on it would shadow the route just as broadly.
#[tokio::test]
async fn an_options_request_with_only_an_origin_still_routes() {
    let state = routed_state().with_cors_for_test(crate::CorsConfig::new("https://example.test"));

    let response = with_server(state, |addr| async move {
        roundtrip(
            addr,
            b"OPTIONS /echo HTTP/1.1\r\nHost: a\r\nOrigin: https://example.test\r\n\
              Connection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "only `Access-Control-Request-Method` marks a preflight: {response:?}"
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

// ---------------------------------------------------------------------------
// Connection behaviours the backend swap changed.
//
// Pipelining and `Expect: 100-continue` are the two places where `armature-h1`
// does something hyper did not, on the wire, for requests a client is entitled
// to send. Neither was asserted anywhere, so both were free to change again
// without a test noticing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_pipelined_requests_are_answered_in_request_order() {
    // Both requests go out in one write, so they are on the wire together
    // rather than one-then-the-other. `keep_alive_serves_a_second_request_on_one_connection`
    // reads the first response before sending the second and therefore never
    // reaches this case at all.
    //
    // `armature-h1` reads no further than one head and does not read again
    // until that response is written, so it serialises where hyper pipelined.
    // Serialising is fine; answering out of order would not be, because a
    // pipelining client matches responses to requests by position and nothing
    // on the wire would tell it the pairing had shifted.
    let response = with_server(routed_state(), |addr| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                b"GET /echo?first HTTP/1.1\r\nHost: a\r\n\r\n\
                  GET /echo?second HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write both requests");

        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("both responses within 5s")
            .expect("read");
        String::from_utf8_lossy(&out).into_owned()
    })
    .await;

    let first = response
        .find("path=/echo?first")
        .unwrap_or_else(|| panic!("the first pipelined request was never answered: {response:?}"));
    let second = response
        .find("path=/echo?second")
        .unwrap_or_else(|| panic!("the second pipelined request was never answered: {response:?}"));
    assert!(
        first < second,
        "pipelined responses must come back in request order, because that \
         position is the only thing pairing them with their requests: \
         {response:?}"
    );
}

#[tokio::test]
async fn an_expect_continue_request_receives_the_interim_response_and_is_served() {
    // Sent with the body rather than waiting for the go-ahead, which is what a
    // client is allowed to do and what makes this observable in one exchange.
    let response = with_server(test_state(DEFAULT_MAX_BODY_SIZE), |addr| async move {
        roundtrip(
            addr,
            b"POST /echo HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\
              Content-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
    })
    .await;

    // Pinned as observed, not as designed. `armature-h1` emits the interim
    // response lazily — the body reader writes it on the first read rather
    // than the connection loop writing it when the head is parsed, as hyper
    // did. Both orderings put `100 Continue` first on the wire here because
    // this request's body *is* read; the difference only shows for a request
    // whose body is never read, where the lazy stack sends no interim response
    // at all. If this assertion ever fails, the mechanism changed and that is
    // a decision to make deliberately rather than a test to relax.
    assert!(
        response.starts_with("HTTP/1.1 100 Continue"),
        "a client that honours 100-continue waits for this before sending its \
         body, so not sending it stalls the request until a timeout: \
         {response:?}"
    );
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "the interim response is not the answer — the real one must follow it \
         on the same connection: {response:?}"
    );
    assert!(
        response.contains("body=hello"),
        "the body must still reach the handler after the interim response: \
         {response:?}"
    );
}

// ---------------------------------------------------------------------------
// The exception-filter chain on this path.
//
// `dispatch_via_h1` → `dispatch_request` → `respond_to_error` → `to_h1_response`
// is a final hop the hyper adapter does not take, and the only live-socket
// filter tests in this crate drive the hyper adapter. A filter response losing
// its status or its body in that last conversion is invisible to all of them.
// ---------------------------------------------------------------------------

use crate::exception_filter::{ExceptionContext, ExceptionFilter, ExceptionFilterChain};
use std::sync::atomic::{AtomicBool, Ordering};

/// Claims every error, answering with a status and body nothing else in this
/// suite produces — so a response carrying them can only have come from here.
struct RecordingFilter {
    ran: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ExceptionFilter for RecordingFilter {
    async fn catch(&self, _error: &Error, _ctx: &ExceptionContext) -> Option<HttpResponse> {
        self.ran.store(true, Ordering::SeqCst);
        Some(HttpResponse::new(599).with_body(b"caught-by-the-e2e-filter".to_vec()))
    }
}

/// Always fails, so the filter chain has something to catch.
async fn always_fails(_req: HttpRequest) -> Result<HttpResponse, Error> {
    Err(Error::Internal("handler boom".to_string()))
}

#[tokio::test]
async fn a_global_filters_response_reaches_the_wire_intact_over_h1() {
    let ran = Arc::new(AtomicBool::new(false));
    let mut router = Router::new();
    router.add_route(Route::new(HttpMethod::GET, "/broken", always_fails));
    let state = ServeState::for_test(
        Arc::new(OptimizedRouter::from_router(&router)),
        DEFAULT_MAX_BODY_SIZE,
    )
    .with_filter_chain_for_test(ExceptionFilterChain::new().add_filter(RecordingFilter {
        ran: Arc::clone(&ran),
    }));

    let response = with_server(state, |addr| async move {
        roundtrip(
            addr,
            b"GET /broken HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        )
        .await
    })
    .await;

    assert!(
        response.starts_with("HTTP/1.1 599"),
        "the filter's status must survive the h1 response conversion; a 500 \
         here means the chain was consulted and its answer then discarded, or \
         never consulted at all: {response:?}"
    );
    assert!(
        response.contains("caught-by-the-e2e-filter"),
        "the filter's body must survive too — a filter that keeps its status \
         and loses its body has still lost everything it was written to say, \
         and the status alone cannot tell the two apart: {response:?}"
    );
    assert!(
        ran.load(Ordering::SeqCst),
        "the filter never ran, so whatever produced the response above did so \
         by coincidence: {response:?}"
    );
    // The 5xx redaction in `error_response` would have replaced "handler boom"
    // with a generic body. Its absence is what proves the fallback did not run.
    assert!(
        !response.contains("Internal Server Error"),
        "a registered filter's answer replaces the default mapping rather than \
         being merged with it: {response:?}"
    );
}

// ---------------------------------------------------------------------------
// Cancelling the serve future.
//
// `ShutdownOnDrop` is what makes the idiom every caller writes —
// `select! { _ = app.listen_on(addr) => {}, _ = ctrl_c() => {} }` — actually
// close the listener. Every other test here shuts the server down through the
// handle, so the drop path is never taken: deleting the guard breaks graceful
// shutdown for every user of that idiom and the rest of this suite still
// passes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dropping_the_serve_future_stops_the_listener() {
    let cfg = h1_config(
        "127.0.0.1:0".parse().expect("addr"),
        &PipelineConfig::default(),
        Some(1),
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    // Deliberately not spawned, which is the one place this test cannot use
    // `with_server`. Dropping a `JoinHandle` detaches its task rather than
    // dropping its future, so the guard under test would never run; the future
    // has to be owned here for `drop` to reach it. Nothing is leaked by that:
    // the guard is precisely what turns this drop into a shutdown, so if the
    // test passes the threads are gone, and if it fails the assertion below
    // names why rather than the runtime hanging anonymously at drop.
    let mut server = Box::pin(serve_bound(
        cfg,
        test_state(DEFAULT_MAX_BODY_SIZE),
        None,
        move |addr, _handle| {
            let _ = tx.send(addr);
        },
    ));

    // Polled only far enough to bind and hand the address back — `serve_bound`
    // moves the server onto a blocking thread and returns `Pending`, so it
    // keeps serving without being polled again.
    let addr = tokio::select! {
        result = &mut server => panic!("the server stopped before it bound: {result:?}"),
        addr = tokio::time::timeout(Duration::from_secs(5), rx) => addr
            .expect("server bound within 5s")
            .expect("bind address"),
    };

    let response = roundtrip(
        addr,
        b"GET /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the server has to actually be up first, or the refused connection \
         below would prove nothing: {response:?}"
    );

    drop(server);

    // Retried rather than checked once: the workers are OS threads unwinding
    // asynchronously, so the listener closes shortly after the drop rather
    // than during it.
    let mut refused = false;
    for _ in 0..100 {
        match tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Err(_)) => {
                refused = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(
        refused,
        "the listener on {addr} was still accepting 5s after the serve future \
         was dropped, so a cancelled `listen_on` leaves a bound socket and \
         workers still serving requests nobody is waiting for"
    );
}

// ---------------------------------------------------------------------------
// Adapter parity.
//
// `handle_request` and `dispatch_via_h1` are two transport-facing edges onto
// one `dispatch_request`, and in a default build both are live at once: hyper
// serves every HTTP/2 connection, `armature-h1` every HTTP/1.1 one. So a
// divergence between them is not a tidiness problem, it is the same request
// getting two different answers depending on which protocol the client
// negotiated. They had already diverged once, on how a repeated header field
// is stored, which is the last case in the corpus below.
// ---------------------------------------------------------------------------

/// Like [`echo`] but without the peer, which is a different socket on each of
/// the two servers by construction and would make every comparison fail for a
/// reason that is not a divergence.
async fn echo_without_peer(req: HttpRequest) -> Result<HttpResponse, Error> {
    let body = format!(
        "method={} path={} trace={} body={}",
        req.method,
        req.path,
        req.headers.get("x-trace-id").unwrap_or("-"),
        String::from_utf8_lossy(&req.body),
    );
    Ok(HttpResponse::ok().with_body(body.into_bytes()))
}

/// Reports the client address the framework derives with one trusted proxy.
///
/// The case the parity harness exists for. `client_address` reads
/// `get_all("X-Forwarded-For")` and joins every field line per RFC 9110 §5.3,
/// so an adapter that stores a repeated field by replacing rather than
/// appending hands it one line where the other hands it two — and the same
/// request resolves to a different client over HTTP/2 than over HTTP/1.1.
async fn echo_client_address(req: HttpRequest) -> Result<HttpResponse, Error> {
    let client = req
        .client_address(1)
        .map_or("-".to_string(), |ip| ip.to_string());
    Ok(HttpResponse::ok().with_body(format!("client={client}").into_bytes()))
}

fn parity_state(max_body_size: usize) -> ServeState {
    let mut router = Router::new();
    router.add_route(Route::new(HttpMethod::GET, "/echo", echo_without_peer));
    router.add_route(Route::new(HttpMethod::POST, "/echo", echo_without_peer));
    router.add_route(Route::new(HttpMethod::GET, "/empty", empty_ok));
    router.add_route(Route::new(HttpMethod::GET, "/nothing", no_content));
    router.add_route(Route::new(HttpMethod::HEAD, "/head", echo_without_peer));
    router.add_route(Route::new(HttpMethod::GET, "/client", echo_client_address));
    ServeState::for_test(
        Arc::new(OptimizedRouter::from_router(&router)),
        max_body_size,
    )
}

/// Serve exactly one connection through the hyper adapter and return the raw
/// bytes it produced.
///
/// The counterpart of [`with_server`] + [`roundtrip`] for the other adapter,
/// built the same way `Application::listen_on` builds it so the thing under
/// test is the real `handle_request` rather than a reconstruction.
async fn hyper_roundtrip(state: ServeState, request: &[u8]) -> String {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, body::Incoming};
    use hyper_util::rt::TokioIo;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind the hyper listener");
    let addr = listener.local_addr().expect("hyper listener address");

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept");
        // Stamped the same way the real listener stamps it, so the two
        // adapters differ only in the transport and not in what they were
        // handed.
        let state = state.for_peer(peer);
        let service = service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            async move { crate::application::handle_request(req, state).await }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the hyper server");
    stream.write_all(request).await.expect("write request");
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
        .await
        .expect("the hyper adapter answered within 5s")
        .expect("read");
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the hyper connection task finished within 5s")
        .expect("the hyper connection task panicked");
    String::from_utf8_lossy(&out).into_owned()
}

/// A raw response reduced to what the two adapters are obliged to agree on.
///
/// `Date` is a clock reading and `Server` names the stack, so neither can
/// match and neither is a promise to the client. Header *order* is dropped
/// too — RFC 9110 §5.3 makes it insignificant for fields that do not repeat,
/// and the two stacks emit their own framing headers at different points.
///
/// The status *code* is kept and the reason phrase is not, because the two
/// stacks genuinely disagree on one and RFC 9110 §15 makes the phrase
/// advisory: a client is required to act on the code. That disagreement is
/// pinned by
/// [`the_two_adapters_spell_413s_reason_phrase_differently`] rather than
/// quietly absorbed here — dropping it from the comparison without a test
/// naming it would be exactly the papering-over this harness exists to
/// prevent. Everything else — the code, the header set, the values, the body —
/// is compared exactly.
fn normalised(response: &str) -> String {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let mut headers: Vec<String> = lines
        .filter(|line| {
            let name = line
                .split_once(':')
                .map_or_else(String::new, |(k, _)| k.trim().to_ascii_lowercase());
            name != "date" && name != "server"
        })
        .map(|line| line.trim().to_ascii_lowercase())
        .filter(|line| !line.is_empty())
        .collect();
    headers.sort();
    format!("{status}\n{}\n\n{body}", headers.join("\n"))
}

#[tokio::test]
async fn the_two_adapters_answer_the_same_request_the_same_way() {
    let cors = crate::CorsConfig::new("https://example.test");
    let cases: Vec<(&str, ServeState, &[u8])> = vec![
        (
            "a routed 200",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"GET /echo?q=1 HTTP/1.1\r\nHost: a\r\nX-Trace-Id: abc\r\nConnection: close\r\n\r\n",
        ),
        (
            "an unrouted 404",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"GET /nope HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            "a declared-length 413",
            parity_state(16),
            b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
        ),
        (
            "an OPTIONS preflight",
            parity_state(DEFAULT_MAX_BODY_SIZE).with_cors_for_test(cors.clone()),
            b"OPTIONS /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            "a guard refusal",
            parity_state(DEFAULT_MAX_BODY_SIZE).with_guard_for_test(Arc::new(DenyAll)),
            b"GET /echo HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            "a HEAD",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"HEAD /head HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            "an empty 200",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"GET /empty HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            "a 204",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"GET /nothing HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        ),
        (
            // Two field lines, not one comma-joined value: the shape a proxy
            // that appends its own line produces, and the one an adapter
            // storing headers by replacement silently collapses.
            "a repeated X-Forwarded-For",
            parity_state(DEFAULT_MAX_BODY_SIZE),
            b"GET /client HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 198.51.100.9\r\n\
              X-Forwarded-For: 203.0.113.7\r\nConnection: close\r\n\r\n",
        ),
    ];

    // Collected rather than asserted case by case, so one run reports every
    // divergence instead of the first.
    let mut divergences = Vec::new();
    for (name, state, request) in cases {
        let via_hyper = normalised(&hyper_roundtrip(state.clone(), request).await);
        let request = request.to_vec();
        let via_h1 = with_server(
            state,
            move |addr| async move { roundtrip(addr, &request).await },
        )
        .await;
        let via_h1 = normalised(&via_h1);

        if via_hyper != via_h1 {
            divergences.push(format!(
                "\n=== {name} ===\n--- hyper ---\n{via_hyper}\n--- armature-h1 ---\n{via_h1}"
            ));
        }
    }

    assert!(
        divergences.is_empty(),
        "the two adapters answered the same bytes differently. Both are live \
         in a default build — hyper serves HTTP/2, armature-h1 serves \
         HTTP/1.1 — so each difference below is one request getting two \
         answers depending only on which protocol the client negotiated:{}",
        divergences.join("")
    );
}

/// The one divergence the parity harness above found, pinned so it stays the
/// only one.
///
/// RFC 9110 §15.5.14 renamed 413 from "Payload Too Large" to "Content Too
/// Large"; hyper's `StatusCode::canonical_reason` still returns the old
/// spelling and `armature-h1`'s `reason_phrase` returns the new one. So the
/// same over-limit upload is answered "413 Payload Too Large" over HTTP/2 and
/// "413 Content Too Large" over HTTP/1.1 in a default build.
///
/// Recorded rather than fixed, and this is the argument for leaving it: RFC
/// 9110 §15 makes the reason phrase advisory and requires clients to act on
/// the three-digit code, which is identical, as is the JSON envelope every
/// caller actually parses. Changing either stack's table to match the other
/// would be churn in a sibling crate to satisfy a test. If this ever starts
/// failing, the two stacks have converged and this test should be deleted
/// along with the carve-out in [`normalised`].
#[tokio::test]
async fn the_two_adapters_spell_413s_reason_phrase_differently() {
    let request: &[u8] =
        b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";

    let via_hyper = hyper_roundtrip(parity_state(16), request).await;
    let via_h1 = with_server(parity_state(16), move |addr| async move {
        roundtrip(addr, request).await
    })
    .await;

    assert!(
        via_hyper.starts_with("HTTP/1.1 413 Payload Too Large"),
        "hyper's status table is the pre-RFC-9110 spelling; a change here means \
         the divergence moved rather than closed: {via_hyper:?}"
    );
    assert!(
        via_h1.starts_with("HTTP/1.1 413 Content Too Large"),
        "armature-h1's status table is the current RFC 9110 spelling; a change \
         here means the divergence moved rather than closed: {via_h1:?}"
    );
    // What a client is actually required to act on is identical, which is why
    // the phrase is left alone rather than forced.
    for response in [&via_hyper, &via_h1] {
        assert!(
            response.contains("\"error\":\"Payload Too Large\",\"status\":413"),
            "the envelope callers parse must be byte-identical on both \
             adapters even though the advisory phrase is not: {response:?}"
        );
    }
}
