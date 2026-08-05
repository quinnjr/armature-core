# Changelog — `armature-core`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes at or before `0.6.0` are recorded in the workspace
[`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.9.0] - 2026-08-05

### Release ordering

This release depends on `armature-h1 >= 0.3.0`, and `armature-h1` re-exports
into this crate's public API (`ByteStr`, `HeaderId`, `Method`, `header_id`,
and the signatures that use them), so it is a **public dependency**: two
incompatible `armature-h1` versions in one graph produce `expected HeaderId,
found HeaderId`. That is why this is `0.9.0` and not another `0.8.x` — moving
a public dependency across a `0.x` minor is a breaking change for consumers.

Publish in this order:

1. `armature-h1 0.3.0` to crates.io.
2. `armature-core 0.9.0`.
3. Every sibling crate that pins `armature-core`, re-pinned to `"0.9"` and
   released in the same train — a sibling still requiring `"0.8"` would
   resolve a second, incompatible `armature-core` alongside this one.

### Added

- `h1-backend` cargo feature, **on by default**: HTTP/1.1 is served by
  `armature-h1` rather than `hyper::server::conn::http1`. HTTP/2 is still
  hyper's, reached through `armature-h1`'s `H2Fallback` hook when a connection
  negotiates ALPN `h2` — but see the HTTP/2 entries below, because it is not
  wholly unchanged. HTTP/3 is untouched. Turn the feature off
  (`default-features = false`) to keep the previous hyper HTTP/1.1 path.
  Note that Cargo unifies features across a whole dependency graph, so
  `default-features = false` is only reliable if *nothing* else in the build
  enables this crate's defaults.
- `HeaderMap::insert_id` and `HeaderMap::append_id`: insert or append a header
  whose name is already interned. `append_id` is the serve path's entry point
  and is what makes it zero-copy — `armature-h1` parses names straight into
  `HeaderId` and values into `Bytes` slices of the connection's read buffer, so
  a head crosses into `HttpRequest` as a sequence of moves rather than a copy
  per value and a re-intern per name.

### Changed

- **Breaking (behaviour, not signature)**: with default features, HTTP/1.1
  parsing is `armature-h1`'s and is stricter than hyper's. A bare LF as a line
  terminator, a `#` fragment in the request target, and an unsupported transfer
  coding are refused rather than accepted or silently repaired, and every
  framing rejection closes the connection. That strictness is the reason for
  the swap — leniency that differs from a peer's leniency is the request
  smuggling vector — but a client that relied on hyper's permissiveness will
  now be refused. See `armature-h1`'s `BACKENDS.md`.
- `PipelineConfig::keep_alive_timeout` and `PipelineConfig::max_header_size`
  are now wired on the `h1-backend` path, to `Limits::idle_timeout` and
  `Limits::max_head_bytes`. Both documented themselves as unwired because
  hyper's H1 builder had no knob for them; `armature-h1` does. Configurations
  that set them and saw no effect will now see one.
- `Application::listen_on`, `listen_https`, `listen_https_h2`,
  `listen_with_config` and `listen_dual_stack` keep their signatures. Serving
  moves onto `armature-h1`'s thread-per-core worker threads, run from a
  blocking-pool thread so the caller's runtime is not blocked.
- **A handler must not block on the `h1-backend` path.** One thread serves
  every connection on its core, so a blocking handler stalls all of them. The
  hyper path's work-stealing runtime hid this; this one does not. Move
  genuinely blocking work to a shared pool.
- Repeated header fields are preserved rather than collapsed. The hyper path
  stored headers with `HeaderMap::insert`, which replaces, so a field the wire
  sent twice survived only as its last occurrence; the serve path now appends,
  and a single-valued lookup returns the first. See the `client_address` entry
  under **Fixed** for why this mattered.
- The per-request `trace!("Incoming request")` record now comes from the shared
  dispatch path, so both backends emit it. It was previously written only by
  the hyper adapter, which would have left HTTP/1.1 with no arrival record at
  all — and none whatsoever for a request rejected at CORS preflight or the
  body limit, which are decided before routing.

### Fixed

- **HTTP/1.1-only HTTPS listeners no longer advertise ALPN `h2` and then hang
  up on it.** `TlsConfig` offers `h2, http/1.1` unconditionally, so
  `listen_https` and `listen_with_config` — which serve HTTP/1.1 only —
  negotiated `h2` with every modern browser and then closed the connection
  without a byte of HTTP. Both now strip `h2` from the offer, so the handshake
  settles on `http/1.1` and the connection is served. `listen_https_h2` is
  unaffected: it genuinely serves HTTP/2.

  This was pre-existing rather than introduced by the backend swap — hyper's
  HTTP/1.1 server also rejects an h2 preface — and the fix is applied on both
  paths, so an h2-only client now receives a `no_application_protocol` TLS
  alert instead of a successful handshake followed by silence. That is a
  behaviour change on the hyper path too, and a more diagnosable one.

- **`with_cors` was silently ignored by every TLS listener.** `listen_https`,
  `listen_https_h2`, `listen_with_config`, `listen_h2c` and `listen_dual_stack`
  all built their serve state with no CORS configuration, so an HTTPS server
  configured with `with_cors` sent no CORS headers at all. Only `listen_on`
  honoured it. Every listener now does. **This changes behaviour for existing
  HTTPS deployments**: CORS headers now appear on their responses, and because
  the preflight handler answers *every* `OPTIONS` request with 204 before the
  router is consulted, an `OPTIONS` route registered on an HTTPS listener stops
  being reachable while CORS is configured. See `Application::with_cors`.
- **HTTP/2 lost the client's address on the `h1-backend` path.** `H2Fallback`
  had no way to report which peer a connection came from, so every HTTP/2
  request arrived with `HttpRequest::peer` of `None` while HTTP/1.1 on the same
  socket kept a real one — silently sending `client_address` to the
  caller-controlled `X-Forwarded-For` header for rate limiting, deduplication
  and audit attribution. Fixed by passing the peer through the hook, which is a
  **breaking change to `armature-h1`'s `H2Fallback` trait** (see that crate's
  changelog).
- **`HttpRequest::client_address` could be spoofed via a repeated
  `X-Forwarded-For`.** It read a single field line, so where a proxy appends
  its own line rather than extending the client's — HAProxy's `option
  forwardfor` and several ingress configurations do this — the client's line
  won and `client_address` returned an address the caller chose. Repeated field
  lines are now joined per RFC 9110 §5.3 before the rightmost hop is selected,
  which is also the only reading that makes both backends agree.
- A declared `Content-Length` over the configured limit now returns this
  framework's `{"error":"Payload Too Large","status":413}` envelope with CORS
  headers, as every other transport does. `armature-h1`'s own body cap was
  configured with the same value and is evaluated before the service runs, so
  it answered first with a bare status line — leaving a browser doing a CORS
  upload with an opaque CORS failure instead of a 413.

### Removed

- On the `h1-backend` path, `PipelineStats` and `Http2Stats` connection and
  request counters stay at zero: `armature-h1` owns the accept loop and exposes
  no hook to count from. This is observability, not behaviour — but a dashboard
  reading them will go flat. The same applies to `with_socket_tuning`
  (`EpollConfig`), which reaches for the raw fd of a listener this process no
  longer owns; `armature-h1`'s own `TcpConfig` covers `nodelay`, backlog and
  `SO_REUSEPORT` (and sets the last of those *before* bind, where it actually
  takes effect). `with_socket_tuning` still applies on `listen_h2c`, which
  remains a hyper listener.
- `PipelineConfig::pipeline_flush` and `PipelineConfig::read_buffer_size`, both
  documented as wired, are not honoured on the `h1-backend` path: `armature-h1`
  writes each response as it is produced and grows its read buffer from a fixed
  chunk size, so it exposes no knob for either. They still reach the HTTP/2
  connections hyper serves.

## [0.8.5] - 2026-08-04

### Added

- `HttpRequest::peer: Option<SocketAddr>` — the address of the socket a request
  arrived on. This is the only client identifier a handler can trust: every
  address in a header (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`) is set by the
  caller, so anything that rate-limits, deduplicates, or logs by "client address"
  without it is keyed on a value the client chooses. `None` means genuinely
  unknown rather than a plausible-looking `0.0.0.0`, so a fabricated address
  cannot reach an audit log through an unwrap-shaped default.

  Populated by every serve path: HTTP/1.1, HTTPS, HTTP/2 and the ALPN-multiplexed
  listener carry it on the per-connection `ServeState`; HTTP/3 takes it from the
  QUIC connection's `remote_address()`; `micro` takes it from its accept loop.
  Two accept loops previously discarded the address outright.

  Additive, and not a breaking change: `HttpRequest` has a private field, so it
  was never constructible outside this crate by struct literal.

- `HttpRequest::with_peer` and `HttpRequest::client_address(trusted_proxy_depth)`.
  The latter answers "which address do I attribute this request to", given how
  many reverse proxies sit in front of the process, and exists so applications
  stop reimplementing the rule — which is easy to state and easy to get exactly
  backwards.

  `X-Forwarded-For` is *appended* to by each proxy, so the rightmost hops are the
  ones your own infrastructure added and the only ones worth believing. The
  client is selected `depth`-from-the-right (1-indexed). Taking the leftmost
  entry — the obvious reading of "the first one is the client" — is a spoof: a
  caller sends `X-Forwarded-For: 198.51.100.9`, the real proxy appends what it
  actually saw, and the leftmost entry is the fabrication. That defeats rate
  limiting (rotate it per request for a fresh bucket) and abuse attribution (name
  a victim and let them absorb it).

  A `depth` of `0` trusts no proxy, ignores the header, and uses the socket peer;
  that is the right default for a directly reachable process. A `depth` deeper
  than the chain actually present returns `None` rather than falling back to the
  peer, because the request did not traverse the proxies the deployment is
  configured for, and attributing it to the proxy would collapse every client
  into one bucket.

  This matches `forwarded_ip_at_depth` in `armature-ratelimit`, whose
  implementation of the same rule previously had to note that this crate exposed
  no peer to fall back to.

- Adopted the framework's criterion benchmarks that measure this crate: `core`, `arena`, `body`, `json`, `micro`, `pipeline`, `resilience`, `simd_parser` and `internal_overhead` moved here from the root package's `benches/`. Run them with `cargo bench -p armature-core --bench <name>`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry. `criterion` also gains the `async_tokio` feature: `internal_overhead`, `micro` and `resilience` drive async work through `Bencher::to_async`, which is feature-gated, so without it these benches do not compile outside the workspace.

## [0.8.4] - 2026-08-04

### Changed

- The `armature-h1` requirement names `0.2`. That release seals `Head` behind
  `Head::new` and `Head::target()`, which this crate never constructed or
  reassigned, so nothing here changes: the re-exported `ByteStr`, `HeaderId`
  and `Method` are the same types they were. It also carries the framing and
  deadline fixes that release documents — a handler `Transfer-Encoding` that
  does not frame its body no longer suppresses the writer's own framing, and
  a streamed response flushes when its source goes idle rather than waiting
  for a byte threshold.

  Note for anyone depending on both crates directly: `armature-core` now
  re-exports those types from `armature-h1 0.2`, so a direct
  `armature-h1 = "0.1"` alongside this release resolves two copies and the
  types will not be interchangeable. Move the direct requirement to `0.2`.

## [0.8.3] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.

## [0.8.2] - 2026-08-04

### Fixed

- **Registration order decides between two overlapping parameterized routes
  again.** Both went into the same `matchit` tree, where the winner is chosen
  by specificity — static beats parameter beats catch-all — which is the
  opposite of this framework's first-registered-wins rule, and the fallback
  rescan could not correct it because it only considers routes the tree does
  not hold. Registering `/:x/:y` and then `/a/:z` handed `/a/q` to the *later*
  route. A parameterized pattern that overlaps an earlier one is now answered
  by the linear scan instead, which restores the order while leaving it in sole
  charge of everything the earlier pattern does not describe. Affects 0.8.0 and
  0.8.1.
- **Registering a route with 26 or more parameters no longer aborts the
  process.** `matchit` rewrites each non-catch-all parameter to a single letter
  starting at `a` and *panics* — it does not return an error — once a route
  needs one past `z`, so the `insert(..).is_err()` arm that exists to divert
  awkward patterns to the linear scan could not catch it. The count is checked
  before the insert, on the translated pattern, since a segment written with
  braces is a parameter to `matchit` while being invisible to `param_names`.
  Affects 0.8.0 and 0.8.1.

## [0.8.1] - 2026-08-03

### Changed

- **Behaviour — static assets:** a pre-compressed sibling (`.gz`, `.br`, …) is
  now ignored unless it can be *proven* fresh. Previously a sibling older than
  its source was served, and so was one whose freshness could not be
  established at all (the source's or the sibling's mtime being unreadable).
  Either case hands the client outdated bytes under the current `ETag` and
  `Last-Modified`, which caches then hold. When freshness is unprovable the
  server now compresses the current source on the fly, which is always correct
  and merely costs CPU. A sibling's own mtime and length also feed the `ETag`
  and the in-memory content-cache key, so rewriting only the artifact — the
  usual `gzip -k` re-run — no longer reuses the source-derived validator.
- **Behaviour — `handle_websocket`:** stream and handler errors now propagate
  through the `Result` instead of being logged and swallowed, so a caller can
  distinguish a clean client close from a protocol or handler failure. A
  received Close frame is passed to the handler for teardown and the close
  handshake is flushed before the stream is dropped, replacing the abortive TCP
  close peers previously observed (RFC 6455 §5.5.1).
- **Behaviour — `WebSocketRoom::broadcast`:** connections whose receivers have
  all been dropped are reaped instead of accumulating in the room forever.
- `From<tungstenite::Message>` maps a raw `Frame` to `Binary` rather than
  `Close`; the previous catch-all told handlers the peer was closing when it
  was not.
- `LoggerMiddleware` records `duration_ms` as a number, matching
  `RequestLoggerMiddleware`, instead of a unit-varying `Debug` string.

### Fixed

- Catch-all routes match zero remaining segments again, and a trailing slash no
  longer changes the outcome. `matchit` requires a catch-all to consume at least
  one segment and treats a trailing slash as significant, so `Router` had begun
  answering differently from `OptimizedRouter` — an invariant AGENTS.md states
  and `route_cache`'s precedence test exists to enforce. A differential test now
  drives a pattern/target matrix through both routers and compares which handler
  answered.
- Route-parameter names are interned once at registration. Every captured
  parameter on every request took a process-global mutex, and the comment
  claiming the compiled router already interned at registration was false.
- `interceptor::cache_key` folded the query in twice — once raw via the target,
  once sorted — defeating the canonicalization it documents, so `?a=1&b=2` and
  `?b=2&a=1` were separate entries. `CacheKey::from_request` could also collide
  `?a=1%26b%3D2` with `?a=1&b=2` and serve one request another's body.
- `clone_response` shares the cached body instead of copying it on every hit.
- `HeaderMap` by-name lookups no longer allocate a `HeaderId::Other` per call for
  a custom name, which had made them strictly worse than the `HashMap` they
  replaced.
- Static assets resolve against `path_only()`, so a cache-busting `?v=2` no
  longer 404s, and the serve path no longer makes blocking `canonicalize`,
  `exists` and `is_dir` syscalls on the async executor.
- `param_intern` is hard-capped. `push_param` and `from_parts` let
  request-derived names reach an interner whose own documentation forbids
  exactly that.
- `RouteConstraints::validate` rejects a non-UTF-8 parameter rather than
  skipping the constraint, and `simd_parser` reports truncated input instead of
  fabricating a `GET /`.

### Breaking — `0.7.0` → `0.8.0`

The request and response types are now backed by `Bytes` rather than owned
`String`s and `Vec<u8>`s, and the work the serve path used to do eagerly is done
on demand or not at all.

- `HttpRequest.method` is a `Method` (was `String`). Constructors take
  `impl Into<Method>`, so `HttpRequest::new("GET", …)` and
  `HttpRequest::new("GET".to_string(), …)` both still compile. `method_str()`
  gives a `&str` and `req.method == "GET"` still works. Method tokens are now
  matched case-sensitively per RFC 9110 §9.1, and routing rejects CONNECT and
  TRACE rather than mapping them onto a routable method.
- `HttpRequest.path` is a `ByteStr` (was `String`). It derefs to `str`, so most
  uses are unaffected; `path_str()` is the explicit accessor. It now holds the
  *raw target*, query string included — `path_only()` is what routing matches on.
- `HttpRequest.body` and `HttpResponse.body` are `Bytes` (were `Vec<u8>`), and
  the private `body_bytes` shadow field is gone, so the two can no longer
  disagree about which holds the body. `body_slice()` returns `&[u8]`;
  `body_bytes()`, `set_body_bytes()`, `has_bytes_body()` and `body_ref()` remain
  as forwarders. `HttpResponse::with_capacity`'s capacity argument is now
  ignored: `Bytes` is handed a finished buffer rather than grown in place.
- `HttpRequest.query_params` is removed. `query()` returns a lazily parsed
  `QueryView<'_>`, `query_param(name)` replaces the old `query(name)`,
  `query_string()` gives the raw query and `push_query_param` appends an encoded
  pair. Repeated keys are all preserved in client order rather than collapsing
  to the last. `from_parts` still accepts a `query_params` argument and ignores
  it.
- `HttpRequest.path_params` is `RouteParams = SmallVec<[(&'static str, Bytes); 4]>`.
  `param(name)` returns `Option<&str>` (was `Option<&String>`), `param_bytes`
  returns the raw span, and `push_param`/`set_params` replace map insertion.
  `RouteParamsExt` adds `get_str`/`get_bytes` for by-name lookup.
- `HeaderMap` stores `(HeaderId, Bytes)`. `get` returns `Option<&str>` and
  yields `None` for a value that is not UTF-8 — `get_bytes` returns those.
  `remove` returns `Option<Bytes>`. Custom header names are lowercased at insert,
  so `to_hash_map()`, `keys()` and `iter()` report canonical names.
- `Router::match_route` returns `Option<(BoxedHandler, RouteParams)>` and
  `RouteConstraints::validate` takes `&RouteParams`.
- `zero_cost::Method` and `zero_cost::RequestPath` wrap `Method`/`ByteStr`;
  `extractors::RawBody` wraps `Bytes`; `extractors::Method` is renamed
  `MethodExtractor` to avoid colliding with the re-exported `Method`.

### Added

- `armature-core` re-exports `Method`, `ByteStr`, `HeaderId` and `header_id` from
  the new `armature-h1` crate, plus `bytes::Bytes`, so downstream crates can name
  the body type without taking their own `bytes` dependency.
- `query` module (`QueryView`) and `param_intern` module (leak-once interning of
  route parameter names, bounded by the route table rather than by traffic).

### Performance

- Dispatch goes through one `matchit` tree per routable method instead of a
  linear scan with a per-candidate method string comparison. Registration order
  still decides precedence: patterns `matchit` rejects fall back to the scan, and
  a static route an earlier same-method route already answers is left out of the
  tree, so `matchit`'s static-over-parameter preference cannot override
  first-registered-wins.
- `Extensions` is a `SmallVec` with eight inline slots instead of a `HashMap`.
- The query string is not parsed or percent-decoded unless a handler reads it.
- The serve path no longer copies the request body out of hyper's `Bytes`, and
  header values are inserted without a `String` allocation per value.
- Serving a response-cache hit clones the stored `Bytes` instead of copying it.

### Migration

`tokio::spawn` inside handlers is unaffected by this release; the `Send`-bound
change is a later one.
- Static asset serving no longer makes blocking `std::fs` calls on the async
  request path, and stats each inode once per request rather than up to four
  times.
- Lifecycle hook dispatch no longer holds the hook-registry read lock across
  hook `await`s, which starved concurrent registration under a write-preferring
  lock, deadlocked a hook that registered another hook, and caused
  `register_on_init_sync` to silently drop hooks registered from inside one.


### Removed

- **Breaking — `0.6.0` → `0.7.0`:** removed the `tower_compat` module and the
  `tower`/`tower-service` dependencies. The module existed solely for Tower
  interop — `ArmatureService`, `HyperServiceAdapter`, `ServiceFactory` and
  `ArmatureLayerService` implemented `tower_service::Service`, `ArmatureLayer`
  implemented `tower::Layer`, and `tower_stats()`/`TowerStats` counted
  conversions — which pulled the whole `tower` façade (plus its unused `util`
  feature) into every `armature-core` build for a single trait impl. The
  `http`-crate conversion traits that lived alongside it (`IntoHttpRequest`,
  `FromHttpRequest`, `IntoHttpResponse`, `HttpResponseFromHttp`, `HeaderMapExt`,
  `ArmatureHeaderMapExt`) are removed with it; they had no consumers outside the
  module. No in-tree crate, example, or template referenced any of it.
