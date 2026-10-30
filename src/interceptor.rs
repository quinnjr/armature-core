//! Interceptors for transforming requests and responses.
//!
//! [`CacheInterceptor`] is a shared response cache. It stores a response only
//! when the handler explicitly marks it shareable (`Cache-Control: public` or
//! `s-maxage`); anything else passes through uncached. It must sit inside
//! every guard and authentication layer, since a hit answers the request
//! without running anything it wraps.

use crate::{Error, HttpRequest, HttpResponse};
use async_trait::async_trait;
use lru::LruCache;
use parking_lot::RwLock;
use std::fmt::Write as _;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Execution context passed to interceptors
pub struct ExecutionContext {
    pub request: HttpRequest,
}

impl ExecutionContext {
    pub fn new(request: HttpRequest) -> Self {
        Self { request }
    }
}

/// Interceptor trait for request/response transformation
#[async_trait]
pub trait Interceptor: Send + Sync {
    /// Intercept the request before/after handler execution
    async fn intercept(
        &self,
        context: ExecutionContext,
        next: Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>,
    ) -> Result<HttpResponse, Error>;
}

/// Logging interceptor
pub struct LoggingInterceptor;

#[async_trait]
impl Interceptor for LoggingInterceptor {
    async fn intercept(
        &self,
        context: ExecutionContext,
        next: Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>,
    ) -> Result<HttpResponse, Error> {
        let start = std::time::Instant::now();
        let method = context.request.method.clone();
        // The path alone: the query string routinely carries tokens, reset
        // codes and API keys (`?token=...`), and a log line outlives the
        // request by months in places the secret was never meant to reach.
        let path = context.request.path_only().to_owned();

        tracing::info!(method = %method, path = %path, "request started");

        let result = next.await;

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        match &result {
            Ok(response) => {
                tracing::info!(
                    method = %method,
                    path = %path,
                    status = response.status,
                    duration_ms,
                    "request completed"
                );
            }
            Err(e) => {
                tracing::error!(
                    method = %method,
                    path = %path,
                    error = %e.log_display(),
                    duration_ms,
                    "request failed"
                );
            }
        }

        result
    }
}

/// Transform interceptor for modifying responses
pub struct TransformInterceptor<F>
where
    F: Fn(HttpResponse) -> HttpResponse + Send + Sync,
{
    transform: F,
}

impl<F> TransformInterceptor<F>
where
    F: Fn(HttpResponse) -> HttpResponse + Send + Sync,
{
    pub fn new(transform: F) -> Self {
        Self { transform }
    }
}

#[async_trait]
impl<F> Interceptor for TransformInterceptor<F>
where
    F: Fn(HttpResponse) -> HttpResponse + Send + Sync,
{
    async fn intercept(
        &self,
        _context: ExecutionContext,
        next: Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>,
    ) -> Result<HttpResponse, Error> {
        let response = next.await?;
        Ok((self.transform)(response))
    }
}

/// Response-cache interceptor.
///
/// **Opt-in per response.** Only a response that carries an explicit
/// `Cache-Control: public` or `s-maxage` directive is stored; a response
/// without one passes through uncached. Whether a request is credentialed is
/// judged from header names (see below), and no name list covers every
/// gateway's identity header, so absent an explicit statement from the
/// handler that the body is the same for every caller, it is not shared.
///
/// Caches successful **GET/HEAD** responses keyed by
/// `METHOD:host:path?sorted-query` for `ttl_seconds`. Query parameters are
/// folded into the key (sorted by name) so that requests differing only in the
/// query string — e.g. `?q=cats` vs `?q=dogs` — never collide, and the `Host`
/// is folded in so two virtual hosts never share an entry. On a fresh hit the
/// cached response is returned without invoking the downstream handler;
/// otherwise the handler runs and its response is stored.
///
/// The store holds at most `max_entries` responses
/// ([`DEFAULT_MAX_ENTRIES`](Self::DEFAULT_MAX_ENTRIES) unless set with
/// [`with_capacity`](Self::with_capacity)); past that the oldest is evicted.
/// An expired entry is dropped when a lookup finds it, or evicted by capacity.
///
/// Bytes are bounded too, since an entry count alone lets a handful of large
/// responses pin arbitrary memory: a body over
/// [`max_body_bytes`](Self::with_max_body_bytes) is never stored, and the
/// bodies held together never exceed
/// [`max_total_bytes`](Self::with_max_total_bytes) (oldest evicted first).
///
/// The cache is process-local and shared across clones of the interceptor via
/// an `Arc`, so a single `CacheInterceptor` value serves every request routed
/// through it.
///
/// # Safety: do not use on per-user or authenticated routes
///
/// This is a **shared, unkeyed-by-identity** cache: it does not discriminate on
/// `Authorization`, `Cookie`, or any other per-user dimension. Placing it on a
/// route whose response depends on the caller's identity would serve one user's
/// body to another. To reduce that blast radius a *credentialed* request
/// bypasses the cache entirely — it is never served a hit and its response is
/// never stored. Credentialed means it carries any credential header
/// (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Session-*`, ...
/// — every [sensitive](crate::headers::is_sensitive_header) header except
/// anti-CSRF tokens) or an authentication layer has attached a
/// [`VerifiedIdentity`](crate::VerifiedIdentity) /
/// [`RequestRoles`](crate::RequestRoles). A request with more than one `Host`
/// bypasses it too. Otherwise the cache will **not store** a response that:
///
/// - lacks an explicit `Cache-Control: public` or `s-maxage` directive, or
/// - was produced by a method other than `GET` or `HEAD`, or
/// - carries a `Set-Cookie` header (session/user state), or
/// - carries `Cache-Control: private`, `no-store` or `no-cache` (this cache
///   never revalidates, so `no-cache` can't be honoured), or
/// - carries a non-empty `Vary` header, or
/// - carries a non-empty `Content-Encoding` header.
///
/// The `Vary`/`Content-Encoding` guards exist because the cache key is built
/// from the request line only (method, path, query) — it does not fold in
/// request headers such as `Accept-Encoding`. A response that varies by, or
/// is compressed according to, a header the key ignores must not be stored
/// here: it could be replayed to a caller that never negotiated that
/// representation.
///
/// These guards are defensive, not a substitute for correct placement: only
/// attach this interceptor to routes whose responses are identical for every
/// caller.
///
/// **Ordering.** The verified-identity check only sees what has already been
/// attached, so the cache must run *after* every middleware that authenticates
/// the request and inserts a [`VerifiedIdentity`](crate::VerifiedIdentity) /
/// [`RequestRoles`](crate::RequestRoles) — in particular one that
/// authenticates from something the header check cannot see (mTLS, or a
/// gateway header it strips). Register the authentication middleware so it
/// wraps the handler this interceptor is attached to.
///
/// **A hit short-circuits everything inside the cache.** A fresh entry is
/// returned without running the downstream future, so any guard, interceptor
/// or middleware wrapped *by* this one never sees the request. Place it
/// inside every guard and authorization check, never around one; otherwise a
/// response cached for an admitted caller is served to a caller the guard
/// would have rejected.
pub struct CacheInterceptor {
    /// Freshness window, in seconds. A cached entry is served only while its
    /// age is strictly less than this. `0` disables caching (nothing is ever
    /// fresh).
    pub ttl_seconds: u64,
    /// Backing store: cache key -> (stored-at instant, response).
    ///
    /// Bounded, so the number of distinct URLs a client can mint (every query
    /// value is a new key) can't grow it without limit. Reads use `peek`,
    /// which leaves recency alone, so lookups share the read lock and
    /// eviction is oldest-stored-first.
    store: Arc<RwLock<Store>>,
    /// Largest body stored; bigger responses pass through uncached.
    max_body_bytes: usize,
    /// Budget for the bodies (and keys) held together.
    max_total_bytes: usize,
}

/// The LRU plus a running total of the bytes it holds, kept under one lock so
/// the total can't drift from the entries it counts.
struct Store {
    entries: LruCache<String, (Instant, HttpResponse)>,
    bytes: usize,
}

/// What an entry counts against the byte budget: its body and its key (the
/// key carries the attacker-chosen path and query, so it is not free either).
fn entry_cost(key: &str, response: &HttpResponse) -> usize {
    key.len() + response.body.len()
}

impl Store {
    fn pop(&mut self, key: &str) {
        if let Some((_, response)) = self.entries.pop(key) {
            self.bytes -= entry_cost(key, &response);
        }
    }

    /// Insert, evicting oldest entries until both the count and the byte
    /// budget hold.
    fn insert(&mut self, key: String, response: HttpResponse, max_total_bytes: usize) {
        let cost = entry_cost(&key, &response);
        // Something that can never fit must not flush the whole cache trying.
        if cost > max_total_bytes {
            return;
        }
        // A re-store replaces the old entry; take its bytes off first so the
        // eviction loop below doesn't count it twice.
        self.pop(&key);
        while self.bytes + cost > max_total_bytes {
            match self.entries.pop_lru() {
                Some((k, (_, r))) => self.bytes -= entry_cost(&k, &r),
                None => break,
            }
        }
        // `push` hands back what the count bound evicted.
        if let Some((k, (_, r))) = self.entries.push(key, (Instant::now(), response)) {
            self.bytes -= entry_cost(&k, &r);
        }
        self.bytes += cost;
    }
}

impl CacheInterceptor {
    /// Entries held by [`new`](Self::new) before the oldest is evicted.
    pub const DEFAULT_MAX_ENTRIES: usize = 1024;
    /// Default largest body stored: 1 MiB.
    pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
    /// Default budget for all stored bodies together: 64 MiB.
    pub const DEFAULT_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

    pub fn new(ttl_seconds: u64) -> Self {
        Self::with_capacity(ttl_seconds, Self::DEFAULT_MAX_ENTRIES)
    }

    /// A cache holding at most `max_entries` responses (at least one).
    pub fn with_capacity(ttl_seconds: u64, max_entries: usize) -> Self {
        let capacity = NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            ttl_seconds,
            store: Arc::new(RwLock::new(Store {
                entries: LruCache::new(capacity),
                bytes: 0,
            })),
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            max_total_bytes: Self::DEFAULT_MAX_TOTAL_BYTES,
        }
    }

    /// Never store a response whose body is larger than `bytes`
    /// (default [`DEFAULT_MAX_BODY_BYTES`](Self::DEFAULT_MAX_BODY_BYTES)).
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }

    /// Hold at most `bytes` of bodies and keys in total, evicting the oldest
    /// entries to make room (default
    /// [`DEFAULT_MAX_TOTAL_BYTES`](Self::DEFAULT_MAX_TOTAL_BYTES)).
    pub fn with_max_total_bytes(mut self, bytes: usize) -> Self {
        self.max_total_bytes = bytes;
        self
    }

    /// Bytes currently held (bodies plus keys).
    pub fn total_bytes(&self) -> usize {
        self.store.read().bytes
    }

    /// Number of entries currently held (including any not-yet-pruned expired
    /// ones). Primarily useful for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.store.read().entries.len()
    }

    /// Whether the cache currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.store.read().entries.is_empty()
    }
}

/// Produce an owned copy of a response. `HttpResponse` is deliberately not
/// `Clone` (it carries zero-copy `Bytes` internals), so we rebuild it from its
/// observable parts, preserving status, headers, cookies, and body.
fn clone_response(response: &HttpResponse) -> HttpResponse {
    let mut copy = HttpResponse::new(response.status);
    for (name, value) in response.headers.iter() {
        copy.headers.insert(name.clone(), value.clone());
    }
    copy.cookies = response.cookies.clone();
    // The body is shared, not copied: `Bytes::clone` is a refcount bump, so
    // serving a hit costs nothing proportional to the response size.
    copy.with_bytes_body(response.body.clone())
}

/// Build the cache key for a request: `METHOD:` then, when the request has a
/// `Host`, `@{len}:{host}:` (normalized as the response cache does it), then
/// `{path.len()}:path` — where
/// `path` is the target with the query stripped off — with a canonicalized
/// query string appended, sorted by parameter name. Sorting
/// means logically-identical requests with different parameter orderings map
/// to the same entry, while any difference in a query value yields a distinct
/// entry (so `?q=cats` and `?q=dogs` never share a cached body).
///
/// The path is itself length-prefixed, not just joined after `METHOD:`. If it
/// were joined as plain `METHOD:path`, a request whose `path` happens to
/// contain a literal `?` could serialize to the exact same string as a
/// different, shorter path combined with query parameters — e.g. path
/// `"/a?1:b=1:c&"` (no query params) would collide with path `"/a"` plus query
/// `{"b": "c"}`, since both naively join to `"GET:/a?1:b=1:c&"`.
/// Length-prefixing the path (`{path.len()}:{path}`) fixes exactly where the
/// path ends regardless of `?`-like bytes inside it, the same trick used
/// below for query params, so the two can never collide.
///
/// Query params are already percent-decoded by the time they reach here, so a
/// decoded value may itself contain `&` or `=`. To keep the key injective we
/// length-prefix each key and value as `{len}:{bytes}` before joining with `=`
/// and `&` — the prefix lets a (hypothetical) parser skip exactly `len` bytes
/// regardless of what delimiter-like characters they contain, so two params
/// with different decoded content can never serialize to the same key. (E.g.
/// decoded `{"a": "1&b=2"}` and decoded `{"a": "1", "b": "2"}` would both join
/// to the literal string `a=1&b=2` under naive concatenation; length-prefixing
/// makes them `5:1&b=2` vs. `1:1` + `1:2` under distinct keys.)
fn cache_key(request: &HttpRequest) -> String {
    let method = request.method.as_str();
    // `path_only`, not `path`: the raw target carries the query verbatim, and
    // folding that in ahead of the canonicalized form would make `?a=1&b=2` and
    // `?b=2&a=1` distinct keys again — exactly what the sorting below exists to
    // prevent.
    let path = request.path_only();

    // Cheap upper-bound capacity pass so the common case (few short params)
    // needs no reallocation while building the key below.
    let mut capacity = method.len() + 1 + 20 + 1 + path.len() + 1;
    let segments = crate::query::raw_segments_sorted(request.query_string().unwrap_or(""));
    for segment in &segments {
        capacity += 20 + 1 + segment.len() + 1;
    }
    let authority = request
        .headers
        .get("host")
        .map(crate::response_cache::normalize_authority);
    capacity += authority.as_ref().map_or(0, |a| a.len() + 23);
    let mut key = String::with_capacity(capacity);

    key.push_str(method);
    key.push(':');
    // `@` can't start the path's (numeric) length prefix, so a keyed host can
    // never render the same as a hostless key.
    if let Some(authority) = authority {
        let _ = write!(key, "@{}:{}:", authority.len(), authority);
    }
    let _ = write!(key, "{}", path.len());
    key.push(':');
    key.push_str(path);

    if segments.is_empty() {
        return key;
    }
    // Raw segments, not decoded pairs: see `query::raw_segments_sorted`.
    key.push('?');
    for segment in segments {
        let _ = write!(key, "{}", segment.len());
        key.push(':');
        key.push_str(segment);
        key.push('&');
    }
    key
}

/// Only safe, idempotent methods are cacheable here: `GET` and `HEAD`.
fn is_cacheable_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

/// Whether a request must skip the cache in both directions.
///
/// A credential — any credential header, not just `Authorization`/`Cookie`
/// (an `X-Api-Key` identifies the caller just as well), or a verified
/// identity an auth middleware attached — means the handler is likely
/// answering *this* caller; the key has no identity in it, so a hit would
/// hand them someone else's body and a store would hand theirs to everyone.
/// Two `Host` lines leave which site the response is for a guess, so it
/// isn't keyed on either.
fn must_bypass(request: &HttpRequest) -> bool {
    crate::guard::is_credentialed_request(request) || request.headers.get_unique("host").is_err()
}

/// Whether a response must not be stored in this shared, identity-agnostic
/// cache: it carries a `Set-Cookie` (per-user session state), a
/// `Cache-Control` directive that forbids shared storage
/// (`private`/`no-store`) or requires revalidation this cache can't do
/// (`no-cache`), a non-empty `Vary` header, or a non-empty `Content-Encoding`
/// header.
///
/// The `Vary`/`Content-Encoding` checks exist because [`cache_key`] never
/// folds in request headers (there is no `Accept-Encoding`, `Accept-Language`,
/// etc. in the key) — it only sees method, path, and query. A response that
/// legitimately differs per the `Vary`-named request header, or that is
/// encoded per `Content-Encoding` (e.g. `gzip`, negotiated via
/// `Accept-Encoding`), would otherwise be cached under a key that can't tell
/// two different negotiated variants apart, and a client that never asked for
/// that variant could be served it verbatim from cache.
///
/// `HttpResponse.headers` (`LazyHeaders`) is backed by a plain `HashMap` whose
/// `get`/`contains_key` are case-sensitive, but HTTP header *names* are not —
/// and nothing normalizes response header casing before it reaches here. A
/// handler emitting `cache-control: private` or `set-cookie: ...` (any casing
/// is legal) must be caught just like the canonically-cased form, so every
/// check here walks `headers.iter()` and compares names with
/// `eq_ignore_ascii_case`.
fn must_not_cache(response: &HttpResponse) -> bool {
    if !response.cookies.is_empty() {
        return true;
    }
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("set-cookie") {
            return true;
        }
        if name.eq_ignore_ascii_case("vary") && !value.trim().is_empty() {
            return true;
        }
        if name.eq_ignore_ascii_case("content-encoding") && !value.trim().is_empty() {
            return true;
        }
        // Every Cache-Control line, not just the last one iterated: the map is
        // case-sensitive, so `Cache-Control: public` and `cache-control:
        // private` can both be present, and either line forbidding storage
        // is enough.
        if name.eq_ignore_ascii_case("cache-control")
            && value.split(',').any(|directive| {
                // `private="Set-Cookie"` and `no-cache="..."` are still the
                // directive; only the name decides.
                let name = directive.split('=').next().unwrap_or("").trim();
                name.eq_ignore_ascii_case("private")
                    || name.eq_ignore_ascii_case("no-store")
                    || name.eq_ignore_ascii_case("no-cache")
            })
        {
            return true;
        }
    }
    false
}

/// Whether the handler explicitly declared `response` storable by a shared
/// cache: some `Cache-Control` line carries `public` or `s-maxage`.
///
/// Required for every store, not just a tie-breaker: the credential check
/// works from header names, and an identity header it doesn't know would
/// otherwise let a per-caller body into the shared store. Every line is
/// walked, case-insensitively, for the same reason as in [`must_not_cache`].
fn is_explicitly_shareable(response: &HttpResponse) -> bool {
    response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("cache-control")
            && value.split(',').any(|directive| {
                let name = directive.split('=').next().unwrap_or("").trim();
                name.eq_ignore_ascii_case("public") || name.eq_ignore_ascii_case("s-maxage")
            })
    })
}

#[async_trait]
impl Interceptor for CacheInterceptor {
    async fn intercept(
        &self,
        context: ExecutionContext,
        next: Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>,
    ) -> Result<HttpResponse, Error> {
        let ttl = Duration::from_secs(self.ttl_seconds);
        // Only safe methods (GET/HEAD) ever read from or write to the cache.
        // Build the key only when it will actually be used: for the (common)
        // case of a non-GET/HEAD request, this skips the allocation and
        // length-prefixing work entirely.
        let cache_key = (is_cacheable_method(context.request.method_str())
            && !must_bypass(&context.request))
        .then(|| cache_key(&context.request));

        // Lookup: serve a fresh hit without touching the handler.
        if let Some(key) = cache_key.as_deref() {
            let expired = {
                let store = self.store.read();
                match store.entries.peek(key) {
                    Some((stored_at, cached)) if stored_at.elapsed() < ttl => {
                        return Ok(clone_response(cached));
                    }
                    Some(_) => true,
                    None => false,
                }
            };
            // Drop an expired entry now rather than let it hold a slot until
            // capacity pushes it out.
            if expired {
                let mut store = self.store.write();
                if store
                    .entries
                    .peek(key)
                    .is_some_and(|(at, _)| at.elapsed() >= ttl)
                {
                    store.pop(key);
                }
            }
        }

        // Miss (or stale): run the handler.
        let response = next.await?;

        // Store only when: the method is safe, caching is enabled, the response
        // is a success (2xx), the handler marked it `public`/`s-maxage`, and
        // nothing contradicts that — no Set-Cookie, private/no-store/no-cache
        // Cache-Control, Vary, or Content-Encoding. This keeps per-user bodies,
        // session cookies, and negotiated/encoded representations from
        // bleeding across callers.
        if let Some(key) = cache_key
            && self.ttl_seconds > 0
            && (200..300).contains(&response.status)
            && is_explicitly_shareable(&response)
            && !must_not_cache(&response)
            && response.body.len() <= self.max_body_bytes
        {
            // Amortized O(1): the count and byte bounds, not a full sweep under
            // the write lock, are what keep the store from growing.
            self.store
                .write()
                .insert(key, clone_response(&response), self.max_total_bytes);
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_logging_interceptor_creation() {
        let _interceptor = LoggingInterceptor;
    }

    #[test]
    fn test_cache_interceptor_creation() {
        let interceptor = CacheInterceptor::new(60);
        assert_eq!(interceptor.ttl_seconds, 60);
    }

    #[test]
    fn test_cache_interceptor_different_ttls() {
        let i1 = CacheInterceptor::new(30);
        let i2 = CacheInterceptor::new(120);
        let i3 = CacheInterceptor::new(3600);

        assert_eq!(i1.ttl_seconds, 30);
        assert_eq!(i2.ttl_seconds, 120);
        assert_eq!(i3.ttl_seconds, 3600);
    }

    #[test]
    fn test_transform_interceptor_creation() {
        let _interceptor = TransformInterceptor::new(|res| res);
    }

    #[test]
    fn test_execution_context_creation() {
        let request = crate::HttpRequest::new("GET", "/test".to_string());

        let context = ExecutionContext::new(request.clone());
        assert_eq!(context.request.method, "GET");
        assert_eq!(context.request.path, "/test");
    }

    #[test]
    fn test_execution_context_with_metadata() {
        let mut request = crate::HttpRequest::new("POST", "/api/users".to_string());
        request.body = Bytes::from(vec![1, 2, 3]);

        let context = ExecutionContext::new(request.clone());
        assert_eq!(context.request.body.len(), 3);
    }

    #[test]
    fn cache_key_keeps_raw_query_bytes_apart() {
        // Both decode to U+FFFD / a space; a handler reading the raw query
        // tells them apart, so the cache must too.
        let key = |t| cache_key(&crate::HttpRequest::new("GET", t));
        assert_ne!(key("/s?a=%FF"), key("/s?a=%FE"));
        assert_ne!(key("/s?a=+"), key("/s?a=%20"));
    }

    #[test]
    fn cache_key_is_order_insensitive_across_query_orderings() {
        let a = crate::HttpRequest::new("GET", "/search?a=1&b=2");
        let b = crate::HttpRequest::new("GET", "/search?b=2&a=1");
        assert_eq!(cache_key(&a), cache_key(&b));

        // …but only orderings collapse. A different value is a different entry.
        let c = crate::HttpRequest::new("GET", "/search?a=1&b=3");
        assert_ne!(cache_key(&a), cache_key(&c));
    }

    #[test]
    fn test_cache_interceptor_zero_ttl() {
        let interceptor = CacheInterceptor::new(0);
        assert_eq!(interceptor.ttl_seconds, 0);
    }

    #[test]
    fn test_cache_interceptor_long_ttl() {
        let one_day = 86400;
        let interceptor = CacheInterceptor::new(one_day);
        assert_eq!(interceptor.ttl_seconds, one_day);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counting_next(
        calls: Arc<AtomicUsize>,
        status: u16,
        body: &'static [u8],
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>> {
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let mut resp = HttpResponse::new(status);
            resp.body = Bytes::copy_from_slice(body);
            resp.headers
                .insert("Cache-Control".to_string(), "public".to_string());
            Ok(resp)
        })
    }

    /// Regression: a fresh hit must be served from the store without invoking
    /// the downstream handler a second time. The old passthrough implementation
    /// called `next` on every request, so this asserted call-count of 1 failed.
    #[tokio::test]
    async fn test_cache_interceptor_caches_within_ttl() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let ctx = ExecutionContext::new(HttpRequest::new("GET", "/cached"));
        let first = interceptor
            .intercept(ctx, counting_next(calls.clone(), 200, b"payload"))
            .await
            .unwrap();
        assert_eq!(first.body_ref(), b"payload");

        let ctx = ExecutionContext::new(HttpRequest::new("GET", "/cached"));
        let second = interceptor
            .intercept(ctx, counting_next(calls.clone(), 200, b"payload"))
            .await
            .unwrap();
        assert_eq!(second.body_ref(), b"payload");
        assert_eq!(second.status, 200);

        // Handler ran exactly once; the second response came from cache.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(interceptor.len(), 1);
    }

    /// A zero TTL means nothing is ever fresh, so every request must hit the
    /// handler (the freshness gate, exercised in the "miss" direction).
    #[tokio::test]
    async fn test_cache_interceptor_zero_ttl_never_caches() {
        let interceptor = CacheInterceptor::new(0);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/x"));
            interceptor
                .intercept(ctx, counting_next(calls.clone(), 200, b"body"))
                .await
                .unwrap();
        }

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(interceptor.is_empty());
    }

    /// Distinct method/path pairs are cached independently and do not collide.
    #[tokio::test]
    async fn test_cache_interceptor_distinct_keys() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let ctx = ExecutionContext::new(HttpRequest::new("GET", "/a"));
        interceptor
            .intercept(ctx, counting_next(calls.clone(), 200, b"a"))
            .await
            .unwrap();
        let ctx = ExecutionContext::new(HttpRequest::new("GET", "/b"));
        interceptor
            .intercept(ctx, counting_next(calls.clone(), 200, b"b"))
            .await
            .unwrap();

        // Two distinct keys => two handler invocations, two cached entries.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(interceptor.len(), 2);
    }

    /// Non-success responses must not be cached (errors should not be pinned).
    #[tokio::test]
    async fn test_cache_interceptor_skips_non_success() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/err"));
            interceptor
                .intercept(ctx, counting_next(calls.clone(), 500, b"boom"))
                .await
                .unwrap();
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(interceptor.is_empty());
    }

    /// Requests that differ only in a query parameter must not collide: the
    /// second must receive its own body, not a replay of the first. The old
    /// `method:path` key ignored the query string entirely, so `?q=cats` and
    /// `?q=dogs` shared one entry.
    #[tokio::test]
    async fn test_cache_interceptor_query_params_distinct() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let req_cats = HttpRequest::new("GET", "/search?q=cats");
        let first = interceptor
            .intercept(
                ExecutionContext::new(req_cats),
                counting_next(calls.clone(), 200, b"cats-result"),
            )
            .await
            .unwrap();
        assert_eq!(first.body_ref(), b"cats-result");

        let req_dogs = HttpRequest::new("GET", "/search?q=dogs");
        let second = interceptor
            .intercept(
                ExecutionContext::new(req_dogs),
                counting_next(calls.clone(), 200, b"dogs-result"),
            )
            .await
            .unwrap();
        // Must be the dogs handler's body, not a replay of the cats entry.
        assert_eq!(second.body_ref(), b"dogs-result");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    fn cookie_next(
        calls: Arc<AtomicUsize>,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>> {
        Box::pin(async move {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let mut resp = HttpResponse::ok();
            resp.body = Bytes::from(format!("user-{n}").into_bytes());
            resp.headers
                .insert("Cache-Control".to_string(), "public".to_string());
            resp.cookies.push(format!("session=secret-{n}; HttpOnly"));
            Ok(resp)
        })
    }

    /// A response carrying a `Set-Cookie` holds per-user session state and must
    /// never be cached: the handler must be re-invoked on the next request and
    /// user A's cookie must never be replayed to user B.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_set_cookie() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let first = interceptor
            .intercept(
                ExecutionContext::new(HttpRequest::new("GET", "/me")),
                cookie_next(calls.clone()),
            )
            .await
            .unwrap();
        assert_eq!(first.body_ref(), b"user-0");
        assert_eq!(
            first.cookies,
            vec!["session=secret-0; HttpOnly".to_string()]
        );

        // Second request must NOT be served user-0's body or cookie from cache.
        let second = interceptor
            .intercept(
                ExecutionContext::new(HttpRequest::new("GET", "/me")),
                cookie_next(calls.clone()),
            )
            .await
            .unwrap();
        assert_eq!(second.body_ref(), b"user-1");
        assert_eq!(
            second.cookies,
            vec!["session=secret-1; HttpOnly".to_string()]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a Set-Cookie response must be re-fetched, never cached"
        );
        assert!(interceptor.is_empty());
    }

    /// Only safe methods (GET/HEAD) are cached. A cacheable-status POST must run
    /// its handler on every request and must not be stored.
    #[tokio::test]
    async fn test_cache_interceptor_skips_unsafe_methods() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("POST", "/submit"));
            interceptor
                .intercept(ctx, counting_next(calls.clone(), 200, b"ok"))
                .await
                .unwrap();
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(interceptor.is_empty(), "POST responses must not be cached");
    }

    // ---- Round 2 regression tests -----------------------------------------

    fn header_next(
        calls: Arc<AtomicUsize>,
        header_name: &'static str,
        header_value: &'static str,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>> {
        Box::pin(async move {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let mut resp = HttpResponse::ok();
            resp.body = Bytes::from(format!("body-{n}").into_bytes());
            // Explicitly shareable, so a refusal is down to the header under
            // test (which overwrites this line when it is `Cache-Control`).
            resp.headers
                .insert("Cache-Control".to_string(), "public".to_string());
            resp.headers
                .insert(header_name.to_string(), header_value.to_string());
            Ok(resp)
        })
    }

    /// FIX A (RED->GREEN): HTTP header names are case-insensitive and nothing
    /// normalizes response header casing before it reaches the cache. A
    /// response carrying a lowercased `cache-control: private` must be refused
    /// exactly like the canonically-cased form.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_lowercase_cache_control_private() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/private"));
            interceptor
                .intercept(ctx, header_next(calls.clone(), "cache-control", "private"))
                .await
                .unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a lowercased Cache-Control: private response must never be cached"
        );
        assert!(interceptor.is_empty());
    }

    /// FIX A (RED->GREEN): same as above for the `no-store` directive, and for
    /// a value with mixed case and trailing directives (`No-Store, max-age=0`).
    #[tokio::test]
    async fn test_cache_interceptor_refuses_lowercase_cache_control_no_store() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/no-store"));
            interceptor
                .intercept(
                    ctx,
                    header_next(calls.clone(), "cache-control", "No-Store, max-age=0"),
                )
                .await
                .unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a lowercased Cache-Control: no-store response must never be cached"
        );
        assert!(interceptor.is_empty());
    }

    /// FIX A (RED->GREEN): the `Set-Cookie` *header* check (independent of the
    /// `response.cookies` backstop) must also be case-insensitive.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_lowercase_set_cookie_header() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/lc-cookie"));
            interceptor
                .intercept(
                    ctx,
                    header_next(calls.clone(), "set-cookie", "session=abc; HttpOnly"),
                )
                .await
                .unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a lowercased set-cookie header must never be cached"
        );
        assert!(interceptor.is_empty());
    }

    /// FIX B (RED->GREEN): two requests whose DECODED query params differ —
    /// `{"a": "1&b=2"}` (what `?a=1%26b%3D2` decodes to) vs.
    /// `{"a": "1", "b": "2"}` (what `?a=1&b=2` decodes to) — must not collide
    /// on the same cache key. The old joiner concatenated raw decoded values
    /// with literal unescaped `&`/`=`, so both produced the literal string
    /// `a=1&b=2` and shared one entry.
    #[tokio::test]
    async fn test_cache_interceptor_query_delimiter_injection_distinct() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let req_encoded = HttpRequest::new("GET", "/inject?a=1%26b%3D2");
        let first = interceptor
            .intercept(
                ExecutionContext::new(req_encoded),
                counting_next(calls.clone(), 200, b"encoded-result"),
            )
            .await
            .unwrap();
        assert_eq!(first.body_ref(), b"encoded-result");

        let req_plain = HttpRequest::new("GET", "/inject?a=1&b=2");
        let second = interceptor
            .intercept(
                ExecutionContext::new(req_plain),
                counting_next(calls.clone(), 200, b"plain-result"),
            )
            .await
            .unwrap();

        // Must be the plain handler's own body, not a replay of the encoded entry.
        assert_eq!(second.body_ref(), b"plain-result");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "delimiter-colliding decoded query params must not share a cache entry"
        );
    }

    // ---- Round 2 audit fixes: C1 (Vary/Content-Encoding) & C2 (path/? key) --

    /// C1 (RED->GREEN): the interceptor key never folds in request headers
    /// (no `Accept-Encoding`), so a response carrying `Content-Encoding` is a
    /// negotiated representation the key can't distinguish. It must never be
    /// cached: the handler must be re-invoked on every request.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_content_encoding() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/gz"));
            interceptor
                .intercept(ctx, header_next(calls.clone(), "Content-Encoding", "gzip"))
                .await
                .unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a Content-Encoding response must never be cached"
        );
        assert!(interceptor.is_empty());
    }

    /// C1 (RED->GREEN): same rationale for `Vary` — a response that varies by
    /// a header the key ignores must not be stored here.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_vary() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let ctx = ExecutionContext::new(HttpRequest::new("GET", "/vary"));
            interceptor
                .intercept(ctx, header_next(calls.clone(), "Vary", "Accept-Encoding"))
                .await
                .unwrap();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a Vary response must never be cached"
        );
        assert!(interceptor.is_empty());
    }

    /// C2 (RED->GREEN): a `path` containing a literal `?` must not collide
    /// with a different, shorter path plus query parameters that happen to
    /// naively join to the same string. Under the old `METHOD:path` + `?` +
    /// length-prefixed-params join (no length prefix on the path itself),
    /// path `"/a?1:b=1:c&"` (no query params) and path `"/a"` with query
    /// `{"b": "c"}` both serialized to `"GET:/a?1:b=1:c&"`. Length-prefixing
    /// the path fixes this: the two now carry different path-length prefixes
    /// (`11` vs. `2`) and can never collide.
    #[tokio::test]
    async fn test_cache_interceptor_path_query_boundary_distinct() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let req_literal_path = HttpRequest::new("GET", "/a?1:b=1:c&");
        let first = interceptor
            .intercept(
                ExecutionContext::new(req_literal_path),
                counting_next(calls.clone(), 200, b"path-result"),
            )
            .await
            .unwrap();
        assert_eq!(first.body_ref(), b"path-result");

        let req_path_plus_query = HttpRequest::new("GET", "/a?b=c");
        let second = interceptor
            .intercept(
                ExecutionContext::new(req_path_plus_query),
                counting_next(calls.clone(), 200, b"query-result"),
            )
            .await
            .unwrap();

        // Must be the second handler's own body, not a replay of the first.
        assert_eq!(second.body_ref(), b"query-result");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a path containing a literal '?' must not collide with a distinct path+query"
        );
        assert_eq!(interceptor.len(), 2);
    }

    // ---- Security hardening ------------------------------------------------

    fn with_header(mut request: HttpRequest, name: &str, value: &str) -> HttpRequest {
        request.headers.append(name, value.to_string());
        request
    }

    /// A request carrying credentials gets a per-caller answer the key can't
    /// tell apart, so it must neither be served from nor populate the cache.
    #[tokio::test]
    async fn test_cache_interceptor_bypasses_credentialed_requests() {
        for header in ["Authorization", "Cookie"] {
            let interceptor = CacheInterceptor::new(60);
            let calls = Arc::new(AtomicUsize::new(0));

            let alice = with_header(HttpRequest::new("GET", "/me"), header, "alice");
            let first = interceptor
                .intercept(
                    ExecutionContext::new(alice),
                    counting_next(calls.clone(), 200, b"alice"),
                )
                .await
                .unwrap();
            assert_eq!(first.body_ref(), b"alice");
            assert!(interceptor.is_empty(), "{header}: must not store");

            // Even with something already cached for the path, a credentialed
            // request goes to the handler.
            interceptor
                .intercept(
                    ExecutionContext::new(HttpRequest::new("GET", "/me")),
                    counting_next(calls.clone(), 200, b"anon"),
                )
                .await
                .unwrap();
            let bob = with_header(HttpRequest::new("GET", "/me"), header, "bob");
            let second = interceptor
                .intercept(
                    ExecutionContext::new(bob),
                    counting_next(calls.clone(), 200, b"bob"),
                )
                .await
                .unwrap();
            assert_eq!(
                second.body_ref(),
                b"bob",
                "{header}: must not be served a hit"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }
    }

    /// `no-cache` means "revalidate before every reuse"; this cache never
    /// revalidates, so it must not store such a response.
    #[tokio::test]
    async fn test_cache_interceptor_refuses_no_cache() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            interceptor
                .intercept(
                    ExecutionContext::new(HttpRequest::new("GET", "/nc")),
                    header_next(calls.clone(), "Cache-Control", "no-cache"),
                )
                .await
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(interceptor.is_empty());
    }

    /// Differently-cased Cache-Control lines coexist in the response map; a
    /// `private` on either must win over a `public` on the other, whatever
    /// order the map iterates them in.
    #[test]
    fn test_must_not_cache_sees_every_cache_control_line() {
        for (a, b) in [("public", "private"), ("private", "public")] {
            let mut resp = HttpResponse::ok();
            resp.headers
                .insert("Cache-Control".to_string(), a.to_string());
            resp.headers
                .insert("cache-control".to_string(), b.to_string());
            assert!(must_not_cache(&resp), "{a} / {b}");
        }
        let mut resp = HttpResponse::ok();
        resp.headers
            .insert("Cache-Control".to_string(), "public".to_string());
        resp.headers
            .insert("CACHE-CONTROL".to_string(), "max-age=60".to_string());
        assert!(!must_not_cache(&resp));
    }

    /// Different virtual hosts must not share an entry for the same path.
    #[tokio::test]
    async fn test_cache_interceptor_keys_on_host() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));

        let a = with_header(HttpRequest::new("GET", "/"), "Host", "a.example");
        interceptor
            .intercept(
                ExecutionContext::new(a),
                counting_next(calls.clone(), 200, b"a"),
            )
            .await
            .unwrap();
        let b = with_header(HttpRequest::new("GET", "/"), "Host", "b.example");
        let resp = interceptor
            .intercept(
                ExecutionContext::new(b),
                counting_next(calls.clone(), 200, b"b"),
            )
            .await
            .unwrap();
        assert_eq!(resp.body_ref(), b"b");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Two `Host` lines: neither served nor stored.
        let dup = with_header(
            with_header(HttpRequest::new("GET", "/"), "Host", "a.example"),
            "Host",
            "b.example",
        );
        let resp = interceptor
            .intercept(
                ExecutionContext::new(dup),
                counting_next(calls.clone(), 200, b"dup"),
            )
            .await
            .unwrap();
        assert_eq!(resp.body_ref(), b"dup");
        assert_eq!(interceptor.len(), 2);
    }

    /// The store is bounded: distinct keys past capacity evict the oldest
    /// instead of growing the map without limit.
    #[tokio::test]
    async fn test_cache_interceptor_is_bounded() {
        let interceptor = CacheInterceptor::with_capacity(60, 2);
        let calls = Arc::new(AtomicUsize::new(0));
        for path in ["/1", "/2", "/3"] {
            interceptor
                .intercept(
                    ExecutionContext::new(HttpRequest::new("GET", path)),
                    counting_next(calls.clone(), 200, b"x"),
                )
                .await
                .unwrap();
        }
        assert_eq!(interceptor.len(), 2);

        // `/1` was the oldest, so it is the one that went.
        interceptor
            .intercept(
                ExecutionContext::new(HttpRequest::new("GET", "/1")),
                counting_next(calls.clone(), 200, b"x"),
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// Every credential header — not just `Authorization`/`Cookie` — and a
    /// verified identity attached by middleware make the request bypass the
    /// cache in both directions. Anti-CSRF tokens alone do not.
    #[tokio::test]
    async fn test_cache_interceptor_bypasses_all_credentials() {
        let credentialed: Vec<Box<dyn Fn() -> HttpRequest>> = vec![
            Box::new(|| with_header(HttpRequest::new("GET", "/me"), "X-Api-Key", "k")),
            Box::new(|| with_header(HttpRequest::new("GET", "/me"), "X-Auth-Token", "t")),
            Box::new(|| with_header(HttpRequest::new("GET", "/me"), "X-Session-Id", "s")),
            Box::new(|| {
                let mut r = HttpRequest::new("GET", "/me");
                r.extensions.insert(crate::VerifiedIdentity::new("alice"));
                r
            }),
            Box::new(|| {
                let mut r = HttpRequest::new("GET", "/me");
                r.extensions.insert(crate::RequestRoles::new(["admin"]));
                r
            }),
        ];
        for make in credentialed {
            let interceptor = CacheInterceptor::new(60);
            let calls = Arc::new(AtomicUsize::new(0));
            // Seed an anonymous entry, then make sure the credentialed request
            // is neither served it nor stores its own.
            interceptor
                .intercept(
                    ExecutionContext::new(HttpRequest::new("GET", "/me")),
                    counting_next(calls.clone(), 200, b"anon"),
                )
                .await
                .unwrap();
            let resp = interceptor
                .intercept(
                    ExecutionContext::new(make()),
                    counting_next(calls.clone(), 200, b"mine"),
                )
                .await
                .unwrap();
            assert_eq!(resp.body_ref(), b"mine", "{:?}", make());
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(interceptor.len(), 1);
        }

        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let req = with_header(HttpRequest::new("GET", "/p"), "X-CSRF-Token", "c");
            interceptor
                .intercept(
                    ExecutionContext::new(req),
                    counting_next(calls.clone(), 200, b"x"),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "CSRF token alone is cacheable"
        );
    }

    /// `host:443` and `host` may be different origins (`http://host:443` is
    /// not `http://host`), so they must not share an entry.
    #[tokio::test]
    async fn test_cache_interceptor_keeps_port_in_key() {
        let interceptor = CacheInterceptor::new(60);
        let calls = Arc::new(AtomicUsize::new(0));
        for (host, body) in [("h.example:443", &b"tls"[..]), ("h.example", b"plain")] {
            let resp = interceptor
                .intercept(
                    ExecutionContext::new(with_header(HttpRequest::new("GET", "/"), "Host", host)),
                    counting_next(calls.clone(), 200, body),
                )
                .await
                .unwrap();
            assert_eq!(resp.body_ref(), body);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Bodies over the per-entry limit pass through uncached, and the total
    /// byte budget evicts the oldest entries.
    #[tokio::test]
    async fn test_cache_interceptor_is_byte_bounded() {
        let interceptor = CacheInterceptor::new(60)
            .with_max_body_bytes(8)
            .with_max_total_bytes(64);
        let calls = Arc::new(AtomicUsize::new(0));
        interceptor
            .intercept(
                ExecutionContext::new(HttpRequest::new("GET", "/big")),
                counting_next(calls.clone(), 200, b"0123456789"),
            )
            .await
            .unwrap();
        assert!(interceptor.is_empty(), "oversized body must not be stored");

        // Each entry costs key (~12 bytes) + 8 body bytes; 64 bytes holds ~3.
        for i in 0..10 {
            let path = format!("/s{i}");
            interceptor
                .intercept(
                    ExecutionContext::new(HttpRequest::new("GET", path)),
                    counting_next(calls.clone(), 200, b"01234567"),
                )
                .await
                .unwrap();
            assert!(interceptor.total_bytes() <= 64);
        }
        assert!(interceptor.len() < 10 && !interceptor.is_empty());

        // Re-storing the same key doesn't double-count.
        let mut store = Store {
            entries: LruCache::new(NonZeroUsize::new(4).unwrap()),
            bytes: 0,
        };
        for _ in 0..3 {
            let mut r = HttpResponse::new(200);
            r.body = Bytes::from_static(b"abcd");
            store.insert("k".to_string(), r, 1024);
        }
        assert_eq!(store.bytes, 5);
        store.pop("k");
        assert_eq!(store.bytes, 0);
    }

    /// The key must tell apart queries the handler's `Query<T>` reads
    /// differently: an extra empty-key pair, and `%FF` vs a literal `%FF`.
    #[test]
    fn cache_key_distinguishes_empty_keys_and_invalid_utf8() {
        let key = |p: &str| cache_key(&HttpRequest::new("GET", p.to_string()));
        assert_ne!(key("/s?q=1&=x"), key("/s?q=1"));
        assert_ne!(key("/s?q=%FF"), key("/s?q=%25FF"));
    }

    /// Only a response the handler explicitly marked `public` / `s-maxage`
    /// is stored; one without a Cache-Control statement passes through, since
    /// an identity header the credential check doesn't know would otherwise
    /// let a per-caller body into the shared store.
    #[tokio::test]
    async fn test_cache_interceptor_stores_only_explicitly_public_responses() {
        fn next_with(
            calls: Arc<AtomicUsize>,
            cache_control: Option<&'static str>,
        ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>> {
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let mut resp = HttpResponse::ok();
                resp.body = Bytes::from_static(b"x");
                if let Some(cc) = cache_control {
                    resp.headers
                        .insert("cache-control".to_string(), cc.to_string());
                }
                Ok(resp)
            })
        }
        for (cc, stored) in [
            (None, false),
            (Some("max-age=60"), false),
            (Some("public"), true),
            (Some("Public, max-age=60"), true),
            (Some("s-maxage=60"), true),
            (Some("public, private"), false),
        ] {
            let interceptor = CacheInterceptor::new(60);
            let calls = Arc::new(AtomicUsize::new(0));
            for _ in 0..2 {
                // An unknown gateway identity header: not caught by name.
                let mut req = HttpRequest::new("GET", "/me");
                req.headers.insert("x-acme-gateway-user", "alice");
                interceptor
                    .intercept(ExecutionContext::new(req), next_with(calls.clone(), cc))
                    .await
                    .unwrap();
            }
            assert_eq!(!interceptor.is_empty(), stored, "{cc:?}");
            assert_eq!(calls.load(Ordering::SeqCst), if stored { 1 } else { 2 });
        }
    }
}
