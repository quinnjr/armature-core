// Middleware system for request/response processing

use crate::logging::{debug, error, info, trace};
use crate::{Error, HttpRequest, HttpResponse};
use async_trait::async_trait;
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

/// Type alias for the next handler in the middleware chain
pub type Next = Box<
    dyn FnOnce(HttpRequest) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        + Send,
>;

/// Type alias for handler functions
pub type HandlerFn = Arc<
    dyn Fn(HttpRequest) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        + Send
        + Sync,
>;

/// Middleware trait for processing requests before they reach the handler
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Process the request and optionally pass to next middleware
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error>;
}

/// Middleware chain executor
#[derive(Clone)]
pub struct MiddlewareChain {
    middlewares: Arc<Vec<Arc<dyn Middleware>>>,
}

impl MiddlewareChain {
    pub fn new() -> Self {
        Self {
            middlewares: Arc::new(Vec::new()),
        }
    }

    /// Add a middleware to the chain
    pub fn use_middleware<M: Middleware + 'static>(&mut self, middleware: M) {
        let mut mws = (*self.middlewares).clone();
        mws.push(Arc::new(middleware));
        self.middlewares = Arc::new(mws);
    }

    /// The number of middleware in the chain.
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }

    /// Whether the chain has no middleware.
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }

    /// Execute the middleware chain with a handler
    pub async fn apply(&self, req: HttpRequest, handler: HandlerFn) -> Result<HttpResponse, Error> {
        // Fast path: with no middleware there is no chain to build, so call the
        // handler directly and skip the per-index recursion and boxing.
        if self.middlewares.is_empty() {
            trace!("No middleware registered, calling handler directly");
            return handler(req).await;
        }

        debug!(
            middleware_count = self.middlewares.len(),
            path = %req.path_only(),
            method = %req.method,
            "Executing middleware chain"
        );
        self.execute_from(0, req, handler).await
    }

    fn execute_from(
        &self,
        index: usize,
        req: HttpRequest,
        handler: HandlerFn,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>> {
        if index >= self.middlewares.len() {
            // No more middleware, call the handler
            trace!("Middleware chain complete, calling handler");
            handler(req)
        } else {
            let middleware = self.middlewares[index].clone();
            let chain = self.clone();
            let handler_clone = handler.clone();

            trace!(middleware_index = index, "Executing middleware");
            Box::pin(async move {
                middleware
                    .handle(
                        req,
                        Box::new(move |req| chain.execute_from(index + 1, req, handler_clone)),
                    )
                    .await
            })
        }
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Built-in Middleware ==========

/// CORS (Cross-Origin Resource Sharing) middleware
///
/// A single static `allow_origin`. `Access-Control-Allow-Credentials: true` is
/// only ever sent alongside a **specific** origin: with the default wildcard
/// (`*`) it is withheld even if [`allow_credentials`](Self::allow_credentials)
/// is set, because that pair is invalid and browsers reject it. For a list of
/// origins, reflection, or regex matching use `armature-security`'s CORS, or
/// [`crate::micro::Cors`].
pub struct CorsMiddleware {
    pub allow_origin: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub allow_credentials: bool,
    pub max_age: u32,
}

impl CorsMiddleware {
    pub fn new() -> Self {
        Self {
            allow_origin: "*".to_string(),
            allow_methods: "GET, POST, PUT, DELETE, OPTIONS, PATCH".to_string(),
            allow_headers: "Content-Type, Authorization, Accept".to_string(),
            allow_credentials: false,
            max_age: 86400, // 24 hours
        }
    }

    pub fn allow_origin(mut self, origin: &str) -> Self {
        self.allow_origin = origin.to_string();
        self
    }

    pub fn allow_methods(mut self, methods: &str) -> Self {
        self.allow_methods = methods.to_string();
        self
    }

    pub fn allow_headers(mut self, headers: &str) -> Self {
        self.allow_headers = headers.to_string();
        self
    }

    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }
}

impl Default for CorsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        // Credentials never go out with a wildcard origin.
        let credentials = self.allow_credentials && self.allow_origin.trim() != "*";
        // A preflight is `OPTIONS` + `Origin` + `Access-Control-Request-Method`
        // (Fetch standard); any other `OPTIONS` is an ordinary request and is
        // routed.
        let is_preflight = req.method == "OPTIONS"
            && req.headers.contains_key("origin")
            && req.headers.contains_key("access-control-request-method");
        if is_preflight {
            let mut headers = HashMap::new();
            headers.insert(
                "Access-Control-Allow-Origin".to_string(),
                self.allow_origin.clone(),
            );
            headers.insert(
                "Access-Control-Allow-Methods".to_string(),
                self.allow_methods.clone(),
            );
            headers.insert(
                "Access-Control-Allow-Headers".to_string(),
                self.allow_headers.clone(),
            );
            headers.insert(
                "Access-Control-Max-Age".to_string(),
                self.max_age.to_string(),
            );

            if credentials {
                headers.insert(
                    "Access-Control-Allow-Credentials".to_string(),
                    "true".to_string(),
                );
            }

            return Ok(HttpResponse::with_status_and_headers(204, headers));
        }

        // Process request and add CORS headers to response
        let mut response = next(req).await?;

        response.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            self.allow_origin.clone(),
        );
        if credentials {
            response.headers.insert(
                "Access-Control-Allow-Credentials".to_string(),
                "true".to_string(),
            );
        }

        Ok(response)
    }
}

/// Logging middleware
///
/// Logs the request **path only**: the query string is never written, since it
/// routinely carries password-reset codes, OAuth `code`/`state`, API keys and
/// other bearer secrets that must not land in shipped logs.
pub struct LoggerMiddleware {
    /// Log the request body's *size* (`body_bytes`), not its contents.
    ///
    /// Request bodies routinely carry credentials, tokens and PII, and logs are
    /// shipped to places with a wider audience than the service itself, so only
    /// the byte count is recorded here. If you need to see the payload during
    /// development, use [`LoggingMiddleware::with_request_body`], which logs a
    /// truncated, deliberately opt-in body preview.
    pub log_body: bool,
}

impl LoggerMiddleware {
    pub fn new() -> Self {
        Self { log_body: false }
    }

    /// Record the request body's *size* (`body_bytes`) alongside each request.
    ///
    /// This does not log the body's contents: bodies routinely carry
    /// credentials, tokens and PII, and logs are shipped to places with a wider
    /// audience than the service itself, so the size is logged instead. For a
    /// truncated preview of the actual payload, use
    /// [`LoggingMiddleware::with_request_body`].
    pub fn with_body(mut self) -> Self {
        self.log_body = true;
        self
    }
}

impl Default for LoggerMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for LoggerMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        let start = std::time::Instant::now();
        let method = req.method.clone();
        // Path only: the query string can carry secrets (see the type docs).
        let path = req.path_only().to_owned();

        if self.log_body && !req.body.is_empty() {
            info!(
                method = %method,
                path = %path,
                body_bytes = req.body.len(),
                "request received"
            );
        } else {
            info!(method = %method, path = %path, "request received");
        }

        let result = next(req).await;
        let duration = start.elapsed();

        match &result {
            Ok(response) => {
                info!(
                    method = %method,
                    path = %path,
                    status = response.status,
                    duration_ms = duration.as_millis(),
                    "response sent"
                );
            }
            Err(e) => {
                error!(
                    method = %method,
                    path = %path,
                    error = %e.log_display(),
                    duration_ms = duration.as_millis(),
                    "request failed"
                );
            }
        }

        result
    }
}

/// Request ID middleware
pub struct RequestIdMiddleware;

#[async_trait]
impl Middleware for RequestIdMiddleware {
    async fn handle(&self, mut req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        // Generate or use existing request ID
        // A client-supplied ID is reflected into the response, so it is only
        // reused when well-formed; anything else is replaced with a fresh one.
        let request_id = req
            .headers
            .get("x-request-id")
            .filter(|id| crate::headers::is_valid_request_id(id))
            .map(str::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        req.headers.insert("x-request-id", request_id.as_str());

        let mut response = next(req).await?;
        response
            .headers
            .insert("x-request-id".to_string(), request_id);

        Ok(response)
    }
}

/// Body size limit middleware
pub struct BodySizeLimitMiddleware {
    max_size: usize,
}

impl BodySizeLimitMiddleware {
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

#[async_trait]
impl Middleware for BodySizeLimitMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        if req.body.len() > self.max_size {
            return Err(Error::PayloadTooLarge(format!(
                "Request body exceeds maximum size of {} bytes",
                self.max_size
            )));
        }

        next(req).await
    }
}

// TimeoutMiddleware is now defined in the `timeout` module with more features.
// Re-exported from crate::timeout::{TimeoutMiddleware, ConfigurableTimeoutMiddleware, TimeoutConfig}

/// Security headers middleware
///
/// Sets `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
/// `X-Frame-Options: DENY` and `X-XSS-Protection: 0`.
///
/// `X-XSS-Protection` is sent as `0` (filter off), per OWASP: the legacy
/// browser XSS auditor that `1; mode=block` switched on could itself be
/// abused to detect or block page content cross-site (XS-leaks), and modern
/// browsers have removed it. Use a `Content-Security-Policy` instead.
pub struct SecurityHeadersMiddleware {
    hsts_enabled: bool,
    nosniff_enabled: bool,
    xss_protection_enabled: bool,
    frame_options: Option<String>,
}

impl SecurityHeadersMiddleware {
    pub fn new() -> Self {
        Self {
            hsts_enabled: true,
            nosniff_enabled: true,
            xss_protection_enabled: true,
            frame_options: Some("DENY".to_string()),
        }
    }

    pub fn with_hsts(mut self, enabled: bool) -> Self {
        self.hsts_enabled = enabled;
        self
    }

    pub fn with_frame_options(mut self, value: &str) -> Self {
        self.frame_options = Some(value.to_string());
        self
    }
}

impl Default for SecurityHeadersMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for SecurityHeadersMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        let mut response = next(req).await?;

        if self.hsts_enabled {
            response.headers.insert(
                "Strict-Transport-Security".to_string(),
                "max-age=31536000; includeSubDomains".to_string(),
            );
        }

        if self.nosniff_enabled {
            response
                .headers
                .insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        }

        if self.xss_protection_enabled {
            response
                .headers
                .insert("X-XSS-Protection".to_string(), "0".to_string());
        }

        if let Some(frame_opts) = &self.frame_options {
            response
                .headers
                .insert("X-Frame-Options".to_string(), frame_opts.clone());
        }

        Ok(response)
    }
}

/// Gzip-compression middleware.
///
/// Compresses response bodies larger than `min_size` with gzip when the client's
/// `Accept-Encoding` permits it, setting `Content-Encoding: gzip` and merging
/// `Accept-Encoding` into `Vary` — merged rather than overwritten, so a
/// pre-existing `Vary` (e.g. `Vary: Origin` from CORS middleware upstream)
/// survives. Small bodies, bodies that are already content-encoded, and
/// clients that do not accept gzip are passed through unchanged (but still
/// gain `Vary`).
///
/// # BREACH
///
/// Compressing a response that reflects attacker-influenced input next to a
/// secret (a CSRF token, a session ID) lets an attacker who can observe
/// ciphertext lengths recover the secret byte by byte (BREACH). By default
/// this middleware therefore leaves uncompressed any response that looks
/// secret-bearing: one that sets a cookie (`Set-Cookie`) or is marked
/// `Cache-Control: no-store` or `private`. Override the decision with
/// [`skip_when`](Self::skip_when); routes that echo user input alongside
/// secrets in an ordinary cacheable response still need application-level
/// mitigation (e.g. per-response masking of CSRF tokens).
pub struct CompressionMiddleware {
    min_size: usize,
    level: crate::micro::CompressionLevel,
    skip: CompressionSkip,
}

type CompressionSkip = Arc<dyn Fn(&HttpResponse) -> bool + Send + Sync>;

/// The default BREACH heuristic: skip responses that carry a cookie or are
/// marked non-shareable, which is where per-user secrets live.
///
/// Cookies count wherever they are: `HttpResponse::cookie`/`set_cookie`/
/// `cookie_raw` put them in `response.cookies`, not in `headers`, and that is
/// the usual way a session cookie gets set. A directive is matched on its
/// name alone, so `private="Set-Cookie"` and `no-store=...` count too. Same
/// rule as the micro server's compression path.
pub fn is_likely_secret_bearing(response: &HttpResponse) -> bool {
    if !response.cookies.is_empty() {
        return true;
    }
    response.headers.iter().any(|(name, value)| {
        if name.eq_ignore_ascii_case("set-cookie") {
            return true;
        }
        name.eq_ignore_ascii_case("cache-control")
            && value.split(',').any(|directive| {
                let d = directive.split('=').next().unwrap_or("").trim();
                d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("private")
            })
    })
}

impl CompressionMiddleware {
    pub fn new() -> Self {
        Self {
            min_size: 1024, // Only compress responses > 1KB
            level: crate::micro::CompressionLevel::Default,
            skip: Arc::new(is_likely_secret_bearing),
        }
    }

    /// Replace the predicate that decides which responses are left
    /// uncompressed (default: [`is_likely_secret_bearing`]). Return `true`
    /// to skip compression for that response.
    pub fn skip_when<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&HttpResponse) -> bool + Send + Sync + 'static,
    {
        self.skip = Arc::new(predicate);
        self
    }

    pub fn with_min_size(mut self, size: usize) -> Self {
        self.min_size = size;
        self
    }

    /// Set the gzip compression level.
    pub fn with_level(mut self, level: crate::micro::CompressionLevel) -> Self {
        self.level = level;
        self
    }
}

impl Default for CompressionMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for CompressionMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        // Negotiate before `req` is consumed by the handler.
        let client_accepts_gzip = crate::micro::accepts_gzip(&req);
        let mut response = next(req).await?;

        // Advertise Accept-Encoding as a cache-varying dimension regardless of
        // whether we compress this particular response. Merges with any
        // pre-existing `Vary` (e.g. `Vary: Origin` from CORS middleware
        // upstream) instead of clobbering it.
        crate::micro::add_vary_accept_encoding(&mut response);

        let already_encoded = response.headers.contains_key("Content-Encoding");
        if client_accepts_gzip
            && !already_encoded
            && response.body_ref().len() > self.min_size
            && !(self.skip)(&response)
        {
            response = crate::micro::apply_gzip_offload(response, self.level).await;
        }

        Ok(response)
    }
}

/// HTTP Request/Response Logging Middleware
///
/// Automatically logs HTTP requests and responses with configurable detail level.
/// Logs include method, path, status code, duration, and optional request/response bodies.
/// The path is logged without its query string, which routinely carries secrets
/// (reset codes, OAuth `code`, API keys).
///
/// Body logging is off by default. When enabled, a body is redacted
/// *structurally*, chosen by its `Content-Type`:
///
/// - JSON (`application/json`, `*+json`): parsed, and the whole value of any
///   member whose key names a credential (`password`, `user.password`,
///   `authToken`, `pin_code`, ... — object and array values included) is
///   replaced with `"[FILTERED]"`, recursively, including JSON embedded in
///   string values.
/// - `application/x-www-form-urlencoded`: decoded pair by pair; a sensitive
///   field name (`password`, `user[password]`, `user%5Bpassword%5D`, a bare
///   OAuth `code`) has its value replaced.
/// - `multipart/form-data`: only part names and sizes are logged.
/// - Anything else, or a body that does not parse as its declared type, or
///   one too large to parse: only `<N bytes>` is logged (fail closed).
///
/// Redaction is by field name and cannot recognize a secret in a field it
/// has no reason to suspect, so leave body logging off in production.
///
/// # Examples
///
/// ```no_run
/// use armature_core::{MiddlewareChain, LoggingMiddleware};
///
/// let mut chain = MiddlewareChain::new();
/// chain.use_middleware(LoggingMiddleware::new());
/// ```
pub struct LoggingMiddleware {
    /// Log request bodies
    pub log_request_body: bool,
    /// Log response bodies
    pub log_response_body: bool,
    /// Maximum body size to log (in bytes)
    pub max_body_size: usize,
}

impl LoggingMiddleware {
    /// Create a new logging middleware with default settings
    pub fn new() -> Self {
        Self {
            log_request_body: false,
            log_response_body: false,
            max_body_size: 1024, // 1KB
        }
    }

    /// Enable request body logging
    pub fn with_request_body(mut self, enable: bool) -> Self {
        self.log_request_body = enable;
        self
    }

    /// Enable response body logging
    pub fn with_response_body(mut self, enable: bool) -> Self {
        self.log_response_body = enable;
        self
    }

    /// Set maximum body size to log
    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }
}

/// How far past the preview limit a body may run and still be parsed for
/// redaction. Structural redaction needs the whole body (a truncated JSON
/// document does not parse), so this bounds the work logging one request
/// can cost; a larger body logs as `<N bytes>`.
const BODY_REDACTION_SLACK: usize = 64 * 1024;

/// How many levels of JSON-inside-a-JSON-string are unpacked and redacted.
/// Deeper nesting is logged as `<N bytes>` rather than trusted.
const EMBEDDED_JSON_DEPTH: usize = 4;

/// How many strings, numbers and form values one body may run through the
/// value redactor. Each is a regex scan on the async worker, and a body of
/// thousands of tiny values would otherwise cost thousands of them; past the
/// budget the body is withheld instead.
const REDACTION_LEAF_BUDGET: usize = 4096;

/// Shorter text cannot hold anything the value redactor matches (the
/// shortest, `pw=x`, is four bytes), so it skips the redactor and the budget.
const MIN_REDACTABLE_LEN: usize = 4;

/// The body shapes [`body_log_preview`] knows how to redact structurally.
enum BodyKind<'a> {
    Json,
    Form,
    /// Carries the full `Content-Type`, which holds the boundary.
    Multipart(&'a str),
}

impl<'a> BodyKind<'a> {
    fn of(content_type: Option<&'a str>) -> Option<Self> {
        let content_type = content_type?;
        let essence = content_type.split(';').next().unwrap_or("").trim();
        let essence = essence.to_ascii_lowercase();
        if essence == "application/json"
            || (essence.starts_with("application/") && essence.ends_with("+json"))
        {
            Some(Self::Json)
        } else if essence == "application/x-www-form-urlencoded" {
            Some(Self::Form)
        } else if essence == "multipart/form-data" {
            Some(Self::Multipart(content_type))
        } else {
            None
        }
    }
}

/// Replace the value of every credential-named member of `value`, whatever
/// its type, with `"[FILTERED]"`; recurse into everything else. `None` once
/// `budget` (see [`REDACTION_LEAF_BUDGET`]) runs out.
fn redact_json_value(
    value: &mut serde_json::Value,
    depth: usize,
    budget: &mut usize,
) -> Option<()> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            for (key, member) in map.iter_mut() {
                if crate::error_transform::is_sensitive_key(key) {
                    *member = Value::String("[FILTERED]".to_owned());
                } else {
                    redact_json_value(member, depth, budget)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item, depth, budget)?;
            }
        }
        Value::String(text) => {
            if let Cow::Owned(redacted) = redact_json_string(text, depth, budget)? {
                *text = redacted;
            }
        }
        // Numbers get the same value patterns as strings: a card number or
        // SSN sent bare (`"card":4111111111111111`) is as sensitive as one
        // sent quoted, and a key-name list cannot anticipate every field.
        Value::Number(number) => {
            let text = number.to_string();
            if text.len() >= MIN_REDACTABLE_LEN {
                *budget = budget.checked_sub(1)?;
                if let Cow::Owned(filtered) = crate::error_transform::redact_sensitive(&text) {
                    *value = Value::String(filtered);
                }
            }
        }
        _ => {}
    }
    Some(())
}

/// A JSON string value as it may be logged. One that itself holds JSON —
/// an object or array (`"{\"password\":\"x\"}"`), or a JSON-encoded string
/// of one (double-stringified) — is parsed and redacted structurally, up to
/// [`EMBEDDED_JSON_DEPTH`] levels; past that it is replaced by its size.
/// Anything else goes through [`redact_text`].
fn redact_json_string<'a>(text: &'a str, depth: usize, budget: &mut usize) -> Option<Cow<'a, str>> {
    if text.len() < MIN_REDACTABLE_LEN {
        return Some(Cow::Borrowed(text));
    }
    *budget = budget.checked_sub(1)?;
    if text.trim_start().starts_with(['{', '[', '"']) {
        let Some(depth) = depth.checked_sub(1) else {
            return Some(Cow::Owned(format!("<{} bytes>", text.len())));
        };
        if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(text) {
            redact_json_value(&mut inner, depth, budget)?;
            return Some(Cow::Owned(inner.to_string()));
        }
    }
    Some(redact_text(text))
}

/// Free text (a non-JSON string value or a form value) as it may be logged:
/// the shared value patterns, then a fail-closed check. If a credential key
/// still sits in quotes without a `[FILTERED]` value after it — Python repr
/// (`{'password': 'x'}`), stray escapes (`\"token\": \"x\"`), or any shape
/// the patterns do not know — the whole text is withheld rather than trusted.
///
/// `Cow::Borrowed` means "unchanged": callers keep the original text then.
fn redact_text(text: &str) -> Cow<'_, str> {
    // A quoted key needs a quote: most text skips the second scan.
    let filtered = crate::error_transform::redact_sensitive(text);
    if filtered.contains(['"', '\'']) && has_unredacted_quoted_key(&filtered) {
        return Cow::Owned("[WITHHELD]".to_owned());
    }
    filtered
}

/// Whether `text` holds a quoted, credential-named key (see
/// [`crate::error_transform::is_sensitive_key`]) not followed by the
/// `[FILTERED]` marker the value patterns leave behind.
fn has_unredacted_quoted_key(text: &str) -> bool {
    static QUOTED_KEY: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
        let re = regex::Regex::new(r#"[\\'"]([A-Za-z0-9_.\[\]-]{1,128})\\?['"]"#);
        debug_assert!(re.is_ok(), "bad quoted-key pattern: {re:?}");
        re.ok()
    });
    // Unable to look: assume the worst.
    let Some(re) = QUOTED_KEY.as_ref() else {
        return true;
    };
    re.captures_iter(text).any(|caps| {
        let (Some(whole), Some(key)) = (caps.get(0), caps.get(1)) else {
            return false;
        };
        crate::error_transform::is_sensitive_key(key.as_str())
            && !text[whole.end()..]
                .trim_start_matches(['\\', '\'', '"', ':', '=', ' ', '\t'])
                .starts_with("[FILTERED]")
    })
}

/// Whether a urlencoded field name names a credential. Besides the shared
/// key test, a bare `code` (as the whole name or its last bracket segment) is
/// the OAuth authorization code here, not an error code as it is in JSON.
fn is_sensitive_form_key(key: &str) -> bool {
    let last = key.rsplit('[').next().unwrap_or(key).trim_end_matches(']');
    crate::error_transform::is_sensitive_key(key) || last.eq_ignore_ascii_case("code")
}

/// Whether a decoded form or multipart field name looks like one. Names are
/// logged verbatim, so one that does not is likely the real content of a
/// mislabeled body — JSON sent as a form (`{"password":"x"}` parses as one
/// pair whose *name* is the whole document), or multipart text — and the
/// body is withheld rather than logged through a name nobody redacts.
fn is_plausible_field_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'[' | b']' | b'-'))
}

/// The full redacted rendering of `body`, or `None` if it cannot be shown
/// safely (unknown type, or it does not parse as the declared one).
fn redact_body(kind: BodyKind<'_>, body: &[u8]) -> Option<String> {
    match kind {
        BodyKind::Json => {
            let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
            redact_json_value(&mut value, EMBEDDED_JSON_DEPTH, &mut {
                REDACTION_LEAF_BUDGET
            })?;
            Some(value.to_string())
        }
        BodyKind::Form => {
            // Same decoding the handler's `Form`/`Query` readers use, so the
            // name tested is the name the application sees: `user%5Bpassword%5D`
            // is `user[password]` here.
            let text = std::str::from_utf8(body).ok()?;
            let pairs = crate::query::parse(text);
            if !pairs.iter().all(|(key, _)| is_plausible_field_name(key)) {
                return None;
            }
            let mut budget = REDACTION_LEAF_BUDGET;
            let mut rendered = Vec::with_capacity(pairs.len());
            for (key, value) in pairs.iter() {
                let value = if is_sensitive_form_key(key) {
                    "[FILTERED]".to_owned()
                } else {
                    if value.len() >= MIN_REDACTABLE_LEN {
                        budget = budget.checked_sub(1)?;
                    }
                    urlencoding::encode(&redact_text(value)).into_owned()
                };
                rendered.push(format!("{}={value}", urlencoding::encode(key)));
            }
            Some(rendered.join("&"))
        }
        BodyKind::Multipart(content_type) => {
            let parser = crate::form::MultipartParser::from_content_type(content_type).ok()?;
            let mut parts = Vec::new();
            for field in parser.parts(body) {
                let field = field.ok()?;
                if !is_plausible_field_name(&field.name) {
                    return None;
                }
                let size = match (&field.file, &field.value) {
                    (Some(file), _) => file.data.len(),
                    (None, Some(value)) => value.len(),
                    (None, None) => 0,
                };
                parts.push(format!(
                    "{}=<{size} bytes>",
                    urlencoding::encode(&field.name)
                ));
            }
            Some(format!("multipart[{}]", parts.join(", ")))
        }
    }
}

/// A truncated, structurally redacted view of `body` for logging, chosen by
/// its `Content-Type` (see [`LoggingMiddleware`]).
///
/// Redacts first, then truncates: truncating first would leave a JSON body
/// unparseable and cut a secret in half at the limit. A body too large to
/// parse within the redaction budget, of an unrecognized type, or that fails
/// to parse logs as `<N bytes>` only.
fn body_log_preview(content_type: Option<&str>, body: &[u8], max: usize) -> String {
    let withheld = || format!("<{} bytes>", body.len());
    if body.len() > max.saturating_add(BODY_REDACTION_SLACK) {
        return withheld();
    }
    let Some(redacted) = BodyKind::of(content_type).and_then(|kind| redact_body(kind, body)) else {
        return withheld();
    };
    if redacted.len() > max {
        // Cut on a char boundary at or below `max`.
        let mut end = max.min(redacted.len());
        while !redacted.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... ({} bytes)", &redacted[..end], body.len())
    } else {
        redacted
    }
}

impl Default for LoggingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(&self, req: HttpRequest, next: Next) -> Result<HttpResponse, Error> {
        use std::time::Instant;

        let start = Instant::now();
        let method = req.method.clone();
        // Path only: the query string can carry secrets (see the type docs).
        let path = req.path_only().to_owned();

        // Log request
        if self.log_request_body && !req.body.is_empty() {
            // One unambiguous Content-Type, or the body is withheld: two
            // lines leave which parser the application used a guess.
            let content_type = match req.headers.get_all("content-type").as_slice() {
                [one] => Some(*one),
                _ => None,
            };
            let body_preview = body_log_preview(content_type, &req.body, self.max_body_size);

            crate::logging::info!(
                method = %method,
                path = %path,
                body = %body_preview,
                "HTTP request received"
            );
        } else {
            crate::logging::info!(
                method = %method,
                path = %path,
                "HTTP request received"
            );
        }

        // Process request
        let result = next(req).await;
        let duration = start.elapsed();

        // Log response
        match &result {
            Ok(response) => {
                if self.log_response_body && !response.body.is_empty() {
                    // Response header names are case-sensitive map keys
                    // here, so look across every casing; more than one line
                    // withholds the body.
                    let mut types = response
                        .headers
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                        .map(|(_, value)| value.as_str());
                    let content_type = match (types.next(), types.next()) {
                        (Some(one), None) => Some(one),
                        _ => None,
                    };
                    let body_preview =
                        body_log_preview(content_type, &response.body, self.max_body_size);

                    crate::logging::info!(
                        method = %method,
                        path = %path,
                        status = response.status,
                        duration_ms = duration.as_millis(),
                        body = %body_preview,
                        "HTTP response sent"
                    );
                } else {
                    crate::logging::info!(
                        method = %method,
                        path = %path,
                        status = response.status,
                        duration_ms = duration.as_millis(),
                        "HTTP response sent"
                    );
                }
            }
            Err(err) => {
                crate::logging::error!(
                    method = %method,
                    path = %path,
                    duration_ms = duration.as_millis(),
                    error = %err.log_display(),
                    "HTTP request failed"
                );
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn compression_skips_secret_bearing_responses_by_default() {
        fn gzip_req() -> HttpRequest {
            let mut req = HttpRequest::new("GET", "/".to_string());
            req.headers.insert("accept-encoding", "gzip");
            req
        }
        let big = vec![b'a'; 4096];

        let body = big.clone();
        let next: Next = Box::new(move |_req| {
            Box::pin(async move {
                let mut r = HttpResponse::ok().with_body(body);
                r.headers
                    .insert("Set-Cookie".to_string(), "sid=1".to_string());
                Ok(r)
            })
        });
        let resp = CompressionMiddleware::new()
            .handle(gzip_req(), next)
            .await
            .unwrap();
        assert!(!resp.headers.contains_key("Content-Encoding"));

        let body = big.clone();
        let next: Next = Box::new(move |_req| {
            Box::pin(async move {
                let mut r = HttpResponse::ok().with_body(body);
                r.headers.insert(
                    "cache-control".to_string(),
                    "max-age=0, Private".to_string(),
                );
                Ok(r)
            })
        });
        let resp = CompressionMiddleware::new()
            .handle(gzip_req(), next)
            .await
            .unwrap();
        assert!(!resp.headers.contains_key("Content-Encoding"));

        let body = big.clone();
        let next: Next =
            Box::new(move |_req| Box::pin(async move { Ok(HttpResponse::ok().with_body(body)) }));
        let resp = CompressionMiddleware::new()
            .handle(gzip_req(), next)
            .await
            .unwrap();
        assert!(resp.headers.contains_key("Content-Encoding"));

        let body = big.clone();
        let next: Next =
            Box::new(move |_req| Box::pin(async move { Ok(HttpResponse::ok().with_body(body)) }));
        let resp = CompressionMiddleware::new()
            .skip_when(|_| true)
            .handle(gzip_req(), next)
            .await
            .unwrap();
        assert!(!resp.headers.contains_key("Content-Encoding"));
    }

    #[tokio::test]
    async fn request_id_middleware_replaces_malformed_inbound_id() {
        let mut req = HttpRequest::new("GET", "/".to_string());
        req.headers.insert("x-request-id", "bad id<script>");
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        let response = RequestIdMiddleware.handle(req, next).await.unwrap();
        let echoed = response.headers.get("x-request-id").unwrap();
        assert_ne!(echoed, "bad id<script>");
        assert!(crate::headers::is_valid_request_id(echoed));

        let mut req = HttpRequest::new("GET", "/".to_string());
        req.headers.insert("x-request-id", "req-42");
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        let response = RequestIdMiddleware.handle(req, next).await.unwrap();
        assert_eq!(
            response.headers.get("x-request-id").map(String::as_str),
            Some("req-42")
        );
    }

    const JSON: Option<&str> = Some("application/json");
    const FORM: Option<&str> = Some("application/x-www-form-urlencoded");

    #[test]
    fn logged_bodies_are_redacted() {
        let body = br#"{"user":"a","password":"hunter2","api_key":"k-1"}"#;
        let out = body_log_preview(JSON, body, 1024);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(!out.contains("k-1"), "{out}");
        assert!(out.contains(r#""user":"a""#), "{out}");

        let out = body_log_preview(FORM, b"token=abc&x=1", 1024);
        assert!(!out.contains("abc"), "{out}");
        assert!(out.contains("x=1"), "{out}");

        // A secret cut by the preview limit is still redacted: the whole
        // body is parsed (and filtered) before the cut.
        let body = br#"{"password":"hunter2-is-long"}"#;
        let out = body_log_preview(JSON, body, 18);
        assert!(!out.contains("hun"), "{out}");
        assert!(
            out.ends_with(&format!("... ({} bytes)", body.len())),
            "{out}"
        );

        // Multi-byte text is cut on a char boundary, not mid-codepoint.
        let out = body_log_preview(JSON, r#""ééé""#.as_bytes(), 3);
        assert_eq!(out, "\"é... (8 bytes)");
    }

    #[test]
    fn json_numbers_that_are_not_secrets_stay_numbers() {
        let logged = body_log_preview(
            Some("application/json"),
            br#"{"amount":1500,"year":2026}"#,
            1024,
        );
        assert_eq!(logged, r#"{"amount":1500,"year":2026}"#);
    }

    #[test]
    fn json_numbers_get_the_value_patterns_too() {
        let logged = body_log_preview(
            Some("application/json"),
            br#"{"card":4111111111111111,"tax_id":123456789,"qty":3}"#,
            1024,
        );
        assert!(!logged.contains("4111111111111111"), "{logged}");
        assert!(!logged.contains("123456789"), "{logged}");
        assert!(logged.contains("\"qty\":3"), "{logged}");
    }

    /// Every round-4 bypass of the old regex-only redaction.
    #[test]
    fn json_bodies_are_redacted_structurally() {
        for body in [
            // Dotted / bracketed / camelCase keys.
            r#"{"user.password":"s3cr3t"}"#,
            r#"{"user[password]":"s3cr3t"}"#,
            r#"{"authToken":"s3cr3t"}"#,
            // Non-scalar values: the whole value goes.
            r#"{"password":["s3cr3t"]}"#,
            r#"{"token":{"value":"s3cr3t","kind":"bearer"}}"#,
            r#"{"password":{"nested":["s3cr3t"]}}"#,
            // Nested under an innocent key, and inside arrays.
            r#"{"user":{"credentials":{"pw":"s3cr3t"}}}"#,
            r#"[{"name":"a","secret":"s3cr3t"}]"#,
            // Escaped JSON inside a string, and form text inside a string.
            r#"{"payload":"{\"password\":\"s3cr3t\"}"}"#,
            r#"{"payload":"{\"inner\":\"{\\\"token\\\":[\\\"s3cr3t\\\"]}\"}"}"#,
            r#"{"note":"password = s3cr3t"}"#,
            // The added key names.
            r#"{"pass":"s3cr3t","passphrase":"s3cr3t","pw":"s3cr3t","auth":"s3cr3t"}"#,
            r#"{"jwt":"s3cr3t","signature":"s3cr3t","cookie":"s3cr3t","pin_code":"s3cr3t"}"#,
        ] {
            let out = body_log_preview(JSON, body.as_bytes(), 4096);
            assert!(!out.contains("s3cr3t"), "{body} -> {out}");
            assert!(out.contains("[FILTERED]"), "{body} -> {out}");
        }
        // `+json` media types are JSON too.
        let out = body_log_preview(
            Some("application/vnd.api+json; charset=utf-8"),
            br#"{"password":"s3cr3t"}"#,
            4096,
        );
        assert!(!out.contains("s3cr3t"), "{out}");
    }

    #[test]
    fn form_bodies_are_redacted_by_decoded_key() {
        for body in [
            "password=s3cr3t",
            "user[password]=s3cr3t",
            "user%5Bpassword%5D=s3cr3t",
            "user[0][pin]=s3cr3t",
            "code=s3cr3t&state=xyz",
            "x[code]=s3cr3t",
            "passphrase=s3cr3t&pw=s3cr3t&auth=s3cr3t&jwt=s3cr3t",
            "signature=s3cr3t&cookie=s3cr3t&pin_code=s3cr3t&pass=s3cr3t",
            "note=password+%3D+s3cr3t",
        ] {
            let out = body_log_preview(FORM, body.as_bytes(), 4096);
            assert!(!out.contains("s3cr3t"), "{body} -> {out}");
        }
        let out = body_log_preview(FORM, b"name=alice&state=xyz", 4096);
        assert_eq!(out, "name=alice&state=xyz");
    }

    #[test]
    fn multipart_bodies_log_part_names_and_sizes_only() {
        let ct = "multipart/form-data; boundary=XyZ";
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nalice\r\n--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\ns3cr3t\r\n--XyZ--\r\n";
        let out = body_log_preview(Some(ct), body, 4096);
        assert!(!out.contains("s3cr3t") && !out.contains("alice"), "{out}");
        assert!(out.contains("username=<5 bytes>"), "{out}");
        assert!(out.contains("password=<6 bytes>"), "{out}");
    }

    /// Unknown or missing types, bodies that don't parse as their declared
    /// type, and bodies too large to parse are withheld entirely.
    #[test]
    fn unparseable_or_unknown_bodies_fail_closed() {
        let secret = b"password = s3cr3t";
        for ct in [
            None,
            Some("text/plain"),
            Some("application/octet-stream"),
            JSON,
        ] {
            assert_eq!(body_log_preview(ct, secret, 4096), "<17 bytes>", "{ct:?}");
        }
        // Truncated JSON does not parse.
        assert_eq!(
            body_log_preview(JSON, br#"{"password":"s3cr"#, 4096),
            "<17 bytes>"
        );
        // Malformed multipart.
        assert_eq!(
            body_log_preview(Some("multipart/form-data; boundary=XyZ"), secret, 4096),
            "<17 bytes>"
        );
        // Over the parse budget.
        let big = vec![b' '; BODY_REDACTION_SLACK + 11];
        assert_eq!(
            body_log_preview(JSON, &big, 10),
            format!("<{} bytes>", big.len())
        );
    }

    /// A body mislabeled as a form parses as pairs whose *names* are the
    /// real content; names are logged verbatim, so any implausible name
    /// withholds the whole body.
    #[test]
    fn mislabeled_form_bodies_fail_closed() {
        for body in [
            &br#"{"password":"s3cr3t","user":"a"}"#[..],
            b"--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\ns3cr3t\r\n--XyZ--\r\n",
            b"=s3cr3t",
        ] {
            let out = body_log_preview(FORM, body, 4096);
            assert_eq!(out, format!("<{} bytes>", body.len()), "{out}");
        }
        // Bracketed, dotted and dashed names are still fine.
        let out = body_log_preview(FORM, b"user[0][name]=a&x.y-z_1=b", 4096);
        assert_eq!(out, "user%5B0%5D%5Bname%5D=a&x.y-z_1=b");

        // Multipart part names get the same test.
        let ct = "multipart/form-data; boundary=XyZ";
        let body =
            b"--XyZ\r\nContent-Disposition: form-data; name=\"pw: s3cr3t\"\r\n\r\nx\r\n--XyZ--\r\n";
        let out = body_log_preview(Some(ct), body, 4096);
        assert_eq!(out, format!("<{} bytes>", body.len()), "{out}");
    }

    /// A JSON string holding a JSON-encoded string (double-stringified) is
    /// decoded and redacted; a quoted credential key the redactor still
    /// cannot see past (Python repr, stray escapes) withholds the string.
    #[test]
    fn stringified_and_repr_credentials_fail_closed() {
        let inner = r#"{"password":"s3cr3t"}"#;
        let once = serde_json::to_string(inner).unwrap();
        let twice = serde_json::to_string(&once).unwrap();
        for payload in [
            once.clone(),
            twice,
            "{'password': 's3cr3t'}".to_owned(),
            r#"x \"token\": \"s3cr3t\""#.to_owned(),
        ] {
            let body = serde_json::json!({ "payload": payload }).to_string();
            let out = body_log_preview(JSON, body.as_bytes(), 4096);
            assert!(!out.contains("s3cr3t"), "{body} -> {out}");
        }
        // Ordinary values that merely *are* a credential word survive.
        let out = body_log_preview(JSON, br#"{"grant_type":"password","u":"a"}"#, 4096);
        assert_eq!(out, r#"{"grant_type":"password","u":"a"}"#);
    }

    /// Redaction work per body is bounded: past the leaf budget the body is
    /// withheld instead of running the redactor on every node.
    #[test]
    fn redaction_work_is_bounded() {
        let items: Vec<String> = (0..REDACTION_LEAF_BUDGET + 1)
            .map(|i| format!("v{i:04}"))
            .collect();
        let body = serde_json::to_vec(&items).unwrap();
        assert_eq!(
            body_log_preview(JSON, &body, 1024),
            format!("<{} bytes>", body.len())
        );
        // Tiny strings and small numbers are not counted against it.
        let body = serde_json::to_vec(&vec!["ab"; REDACTION_LEAF_BUDGET * 2]).unwrap();
        assert!(body_log_preview(JSON, &body, 64).starts_with("[\"ab\""));
    }

    /// The BREACH heuristic sees cookies set through the cookie API (which
    /// live in `response.cookies`, not `headers`) and directives that carry
    /// an argument.
    #[test]
    fn breach_heuristic_sees_cookie_api_and_directive_arguments() {
        let r = HttpResponse::ok().cookie("sid", "abc");
        assert!(
            r.headers
                .iter()
                .all(|(n, _)| !n.eq_ignore_ascii_case("set-cookie"))
        );
        assert!(is_likely_secret_bearing(&r));

        for cc in [
            r#"private="Set-Cookie""#,
            "no-store=1",
            "max-age=0, PRIVATE",
        ] {
            let mut r = HttpResponse::ok();
            r.headers
                .insert("Cache-Control".to_string(), cc.to_string());
            assert!(is_likely_secret_bearing(&r), "{cc}");
        }
        let mut r = HttpResponse::ok();
        r.headers.insert(
            "Cache-Control".to_string(),
            "public, max-age=60".to_string(),
        );
        assert!(!is_likely_secret_bearing(&r));
    }

    /// H7: the legacy CORS middleware never pairs `*` with credentials.
    #[tokio::test]
    async fn cors_middleware_withholds_credentials_from_a_wildcard() {
        let cors = CorsMiddleware::new().allow_credentials(true);
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        let response = cors
            .handle(HttpRequest::new("GET", "/x".to_string()), next)
            .await
            .unwrap();
        assert_eq!(
            response
                .headers
                .get("Access-Control-Allow-Origin")
                .map(String::as_str),
            Some("*")
        );
        assert!(
            !response
                .headers
                .contains_key("Access-Control-Allow-Credentials")
        );

        let cors = CorsMiddleware::new()
            .allow_origin("https://app.example")
            .allow_credentials(true);
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        let response = cors
            .handle(HttpRequest::new("GET", "/x".to_string()), next)
            .await
            .unwrap();
        assert_eq!(
            response
                .headers
                .get("Access-Control-Allow-Credentials")
                .map(String::as_str),
            Some("true")
        );
    }

    /// A shared buffer the log subscriber writes into.
    #[derive(Clone, Default)]
    struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// M8: neither logging middleware writes the query string, which carries
    /// reset codes, OAuth `code`s and API keys.
    #[tokio::test]
    async fn logging_middleware_never_logs_the_query_string() {
        let sink = LogSink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let target = "/reset?token=SECRET-RESET-CODE&code=SECRET-OAUTH";
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        LoggerMiddleware::new()
            .handle(HttpRequest::new("GET", target.to_string()), next)
            .await
            .unwrap();
        let next: Next = Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) }));
        LoggingMiddleware::new()
            .handle(HttpRequest::new("GET", target.to_string()), next)
            .await
            .unwrap();

        let logged = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("/reset"),
            "the path is still logged: {logged}"
        );
        assert!(
            !logged.contains("SECRET"),
            "a query secret was logged: {logged}"
        );
    }

    #[tokio::test]
    async fn test_middleware_chain() {
        let mut chain = MiddlewareChain::new();
        chain.use_middleware(LoggerMiddleware::new());

        let req = HttpRequest::new("GET", "/test".to_string());

        let handler = Arc::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });

        let result = chain.apply(req, handler).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_chain_calls_handler_directly() {
        // With no middleware registered, apply() must still invoke the handler
        // and return its response unchanged.
        let chain = MiddlewareChain::new();
        let req = HttpRequest::new("GET", "/test".to_string());

        let handler = Arc::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok().with_body(b"direct".to_vec())) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });

        let response = chain.apply(req, handler).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, Bytes::from_static(b"direct"));
    }

    #[tokio::test]
    async fn test_cors_middleware() {
        let cors = CorsMiddleware::new().allow_origin("https://example.com");
        let req = HttpRequest::new("GET", "/api".to_string());

        let result = cors
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(
            response.headers.get("Access-Control-Allow-Origin"),
            Some(&"https://example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_body_size_limit() {
        let middleware = BodySizeLimitMiddleware::new(10);
        let mut req = HttpRequest::new("POST", "/api".to_string());
        req.body = Bytes::from(vec![0; 20]); // 20 bytes, exceeds limit

        let result = middleware
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_id_middleware() {
        let middleware = RequestIdMiddleware;
        let req = HttpRequest::new("GET", "/test".to_string());

        let result = middleware
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.headers.contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn test_security_headers_middleware() {
        let middleware = SecurityHeadersMiddleware::new();
        let req = HttpRequest::new("GET", "/test".to_string());

        let result = middleware
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.headers.contains_key("X-Content-Type-Options"));
        assert!(response.headers.contains_key("X-Frame-Options"));
        // The auditor is switched off, not into `mode=block` (XS-leaks).
        assert_eq!(
            response.headers.get("X-XSS-Protection").map(String::as_str),
            Some("0")
        );
    }

    #[tokio::test]
    async fn test_timeout_middleware() {
        use crate::timeout::TimeoutMiddleware;

        let middleware = TimeoutMiddleware::new(5);
        let req = HttpRequest::new("GET", "/test".to_string());

        let result = middleware
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_cors_middleware_builder() {
        let cors = CorsMiddleware::new()
            .allow_origin("https://example.com")
            .allow_credentials(true);

        assert_eq!(cors.allow_origin, "https://example.com");
        assert!(cors.allow_credentials);
    }

    #[test]
    fn test_body_size_limit_creation() {
        let middleware = BodySizeLimitMiddleware::new(1024);
        assert_eq!(middleware.max_size, 1024);
    }

    #[test]
    fn test_logger_middleware_creation() {
        let _middleware = LoggerMiddleware::new();
        // Just test that it can be created
    }

    #[tokio::test]
    async fn test_compression_middleware() {
        let middleware = CompressionMiddleware::new();
        let req = HttpRequest::new("GET", "/test".to_string());

        let result = middleware
            .handle(
                req,
                Box::new(|_req| {
                    Box::pin(async {
                        Ok(HttpResponse::ok().with_body(b"test response body".to_vec()))
                    })
                }),
            )
            .await;

        assert!(result.is_ok());
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).expect("valid gzip stream");
        out
    }

    /// Regression: a body above `min_size` is actually gzip-compressed (not just
    /// flagged) when the client accepts gzip. The old stub only set an
    /// `X-Compression-Eligible` header and never compressed.
    #[tokio::test]
    async fn test_compression_middleware_gzips_large_body() {
        let middleware = CompressionMiddleware::new().with_min_size(16);
        let mut req = HttpRequest::new("GET", "/test".to_string());
        req.headers.insert("accept-encoding", "gzip");

        let original = vec![b'z'; 4096];
        let expected = original.clone();
        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move { Ok(HttpResponse::ok().with_body(original)) })
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers.get("Content-Encoding").map(String::as_str),
            Some("gzip")
        );
        assert_eq!(
            response.headers.get("Vary").map(String::as_str),
            Some("Accept-Encoding")
        );
        assert!(response.body_ref().len() < expected.len());
        assert_eq!(gunzip(response.body_ref()), expected);
        // The stale eligibility-flag header must be gone.
        assert!(response.headers.get("X-Compression-Eligible").is_none());
    }

    /// Regression: `HttpResponse` stores its body in one of two places — the
    /// legacy `body: Vec<u8>` field, or the zero-copy `body_bytes:
    /// Option<Bytes>` storage set by `with_bytes_body` (used by static-file
    /// serving, `FastResponse`, and `ResponseBuilder::build()`), which takes
    /// precedence when present and leaves `body` empty. A body-storage-naive
    /// call site that only reads/writes the legacy `body` field would see an
    /// empty `Vec`, "successfully" gzip-encode zero bytes, and then wipe out
    /// the real content in `body_bytes` when installing the (bogus, empty)
    /// compressed result. This proves a `body_bytes`-backed body above the
    /// offload threshold is read and compressed correctly by
    /// `CompressionMiddleware` too (it shares `apply_gzip_offload` with
    /// `micro::Compress`).
    #[tokio::test]
    async fn test_compression_middleware_handles_bytes_backed_body_above_offload_threshold() {
        let middleware = CompressionMiddleware::new().with_min_size(16);
        let mut req = HttpRequest::new("GET", "/test".to_string());
        req.headers.insert("accept-encoding", "gzip");

        let original: Vec<u8> = (0..(crate::micro::GZIP_OFFLOAD_THRESHOLD * 4))
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(original.len() > crate::micro::GZIP_OFFLOAD_THRESHOLD);
        let bytes_body = bytes::Bytes::from(original.clone());

        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move { Ok(HttpResponse::ok().with_bytes_body(bytes_body)) })
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers.get("Content-Encoding").map(String::as_str),
            Some("gzip")
        );
        assert!(
            !response.body_ref().is_empty(),
            "compressed body must not be empty"
        );
        assert_eq!(gunzip(response.body_ref()), original);
    }

    /// Below `min_size`, the body must pass through uncompressed.
    #[tokio::test]
    async fn test_compression_middleware_respects_min_size() {
        let middleware = CompressionMiddleware::new().with_min_size(1024);
        let mut req = HttpRequest::new("GET", "/test".to_string());
        req.headers.insert("accept-encoding", "gzip");

        let small = b"tiny".to_vec();
        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move { Ok(HttpResponse::ok().with_body(small)) })
                }),
            )
            .await
            .unwrap();

        assert!(
            response
                .headers
                .get("Content-Encoding")
                .map(String::as_str)
                .is_none()
        );
        assert_eq!(response.body_ref(), b"tiny");
    }

    /// Without `Accept-Encoding: gzip`, a large body is left uncompressed.
    #[tokio::test]
    async fn test_compression_middleware_skips_without_accept_encoding() {
        let middleware = CompressionMiddleware::new().with_min_size(16);
        let req = HttpRequest::new("GET", "/test".to_string());

        let original = vec![b'q'; 4096];
        let expected = original.clone();
        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move { Ok(HttpResponse::ok().with_body(original)) })
                }),
            )
            .await
            .unwrap();

        assert!(
            response
                .headers
                .get("Content-Encoding")
                .map(String::as_str)
                .is_none()
        );
        assert_eq!(response.body_ref(), expected.as_slice());
    }

    /// Regression: a pre-existing `Vary` header (e.g. `Vary: Origin` set by
    /// CORS middleware upstream) must be preserved, not clobbered, when
    /// `CompressionMiddleware` adds its own `Accept-Encoding` dimension.
    #[tokio::test]
    async fn test_compression_middleware_merges_vary_with_existing_value() {
        let middleware = CompressionMiddleware::new().with_min_size(16);
        let mut req = HttpRequest::new("GET", "/test".to_string());
        req.headers.insert("accept-encoding", "gzip");

        let original = vec![b'z'; 4096];
        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move {
                        let mut resp = HttpResponse::ok().with_body(original);
                        resp.headers
                            .insert("Vary".to_string(), "Origin".to_string());
                        Ok(resp)
                    })
                }),
            )
            .await
            .unwrap();

        let vary = response.headers.get("Vary").cloned().unwrap_or_default();
        let tokens: Vec<&str> = vary.split(',').map(str::trim).collect();
        assert!(
            tokens.contains(&"Origin"),
            "Vary lost pre-existing Origin token: {vary}"
        );
        assert!(
            tokens
                .iter()
                .any(|t| t.eq_ignore_ascii_case("Accept-Encoding")),
            "Vary missing Accept-Encoding token: {vary}"
        );
    }

    /// A body larger than the gzip offload threshold is encoded on the
    /// `spawn_blocking` path; the result must be byte-identical to inline
    /// encoding, so gzip-decoding it reproduces the original exactly.
    #[tokio::test]
    async fn test_compression_middleware_offloads_large_body_and_round_trips() {
        let threshold = crate::micro::GZIP_OFFLOAD_THRESHOLD;
        let middleware = CompressionMiddleware::new().with_min_size(16);
        let mut req = HttpRequest::new("GET", "/test".to_string());
        req.headers.insert("accept-encoding", "gzip");

        // Well past the offload threshold, non-repeating so it does not trivially
        // collapse to nothing.
        let original: Vec<u8> = (0..(threshold * 4))
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(original.len() > threshold);
        let expected = original.clone();

        let response = middleware
            .handle(
                req,
                Box::new(move |_req| {
                    Box::pin(async move { Ok(HttpResponse::ok().with_body(original)) })
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers.get("Content-Encoding").map(String::as_str),
            Some("gzip")
        );
        assert_eq!(gunzip(response.body_ref()), expected);
    }

    #[tokio::test]
    async fn test_middleware_chain_multiple() {
        let mut chain = MiddlewareChain::new();
        chain.use_middleware(LoggerMiddleware::new());
        chain.use_middleware(RequestIdMiddleware);
        chain.use_middleware(SecurityHeadersMiddleware::new());

        let req = HttpRequest::new("GET", "/test".to_string());

        let handler = Arc::new(|_req: HttpRequest| {
            Box::pin(async { Ok(HttpResponse::ok()) })
                as Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send>>
        });

        let result = chain.apply(req, handler).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.headers.contains_key("x-request-id"));
        assert!(response.headers.contains_key("X-Content-Type-Options"));
    }

    #[tokio::test]
    async fn test_cors_preflight() {
        let cors = CorsMiddleware::new().allow_origin("https://example.com");

        let mut req = HttpRequest::new("OPTIONS", "/api".to_string());
        req.headers.insert("Origin", "https://example.com");
        req.headers
            .insert("Access-Control-Request-Method", "POST".to_string());

        let result = cors
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.headers.contains_key("Access-Control-Allow-Origin"));
        assert!(
            response
                .headers
                .contains_key("Access-Control-Allow-Methods")
        );
    }

    #[tokio::test]
    async fn test_body_size_within_limit() {
        let middleware = BodySizeLimitMiddleware::new(100);
        let mut req = HttpRequest::new("POST", "/api".to_string());
        req.body = Bytes::from(vec![0; 50]); // 50 bytes, within limit

        let result = middleware
            .handle(
                req,
                Box::new(|_req| Box::pin(async { Ok(HttpResponse::ok()) })),
            )
            .await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_cors_default_origin() {
        let cors = CorsMiddleware::new();
        assert_eq!(cors.allow_origin, "*");
    }
}
