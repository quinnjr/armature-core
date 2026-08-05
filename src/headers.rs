//! Interned, `Bytes`-backed HTTP header storage.
//!
//! Most requests have fewer than 12 headers, so they are stored inline on the
//! stack. Names are interned to a [`HeaderId`] — an enum variant for the ~33
//! well-known fields, a lowercased [`ByteStr`] for everything else — so a lookup
//! for a well-known name is an integer comparison rather than a
//! case-insensitive string compare. A custom name (`x-request-id` and friends)
//! still costs an ASCII-insensitive compare per stored header, but no
//! allocation: by-name lookups resolve the needle borrowed rather than
//! materializing a `HeaderId::Other` per call. Values are [`Bytes`], and under
//! the default `h1-backend` feature they are slices of the connection's read
//! buffer rather than copies — see [`append_id`](HeaderMap::append_id), which
//! is the serve path's entry point.
//!
//! ## Case normalization
//!
//! Field names are case-insensitive (RFC 9110 §5.1), and interning settles the
//! question once: `iter()`, `keys()`, and `to_hash_map()` report lowercase names
//! regardless of how they were inserted. Lookups remain case-insensitive.
//!
//! ## Non-UTF-8 values
//!
//! A header value is bytes on the wire, not text. [`HeaderMap::get`] promises a
//! `&str` and therefore returns `None` for a value that is not valid UTF-8;
//! [`HeaderMap::get_bytes`] returns it. Handing back lossy text from `get` would
//! be worse than returning nothing, because the caller would go on to trust it.
//!
//! ## Performance
//!
//! | Operation | HashMap | HeaderMap |
//! |-----------|---------|-----------|
//! | Insert (first 12) | Heap alloc | Stack only |
//! | Lookup | O(1) hash of the name | O(n) compares, no alloc |
//! | Well-known name | `String` alloc | enum variant, no alloc |
//! | Value clone | `String` copy | refcount bump |

use armature_h1::{ByteStr, HeaderId, header as header_id};
use bytes::Bytes;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt;

/// Number of headers to store inline (on stack).
///
/// Most HTTP requests have 5–10 headers.
pub const INLINE_HEADERS: usize = 12;

/// A by-name lookup needle, resolved without allocating.
///
/// `header_id::intern` returns `HeaderId::Other(ByteStr::from(lowercased))` for
/// any name outside the well-known table — a `String` plus a `Bytes` per call.
/// Interning the needle would therefore charge an allocation to every lookup of
/// exactly the custom names applications reach for most (`x-request-id`,
/// `x-tenant-id`). A borrowed needle compares against the stored name instead,
/// while a well-known name still collapses to a discriminant compare.
enum Needle<'a> {
    Known(HeaderId),
    Custom(&'a str),
}

impl<'a> Needle<'a> {
    #[inline]
    fn new(name: &'a str) -> Self {
        match HeaderId::from_bytes(name.as_bytes()) {
            Some(id) => Needle::Known(id),
            None => Needle::Custom(name),
        }
    }

    /// Whether a stored header's name is this needle.
    ///
    /// `HeaderId::as_str` is always the canonical lowercase form, so the
    /// custom arm only has to be insensitive on the needle's side.
    #[inline]
    fn matches(&self, id: &HeaderId) -> bool {
        match self {
            Needle::Known(known) => known == id,
            Needle::Custom(name) => id.as_str().eq_ignore_ascii_case(name),
        }
    }
}

/// A header field: an interned name and a `Bytes` value.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    /// The interned field name.
    pub id: HeaderId,
    /// The field value, exactly as it arrived.
    pub value: Bytes,
}

impl Header {
    /// Create a header, interning the name.
    #[inline]
    pub fn new(name: impl AsRef<str>, value: impl HeaderValueInput) -> Self {
        Self {
            id: header_id::intern(name.as_ref()),
            value: value.into_value(),
        }
    }

    /// The field name, lowercased.
    #[inline]
    pub fn name(&self) -> &str {
        self.id.as_str()
    }

    /// The value as UTF-8, or `None` if it is not valid UTF-8.
    #[inline]
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value_str() {
            Some(v) => write!(f, "{}: {}", self.name(), v),
            None => write!(f, "{}: <{} non-utf8 bytes>", self.name(), self.value.len()),
        }
    }
}

/// Anything that can become a header value.
///
/// This exists so every existing `insert(name, value)` call site keeps compiling
/// across `&str`, `String`, and `Bytes` alike. A plain `impl Into<Bytes>` bound
/// would not: `Bytes: From<&'static str>` but not `From<&'a str>`, so every
/// borrowed-`&str` call site would break.
pub trait HeaderValueInput {
    /// Convert into the stored representation.
    fn into_value(self) -> Bytes;
}

impl HeaderValueInput for Bytes {
    #[inline]
    fn into_value(self) -> Bytes {
        self
    }
}

impl HeaderValueInput for &str {
    #[inline]
    fn into_value(self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}

impl HeaderValueInput for &String {
    #[inline]
    fn into_value(self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}

impl HeaderValueInput for String {
    #[inline]
    fn into_value(self) -> Bytes {
        Bytes::from(self.into_bytes())
    }
}

impl HeaderValueInput for &[u8] {
    #[inline]
    fn into_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl HeaderValueInput for Vec<u8> {
    #[inline]
    fn into_value(self) -> Bytes {
        Bytes::from(self)
    }
}

impl HeaderValueInput for ByteStr {
    #[inline]
    fn into_value(self) -> Bytes {
        self.into_bytes()
    }
}

impl HeaderValueInput for std::borrow::Cow<'_, str> {
    #[inline]
    fn into_value(self) -> Bytes {
        match self {
            std::borrow::Cow::Borrowed(s) => Bytes::copy_from_slice(s.as_bytes()),
            std::borrow::Cow::Owned(s) => Bytes::from(s.into_bytes()),
        }
    }
}

/// A compact header map using `SmallVec` for inline storage.
///
/// # Example
///
/// ```rust
/// use armature_core::headers::HeaderMap;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("Content-Type", "application/json");
/// headers.insert("Accept", "text/html");
///
/// // Lookup is case-insensitive; the value comes back as a `&str`.
/// assert_eq!(headers.get("content-type"), Some("application/json"));
/// assert!(headers.is_inline()); // Still on stack
/// ```
#[derive(Clone, Default)]
pub struct HeaderMap {
    inner: SmallVec<[Header; INLINE_HEADERS]>,
}

impl HeaderMap {
    /// Create a new empty header map.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: SmallVec::new_const(),
        }
    }

    /// Create with pre-allocated capacity.
    ///
    /// If capacity <= `INLINE_HEADERS`, no heap allocation occurs.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: SmallVec::with_capacity(capacity),
        }
    }

    /// Check if storage is inline (no heap allocation).
    #[inline]
    pub fn is_inline(&self) -> bool {
        !self.inner.spilled()
    }

    /// Get the number of headers.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The **first** value of `name` as UTF-8, case-insensitively.
    ///
    /// Returns `None` for a value that is not valid UTF-8; use
    /// [`HeaderMap::get_bytes`] for those.
    ///
    /// # First-wins on a map that carries wire duplicates
    ///
    /// The serve path [appends](Self::append_id) every occurrence a request
    /// carried, so a field the client sent twice is present twice and this
    /// returns the earlier line. For a field defined to repeat (`Accept`,
    /// `X-Forwarded-For`) that is the right first element and
    /// [`get_all`](Self::get_all) has the rest. For a single-valued field it is
    /// a hazard: a fronting proxy that *appends* rather than replaces (Envoy's
    /// `APPEND_IF_EXISTS_OR_ADD`, nginx `add_header`) leaves the client's line
    /// first and its own second, so a client that sends
    /// `X-Authenticated-User: admin` outranks the proxy's `alice` here. Reach
    /// for [`get_unique`](Self::get_unique) whenever the answer is a decision
    /// rather than a report.
    #[inline]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.get_bytes(name)
            .and_then(|v| std::str::from_utf8(v).ok())
    }

    /// The raw **first** value of `name`, case-insensitively.
    ///
    /// First-wins on a repeated field, with the hazard [`get`](Self::get)
    /// describes; see [`get_unique`](Self::get_unique) and
    /// [`get_all`](Self::get_all).
    #[inline]
    pub fn get_bytes(&self, name: &str) -> Option<&Bytes> {
        let needle = Needle::new(name);
        self.inner
            .iter()
            .find(|h| needle.matches(&h.id))
            .map(|h| &h.value)
    }

    /// The raw value of `name` only if it occurs exactly once.
    ///
    /// The duplicate-aware counterpart to [`get_bytes`](Self::get_bytes), for
    /// fields where "which occurrence" is a security question rather than a
    /// formatting one. `Ok(None)` means absent, `Ok(Some(_))` means exactly one
    /// occurrence, and [`DuplicateField`] means the wire carried more than one —
    /// at which point picking either is a guess, and the caller can fail the
    /// request instead of guessing in the attacker's favour.
    ///
    /// ```
    /// use armature_core::headers::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append("X-Authenticated-User", "admin");   // the client's line
    /// headers.append("X-Authenticated-User", "alice");   // the proxy appended
    ///
    /// // `get` hands back the client's claim; `get_unique` refuses to choose.
    /// assert_eq!(headers.get("x-authenticated-user"), Some("admin"));
    /// assert!(headers.get_unique("x-authenticated-user").is_err());
    /// ```
    #[inline]
    pub fn get_unique(&self, name: &str) -> Result<Option<&Bytes>, DuplicateField> {
        let needle = Needle::new(name);
        self.unique_where(|h| needle.matches(&h.id))
            .map(|found| found.map(|h| &h.value))
    }

    /// The raw value for an already-interned name.
    ///
    /// The hot-path accessor: no interning, and for a well-known name the
    /// comparison is on the enum discriminant. First-wins on a repeated field,
    /// with the hazard [`get`](Self::get) describes.
    #[inline]
    pub fn get_id(&self, id: &HeaderId) -> Option<&Bytes> {
        self.inner.iter().find(|h| &h.id == id).map(|h| &h.value)
    }

    /// The value of `name` as UTF-8, case-insensitively.
    ///
    /// Identical to [`HeaderMap::get`]; kept because call sites use both names.
    #[inline]
    pub fn get_ignore_case(&self, name: &str) -> Option<&str> {
        self.get(name)
    }

    /// Check if header exists (case-insensitive).
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        self.get_bytes(name).is_some()
    }

    /// Check if header exists (case-insensitive).
    ///
    /// HashMap-compatible alias for [`contains`](Self::contains).
    #[inline]
    pub fn contains_key(&self, name: &str) -> bool {
        self.contains(name)
    }

    /// Insert a header, replacing any existing header with the same name.
    ///
    /// Returns the old value if one was replaced.
    #[inline]
    pub fn insert(&mut self, name: impl AsRef<str>, value: impl HeaderValueInput) -> Option<Bytes> {
        self.insert_id(header_id::intern(name.as_ref()), value.into_value())
    }

    /// Insert a header whose name is already interned.
    ///
    /// The pre-interned counterpart to [`insert`](Self::insert): `armature-h1`
    /// parses field names straight into [`HeaderId`], so re-deriving one here
    /// would lowercase and re-intern a name already in its final form — an
    /// allocation per unknown header, per request, to arrive back where the
    /// parser started.
    ///
    /// Collapses *every* existing occurrence of the name to the new value, like
    /// `insert` and like `http::HeaderMap::insert`, and returns the value the
    /// first one held. Collapsing rather than replacing-the-first is what makes
    /// the sanitisation idiom sound: the serve path appends every field line a
    /// request carried, so an `insert_id` that spared later duplicates would
    /// leave a client-supplied value exactly where the caller believed it had
    /// overwritten one. The serve path itself uses
    /// [`append_id`](Self::append_id) rather than this, because a field the wire
    /// repeated must not collapse on the way in.
    ///
    /// ```
    /// use armature_core::headers::HeaderMap;
    /// use armature_core::{HeaderId, header_id};
    /// use bytes::Bytes;
    ///
    /// let mut headers = HeaderMap::new();
    /// assert_eq!(headers.insert_id(HeaderId::Accept, Bytes::from_static(b"a")), None);
    /// // The second insert replaces, handing back what it displaced.
    /// let replaced = headers.insert_id(HeaderId::Accept, Bytes::from_static(b"b"));
    /// assert_eq!(replaced.as_deref(), Some(&b"a"[..]));
    /// assert_eq!(headers.get("accept"), Some("b"));
    /// assert_eq!(headers.len(), 1);
    ///
    /// // As the wire may deliver it: three field lines, only the first of which
    /// // any proxy wrote. One `insert_id` leaves one occurrence, not two.
    /// let xff = header_id::intern("x-forwarded-for");
    /// headers.append_id(xff.clone(), Bytes::from_static(b"203.0.113.7"));
    /// headers.append_id(xff.clone(), Bytes::from_static(b"198.51.100.9"));
    /// headers.insert_id(xff, Bytes::from_static(b"10.0.0.1"));
    /// assert_eq!(headers.get_all("x-forwarded-for"), vec!["10.0.0.1"]);
    /// assert_eq!(headers.get_all("x-forwarded-for").len(), 1);
    ///
    /// // A name outside the well-known table interns to the same value the
    /// // parser produces, so it is found by name afterwards.
    /// headers.insert_id(header_id::intern("x-trace-id"), Bytes::from_static(b"t"));
    /// assert_eq!(headers.get("X-Trace-Id"), Some("t"));
    /// ```
    #[inline]
    pub fn insert_id(&mut self, id: HeaderId, value: Bytes) -> Option<Bytes> {
        // Replaces the first occurrence and *drops the rest*, matching
        // `http::HeaderMap::insert`. Replacing only the first would be a
        // security bug now that the serve path appends every occurrence a
        // request carried: the canonical sanitisation idiom is
        // `headers.insert("X-Forwarded-For", trusted_value)`, and if a
        // client-supplied second line survived that call, `client_address`
        // would go on reading it as a hop.
        let mut replaced = None;
        self.inner.retain_mut(|h| {
            if h.id != id {
                return true;
            }
            match replaced {
                None => {
                    replaced = Some(std::mem::replace(&mut h.value, value.clone()));
                    true
                }
                Some(_) => false,
            }
        });
        if replaced.is_none() {
            self.inner.push(Header { id, value });
        }
        replaced
    }

    /// Append a header whose name is already interned, allowing duplicates.
    ///
    /// The serve path's entry point, and the repeating-field counterpart to
    /// [`insert_id`](Self::insert_id); see there for why the pre-interned name
    /// matters. Appending rather than replacing is what keeps a field the wire
    /// sent twice from collapsing to its last occurrence — which matters for
    /// `X-Forwarded-For`, where the occurrences a proxy appended are the
    /// trustworthy ones (see
    /// [`HttpRequest::client_address`](crate::HttpRequest::client_address)).
    ///
    /// ```
    /// use armature_core::headers::HeaderMap;
    /// use armature_core::HeaderId;
    /// use bytes::Bytes;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.append_id(HeaderId::Accept, Bytes::from_static(b"text/html"));
    /// headers.append_id(HeaderId::Accept, Bytes::from_static(b"text/plain"));
    ///
    /// // Both occurrences are kept; a single-valued lookup sees the first.
    /// assert_eq!(headers.get_all("accept").len(), 2);
    /// assert_eq!(headers.get("accept"), Some("text/html"));
    /// ```
    #[inline]
    pub fn append_id(&mut self, id: HeaderId, value: Bytes) {
        self.inner.push(Header { id, value });
    }

    /// Append a header, allowing duplicates.
    ///
    /// Unlike `insert`, this does not replace. Use it for fields that may repeat,
    /// such as `Set-Cookie`.
    #[inline]
    pub fn append(&mut self, name: impl AsRef<str>, value: impl HeaderValueInput) {
        self.inner.push(Header {
            id: header_id::intern(name.as_ref()),
            value: value.into_value(),
        });
    }

    /// Remove *every* occurrence of a header name (case-insensitive), returning
    /// the value the first one held.
    ///
    /// A `remove` that left later duplicates behind would be a hole rather than
    /// a convenience: the serve path appends every field line a request carried,
    /// so code that strips a client-supplied `X-Forwarded-For` or
    /// `Authorization` before trusting the request would strip only the first
    /// line and leave the attacker's second one in the map. Use
    /// [`remove_all`](Self::remove_all) when the count is what you want.
    #[inline]
    pub fn remove(&mut self, name: &str) -> Option<Bytes> {
        let needle = Needle::new(name);
        let mut removed = None;
        self.inner.retain_mut(|h| {
            if !needle.matches(&h.id) {
                return true;
            }
            if removed.is_none() {
                removed = Some(h.value.clone());
            }
            false
        });
        removed
    }

    /// Remove every header with the given name, returning how many were removed.
    #[inline]
    pub fn remove_all(&mut self, name: &str) -> usize {
        let needle = Needle::new(name);
        let before = self.inner.len();
        self.inner.retain(|h| !needle.matches(&h.id));
        before - self.inner.len()
    }

    /// Iterate over headers as `(name, value)`, skipping non-UTF-8 values.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner
            .iter()
            .filter_map(|h| h.value_str().map(|v| (h.name(), v)))
    }

    /// Iterate over every header, including those with non-UTF-8 values.
    #[inline]
    pub fn iter_raw(&self) -> impl Iterator<Item = (&HeaderId, &Bytes)> {
        self.inner.iter().map(|h| (&h.id, &h.value))
    }

    /// Iterate over header names, lowercased.
    #[inline]
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.inner.iter().map(|h| h.name())
    }

    /// Iterate over header names.
    ///
    /// HashMap-compatible alias for [`names`](Self::names).
    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.names()
    }

    /// Iterate over header values, skipping non-UTF-8 ones.
    #[inline]
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.inner.iter().filter_map(|h| h.value_str())
    }

    /// Every value for a header name, for multi-value fields.
    #[inline]
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let needle = Needle::new(name);
        self.inner
            .iter()
            .filter(|h| needle.matches(&h.id))
            .filter_map(|h| h.value_str())
            .collect()
    }

    /// Clear all headers.
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Extend with headers from an iterator.
    #[inline]
    pub fn extend<I, K, V>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: HeaderValueInput,
    {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }

    /// Convert to a `HashMap`, for compatibility.
    ///
    /// Names come out lowercased and non-UTF-8 values are dropped. This
    /// allocates a `String` per name and value — reach for it only when a
    /// `HashMap` is genuinely required.
    #[inline]
    pub fn to_hash_map(&self) -> HashMap<String, String> {
        self.iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    /// Create from a `HashMap`.
    #[inline]
    pub fn from_hash_map(map: HashMap<String, String>) -> Self {
        let mut headers = Self::with_capacity(map.len());
        for (k, v) in map {
            headers.insert(k, v);
        }
        headers
    }

    // ========================================================================
    // Common Header Accessors
    // ========================================================================

    /// Get the `Content-Type` header.
    #[inline]
    pub fn content_type(&self) -> Option<&str> {
        self.str_of(&HeaderId::ContentType)
    }

    /// Get the `Content-Length` header as a `usize`.
    ///
    /// `None` if the field is absent, unparseable, **or present more than
    /// once**. Two `Content-Length` lines are the classic request-smuggling
    /// shape (RFC 9112 §6.3 requires the message be rejected), and the serve
    /// path keeps both, so answering with either one lets the framing this
    /// process believes differ from the framing an upstream believes.
    #[inline]
    pub fn content_length(&self) -> Option<usize> {
        self.unique_str_of(&HeaderId::ContentLength)?.parse().ok()
    }

    /// Get the `Accept` header.
    #[inline]
    pub fn accept(&self) -> Option<&str> {
        self.str_of(&HeaderId::Accept)
    }

    /// Get the `Authorization` header.
    ///
    /// `None` if the field is absent **or present more than once**. RFC 9110
    /// §11.6.2 defines `Authorization` as single-valued, so a second line is
    /// anomalous by construction — and since the serve path keeps both, and a
    /// fronting proxy that appends its own credential leaves the client's line
    /// first, "pick one" would systematically pick the client's. Refusing to
    /// answer sends the request down whatever unauthenticated path the caller
    /// already handles.
    #[inline]
    pub fn authorization(&self) -> Option<&str> {
        self.unique_str_of(&HeaderId::Authorization)
    }

    /// Get the `User-Agent` header.
    #[inline]
    pub fn user_agent(&self) -> Option<&str> {
        self.str_of(&HeaderId::UserAgent)
    }

    /// Get the `Host` header.
    ///
    /// `None` if the field is absent **or present more than once**. `Host`
    /// picks the origin the request is addressed to, so two disagreeing lines
    /// let this process route or cache under one authority while an upstream
    /// used the other; RFC 9112 §3.2 requires such a message be rejected.
    #[inline]
    pub fn host(&self) -> Option<&str> {
        self.unique_str_of(&HeaderId::Host)
    }

    /// Get the `Cookie` header.
    #[inline]
    pub fn cookie(&self) -> Option<&str> {
        self.str_of(&HeaderId::Cookie)
    }

    /// Check for a keep-alive connection.
    #[inline]
    pub fn is_keep_alive(&self) -> bool {
        self.str_of(&HeaderId::Connection)
            .map(|v| v.eq_ignore_ascii_case("keep-alive"))
            .unwrap_or(true) // HTTP/1.1 default is keep-alive
    }

    /// Check for chunked transfer encoding.
    #[inline]
    pub fn is_chunked(&self) -> bool {
        self.str_of(&HeaderId::TransferEncoding)
            .map(|v| v.contains("chunked"))
            .unwrap_or(false)
    }

    /// Set the `Content-Type` header.
    #[inline]
    pub fn set_content_type(&mut self, value: impl HeaderValueInput) {
        self.insert("content-type", value);
    }

    /// Set the `Content-Length` header.
    #[inline]
    pub fn set_content_length(&mut self, len: usize) {
        self.insert("content-length", len.to_string());
    }

    /// The UTF-8 value for an already-interned name.
    #[inline]
    fn str_of(&self, id: &HeaderId) -> Option<&str> {
        self.get_id(id).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// The UTF-8 value for an already-interned name, or `None` if it repeats.
    ///
    /// The fail-closed reading, for the accessors whose answer a caller acts on
    /// rather than reports. A duplicate collapses to `None` here rather than
    /// surfacing as an error because these accessors already return `Option`
    /// and their callers already have an absent branch — which is the branch a
    /// contradictory request belongs in.
    #[inline]
    fn unique_str_of(&self, id: &HeaderId) -> Option<&str> {
        self.unique_where(|h| &h.id == id)
            .ok()
            .flatten()
            .and_then(Header::value_str)
    }

    /// The single header matching `pred`, or [`DuplicateField`] if several do.
    ///
    /// One pass: the count and the first match come out together, so the common
    /// no-duplicate case costs exactly what a `find` would. The error names the
    /// field from the *stored* id rather than from the caller's spelling, so it
    /// is the canonical lowercase form however it was looked up.
    #[inline]
    fn unique_where(
        &self,
        mut pred: impl FnMut(&Header) -> bool,
    ) -> Result<Option<&Header>, DuplicateField> {
        let mut first: Option<&Header> = None;
        let mut count = 0usize;
        for header in &self.inner {
            if !pred(header) {
                continue;
            }
            count += 1;
            if first.is_none() {
                first = Some(header);
            }
        }
        match first {
            // Allocating the name is fine here: this arm is the anomalous
            // request, and a caller logging the rejection wants the name.
            Some(header) if count > 1 => Err(DuplicateField {
                name: header.name().to_owned(),
                count,
            }),
            other => Ok(other),
        }
    }
}

/// A single-valued header field that arrived more than once.
///
/// Returned by [`HeaderMap::get_unique`]. The map keeps every occurrence the
/// wire carried, so a field defined to appear at most once appearing twice is a
/// statement about the request, not about the map: some intermediary added a
/// line without removing the client's, and no occurrence can be shown to be the
/// authoritative one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateField {
    /// The field name, lowercased.
    name: String,
    /// How many occurrences were found; always at least 2.
    count: usize,
}

impl DuplicateField {
    /// The field name, lowercased.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many occurrences the map holds. Always at least 2.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }
}

impl fmt::Display for DuplicateField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "header `{}` appeared {} times but is single-valued; no occurrence \
             can be trusted over another",
            self.name, self.count
        )
    }
}

impl std::error::Error for DuplicateField {}

impl fmt::Debug for HeaderMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(
                self.inner
                    .iter()
                    .map(|h| (h.name(), h.value_str().unwrap_or("<non-utf8>"))),
            )
            .finish()
    }
}

impl<K, V> FromIterator<(K, V)> for HeaderMap
where
    K: AsRef<str>,
    V: HeaderValueInput,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let (min, max) = iter.size_hint();
        let mut map = HeaderMap::with_capacity(max.unwrap_or(min));
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl Extend<(String, String)> for HeaderMap {
    fn extend<I: IntoIterator<Item = (String, String)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

/// Project a header to its `(name, value)` pair, dropping non-UTF-8 values.
///
/// A free function rather than a closure so [`IntoIterator`] can name its
/// iterator type.
fn utf8_pair(h: &Header) -> Option<(&str, &str)> {
    h.value_str().map(|v| (h.name(), v))
}

/// Project an owned header to an owned pair, dropping non-UTF-8 values.
fn owned_utf8_pair(h: Header) -> Option<(String, String)> {
    let name = h.name().to_owned();
    String::from_utf8(h.value.to_vec())
        .ok()
        .map(|value| (name, value))
}

impl<'a> IntoIterator for &'a HeaderMap {
    type Item = (&'a str, &'a str);
    type IntoIter = std::iter::FilterMap<
        std::slice::Iter<'a, Header>,
        fn(&'a Header) -> Option<(&'a str, &'a str)>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter().filter_map(utf8_pair as _)
    }
}

impl IntoIterator for HeaderMap {
    type Item = (String, String);
    type IntoIter = std::iter::FilterMap<
        smallvec::IntoIter<[Header; INLINE_HEADERS]>,
        fn(Header) -> Option<(String, String)>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter().filter_map(owned_utf8_pair as _)
    }
}

// Allow HashMap-like indexing.
impl std::ops::Index<&str> for HeaderMap {
    type Output = str;

    fn index(&self, name: &str) -> &Self::Output {
        self.get(name).expect("header not found")
    }
}

// ============================================================================
// Conversion from/to HashMap for backwards compatibility
// ============================================================================

impl From<HashMap<String, String>> for HeaderMap {
    fn from(map: HashMap<String, String>) -> Self {
        Self::from_hash_map(map)
    }
}

impl From<HeaderMap> for HashMap<String, String> {
    fn from(map: HeaderMap) -> Self {
        map.to_hash_map()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_inline() {
        let headers = HeaderMap::new();
        assert!(headers.is_inline());
        assert!(headers.is_empty());
    }

    #[test]
    fn get_returns_str_and_well_known_names_are_interned() {
        let mut h = HeaderMap::new();
        h.insert("Content-Type", "application/json");
        h.insert("X-Tenant-Id", "acme".to_string());

        // Case-insensitive lookup survives the move to HeaderId.
        assert_eq!(h.get("content-type"), Some("application/json"));
        assert_eq!(h.get("CONTENT-TYPE"), Some("application/json"));
        assert_eq!(h.get("x-tenant-id"), Some("acme"));
        assert_eq!(h.get("absent"), None);

        // Well-known names cost no allocation and compare as a discriminant.
        assert_eq!(
            h.get_id(&HeaderId::ContentType).map(|b| &b[..]),
            Some(&b"application/json"[..])
        );
    }

    #[test]
    fn custom_names_stay_case_insensitive_through_the_borrowed_needle() {
        // Names outside the well-known table take the non-allocating compare
        // path, which still has to honour RFC 9110 case-insensitivity in both
        // directions — however the header was inserted, however it is asked for.
        let mut h = HeaderMap::new();
        h.insert("X-Request-ID", "abc123");
        h.append("x-request-id", "def456");

        assert_eq!(h.get("x-request-id"), Some("abc123"));
        assert_eq!(h.get("X-REQUEST-ID"), Some("abc123"));
        assert!(h.contains("X-Request-Id"));
        assert_eq!(h.get_all("X-Request-Id"), vec!["abc123", "def456"]);

        // A custom needle must not match a well-known stored name, or vice versa.
        h.insert("Content-Type", "text/plain");
        assert_eq!(h.get("x-content-type"), None);

        assert_eq!(h.remove_all("X-Request-ID"), 2);
        assert_eq!(h.get("x-request-id"), None);
    }

    #[test]
    fn non_utf8_value_is_invisible_to_get_but_reachable_as_bytes() {
        let mut h = HeaderMap::new();
        h.insert("x-raw", Bytes::from_static(&[0xff, 0x00]));
        // `get` promises a `&str`, and there isn't one. Returning None beats
        // returning lossy text that a caller would go on to trust.
        assert_eq!(h.get("x-raw"), None);
        assert_eq!(h.get_bytes("x-raw").map(|b| b.len()), Some(2));
        // ...and it is still there, so a caller that iterates raw sees it.
        assert_eq!(h.len(), 1);
        assert_eq!(h.iter().count(), 0);
        assert_eq!(h.iter_raw().count(), 1);
    }

    #[test]
    fn test_insert_and_get() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Accept", "text/html");

        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("Content-Type"), Some("application/json"));
        assert_eq!(headers.get("content-type"), Some("application/json"));
    }

    #[test]
    fn test_insert_replaces() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "text/plain");
        let old = headers.insert("Content-Type", "application/json");

        assert_eq!(old.as_deref(), Some(&b"text/plain"[..]));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("Content-Type"), Some("application/json"));
    }

    #[test]
    fn test_append_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append("Set-Cookie", "session=abc");
        headers.append("Set-Cookie", "user=123");

        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get_all("set-cookie"),
            vec!["session=abc", "user=123"]
        );
    }

    #[test]
    fn test_remove() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Accept", "text/html");

        let removed = headers.remove("Content-Type");
        assert_eq!(removed.as_deref(), Some(&b"application/json"[..]));
        assert_eq!(headers.len(), 1);
        assert!(!headers.contains("Content-Type"));
    }

    #[test]
    fn test_remove_all() {
        let mut headers = HeaderMap::new();
        headers.append("Set-Cookie", "a=1");
        headers.append("set-cookie", "b=2");
        headers.insert("Accept", "*/*");

        assert_eq!(headers.remove_all("Set-Cookie"), 2);
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn test_inline_capacity() {
        let mut headers = HeaderMap::new();

        for i in 0..INLINE_HEADERS {
            headers.insert(format!("Header-{i}"), format!("Value-{i}"));
        }
        assert!(headers.is_inline());

        headers.insert("Extra-Header", "Extra-Value");
        assert!(!headers.is_inline());
    }

    #[test]
    fn test_iter() {
        let mut headers = HeaderMap::new();
        headers.insert("A", "1");
        headers.insert("B", "2");

        let pairs: Vec<_> = headers.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    /// The zero-copy serve path hands `HeaderMap` a [`HeaderId`] produced by a
    /// *different crate* — `armature-h1`'s parser — and never re-interns it. If
    /// that id were not byte-identical to what `header_id::intern` produces for
    /// the same name, every by-name lookup of a custom header would silently
    /// miss: `get` would return `None` for a header that is demonstrably
    /// present, which is the kind of bug that looks like a client problem.
    #[test]
    fn a_parser_produced_id_equals_an_interned_one() {
        use armature_h1::{Limits, parse_head};
        use bytes::Bytes;

        // Mixed case on the wire, since that is the case that forces the
        // parser down its lowercasing path rather than a borrowed slice.
        let raw = Bytes::from_static(b"GET / HTTP/1.1\r\nHost: a\r\nX-Trace-Id: abc\r\n\r\n");
        let head = parse_head(&raw, &Limits::default())
            .expect("parse")
            .expect("complete")
            .0;

        let (parsed_id, value) = head
            .headers
            .iter()
            .find(|(id, _)| id.as_str() == "x-trace-id")
            .cloned()
            .expect("the custom header is present in the parsed head");

        assert_eq!(
            parsed_id,
            header_id::intern("x-trace-id"),
            "a parser-produced id must equal an interned one, or the serve \
             path's stored headers are unreachable by name"
        );

        let mut headers = HeaderMap::new();
        headers.append_id(parsed_id, value);

        // Found by the wire casing and by lowercase alike.
        assert_eq!(headers.get("X-Trace-Id"), Some("abc"));
        assert_eq!(headers.get("x-trace-id"), Some("abc"));

        // And the case-normalization invariant this module documents holds for
        // a name it never interned itself.
        assert!(headers.iter().any(|(k, _)| k == "x-trace-id"));
        assert!(headers.keys().any(|k| k == "x-trace-id"));
        assert!(headers.to_hash_map().contains_key("x-trace-id"));
    }

    /// `insert_id` is the pre-interned `insert`, so it must behave as `insert`
    /// does in the one place they could plausibly differ: what happens to an
    /// existing field of the same name.
    /// The serve path appends every occurrence a request carried, so a
    /// replacing operation that spared later duplicates would leave a
    /// client-supplied value behind exactly where code was trying to overwrite
    /// it. `http::HeaderMap::insert` collapses; so must this.
    #[test]
    fn insert_collapses_every_occurrence_of_a_repeated_field() {
        use bytes::Bytes;

        let mut headers = HeaderMap::new();
        let xff = header_id::intern("x-forwarded-for");
        // Three field lines, which is what a two-proxy chain actually produces,
        // interleaved with an unrelated field. Two occurrences would be passed
        // by a compaction that drops the first plus exactly one more; three
        // interleaved ones also stress the index arithmetic that shifting
        // survivors leftwards depends on.
        headers.append_id(xff.clone(), Bytes::from_static(b"203.0.113.7"));
        headers.append_id(HeaderId::Accept, Bytes::from_static(b"text/html"));
        headers.append_id(xff.clone(), Bytes::from_static(b"198.51.100.9"));
        headers.append_id(HeaderId::UserAgent, Bytes::from_static(b"curl/8"));
        headers.append_id(xff, Bytes::from_static(b"192.0.2.4"));
        assert_eq!(headers.get_all("x-forwarded-for").len(), 3);

        // The canonical sanitisation idiom.
        headers.insert("X-Forwarded-For", "10.0.0.1");

        let all = headers.get_all("x-forwarded-for");
        assert_eq!(
            all,
            vec!["10.0.0.1"],
            "a replacing insert must leave exactly one occurrence; a surviving \
             duplicate is a value the caller believed it had overwritten"
        );
        assert_eq!(
            headers.get("accept"),
            Some("text/html"),
            "collapsing one field must not disturb the fields interleaved with it"
        );
        assert_eq!(headers.get("user-agent"), Some("curl/8"));
        assert_eq!(
            headers.len(),
            3,
            "one X-Forwarded-For plus the two bystanders"
        );
    }

    #[test]
    fn remove_takes_every_occurrence_not_just_the_first() {
        use bytes::Bytes;

        let mut headers = HeaderMap::new();
        // Three occurrences, interleaved: a removal that takes the first plus
        // exactly one more leaves the third behind, and a removal whose index
        // arithmetic slips takes a bystander with it.
        headers.append_id(HeaderId::Accept, Bytes::from_static(b"first"));
        headers.append_id(HeaderId::Host, Bytes::from_static(b"example.com"));
        headers.append_id(HeaderId::Accept, Bytes::from_static(b"second"));
        headers.append_id(HeaderId::UserAgent, Bytes::from_static(b"curl/8"));
        headers.append_id(HeaderId::Accept, Bytes::from_static(b"third"));

        let removed = headers.remove("accept");

        assert_eq!(
            removed.as_deref(),
            Some(&b"first"[..]),
            "the first occurrence comes back, as before"
        );
        assert!(
            headers.get("accept").is_none(),
            "stripping a header must strip all of it, or code that removes an \
             untrusted field before trusting the request keeps the attacker's \
             later lines"
        );
        assert_eq!(
            headers.get_all("accept").len(),
            0,
            "no occurrence of the removed field may survive"
        );
        assert_eq!(
            headers.get("host"),
            Some("example.com"),
            "removing one field must not disturb the fields interleaved with it"
        );
        assert_eq!(headers.get("user-agent"), Some("curl/8"));
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn get_unique_refuses_to_choose_between_duplicate_occurrences() {
        let mut headers = HeaderMap::new();
        headers.append("X-Authenticated-User", "admin");

        assert_eq!(
            headers
                .get_unique("x-authenticated-user")
                .expect("one occurrence is not a duplicate")
                .map(|v| &v[..]),
            Some(&b"admin"[..])
        );
        assert_eq!(
            headers
                .get_unique("absent")
                .expect("absent is not a duplicate"),
            None,
            "an absent field is Ok(None), not an error"
        );

        // A proxy that appends rather than replaces leaves the client's claim
        // first, which is exactly what `get` would hand back.
        headers.append("x-authenticated-user", "alice");
        assert_eq!(headers.get("X-Authenticated-User"), Some("admin"));

        let err = headers
            .get_unique("X-Authenticated-User")
            .expect_err("two occurrences of a single-valued field must be an error");
        assert_eq!(err.name(), "x-authenticated-user");
        assert_eq!(err.count(), 2);
        assert!(
            err.to_string().contains("x-authenticated-user"),
            "the message must name the field, or a rejection log cannot say which"
        );
    }

    #[test]
    fn security_relevant_accessors_fail_closed_on_a_duplicated_field() {
        // A request that says two contradictory things about who it is, how
        // long it is, or where it is addressed is not a request to answer from.
        // Every one of these fields is single-valued by its RFC, and the serve
        // path keeps both lines, so "first wins" would systematically pick the
        // client's over the proxy's.
        let mut headers = HeaderMap::new();
        headers.append("Authorization", "Bearer client-chosen");
        headers.append("Content-Length", "5");
        headers.append("Host", "example.com");
        assert_eq!(headers.authorization(), Some("Bearer client-chosen"));
        assert_eq!(headers.content_length(), Some(5));
        assert_eq!(headers.host(), Some("example.com"));

        headers.append("authorization", "Bearer proxy-issued");
        headers.append("content-length", "500");
        headers.append("host", "internal.example");

        assert_eq!(
            headers.authorization(),
            None,
            "a duplicated Authorization must read as no credential, not as the \
             first line the client happened to send"
        );
        assert_eq!(
            headers.content_length(),
            None,
            "two Content-Length lines are the request-smuggling shape; neither \
             length may be reported as the framing"
        );
        assert_eq!(
            headers.host(),
            None,
            "two Host lines leave no single authority to route or cache under"
        );

        // The raw first-wins accessors are unchanged: only the deciding
        // accessors fail closed.
        assert_eq!(headers.get("authorization"), Some("Bearer client-chosen"));
        assert_eq!(headers.get_all("host").len(), 2);
    }

    #[test]
    fn insert_id_collapses_every_occurrence_like_insert() {
        use bytes::Bytes;

        let mut by_id = HeaderMap::new();
        assert_eq!(
            by_id.insert_id(HeaderId::Accept, Bytes::from_static(b"first")),
            None,
            "the first insert replaces nothing"
        );
        let replaced = by_id.insert_id(HeaderId::Accept, Bytes::from_static(b"second"));
        assert_eq!(replaced.as_deref(), Some(&b"first"[..]));
        assert_eq!(by_id.len(), 1, "replacing must not grow the map");

        let mut by_name = HeaderMap::new();
        by_name.insert("Accept", "first");
        let replaced_by_name = by_name.insert("Accept", "second");

        assert_eq!(
            replaced_by_name.as_deref(),
            Some(&b"first"[..]),
            "insert and insert_id must return the same displaced value"
        );
        assert_eq!(by_id.get("accept"), by_name.get("accept"));
        assert_eq!(by_id.len(), by_name.len());

        // And the property the name claims: three occurrences in, one out.
        let mut repeated = HeaderMap::new();
        for value in [&b"a"[..], b"b", b"c"] {
            repeated.append_id(HeaderId::Accept, Bytes::copy_from_slice(value));
        }
        repeated.insert_id(HeaderId::Accept, Bytes::from_static(b"final"));
        assert_eq!(
            repeated.get_all("accept"),
            vec!["final"],
            "insert_id must collapse every occurrence, as insert and \
             http::HeaderMap::insert do"
        );
    }

    #[test]
    fn iter_yields_lowercased_names_for_custom_headers() {
        let mut h = HeaderMap::new();
        h.insert("X-A", "1");
        // Interning lowercases custom names once, at insert. A caller comparing
        // `name == "x-a"` must not have to guess which case survived.
        assert_eq!(h.iter().collect::<Vec<_>>(), vec![("x-a", "1")]);
    }

    #[test]
    fn test_common_accessors() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Content-Length", "100");
        headers.insert("Connection", "keep-alive");
        headers.insert("Transfer-Encoding", "chunked");

        assert_eq!(headers.content_type(), Some("application/json"));
        assert_eq!(headers.content_length(), Some(100));
        assert!(headers.is_keep_alive());
        assert!(headers.is_chunked());
    }

    #[test]
    fn test_from_hash_map() {
        let mut map = HashMap::new();
        map.insert("Content-Type".to_string(), "application/json".to_string());
        map.insert("Accept".to_string(), "text/html".to_string());

        let headers = HeaderMap::from_hash_map(map);
        assert_eq!(headers.len(), 2);
        assert!(headers.contains("Content-Type"));
    }

    #[test]
    fn test_to_hash_map_normalizes_names_to_lowercase() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");

        let map = headers.to_hash_map();
        // Names are interned, so the case they were inserted with is gone. This
        // is the documented behavior change in 0.6: lookups stay
        // case-insensitive, but a `HashMap` snapshot reports canonical names.
        assert_eq!(
            map.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(map.get("Content-Type"), None);
    }

    #[test]
    fn test_from_iterator() {
        let headers: HeaderMap = [
            ("Content-Type", "application/json"),
            ("Accept", "text/html"),
        ]
        .into_iter()
        .collect();

        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_indexing() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");

        assert_eq!(&headers["Content-Type"], "application/json");
    }

    #[test]
    fn test_contains_key() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");

        assert!(headers.contains_key("Content-Type"));
        assert!(headers.contains_key("content-type"));
        assert!(!headers.contains_key("Accept"));
    }

    #[test]
    fn test_keys() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Accept", "text/html");

        let keys: Vec<_> = headers.keys().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"content-type"));
        assert!(keys.contains(&"accept"));
    }

    #[test]
    fn test_values() {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Accept", "text/html");

        let values: Vec<_> = headers.values().collect();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"application/json"));
        assert!(values.contains(&"text/html"));
    }

    #[test]
    fn test_is_empty() {
        let mut headers = HeaderMap::new();
        assert!(headers.is_empty());
        headers.insert("Content-Type", "application/json");
        assert!(!headers.is_empty());
    }

    #[test]
    fn test_default() {
        let headers = HeaderMap::default();
        assert!(headers.is_empty());
        assert!(headers.is_inline());
    }

    #[test]
    fn test_extend_trait() {
        let mut headers = HeaderMap::new();
        headers.insert("Existing", "1");

        let extra: Vec<(String, String)> = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];
        Extend::extend(&mut headers, extra);

        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get("Content-Type"), Some("application/json"));
    }

    #[test]
    fn test_into_iterator_owned() {
        let mut headers = HeaderMap::new();
        headers.insert("A", "1");
        headers.insert("B", "2");

        let collected: Vec<(String, String)> = headers.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_into_iterator_ref() {
        let mut headers = HeaderMap::new();
        headers.insert("A", "1");

        let collected: Vec<(&str, &str)> = (&headers).into_iter().collect();
        assert_eq!(collected, vec![("a", "1")]);
    }

    #[test]
    fn test_hashmap_roundtrip() {
        let mut map = HashMap::new();
        map.insert("Content-Type".to_string(), "application/json".to_string());

        let headers: HeaderMap = map.clone().into();
        assert!(headers.contains_key("content-type"));
        let back: HashMap<String, String> = headers.into();
        // Canonical (lowercase) name on the way out; see
        // `test_to_hash_map_normalizes_names_to_lowercase`.
        assert_eq!(back.get("content-type"), map.get("Content-Type"));
    }

    #[test]
    fn cloning_a_value_does_not_copy_it() {
        let mut headers = HeaderMap::new();
        let big = Bytes::from(vec![b'x'; 4096]);
        headers.insert("x-big", big.clone());
        let copy = headers.clone();
        assert_eq!(
            copy.get_bytes("x-big").map(|b| b.as_ptr()),
            Some(big.as_ptr())
        );
    }
}
