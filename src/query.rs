//! Lazy query-string parsing.
//!
//! The old path parsed *and* percent-decoded the whole query into a
//! `HashMap<String, String>` on every request that had one, whether or not any
//! handler read it. This parses on first access and memoizes, so a handler that
//! ignores the query pays nothing beyond carrying the raw bytes it already had.
//!
//! # Repeated keys: the first one wins
//!
//! `?role=user&role=admin` is ambiguous, and if one layer (say, an auth check
//! reading [`QueryView::get`]) took the first value while another (the handler's
//! `Query<T>` or a `HashMap` copy) took the last, an attacker could show each
//! layer a different value. Every single-value view of urlencoded input in this
//! crate therefore resolves a repeated key to its **first** occurrence:
//! [`QueryView::get`], [`QueryView::to_hash_map`], the `Query<T>` extractor,
//! [`crate::form::parse_form`], [`crate::form::parse_form_map`], and
//! [`crate::form::MultipartParser::to_map`]. Use [`QueryView::get_all`] when
//! every value is wanted.

use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::HashMap;

/// Parsed query pairs. Eight inline slots covers essentially all real queries.
pub type QueryPairs = SmallVec<[(String, String); 8]>;

/// A parsed view over a request's query string.
///
/// Borrowed from the request, so it cannot outlive it: the view hands out
/// `&str` into the request's memoized pairs, never copies of them. The pairs
/// themselves are owned — percent-decoding has to produce new bytes — but they
/// are built once, on first access, not per lookup.
#[derive(Debug, Clone, Copy)]
pub struct QueryView<'a> {
    pairs: &'a [(String, String)],
}

impl<'a> QueryView<'a> {
    #[inline]
    pub(crate) fn new(pairs: &'a [(String, String)]) -> Self {
        Self { pairs }
    }

    /// The first value for `key`.
    #[inline]
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether `key` appears at all.
    #[inline]
    pub fn contains_key(&self, key: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == key)
    }

    /// Every value for `key`, in the order the client sent them.
    #[inline]
    pub fn get_all(&self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.pairs
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every pair, in the order the client sent them.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of pairs, counting repeated keys separately.
    #[inline]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether the query carried any pairs.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// An owned copy, for the call sites that genuinely need one.
    ///
    /// This is the allocation the lazy path exists to avoid — reach for it only
    /// when a `HashMap` is actually required. Repeated keys collapse to the
    /// *first* one, agreeing with [`get`](Self::get) (see the module docs).
    pub fn to_hash_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(self.pairs.len());
        for (k, v) in self.pairs {
            map.entry(k.clone()).or_insert_with(|| v.clone());
        }
        map
    }
}

impl<'a> IntoIterator for QueryView<'a> {
    type Item = (&'a str, &'a str);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, String)>,
        fn(&'a (String, String)) -> (&'a str, &'a str),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn as_strs(pair: &(String, String)) -> (&str, &str) {
            (pair.0.as_str(), pair.1.as_str())
        }
        self.pairs.iter().map(as_strs as fn(_) -> _)
    }
}

/// Reduce urlencoded `input` to the first occurrence of each key, so serde
/// deserialization (whose `HashMap`s keep the last value and whose structs
/// reject duplicates) agrees with the crate-wide first-wins rule.
///
/// Borrows `input` unchanged in the common case of no repeated key; only input
/// that actually repeats a key (or whose keys need decoding to tell) is
/// re-encoded. Errors carry serde's message, for the caller to log.
pub(crate) fn first_wins_urlencoded(input: &[u8]) -> Result<Cow<'_, [u8]>, String> {
    // Fast path on the raw keys. A key with an escape or `+` could equal
    // another only after decoding, so those take the slow path.
    let mut keys: SmallVec<[&[u8]; 16]> = SmallVec::new();
    let mut needs_decode = false;
    for pair in input.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let key = pair.split(|&b| b == b'=').next().unwrap_or(pair);
        if key.iter().any(|&b| b == b'%' || b == b'+') {
            needs_decode = true;
            break;
        }
        keys.push(key);
    }
    if !needs_decode {
        keys.sort_unstable();
        if keys.windows(2).all(|w| w[0] != w[1]) {
            return Ok(Cow::Borrowed(input));
        }
    }

    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_bytes(input).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::with_capacity(pairs.len());
    let deduped: Vec<(String, String)> = pairs
        .into_iter()
        .filter(|(k, _)| seen.insert(k.clone()))
        .collect();
    serde_urlencoded::to_string(&deduped)
        .map(|s| Cow::Owned(s.into_bytes()))
        .map_err(|e| e.to_string())
}

/// Parse `query` into key/value pairs, percent-decoding both sides.
///
/// The semantics are exactly `application/x-www-form-urlencoded` parsing as
/// the `form_urlencoded` crate (and so `serde_urlencoded`, behind `Query<T>`
/// and `parse_form`) does it: empty `&`-separated pieces are skipped, a bare
/// key gets an empty value, an **empty key is kept**, `+` is a space, an
/// escape that is not `%` plus two hex digits stays literal, and bytes that
/// decode to invalid UTF-8 become U+FFFD.
///
/// Matching is the point, not a nicety. The response caches key on these
/// pairs while the handler reads the query through serde; any input the two
/// read differently (`?q=1&=payload` with the empty key dropped here, or
/// `%FF` kept raw here but replaced by serde) lets two requests the handler
/// answers differently share one cache entry.
///
/// Malformed input degrades rather than erroring. Rejecting a request over a
/// stray `%` would break clients for no security gain — nothing downstream
/// trusts these bytes.
pub(crate) fn parse(query: &str) -> QueryPairs {
    let mut out = QueryPairs::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.push((decode(raw_key).into_owned(), decode(raw_value).into_owned()));
    }
    out
}

/// Percent- and plus-decode one component.
///
/// Returns `Cow::Borrowed` when there is nothing to decode, which is the common
/// case, so the copy happens only for values that need it.
fn decode(s: &str) -> Cow<'_, str> {
    if !s.contains('%') && !s.contains('+') {
        return Cow::Borrowed(s);
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                // `get` does the bounds check, so a truncated escape at the end
                // of the input falls into the `None` arm rather than panicking.
                // Both digits must be hex. `from_str_radix` alone would also
                // take a sign (`%+1` as 0x01), which `form_urlencoded` doesn't.
                match bytes
                    .get(i + 1..i + 3)
                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        // Not a valid escape. Keep it as written.
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    // Lossy, as `form_urlencoded` is. Handing back the raw escaped text
    // instead made `%FF` read as the three characters `%FF` here — the same
    // pair `%25FF` decodes to — while the handler saw U+FFFD.
    match String::from_utf8(out) {
        Ok(decoded) => Cow::Owned(decoded),
        Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use crate::HttpRequest;

    #[test]
    fn parses_on_first_access_and_decodes() {
        let req = HttpRequest::new("GET", "/s?q=hello%20world&page=2");
        let q = req.query();
        assert_eq!(q.get("q"), Some("hello world"));
        assert_eq!(q.get("page"), Some("2"));
        assert_eq!(q.get("absent"), None);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn plus_is_a_space_and_percent_escapes_decode() {
        let req = HttpRequest::new("GET", "/s?a=x+y&b=%2Fpath&c=%E2%9C%93");
        let q = req.query();
        assert_eq!(q.get("a"), Some("x y"));
        assert_eq!(q.get("b"), Some("/path"));
        assert_eq!(q.get("c"), Some("✓"));
    }

    #[test]
    fn repeated_keys_are_all_reachable_and_get_returns_the_first() {
        let req = HttpRequest::new("GET", "/s?tag=a&tag=b");
        let q = req.query();
        assert_eq!(q.get("tag"), Some("a"));
        assert_eq!(q.get_all("tag").collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn to_hash_map_agrees_with_get_on_repeated_keys() {
        let req = HttpRequest::new("GET", "/s?role=user&role=admin");
        let q = req.query();
        assert_eq!(q.get("role"), Some("user"));
        assert_eq!(
            q.to_hash_map().get("role").map(String::as_str),
            Some("user")
        );
    }

    #[test]
    fn first_wins_urlencoded_borrows_when_unique_and_dedupes_otherwise() {
        use super::first_wins_urlencoded;
        use std::borrow::Cow;

        let unique = b"a=1&b=2";
        assert!(matches!(
            first_wins_urlencoded(unique).unwrap(),
            Cow::Borrowed(_)
        ));
        assert_eq!(
            &*first_wins_urlencoded(b"role=user&x=1&role=admin").unwrap(),
            b"role=user&x=1"
        );
        // Keys equal only after decoding are still duplicates.
        assert_eq!(
            &*first_wins_urlencoded(b"role=user&r%6Fle=admin").unwrap(),
            b"role=user"
        );
    }

    #[test]
    fn no_query_string_is_an_empty_view_not_a_panic() {
        let req = HttpRequest::new("GET", "/s");
        assert!(req.query().is_empty());
        assert_eq!(req.query_string(), None);
        assert_eq!(req.query_param("x"), None);
    }

    #[test]
    fn malformed_input_degrades_rather_than_failing() {
        // A bare key, an empty value, a stray '=', and a truncated escape. None of
        // these is worth rejecting a request over, and all of them appear in real
        // traffic.
        let req = HttpRequest::new("GET", "/s?flag&empty=&=novalue&bad=%zz&trunc=%2");
        let q = req.query();
        assert_eq!(q.get("flag"), Some(""));
        assert_eq!(q.get("empty"), Some(""));
        // An undecodable escape is preserved verbatim rather than dropped, so a
        // handler sees what the client actually sent.
        assert_eq!(q.get("bad"), Some("%zz"));
        assert_eq!(q.get("trunc"), Some("%2"));
        // A pair with an empty key is kept, as serde's parser keeps it.
        assert_eq!(q.get(""), Some("novalue"));
        assert_eq!(q.len(), 5);
    }

    /// `QueryView` must read every query exactly as `serde_urlencoded` (and
    /// so `Query<T>`) does, or a cache keyed on the view can be made to
    /// share an entry between requests the handler answers differently.
    #[test]
    fn decoding_matches_serde_urlencoded() {
        for raw in [
            "q=1&=payload",
            "=",
            "q=%FF",
            "q=%25FF",
            "a=%+1&b=%2&c=%zz&d=x+y&e=%E2%9C%93&f",
            "&&k=v&&",
            "k=%C3",
            "%FF=v",
        ] {
            let req = HttpRequest::new("GET", format!("/s?{raw}"));
            let ours: Vec<(String, String)> = req
                .query()
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            let serde: Vec<(String, String)> = serde_urlencoded::from_str(raw).unwrap();
            assert_eq!(ours, serde, "{raw}");
        }
    }

    #[test]
    fn the_view_is_memoized_across_calls() {
        let req = HttpRequest::new("GET", "/s?a=1");
        let first = req.query().get("a").map(str::to_owned);
        let second = req.query().get("a").map(str::to_owned);
        assert_eq!(first, second);
        // Same backing storage both times: the second call must not re-parse.
        let p1 = req.query().iter().next().map(|(k, _)| k.as_ptr());
        let p2 = req.query().iter().next().map(|(k, _)| k.as_ptr());
        assert_eq!(p1, p2);
    }

    #[test]
    fn cloning_a_request_does_not_carry_a_stale_cache() {
        let req = HttpRequest::new("GET", "/s?a=1");
        assert_eq!(req.query().get("a"), Some("1"));
        let mut clone = req.clone();
        clone.path = crate::ByteStr::from("/s?a=2");
        // The clone's path changed, so its cache must not answer for the old one.
        assert_eq!(clone.query().get("a"), Some("2"));
    }
}
