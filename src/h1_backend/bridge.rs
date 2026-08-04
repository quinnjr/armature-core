//! Converting between `armature-h1`'s wire types and this crate's.
//!
//! The conversion in this file is the reason the swap is worth making. Under
//! hyper, `handle_request` copies every header value out of hyper's
//! `HeaderValue` (which owns its own buffer) into a fresh `Bytes`, and
//! re-interns every field name that hyper has already parsed. Here both sides
//! speak the same types — `armature-h1` parses field names straight into
//! [`HeaderId`] and values into [`Bytes`] slices of the connection's read
//! buffer — so a request head crosses this boundary as a sequence of moves.
//!
//! The response direction is not symmetric: [`HttpResponse`] stores headers as
//! `HashMap<String, String>`, so each one is interned and copied on the way out.
//! That is a property of `HttpResponse`, not of this bridge, and changing it is
//! a separate job from swapping the serve path.

use crate::http::{HttpRequest, HttpResponse};
use armature_h1::{HeaderId, Response as H1Response, ResponseBody, header as header_id};
use bytes::Bytes;

/// Build an [`HttpRequest`] from a parsed `armature-h1` head.
///
/// Takes the head by value: every field of it is moved into the result rather
/// than copied, which is only possible with ownership. The body is *not* read
/// here — that is the caller's job, because the size limit that governs it and
/// the response owed when it is exceeded are policy this module has no view of.
pub(crate) fn request_from_head(
    head: armature_h1::Head,
    peer: Option<std::net::SocketAddr>,
) -> HttpRequest {
    // `target()` is the request target as received, query included, which is
    // exactly what `HttpRequest::path` holds; it splits and parses the query on
    // demand, so a handler that ignores it never pays for it. The `ByteStr`
    // clone is a refcount bump on the connection's read buffer, not a copy.
    let target = head.target().clone();
    let mut req = HttpRequest::new(head.method.clone(), target).with_peer(peer);

    // The move that pays for the whole exercise: `head.headers` is already a
    // list of `(HeaderId, Bytes)` in the same representation `HeaderMap` stores,
    // so this neither re-interns a name nor copies a value.
    //
    // `append_id` rather than `insert_id` to preserve a repeated field's
    // occurrences, which the wire allows and which `insert` would collapse to
    // the last one. `HeaderMap::get` returns the first match, so single-valued
    // lookups are unaffected.
    for (id, value) in head.headers {
        req.headers.append_id(id, value);
    }

    req
}

/// Convert an [`HttpResponse`] into an `armature-h1` response, applying CORS.
///
/// `cors` mirrors the hyper path's `to_hyper_response`: the per-response origin
/// pair, added to every response when CORS is configured, as distinct from the
/// preflight answer which carries its own full set.
pub(crate) fn to_h1_response(
    response: HttpResponse,
    cors: Option<&crate::CorsConfig>,
) -> H1Response {
    let status = response.status;
    let mut out = H1Response::new(status);

    for (key, value) in &response.headers {
        out = out.header(header_id::intern(key), Bytes::from(value.clone()));
    }
    // `Set-Cookie` is the canonical repeating field: a response setting two
    // cookies must emit two fields, so this appends rather than replacing.
    for cookie in &response.cookies {
        out.headers
            .push((HeaderId::SetCookie, Bytes::from(cookie.clone())));
    }
    if let Some(cors) = cors {
        out = out.header(
            header_id::intern("access-control-allow-origin"),
            Bytes::from(cors.allow_origin.clone()),
        );
        if cors.allow_credentials {
            out = out.header(
                header_id::intern("access-control-allow-credentials"),
                Bytes::from_static(b"true"),
            );
        }
    }

    let body = response.into_body_bytes();
    if body.is_empty() {
        // Distinct from `Full(empty)`: the writer frames `Empty` without a
        // `Content-Length: 0` on responses that must not carry one (204, 304),
        // which is the difference between a valid response and one a strict
        // proxy rejects.
        out.with_body(ResponseBody::Empty)
    } else {
        out.with_body(ResponseBody::Full(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armature_h1::{Limits, parse_head};

    fn head(raw: &'static [u8]) -> armature_h1::Head {
        parse_head(&Bytes::from_static(raw), &Limits::default())
            .expect("parse")
            .expect("complete")
            .0
    }

    #[test]
    fn the_target_arrives_whole_query_included() {
        let req = request_from_head(head(b"GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: a\r\n\r\n"), None);
        assert_eq!(req.path.as_str(), "/a/b?x=1&y=2");
        assert_eq!(req.query().get("x"), Some("1"));
    }

    #[test]
    fn headers_cross_without_being_re_interned_or_copied() {
        let raw = Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: a\r\nX-Trace-Id: abc\r\nContent-Type: application/json\r\n\r\n",
        );
        let parsed = parse_head(&raw, &Limits::default())
            .expect("parse")
            .expect("complete")
            .0;
        let req = request_from_head(parsed, None);

        assert_eq!(req.headers.get("host"), Some("a"));
        // Lookup is case-insensitive regardless of the case on the wire.
        assert_eq!(req.headers.get("x-trace-id"), Some("abc"));
        assert_eq!(req.headers.get("X-Trace-Id"), Some("abc"));
        assert_eq!(req.headers.get("content-type"), Some("application/json"));

        // The load-bearing assertion: the stored value is a slice of the very
        // buffer that was parsed, not a copy of it. If this bridge ever starts
        // copying, this fails while every value-equality check above still
        // passes.
        let stored = req.headers.get_bytes("x-trace-id").expect("stored");
        let base = raw.as_ptr() as usize;
        let got = stored.as_ptr() as usize;
        assert!(
            got >= base && got < base + raw.len(),
            "header value must point into the parsed buffer, not a copy of it"
        );
    }

    #[test]
    fn a_repeated_field_keeps_every_occurrence() {
        let req = request_from_head(
            head(b"GET / HTTP/1.1\r\nHost: a\r\nAccept: text/html\r\nAccept: text/plain\r\n\r\n"),
            None,
        );
        let all = req.headers.get_all("accept");
        assert_eq!(all.len(), 2, "a repeated field must not collapse: {all:?}");
        // A single-valued lookup still resolves to the first, as before.
        assert_eq!(req.headers.get("accept"), Some("text/html"));
    }

    #[test]
    fn the_peer_address_is_carried_onto_the_request() {
        let peer = "203.0.113.7:44321".parse().expect("addr");
        let req = request_from_head(head(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), Some(peer));
        assert_eq!(req.peer, Some(peer));
    }

    #[test]
    fn an_empty_body_is_framed_as_empty_not_as_a_zero_length_full() {
        let out = to_h1_response(HttpResponse::new(204), None);
        assert_eq!(out.status, 204);
        assert!(
            matches!(out.body, ResponseBody::Empty),
            "an empty body must not become Full(0), which would frame a \
             Content-Length onto a 204"
        );
    }

    #[test]
    fn cookies_and_cors_reach_the_response() {
        let mut resp = HttpResponse::new(200);
        resp.cookies.push("a=1".to_string());
        resp.cookies.push("b=2".to_string());
        let cors = crate::CorsConfig::new("https://example.test").with_credentials();

        let out = to_h1_response(resp, Some(&cors));

        let cookies: Vec<_> = out
            .headers
            .iter()
            .filter(|(id, _)| *id == HeaderId::SetCookie)
            .map(|(_, v)| v.clone())
            .collect();
        assert_eq!(cookies.len(), 2, "each cookie is its own Set-Cookie field");
        assert!(
            out.headers
                .iter()
                .any(|(id, v)| id.as_str() == "access-control-allow-origin"
                    && v.as_ref() == b"https://example.test")
        );
        assert!(
            out.headers
                .iter()
                .any(|(id, v)| id.as_str() == "access-control-allow-credentials"
                    && v.as_ref() == b"true")
        );
    }
}
