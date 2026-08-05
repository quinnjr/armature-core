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
use std::collections::HashMap;

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
    // the last one. `HeaderMap::get` then returns the *first* occurrence, so any
    // reader of a field that may legitimately repeat has to ask for all of them
    // — see `HttpRequest::client_address`, where taking the first line of a
    // two-line `X-Forwarded-For` would return the client's own entry.
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
    // Destructured rather than read through `&response`, so each header value's
    // `String` buffer becomes the `Bytes` instead of being copied into a fresh
    // one — `response` is consumed a few lines further down anyway, so the
    // borrow was buying nothing.
    let HttpResponse {
        status,
        headers,
        cookies,
        body,
    } = response;
    let mut out = H1Response::new(status);

    // Pushed in place rather than through `Response::header`, which takes and
    // returns `self` by value: `Response` embeds a `SmallVec<[(HeaderId,
    // Bytes); 16]>`, so a builder chain moves about a kilobyte of inline
    // storage per field for no gain in a loop that already owns the response.
    for (key, value) in HashMap::from(headers) {
        out.headers
            .push((header_id::intern(&key), Bytes::from(value)));
    }
    // `Set-Cookie` is the canonical repeating field: a response setting two
    // cookies must emit two fields rather than one comma-joined one. Nothing on
    // this side collapses duplicates — `Response::header` appends too, so the
    // loop above preserves a repeated field exactly as this one does — the two
    // loops differ only in where their values come from.
    for cookie in cookies {
        out.headers.push((HeaderId::SetCookie, Bytes::from(cookie)));
    }
    if let Some(cors) = cors {
        out.headers.push((
            header_id::intern("access-control-allow-origin"),
            Bytes::from(cors.allow_origin.clone()),
        ));
        if cors.allow_credentials {
            out.headers.push((
                header_id::intern("access-control-allow-credentials"),
                Bytes::from_static(b"true"),
            ));
        }
    }

    if body.is_empty() {
        // Wire-identical to `Full(empty)`, not a correctness fix: `write_head`
        // gates framing on the status rather than on the variant, so a 204 or
        // 304 gets no `Content-Length` either way and a 200 gets
        // `content-length: 0` either way. The variant is chosen to say what is
        // meant — there is no body — where `Full` would claim a body that
        // happens to be zero bytes long.
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
    fn an_empty_body_is_named_empty_rather_than_a_zero_length_full() {
        let out = to_h1_response(HttpResponse::new(204), None);
        assert_eq!(out.status, 204);
        assert!(
            matches!(out.body, ResponseBody::Empty),
            "an absent body must be spelled Empty, not Full(0) — the wire is \
             the same either way, so the variant is what carries the intent"
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
