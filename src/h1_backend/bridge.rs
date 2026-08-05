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

use crate::application::response_wire;
use crate::http::{HttpRequest, HttpResponse};
use armature_h1::{HeaderId, Response as H1Response, ResponseBody, header as header_id};
use bytes::Bytes;
use response_wire::{
    name_is_token, report_transport_field, report_unemittable, transport_field, value_is_emittable,
};
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

/// The 500 served in place of a response a handler made unemittable, CORS
/// included.
///
/// Assembled field by field from [`internal_error_envelope`] rather than by
/// re-entering [`to_h1_response`]: that would be a recursion whose base case
/// depends on the configured origin being emittable, which is not something this
/// function gets to assume about a configuration.
fn unemittable_response(cors: Option<&crate::CorsConfig>) -> H1Response {
    let envelope = response_wire::internal_error_envelope();
    let mut out = H1Response::new(envelope.status);
    for (key, value) in HashMap::from(envelope.headers) {
        out.headers
            .push((header_id::intern(&key), Bytes::from(value)));
    }
    if let Some(cors) = cors {
        // No handler origin to weigh: this response is the framework's, so the
        // configured pair applies as it would to any response the handler did
        // not touch.
        apply_cors(&mut out, &response_wire::cors_additions(None, cors));
    }
    out.with_body(ResponseBody::Full(envelope.body))
}

/// Add whatever the CORS policy decided to add.
fn apply_cors(out: &mut H1Response, additions: &response_wire::CorsAdditions) {
    if let Some(origin) = &additions.origin {
        out.headers.push((
            header_id::intern("access-control-allow-origin"),
            Bytes::from(origin.clone()),
        ));
    }
    if additions.credentials {
        out.headers.push((
            header_id::intern("access-control-allow-credentials"),
            Bytes::from_static(b"true"),
        ));
    }
    if additions.vary_origin {
        out.headers
            .push((header_id::intern("vary"), Bytes::from_static(b"Origin")));
    }
}

/// Convert an [`HttpResponse`] into an `armature-h1` response, applying CORS.
///
/// `cors` mirrors the hyper path's `to_hyper_response`: the per-response origin
/// pair, added to every response when CORS is configured, as distinct from the
/// preflight answer which carries its own full set.
///
/// `method` and `path` are carried only so the fail-closed 500 can name the
/// request that produced it; nothing else here reads them.
pub(crate) fn to_h1_response(
    response: HttpResponse,
    cors: Option<&crate::CorsConfig>,
    method: &crate::Method,
    path: &str,
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
        if !name_is_token(&key) || !value_is_emittable(value.as_bytes()) {
            report_unemittable(&key, value.as_bytes(), method, path, "header");
            return unemittable_response(cors);
        }
        if let Some(field) = transport_field(&key) {
            report_transport_field(&field, &key);
            continue;
        }
        out.headers
            .push((header_id::intern(&key), Bytes::from(value)));
    }
    // `Set-Cookie` is the canonical repeating field: a response setting two
    // cookies must emit two fields rather than one comma-joined one. Nothing on
    // this side collapses duplicates — `Response::header` appends too, so the
    // loop above preserves a repeated field exactly as this one does — the two
    // loops differ only in where their values come from.
    for cookie in cookies {
        // Only the value is in question: the name is the literal `set-cookie`,
        // which is a token by inspection.
        if !value_is_emittable(cookie.as_bytes()) {
            report_unemittable("set-cookie", cookie.as_bytes(), method, path, "set-cookie");
            return unemittable_response(cors);
        }
        out.headers.push((HeaderId::SetCookie, Bytes::from(cookie)));
    }
    if let Some(cors) = cors {
        let handler_origin = out
            .headers
            .iter()
            .find(|(id, _)| id.as_str() == "access-control-allow-origin")
            .map(|(_, value)| value.clone());
        // The decision itself is `cors_additions`, shared with the hyper
        // adapter; this side only carries the result onto the wire. The origin
        // arrived as bytes and the policy is expressed over `str`, so a
        // non-UTF-8 origin is treated as one the configuration cannot have
        // authorised — which is what it is.
        let additions = response_wire::cors_additions(
            handler_origin
                .as_ref()
                .map(|value| std::str::from_utf8(value).unwrap_or("\u{fffd}")),
            cors,
        );
        apply_cors(&mut out, &additions);
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

    /// Every conversion below answers the same nominal request. The method and
    /// path reach the logs and nothing else, so one pair serves for all of them.
    fn convert(response: HttpResponse, cors: Option<&crate::CorsConfig>) -> H1Response {
        to_h1_response(response, cors, &crate::Method::Get, "/t")
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
        let out = convert(HttpResponse::new(204), None);
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

        let out = convert(resp, Some(&cors));

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

    fn value_of<'a>(out: &'a H1Response, name: &str) -> Option<&'a Bytes> {
        out.headers
            .iter()
            .find(|(id, _)| id.as_str() == name)
            .map(|(_, v)| v)
    }

    fn count_of(out: &H1Response, name: &str) -> usize {
        out.headers
            .iter()
            .filter(|(id, _)| id.as_str() == name)
            .count()
    }

    #[test]
    fn a_handler_cannot_override_the_connection_loops_framing() {
        let mut resp = HttpResponse::new(413);
        resp.headers
            .insert("Connection".to_string(), "keep-alive".to_string());
        resp.headers
            .insert("Transfer-Encoding".to_string(), "chunked".to_string());
        resp.headers
            .insert("Upgrade".to_string(), "websocket".to_string());
        resp.headers
            .insert("Content-Length".to_string(), "999".to_string());
        resp.headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        let out = convert(resp, None);

        for field in [
            "connection",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ] {
            assert_eq!(
                count_of(&out, field),
                0,
                "{field} is the transport's to decide, not the handler's"
            );
        }
        // Only the hop-by-hop and framing fields go; everything else survives.
        assert_eq!(
            value_of(&out, "content-type").map(|v| v.as_ref()),
            Some(&b"text/plain"[..])
        );
    }

    #[test]
    fn an_unwritable_header_fails_the_whole_response_closed() {
        for (name, value) in [
            ("X-Bad", "a\r\nx-injected: 1"),
            ("X-Bad", "a\nb"),
            ("X-Bad", "a\0b"),
            ("X Bad", "fine"),
            ("bad:name", "fine"),
        ] {
            let mut resp = HttpResponse::new(200);
            resp.headers.insert(
                "Content-Security-Policy".to_string(),
                "default-src 'none'".to_string(),
            );
            resp.headers.insert(name.to_string(), value.to_string());

            let out = convert(resp, None);

            assert_eq!(out.status, 500, "{name}: {value:?} must fail closed");
            // Not merely "the bad field is gone": serving the rest would serve
            // the page with its CSP silently dropped.
            assert_eq!(count_of(&out, "content-security-policy"), 0);
            // The framework's envelope, not a bare status: a browser doing a
            // credentialed fetch has to be able to tell a 500 from a network
            // failure.
            let body = match &out.body {
                ResponseBody::Full(bytes) => bytes.clone(),
                other => panic!("{name}: expected an envelope body, got {other:?}"),
            };
            assert_eq!(
                String::from_utf8_lossy(&body),
                r#"{"error":"Internal Server Error","status":500}"#
            );
            assert_eq!(
                value_of(&out, "content-type").map(|v| v.as_ref()),
                Some(&b"application/json"[..])
            );
        }
    }

    #[test]
    fn the_fail_closed_500_still_carries_the_configured_cors_headers() {
        let mut resp = HttpResponse::new(200);
        resp.headers.insert("X Bad".to_string(), "fine".to_string());
        let cors = crate::CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(resp, Some(&cors));

        assert_eq!(out.status, 500);
        assert_eq!(
            value_of(&out, "access-control-allow-origin").map(|v| v.as_ref()),
            Some(&b"https://configured.test"[..]),
            "without these a credentialed fetch sees an opaque CORS failure \
             rather than the 500 that actually happened"
        );
        assert_eq!(count_of(&out, "access-control-allow-credentials"), 1);
    }

    #[test]
    fn an_unwritable_cookie_fails_the_whole_response_closed() {
        let mut resp = HttpResponse::new(200);
        resp.cookies
            .push("session=abc; Secure; HttpOnly\r\nx-injected: 1".to_string());

        let out = convert(resp, None);

        assert_eq!(out.status, 500);
        assert_eq!(count_of(&out, "set-cookie"), 0);
    }

    #[test]
    fn a_valid_response_still_passes_the_writability_check() {
        let mut resp = HttpResponse::new(200);
        resp.headers
            .insert("X-Trace-Id".to_string(), "abc-123".to_string());
        resp.cookies.push("a=1; Secure".to_string());

        let out = convert(resp, None);

        assert_eq!(out.status, 200);
        assert_eq!(count_of(&out, "x-trace-id"), 1);
        assert_eq!(count_of(&out, "set-cookie"), 1);
    }

    #[test]
    fn a_handler_supplied_cors_origin_is_not_duplicated() {
        let mut resp = HttpResponse::new(200);
        resp.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://configured.test".to_string(),
        );
        let cors = crate::CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(resp, Some(&cors));

        assert_eq!(
            count_of(&out, "access-control-allow-origin"),
            1,
            "two origin fields make a browser reject the response outright"
        );
        assert_eq!(
            value_of(&out, "access-control-allow-origin").map(|v| v.as_ref()),
            Some(&b"https://configured.test"[..])
        );
        assert_eq!(
            count_of(&out, "access-control-allow-credentials"),
            1,
            "the handler named the origin the configuration authorises, so the \
             credentialed answer is the one the operator asked for"
        );
        assert_eq!(
            value_of(&out, "vary").map(|v| v.as_ref()),
            Some(&b"Origin"[..]),
            "the origin came from the handler, so the response varies by it and \
             a shared cache has to be told"
        );
    }

    #[test]
    fn a_reflected_origin_the_configuration_does_not_authorise_gets_no_credentials() {
        let mut resp = HttpResponse::new(200);
        resp.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            "https://evil.test".to_string(),
        );
        let cors = crate::CorsConfig::new("https://configured.test").with_credentials();

        let out = convert(resp, Some(&cors));

        assert_eq!(
            value_of(&out, "access-control-allow-origin").map(|v| v.as_ref()),
            Some(&b"https://evil.test"[..]),
            "the handler's field still stands alone; a second one would only \
             make the browser discard the response"
        );
        assert_eq!(
            count_of(&out, "access-control-allow-credentials"),
            0,
            "a handler reflecting Origin unchecked plus credentials is a full \
             credentialed cross-origin read for any site that asks"
        );
    }

    #[test]
    fn credentials_are_withheld_from_a_wildcard_origin() {
        let cors = crate::CorsConfig::new("*").with_credentials();

        let out = convert(HttpResponse::new(200), Some(&cors));

        assert_eq!(
            value_of(&out, "access-control-allow-origin").map(|v| v.as_ref()),
            Some(&b"*"[..])
        );
        assert_eq!(
            count_of(&out, "access-control-allow-credentials"),
            0,
            "browsers reject `*` with credentials, so emitting both fails the \
             request rather than degrading it"
        );
    }
}
