//! Serving HTTP/1.1 through `armature-h1` instead of hyper.
//!
//! Enabled by the `h1-backend` feature, which is on by default. With it off,
//! `Application`'s listeners use `hyper::server::conn::http1` exactly as they
//! did before this module existed.
//!
//! # What changes
//!
//! HTTP/1.1 is served by [`armature_h1`]: its parser, its writer, its framing
//! decisions, and its thread-per-core accept loop. HTTP/2 is still hyper's —
//! reached through [`h2_fallback`] when `armature-h1`'s dispatch classifies a
//! connection as HTTP/2, which today means ALPN `h2` alone. `armature-h1` will
//! also classify the h2c prior-knowledge preface, but only with
//! `Config::detect_h2c` set, which [`serve::h1_config`] leaves off: plaintext
//! HTTP/2 has its own hyper listener rather than sharing the HTTP/1 one.
//! HTTP/3 is untouched.
//!
//! # What this buys
//!
//! Request heads stop being copied. `armature-h1` parses field values into
//! [`bytes::Bytes`] slices of the connection's own read buffer and field names
//! into the same `HeaderId` this crate already stores, so a head crosses into
//! [`HttpRequest`](crate::HttpRequest) as a sequence of moves — where the hyper
//! path copies every value out of a `HeaderValue` and re-interns every name.
//! See [`bridge`].
//!
//! # What it costs
//!
//! `armature-h1` is stricter than hyper about what it will parse (bare LF, a
//! fragment in the request target, an unsupported transfer coding) and closes
//! the connection on every framing rejection. That strictness is the reason to
//! want it — leniency that differs from a peer's leniency is the request
//! smuggling vector — but a client that relied on hyper's permissiveness will
//! now be refused. `armature-h1`'s `BACKENDS.md` documents the divergences from
//! the other direction.
//!
//! It also means a handler must not block: a thread-per-core worker serves
//! every connection on its core from one thread, so a blocking handler stalls
//! them all. The hyper path's work-stealing runtime hid that; this one does not.

pub(crate) mod bridge;
#[cfg(test)]
mod e2e_tests;
pub(crate) mod h2_fallback;
pub(crate) mod serve;

pub(crate) use serve::{h1_config, serve};
