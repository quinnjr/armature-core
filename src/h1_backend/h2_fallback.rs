//! Routing HTTP/2 connections off the `armature-h1` path and into hyper.
//!
//! `armature-h1` serves HTTP/1.1 and nothing else, by design. Its dispatch
//! classifies each connection first — ALPN `h2` after a TLS handshake, or the
//! h2c prior-knowledge preface on plaintext — and hands anything it will not
//! serve to an [`H2Fallback`]. This is that fallback: hyper's HTTP/2 connection
//! driver, which is what served these connections before the swap and still
//! does.
//!
//! The `buffered` contract is one this fallback satisfies without currently
//! exercising. Bytes only accompany a connection on the h2c path, and h2c
//! detection is `armature-h1`'s `Config::detect_h2c`, which is opt-in and which
//! [`h1_config`](super::serve::h1_config) does not enable — plaintext h2c has
//! its own hyper-only listener. So `buffered` is empty on every connection that
//! reaches here today, and [`Replay::wrap`] hands each of those straight to
//! hyper unwrapped. [`Replay`] exists anyway, for the day detection is turned
//! on: the bytes read to *recognise* a preface are part of the HTTP/2 stream
//! and cannot be re-read from the socket, so anything that does not replay them
//! ahead of the transport hands hyper a stream missing its opening frames.

use crate::application::ServeState;
use crate::http2::H2ConnectionServer;
use armature_h1::{H2Fallback, Transport};
use bytes::Bytes;
use std::future::Future;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A transport with already-read bytes spliced in front of it.
///
/// Reads drain `head` first, then fall through to `inner`. Writes and shutdown
/// always go straight to `inner`: the replayed bytes are inbound-only.
pub(crate) struct Replay {
    inner: Box<dyn Transport>,
    head: Bytes,
}

impl Replay {
    /// Splice `head` in front of `inner`.
    ///
    /// Wraps unconditionally; [`Replay::wrap`] is what callers holding a
    /// possibly-empty `head` should reach for.
    pub(crate) fn new(inner: Box<dyn Transport>, head: Bytes) -> Self {
        Self { inner, head }
    }

    /// `inner` with `head` spliced in front of it, or `inner` itself when there
    /// is nothing to replay.
    ///
    /// The empty case is the common one, not the corner one: `head` is empty on
    /// every connection reaching this fallback today, so wrapping regardless
    /// would put a layer with nothing to do underneath every HTTP/2 response the
    /// server writes, and each read and write would pay a second virtual
    /// dispatch on its way to the socket for the privilege.
    pub(crate) fn wrap(inner: Box<dyn Transport>, head: Bytes) -> Box<dyn Transport> {
        if head.is_empty() {
            inner
        } else {
            Box::new(Self::new(inner, head))
        }
    }
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.head.is_empty() {
            // A short read is a legal read, so there is no need to also pull
            // from `inner` in the same call — and doing so would reorder bytes
            // if `inner` were ready and the replay buffer did not fit.
            let n = self.head.len().min(buf.remaining());
            let chunk = self.head.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    // Both of these must be forwarded, not defaulted. hyper's HTTP/2 writer
    // asks `is_write_vectored` whether it may hand the socket a list of frame
    // slices or must first coalesce them into a scratch buffer, and the default
    // answer is `false` — so leaving it to the default would make every HTTP/2
    // response on this path pay a copy the transport underneath is perfectly
    // capable of avoiding. `Replay::wrap` keeps most connections out of here
    // entirely, but the ones it does wrap are the ones carrying real h2c
    // traffic, so answering for the transport underneath still matters.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

/// Serves HTTP/2 connections through hyper, with this application's state.
///
/// Holds a [`ServeState`] rather than a reference: it is created once per
/// worker thread and lives as long as the worker does.
///
/// The connection is driven by [`H2ConnectionServer`], not by a bare hyper
/// builder, and that matters more here than anywhere: `armature-h1` awaits
/// this future in the worker that accepted the socket, holding one of that
/// worker's connection slots until it resolves. hyper's HTTP/2 driver has no
/// preface or idle deadline of its own, so without the connection server's a
/// peer that negotiates `h2` and then sends nothing — or answers keep-alive
/// PINGs forever while opening no streams — would hold the slot for the life
/// of the process.
pub(crate) struct HyperH2 {
    state: ServeState,
    server: H2ConnectionServer,
}

impl HyperH2 {
    /// An HTTP/2 fallback serving `state` with `server`'s tuning and limits.
    pub(crate) fn new(state: ServeState, server: H2ConnectionServer) -> Self {
        Self { state, server }
    }
}

impl H2Fallback for HyperH2 {
    fn handle(
        &self,
        io: Box<dyn Transport>,
        buffered: Bytes,
        peer: Option<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        // Stamped here for the same reason the hyper listener stamped it on the
        // accepted socket: the peer address is the one client identifier a
        // handler can trust, and without it `HttpRequest::client_address` falls
        // back to `X-Forwarded-For` — a header the client writes. This fallback
        // holds one state per worker, not per connection, so serving from it
        // unstamped would give every HTTP/2 request on the socket a forgeable
        // origin while HTTP/1.1 on that same socket kept a real one.
        let state = match peer {
            Some(peer) => self.state.for_peer(peer),
            None => self.state.clone(),
        };
        let server = self.server.clone();
        Box::pin(async move {
            if let Err(err) = server.serve(Replay::wrap(io, buffered), state).await {
                crate::logging::debug!(error = %err, "Error serving HTTP/2 connection");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn replayed_bytes_are_read_before_the_transport() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut replay = Replay::new(Box::new(server), Bytes::from_static(b"PREFACE"));

        client.write_all(b"THEREST").await.expect("write");

        let mut out = [0u8; 14];
        let mut filled = 0;
        while filled < out.len() {
            let n = replay.read(&mut out[filled..]).await.expect("read");
            assert_ne!(n, 0, "unexpected EOF at {filled}");
            filled += n;
        }
        assert_eq!(
            &out[..],
            b"PREFACETHEREST",
            "the bytes read to classify the connection must arrive first, or \
             hyper sees a stream missing its opening frames"
        );
    }

    #[tokio::test]
    async fn writes_bypass_the_replay_buffer() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut replay = Replay::new(Box::new(server), Bytes::from_static(b"PREFACE"));

        // The replay buffer is inbound-only: an unconsumed one must not delay
        // or corrupt what the server writes back.
        replay.write_all(b"SETTINGS").await.expect("write");
        replay.flush().await.expect("flush");

        let mut out = vec![0u8; 8];
        client.read_exact(&mut out).await.expect("read");
        assert_eq!(&out[..], b"SETTINGS");
    }

    #[tokio::test]
    async fn wrap_hands_back_the_transport_when_there_is_nothing_to_replay() {
        let (mut client, server) = tokio::io::duplex(4096);
        let server: Box<dyn Transport> = Box::new(server);
        let addr = std::ptr::addr_of!(*server) as *const ();
        let mut io = Replay::wrap(server, Bytes::new());

        // The pointer identity is the assertion: an empty replay buffer must
        // leave the transport itself in hyper's hands rather than a layer that
        // would forward every read and write for the life of the connection.
        assert_eq!(
            std::ptr::addr_of!(*io) as *const (),
            addr,
            "an empty head must not be wrapped"
        );

        client.write_all(b"THEREST").await.expect("write");
        let mut out = [0u8; 7];
        io.read_exact(&mut out).await.expect("read");
        assert_eq!(&out[..], b"THEREST");
    }

    #[tokio::test]
    async fn wrap_splices_a_non_empty_head() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut io = Replay::wrap(Box::new(server), Bytes::from_static(b"PREFACE"));

        client.write_all(b"THEREST").await.expect("write");

        let mut out = [0u8; 14];
        io.read_exact(&mut out).await.expect("read");
        assert_eq!(&out[..], b"PREFACETHEREST");
    }
}
