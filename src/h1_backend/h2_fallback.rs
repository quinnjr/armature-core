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
//! reaches here today. [`Replay`] exists anyway: the bytes read to *recognise*
//! a preface are part of the HTTP/2 stream and cannot be re-read from the
//! socket, so the day detection is turned on, anything that does not replay
//! them ahead of the transport hands hyper a stream missing its opening frames.

use crate::application::ServeState;
use armature_h1::{H2Fallback, Transport};
use bytes::Bytes;
use hyper::body::Incoming as IncomingBody;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
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
    /// Splice `head` in front of `inner`, or hand back `inner` unchanged when
    /// there is nothing to replay.
    pub(crate) fn new(inner: Box<dyn Transport>, head: Bytes) -> Self {
        Self { inner, head }
    }
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // `buf.remaining() > 0` is not redundant with the emptiness check:
        // filling nothing and returning `Ready(Ok(()))` is how a reader signals
        // EOF, so a zero-capacity poll answered from the replay buffer would
        // announce end-of-stream on a connection that has not even begun. Fall
        // through and let `inner` say whatever it says about a read of nothing.
        if !self.head.is_empty() && buf.remaining() > 0 {
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
    // capable of avoiding. `Replay` wraps unconditionally, so "every" is
    // literal.
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
pub(crate) struct HyperH2 {
    state: ServeState,
    builder: hyper::server::conn::http2::Builder<TokioExecutor>,
}

impl HyperH2 {
    /// An HTTP/2 fallback serving `state` with `builder`'s tuning.
    pub(crate) fn new(
        state: ServeState,
        builder: hyper::server::conn::http2::Builder<TokioExecutor>,
    ) -> Self {
        Self { state, builder }
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
        let builder = self.builder.clone();
        Box::pin(async move {
            let io = TokioIo::new(Replay::new(io, buffered));
            let service = service_fn(move |req: hyper::Request<IncomingBody>| {
                let state = state.clone();
                async move { crate::application::handle_request(req, state).await }
            });
            if let Err(err) = builder.serve_connection(io, service).await {
                crate::logging::error!(error = %err, "Error serving HTTP/2 connection");
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
}
