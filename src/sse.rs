// Server-Sent Events (SSE) support for Armature

use crate::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Server-Sent Event
///
/// `Debug` prints `data`'s length, not its contents.
#[derive(Clone)]
pub struct ServerSentEvent {
    /// Event ID (optional)
    pub id: Option<String>,
    /// Event type (optional)
    pub event: Option<String>,
    /// Event data
    pub data: String,
    /// Retry interval in milliseconds (optional)
    pub retry: Option<u64>,
}

impl std::fmt::Debug for ServerSentEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSentEvent")
            .field("id", &self.id)
            .field("event", &self.event)
            .field("data", &crate::headers::RedactedLen(self.data.len()))
            .field("retry", &self.retry)
            .finish()
    }
}

impl ServerSentEvent {
    /// Create a new SSE with just data
    pub fn new(data: String) -> Self {
        Self {
            id: None,
            event: None,
            data,
            retry: None,
        }
    }

    /// Create a new SSE with data and event type
    pub fn with_event(event: String, data: String) -> Self {
        Self {
            id: None,
            event: Some(event),
            data,
            retry: None,
        }
    }

    /// Create a new SSE with all fields
    pub fn full(id: String, event: String, data: String, retry: u64) -> Self {
        Self {
            id: Some(id),
            event: Some(event),
            data,
            retry: Some(retry),
        }
    }

    /// Check that `id` and `event` can be serialized without alteration.
    ///
    /// A CR or LF in either field would end the field early and let the rest
    /// of the value be parsed as further SSE fields (e.g. a forged `event:` or
    /// `data:` line); a NUL in `id` makes browsers ignore the id entirely.
    /// [`to_string`](Self::to_string) strips those characters regardless, so
    /// this is for callers that would rather reject such input than send a
    /// silently altered value.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(ref id) = self.id
            && id.contains(['\r', '\n', '\0'])
        {
            return Err(Error::Validation(
                "SSE id must not contain CR, LF or NUL".to_string(),
            ));
        }
        if let Some(ref event) = self.event
            && event.contains(['\r', '\n'])
        {
            return Err(Error::Validation(
                "SSE event type must not contain CR or LF".to_string(),
            ));
        }
        Ok(())
    }

    /// Convert to SSE format string
    ///
    /// Single-line fields (`id`, `event`) have CR/LF (and NUL, for `id`)
    /// removed so a value cannot inject additional fields. `data` is split on
    /// every line terminator the SSE grammar recognizes (`\r\n`, `\r`, `\n`)
    /// and each piece is emitted as its own `data:` line, which the client
    /// rejoins with `\n`.
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let mut output = String::new();

        if let Some(ref id) = self.id {
            output.push_str("id: ");
            output.extend(id.chars().filter(|c| !matches!(c, '\r' | '\n' | '\0')));
            output.push('\n');
        }

        if let Some(ref event) = self.event {
            output.push_str("event: ");
            output.extend(event.chars().filter(|c| !matches!(c, '\r' | '\n')));
            output.push('\n');
        }

        // `str::lines` only splits on `\n` (and `\r\n`), so a bare `\r` would
        // pass through and be read by the client as a line break, starting a
        // new, attacker-chosen field.
        let mut rest = self.data.as_str();
        loop {
            match rest.find(['\r', '\n']) {
                Some(pos) => {
                    output.push_str("data: ");
                    output.push_str(&rest[..pos]);
                    output.push('\n');
                    let skip = if rest[pos..].starts_with("\r\n") {
                        2
                    } else {
                        1
                    };
                    rest = &rest[pos + skip..];
                }
                None => {
                    output.push_str("data: ");
                    output.push_str(rest);
                    output.push('\n');
                    break;
                }
            }
        }

        if let Some(retry) = self.retry {
            output.push_str(&format!("retry: {}\n", retry));
        }

        output.push('\n');
        output
    }
}

/// SSE stream builder
pub struct SseStream {
    tx: mpsc::Sender<Result<String, Error>>,
}

impl SseStream {
    /// Create a new SSE stream
    pub fn new() -> (Self, ReceiverStream<Result<String, Error>>) {
        let (tx, rx) = mpsc::channel(100);
        let stream = ReceiverStream::new(rx);
        (Self { tx }, stream)
    }

    /// Send an event
    pub async fn send(&self, event: ServerSentEvent) -> Result<(), Error> {
        self.tx
            .send(Ok(event.to_string()))
            .await
            .map_err(|e| Error::Internal(format!("Failed to send SSE: {}", e)))
    }

    /// Send a simple message
    pub async fn send_message(&self, data: String) -> Result<(), Error> {
        self.send(ServerSentEvent::new(data)).await
    }

    /// Send a typed event
    pub async fn send_event(&self, event: String, data: String) -> Result<(), Error> {
        self.send(ServerSentEvent::with_event(event, data)).await
    }

    /// Send JSON data
    pub async fn send_json<T: serde::Serialize>(&self, data: &T) -> Result<(), Error> {
        let json = serde_json::to_string(data).map_err(|e| Error::Serialization(e.to_string()))?;
        self.send_message(json).await
    }

    /// Send a keep-alive comment
    pub async fn send_keep_alive(&self) -> Result<(), Error> {
        self.tx
            .send(Ok(": keep-alive\n\n".to_string()))
            .await
            .map_err(|e| Error::Internal(format!("Failed to send keep-alive: {}", e)))
    }
}

impl Default for SseStream {
    fn default() -> Self {
        Self::new().0
    }
}

/// SSE broadcaster for multiple clients
pub struct SseBroadcaster {
    clients: tokio::sync::RwLock<Clients>,
    /// Refuse registrations past this many live clients; `None` is unbounded.
    max_clients: Option<usize>,
}

/// The registered senders, and the length at which [`SseBroadcaster::register`]
/// next sweeps out the ones whose receiver is gone.
struct Clients {
    senders: Vec<mpsc::Sender<Result<String, Error>>>,
    prune_at: usize,
}

/// The smallest list worth sweeping on registration.
const MIN_PRUNE_AT: usize = 64;

impl SseBroadcaster {
    /// A broadcaster with **no cap** on the number of clients. Each one costs
    /// a buffered channel and a slot every broadcast visits, so an endpoint
    /// open to anonymous clients should use
    /// [`with_max_clients`](Self::with_max_clients).
    pub fn new() -> Self {
        Self {
            clients: tokio::sync::RwLock::new(Clients {
                senders: Vec::new(),
                prune_at: MIN_PRUNE_AT,
            }),
            max_clients: None,
        }
    }

    /// A broadcaster that serves at most `max` clients at once.
    ///
    /// Every client costs a channel of up to 100 buffered events and a slot
    /// that every broadcast visits, so an endpoint open to anonymous clients
    /// should bound them. Past the cap, [`try_register`](Self::try_register)
    /// fails and [`register`](Self::register) hands back a stream that ends
    /// immediately.
    pub fn with_max_clients(max: usize) -> Self {
        Self {
            max_clients: Some(max),
            ..Self::new()
        }
    }

    /// Register a new client
    ///
    /// Senders whose receiver has been dropped are swept out lazily — when the
    /// list has doubled since the last sweep, or when it is at the client cap
    /// — so registration is amortized O(1) rather than a full scan under the
    /// write lock every time, while an application that registers often but
    /// rarely broadcasts still cannot accumulate dead senders without bound
    /// (they are also reaped by every [`broadcast`](Self::broadcast) and
    /// keep-alive).
    ///
    /// With a client cap ([`with_max_clients`](Self::with_max_clients)) and
    /// the cap reached, the returned stream ends at once; use
    /// [`try_register`](Self::try_register) to refuse the request instead.
    pub async fn register(&self) -> ReceiverStream<Result<String, Error>> {
        self.try_register().await.unwrap_or_else(|_| {
            // Dropping the sender ends the stream for the client.
            let (_tx, rx) = mpsc::channel(1);
            ReceiverStream::new(rx)
        })
    }

    /// [`register`](Self::register), failing with
    /// [`Error::ServiceUnavailable`] when the client cap is reached.
    pub async fn try_register(&self) -> Result<ReceiverStream<Result<String, Error>>, Error> {
        let (tx, rx) = mpsc::channel(100);
        let mut clients = self.clients.write().await;
        let at_cap = |len: usize| self.max_clients.is_some_and(|max| len >= max);
        let len = clients.senders.len();
        if len >= clients.prune_at || at_cap(len) {
            clients.senders.retain(|tx| !tx.is_closed());
            clients.prune_at = (clients.senders.len() * 2).max(MIN_PRUNE_AT);
        }
        if at_cap(clients.senders.len()) {
            return Err(Error::ServiceUnavailable(
                "too many event-stream clients".to_string(),
            ));
        }
        clients.senders.push(tx);
        Ok(ReceiverStream::new(rx))
    }

    /// Broadcast an event to all clients
    ///
    /// Uses non-blocking sends so the client list lock is never held across
    /// an `.await`. Slow clients whose channel buffer is full are
    /// disconnected (dropped from the list) so a single stalled client
    /// cannot block broadcasts or new registrations.
    pub async fn broadcast(&self, event: ServerSentEvent) -> Result<(), Error> {
        let data_str = event.to_string();
        let mut clients = self.clients.write().await;

        // Send to all clients, removing those that are disconnected or
        // whose channel is full (slow consumers).
        clients
            .senders
            .retain(|tx| tx.try_send(Ok(data_str.clone())).is_ok());

        Ok(())
    }

    /// Broadcast a simple message
    pub async fn broadcast_message(&self, data: String) -> Result<(), Error> {
        self.broadcast(ServerSentEvent::new(data)).await
    }

    /// Broadcast JSON data
    pub async fn broadcast_json<T: serde::Serialize>(&self, data: &T) -> Result<(), Error> {
        let json = serde_json::to_string(data).map_err(|e| Error::Serialization(e.to_string()))?;
        self.broadcast_message(json).await
    }

    /// Get number of connected clients
    ///
    /// Counts only clients whose stream is still open: dead senders may sit in
    /// the list until the next sweep.
    pub async fn client_count(&self) -> usize {
        let clients = self.clients.read().await;
        clients.senders.iter().filter(|tx| !tx.is_closed()).count()
    }

    /// Start a keep-alive task
    ///
    /// Like [`broadcast`](Self::broadcast), keep-alives use non-blocking
    /// sends: clients that are disconnected or whose channel is full are
    /// removed so a stalled client cannot deadlock the broadcaster.
    pub fn start_keep_alive(
        self: std::sync::Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                let comment_str = ": keep-alive\n\n".to_string();
                let mut clients = self.clients.write().await;
                clients
                    .senders
                    .retain(|tx| tx.try_send(Ok(comment_str.clone())).is_ok());
            }
        })
    }
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_data_length_only() {
        let out = format!("{:?}", ServerSentEvent::new("token=s3cret".to_string()));
        assert!(
            !out.contains("s3cret") && out.contains("<12 bytes>"),
            "{out}"
        );
    }

    #[test]
    fn test_sse_data_bare_cr_does_not_inject_field() {
        let ev = ServerSentEvent::new("a\rb".to_string());
        assert_eq!(ev.to_string(), "data: a\ndata: b\n\n");
    }

    #[test]
    fn test_sse_data_splits_all_line_terminators() {
        let ev = ServerSentEvent::new("a\r\nb\nc\rd".to_string());
        assert_eq!(ev.to_string(), "data: a\ndata: b\ndata: c\ndata: d\n\n");
    }

    #[test]
    fn test_sse_event_and_id_newlines_are_stripped() {
        let ev = ServerSentEvent {
            id: Some("1\r\nretry: 1\0".to_string()),
            event: Some("x\nevent: y".to_string()),
            data: "d".to_string(),
            retry: None,
        };
        let out = ev.to_string();
        assert_eq!(out, "id: 1retry: 1\nevent: xevent: y\ndata: d\n\n");
        assert!(ev.validate().is_err());
        assert!(
            ServerSentEvent::with_event("ok".into(), "a\nb".into())
                .validate()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_broadcast_does_not_block_on_stalled_client() {
        let broadcaster = SseBroadcaster::new();

        // Register a client that never consumes its stream.
        let _stalled_rx = broadcaster.register().await;

        // Fill the stalled client's bounded channel (capacity 100) and keep
        // going; before the fix this deadlocked on a full channel.
        for i in 0..150 {
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                broadcaster.broadcast_message(format!("event {}", i)),
            )
            .await;
            assert!(result.is_ok(), "broadcast deadlocked on a stalled client");
        }

        // The stalled client should have been disconnected once its channel
        // filled.
        assert_eq!(broadcaster.client_count().await, 0);
    }

    #[tokio::test]
    async fn test_register_prunes_closed_senders() {
        let broadcaster = SseBroadcaster::new();

        // Register three clients, then drop two of their receivers.
        let rx1 = broadcaster.register().await;
        let rx2 = broadcaster.register().await;
        let keep = broadcaster.register().await;
        assert_eq!(broadcaster.client_count().await, 3);

        drop(rx1);
        drop(rx2);

        // Dead senders no longer count as clients (they are swept lazily; see
        // `test_dead_senders_do_not_accumulate`), so we end with the live
        // `keep` client and the newly registered one.
        let _new = broadcaster.register().await;
        assert_eq!(broadcaster.client_count().await, 2);

        drop(keep);
    }

    #[tokio::test]
    async fn test_client_cap_is_enforced_and_frees_on_disconnect() {
        use tokio_stream::StreamExt;

        let broadcaster = SseBroadcaster::with_max_clients(2);
        let first = broadcaster.try_register().await.unwrap();
        let _second = broadcaster.try_register().await.unwrap();
        assert!(matches!(
            broadcaster.try_register().await,
            Err(Error::ServiceUnavailable(_))
        ));
        // `register` past the cap yields a stream that ends at once.
        let mut refused = broadcaster.register().await;
        assert!(refused.next().await.is_none());

        // A disconnected client's slot is reclaimed by the at-cap sweep.
        drop(first);
        let _third = broadcaster.try_register().await.expect("a slot was freed");
        assert_eq!(broadcaster.client_count().await, 2);
    }

    /// Dead senders are swept lazily, so the list stays bounded by twice the
    /// live clients (or the sweep floor) however many come and go.
    #[tokio::test]
    async fn test_dead_senders_do_not_accumulate() {
        let broadcaster = SseBroadcaster::new();
        let _live = broadcaster.register().await;
        for _ in 0..10_000 {
            drop(broadcaster.register().await);
        }
        assert!(broadcaster.clients.read().await.senders.len() <= MIN_PRUNE_AT + 1);
        assert_eq!(broadcaster.client_count().await, 1);
    }

    #[tokio::test]
    async fn test_broadcast_reaches_active_client() {
        use tokio_stream::StreamExt;

        let broadcaster = SseBroadcaster::new();
        let mut rx = broadcaster.register().await;

        broadcaster
            .broadcast_message("hello".to_string())
            .await
            .unwrap();

        let received = rx.next().await.unwrap().unwrap();
        assert!(received.contains("data: hello"));
    }
}
