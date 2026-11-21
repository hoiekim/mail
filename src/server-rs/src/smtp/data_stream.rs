//! The message of one DATA transaction, handed to `on_data` as it arrives.
//!
//! This is the `PassThrough` the Bun server writes the dot-unstuffed message
//! into: the connection pushes what it reads, stops reading its socket while
//! the consumer is behind, and tells a message that ended from one whose
//! connection went away.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Notify;

/// What the stream holds before the connection stops reading its socket: a
/// `PassThrough` fills its writable and its readable side, 64 KiB each.
const HIGH_WATER_MARK: usize = 128 * 1024;

/// The connection reads again once the consumer has brought the backlog
/// down to this.
const LOW_WATER_MARK: usize = HIGH_WATER_MARK / 2;

/// The error a read fails with when the connection was lost before the
/// message's end. See [`SmtpDataStream::is_abandoned`].
#[derive(Debug)]
pub struct SmtpDataAbandoned;

impl fmt::Display for SmtpDataAbandoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the connection was lost before the end of DATA")
    }
}

impl std::error::Error for SmtpDataAbandoned {}

#[derive(Default)]
struct State {
    chunks: VecDeque<Bytes>,
    buffered: usize,
    /// The terminator was seen: no more bytes will follow.
    ended: bool,
    /// The connection closed before the terminator.
    abandoned: bool,
    /// The consumer has read the end, which is when the reply may go out.
    end_read: bool,
    reader_gone: bool,
    /// The connection stopped reading its socket until the backlog is consumed.
    need_drain: bool,
    reader: Option<Waker>,
}

struct Shared {
    state: Mutex<State>,
    /// Wakes the connection: the backlog drained, the end was read, or the
    /// consumer dropped the stream.
    progress: Notify,
}

/// The connection's side of the stream.
pub(crate) struct DataWriter {
    shared: Arc<Shared>,
}

/// The message of a DATA transaction: dot-unstuffed, without the terminator.
///
/// Read it with [`AsyncRead`] or chunk by chunk as a [`Stream`]. It ends
/// (`Ok(0)` / `None`) at the message's terminator; when the connection is
/// lost first, the read fails with an error [`SmtpDataStream::is_abandoned`]
/// recognizes, which is how a consumer tells an abandoned message from a
/// complete one. Dropping the stream discards the rest of the message.
pub struct SmtpDataStream {
    shared: Arc<Shared>,
}

pub(crate) fn data_stream() -> (DataWriter, SmtpDataStream) {
    let shared = Arc::new(Shared { state: Mutex::new(State::default()), progress: Notify::new() });
    (DataWriter { shared: shared.clone() }, SmtpDataStream { shared })
}

impl DataWriter {
    /// Queues message bytes. `false` means the consumer is behind and the
    /// socket should not be read until [`DataWriter::needs_drain`] clears.
    pub fn write(&self, chunk: Bytes) -> bool {
        let mut state = self.shared.state.lock().unwrap();
        if state.reader_gone || state.ended || state.abandoned || chunk.is_empty() {
            return !state.need_drain;
        }
        state.buffered += chunk.len();
        state.chunks.push_back(chunk);
        if state.buffered >= HIGH_WATER_MARK {
            state.need_drain = true;
        }
        let flowing = !state.need_drain;
        let waker = state.reader.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        flowing
    }

    /// Marks the end of the message.
    pub fn end(&self) {
        self.finish(false);
    }

    /// The connection is gone before the message's end.
    pub fn abandon(&self) {
        self.finish(true);
    }

    fn finish(&self, abandoned: bool) {
        let mut state = self.shared.state.lock().unwrap();
        if state.ended || state.abandoned {
            return;
        }
        if abandoned {
            state.abandoned = true;
        } else {
            state.ended = true;
        }
        let waker = state.reader.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Whether [`DataWriter::end`] was called.
    pub fn is_ended(&self) -> bool {
        self.shared.state.lock().unwrap().ended
    }

    /// The consumer has not caught up with what was written yet.
    pub fn needs_drain(&self) -> bool {
        self.shared.state.lock().unwrap().need_drain
    }

    /// The message ended and its consumer has read all of it, or dropped it.
    pub fn is_finished(&self) -> bool {
        let state = self.shared.state.lock().unwrap();
        state.ended && (state.end_read || state.reader_gone)
    }

    /// Resolves when the consumer made progress the connection cares about.
    pub async fn progress(&self) {
        self.shared.progress.notified().await;
    }
}

impl Drop for DataWriter {
    fn drop(&mut self) {
        self.abandon();
    }
}

impl SmtpDataStream {
    /// Whether `error` is this stream reporting that the connection was lost
    /// mid-message — as opposed to the message having ended.
    pub fn is_abandoned(error: &io::Error) -> bool {
        error.get_ref().is_some_and(|inner| inner.is::<SmtpDataAbandoned>())
    }

    /// The bytes that have arrived and not been read yet. The connection
    /// stops reading its socket while this is at the high-water mark.
    pub fn buffered(&self) -> usize {
        self.shared.state.lock().unwrap().buffered
    }

    /// The next piece of the message, `None` at its end.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        std::future::poll_fn(|cx| self.poll_chunk(cx, usize::MAX)).await
    }

    fn poll_chunk(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<Option<Bytes>>> {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(front) = state.chunks.front_mut() {
            let piece = if front.len() <= limit {
                state.chunks.pop_front().expect("the front chunk exists")
            } else {
                front.split_to(limit)
            };
            state.buffered -= piece.len();
            if state.need_drain && state.buffered <= LOW_WATER_MARK {
                state.need_drain = false;
                drop(state);
                self.shared.progress.notify_one();
            }
            return Poll::Ready(Ok(Some(piece)));
        }
        if state.abandoned {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, SmtpDataAbandoned)));
        }
        if state.ended {
            let first = !state.end_read;
            state.end_read = true;
            drop(state);
            if first {
                self.shared.progress.notify_one();
            }
            return Poll::Ready(Ok(None));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncRead for SmtpDataStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_chunk(cx, buf.remaining()) {
            Poll::Ready(Ok(Some(piece))) => {
                buf.put_slice(&piece);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for SmtpDataStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.poll_chunk(cx, usize::MAX) {
            Poll::Ready(Ok(Some(piece))) => Poll::Ready(Some(Ok(piece))),
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for SmtpDataStream {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock().unwrap();
        state.reader_gone = true;
        state.chunks.clear();
        state.buffered = 0;
        state.need_drain = false;
        state.reader = None;
        drop(state);
        self.shared.progress.notify_one();
    }
}

impl fmt::Debug for SmtpDataStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SmtpDataStream")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn delivers_the_message_and_then_its_end() {
        let (writer, mut stream) = data_stream();
        assert!(writer.write(Bytes::from_static(b"Subject: x\r\n")));
        assert!(writer.write(Bytes::from_static(b"\r\nbody\r\n")));
        writer.end();
        assert!(!writer.is_finished());
        let mut message = Vec::new();
        stream.read_to_end(&mut message).await.unwrap();
        assert_eq!(message, b"Subject: x\r\n\r\nbody\r\n");
        assert!(writer.is_finished());
    }

    #[tokio::test]
    async fn fails_the_read_when_the_connection_is_lost_first() {
        let (writer, mut stream) = data_stream();
        writer.write(Bytes::from_static(b"partial"));
        drop(writer);
        assert_eq!(stream.next_chunk().await.unwrap().unwrap(), "partial");
        let error = stream.next_chunk().await.unwrap_err();
        assert!(SmtpDataStream::is_abandoned(&error));
        assert!(!SmtpDataStream::is_abandoned(&io::Error::other("something else")));
    }

    #[tokio::test]
    async fn asks_the_writer_to_wait_while_the_consumer_is_behind() {
        let (writer, mut stream) = data_stream();
        let chunk = Bytes::from(vec![b'a'; 64 * 1024]);
        assert!(writer.write(chunk.clone()));
        assert!(!writer.write(chunk.clone()));
        assert!(writer.needs_drain());
        let progress = writer.progress();
        tokio::pin!(progress);
        assert!(futures_util::poll!(progress.as_mut()).is_pending());
        let mut buffer = vec![0u8; 64 * 1024];
        stream.read_exact(&mut buffer).await.unwrap();
        progress.await;
        assert!(!writer.needs_drain());
    }

    #[tokio::test]
    async fn a_dropped_stream_discards_what_follows() {
        let (writer, stream) = data_stream();
        writer.write(Bytes::from(vec![b'a'; HIGH_WATER_MARK]));
        assert!(writer.needs_drain());
        drop(stream);
        assert!(!writer.needs_drain());
        assert!(writer.write(Bytes::from(vec![b'a'; HIGH_WATER_MARK])));
        writer.end();
        assert!(writer.is_finished());
    }
}
