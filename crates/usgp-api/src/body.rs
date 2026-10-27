//! Response bodies: a whole JSON body, or a bounded stream of verified
//! content chunks.
//!
//! A stream is fed by a channel of capacity one from the reader task, so
//! at most one chunk waits in memory per download (plan M2 section 1.1).
//! Its exact length is known (the manifest size), so hyper sends a
//! `Content-Length` and the client can tell a cut stream from a complete
//! one. An `Err` item aborts the connection (plan section 5.7: a
//! mismatch after the headers went out aborts the stream).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::body::{Body, Bytes, Frame, SizeHint};
use tokio::sync::mpsc;

/// The body of every API response.
#[derive(Debug)]
pub enum ApiBody {
    /// A complete body (`None` once sent).
    Full(Option<Bytes>),
    /// A streamed body of known length.
    Stream {
        /// Chunks from the reader task.
        rx: mpsc::Receiver<Result<Bytes, io::Error>>,
        /// Bytes still to come.
        remaining: u64,
    },
}

impl ApiBody {
    /// A complete body.
    #[must_use]
    pub fn full(bytes: impl Into<Bytes>) -> Self {
        Self::Full(Some(bytes.into()))
    }

    /// An empty body.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Full(None)
    }
}

impl Body for ApiBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream { rx, remaining } => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) if *remaining == 0 => Poll::Ready(None),
                // The reader stopped early without saying why: abort.
                Poll::Ready(None) => Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "content stream ended early",
                )))),
                Poll::Ready(Some(Err(e))) => {
                    *remaining = 0;
                    Poll::Ready(Some(Err(e)))
                }
                Poll::Ready(Some(Ok(b))) => {
                    let n = u64::try_from(b.len()).unwrap_or(u64::MAX);
                    match remaining.checked_sub(n) {
                        Some(r) => {
                            *remaining = r;
                            Poll::Ready(Some(Ok(Frame::data(b))))
                        }
                        None => {
                            *remaining = 0;
                            Poll::Ready(Some(Err(io::Error::other(
                                "content stream longer than its manifest",
                            ))))
                        }
                    }
                }
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(b) => b.as_ref().is_none_or(Bytes::is_empty),
            Self::Stream { remaining, .. } => *remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(b) => SizeHint::with_exact(
                b.as_ref()
                    .map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX)),
            ),
            Self::Stream { remaining, .. } => SizeHint::with_exact(*remaining),
        }
    }
}
