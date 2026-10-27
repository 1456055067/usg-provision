//! A progress-based idle timeout on a connection.
//!
//! One deadline is shared by reads and writes and pushed forward by every
//! byte moved in either direction. A pending read or write past the
//! deadline fails with `TimedOut`, which ends the connection. A transfer
//! that keeps moving never times out, however long it takes
//! (REQ-IMG-032); a silent peer is cut off (SC-5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - slow or silent
//   peers released.
// - NIST 800-53: SC-10 (Network Disconnect) - idle sessions closed.
// - SPEC: specs/os-images.md#REQ-IMG-032 (progress-based, never a total
//   deadline)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// `T` with an idle timeout.
#[derive(Debug)]
pub struct IdleIo<T> {
    inner: T,
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl<T> IdleIo<T> {
    /// Wraps `inner`; the clock starts now.
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    /// The wrapped stream.
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    fn progress(&mut self) {
        let at = Instant::now() + self.timeout;
        self.sleep.as_mut().reset(at);
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.sleep.as_mut().poll(cx).is_ready()
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection idle timeout")
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                if buf.filled().len() > before {
                    this.progress();
                }
                Poll::Ready(r)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.progress();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.progress();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(timed_out())),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn trickle_survives_silence_times_out() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut io = IdleIo::new(a, Duration::from_millis(300));
        let writer = tokio::spawn(async move {
            // 600 ms of bytes, one every 100 ms: longer than the timeout
            // in total, but never idle for 300 ms.
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                b.write_all(b"x").await.unwrap();
            }
            // Then silence, holding the stream open.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(b);
        });
        let mut got = 0;
        let mut buf = [0u8; 8];
        let err = loop {
            match io.read(&mut buf).await {
                Ok(0) => panic!("unexpected EOF"),
                Ok(n) => got += n,
                Err(e) => break e,
            }
        };
        assert_eq!(got, 6);
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        writer.abort();
    }
}
