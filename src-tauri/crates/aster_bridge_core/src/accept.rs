//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const MAX_BACKOFF_MS: u64 = 1000;
const FIRST_BACKOFF_MS: u64 = 5;
const FREE_RETRIES: u32 = 3;

pub struct ResilientAcceptor {
    protocol: &'static str,
    consecutive_errors: u32,
}

impl ResilientAcceptor {
    pub fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            consecutive_errors: 0,
        }
    }

    pub fn consecutive_errors(&self) -> u32 {
        self.consecutive_errors
    }

    pub fn backoff_for(errors: u32) -> Duration {
        if errors <= FREE_RETRIES {
            return Duration::from_millis(0);
        }
        let steps = errors - FREE_RETRIES - 1;
        let ms = FIRST_BACKOFF_MS.saturating_mul(1u64 << steps.min(10));
        Duration::from_millis(ms.min(MAX_BACKOFF_MS))
    }

    pub async fn accept(&mut self, listener: &TcpListener) -> (TcpStream, SocketAddr) {
        loop {
            match listener.accept().await {
                Ok(accepted) => {
                    if self.consecutive_errors > 0 {
                        tracing::warn!(
                            "{} listener recovered after {} consecutive accept errors",
                            self.protocol,
                            self.consecutive_errors
                        );
                        self.consecutive_errors = 0;
                    }
                    return accepted;
                }
                Err(e) => {
                    self.consecutive_errors = self.consecutive_errors.saturating_add(1);
                    tracing::warn!(
                        "{} accept failed ({} in a row), staying up: {}",
                        self.protocol,
                        self.consecutive_errors,
                        e
                    );
                    let wait = Self::backoff_for(self.consecutive_errors);
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
    }
}

pub enum CloseConnectionsOnDrop {
    Graceful(tokio::sync::watch::Sender<()>),
    Immediate(axum_server::Handle),
}

impl CloseConnectionsOnDrop {
    pub fn for_axum() -> (Self, impl std::future::Future<Output = ()> + Send + 'static) {
        let (signal, mut dropped) = tokio::sync::watch::channel(());
        let closed = async move {
            let _ = dropped.changed().await;
        };
        (Self::Graceful(signal), closed)
    }

    pub fn for_axum_server() -> (Self, axum_server::Handle) {
        let handle = axum_server::Handle::new();
        (Self::Immediate(handle.clone()), handle)
    }
}

impl Drop for CloseConnectionsOnDrop {
    fn drop(&mut self) {
        if let Self::Immediate(handle) = self {
            handle.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_to_close(stream: &mut TcpStream) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1024];
        let wait = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        });
        wait.await.is_ok()
    }

    #[tokio::test]
    async fn dropping_the_axum_server_closes_keep_alive_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let server = tokio::spawn(async move {
            let (_close_connections, closed) = CloseConnectionsOnDrop::for_axum();
            let _ = axum::serve(listener, app).with_graceful_shutdown(closed).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

        server.abort();
        assert!(
            read_to_close(&mut stream).await,
            "a keep-alive connection outlived the server that accepted it"
        );
    }

    #[test]
    fn the_first_few_accept_errors_retry_without_delay() {
        assert!(ResilientAcceptor::backoff_for(1).is_zero());
        assert!(ResilientAcceptor::backoff_for(FREE_RETRIES).is_zero());
    }

    #[test]
    fn repeated_accept_errors_back_off_instead_of_spinning_hot() {
        let first = ResilientAcceptor::backoff_for(FREE_RETRIES + 1);
        let later = ResilientAcceptor::backoff_for(FREE_RETRIES + 4);
        assert!(!first.is_zero(), "a repeated failure must not spin at full speed");
        assert!(later > first, "backoff must grow, got {:?} then {:?}", first, later);
        assert!(
            ResilientAcceptor::backoff_for(10_000) <= Duration::from_millis(MAX_BACKOFF_MS),
            "backoff must stay bounded so a recovered listener answers promptly"
        );
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn a_listener_keeps_serving_after_a_client_aborts_before_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut acceptor = ResilientAcceptor::new("TEST");

        for _ in 0..5 {
            let aborter = TcpStream::connect(addr).await.unwrap();
            aborter.set_linger(Some(Duration::from_secs(0))).unwrap();
            drop(aborter);
        }

        let good = tokio::spawn(async move { TcpStream::connect(addr).await });
        let mut served = 0;
        for _ in 0..6 {
            let accepted = tokio::time::timeout(
                Duration::from_secs(5),
                acceptor.accept(&listener),
            )
            .await;
            match accepted {
                Ok(_) => {
                    served += 1;
                    if served >= 6 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = good.await;
        assert!(
            served > 0,
            "the listener went deaf, which is what makes a mail client report a refused connection"
        );
    }
}
