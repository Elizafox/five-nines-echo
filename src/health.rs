//! HTTP `/healthz`-style endpoint.
//!
//! A minimal HTTP/1.1 server (no framework; we just read the request headers, throw them away, and
//! write a response). Any role in [`HealthState::Failed`] yields a 503; otherwise 200. The body
//! always lists each role's state operators can `curl -i` and see what's wrong.
//!
//! Bind address comes from `Config::health.bind_addr`. Empty disables. Defaults to `127.0.0.1:7079`
//! (loopback) so an off-host scrape requires a deliberate config change.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::control::{HealthState, RoleHealth};

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
    roles: Vec<RoleEntry<'a>>,
}

#[derive(Serialize)]
struct RoleEntry<'a> {
    role: &'a str,
    state: &'a str,
}

fn state_name(s: HealthState) -> &'static str {
    match s {
        HealthState::Healthy => "healthy",
        HealthState::Backoff => "backoff",
        HealthState::Flapping => "flapping",
        HealthState::Failed => "failed",
    }
}

/// Accept loop. Each TCP connection gets a one-shot response, then closes
pub async fn run_health_server<F>(addr: String, snapshot_fn: Arc<F>) -> Result<()>
where
    F: Fn() -> Vec<RoleHealth> + Send + Sync + 'static,
{
    if let Some(f) = fault_inject!("health.bind") {
        return Err(f.into_anyhow().context("synthetic health bind failure"));
    }
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind health endpoint {addr}"))?;
    tracing::info!(addr, "health endpoint listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "health accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let snap = snapshot_fn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, snap.as_ref()).await {
                tracing::debug!(?peer, error = %e, "health request error");
            }
        });
    }
}

async fn handle<F>(mut stream: TcpStream, snapshot_fn: &F) -> Result<()>
where
    F: Send + Sync + Fn() -> Vec<RoleHealth>,
{
    // Drain the request headers (we don't actually route; any request gets the same health
    // response). Bound the read so a slowloris client can't park us forever.
    let _ = tokio::time::timeout(Duration::from_millis(500), drain_headers(&mut stream)).await;

    let snapshot = snapshot_fn();
    let any_failed = snapshot.iter().any(|h| h.state == HealthState::Failed);
    let (code, reason) = if any_failed {
        (503, "Service Unavailable")
    } else {
        (200, "OK")
    };

    let roles: Vec<RoleEntry> = snapshot
        .iter()
        .map(|h| RoleEntry {
            role: &h.role,
            state: state_name(h.state),
        })
        .collect();
    let body = serde_json::to_string(&HealthResponse {
        status: if any_failed { "degraded" } else { "ok" },
        roles,
    })
    .unwrap_or_else(|_| "{}".into());

    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body,
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write health response")?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn drain_headers(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            return Ok(());
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        if total == buf.len() {
            // Request bigger than our buffer. Give up reading, just respond.
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Vec<RoleHealth> {
        vec![
            RoleHealth {
                role: "processor".into(),
                state: HealthState::Healthy,
                consecutive_fast_exits: 0,
                next_backoff_ms: 200,
                total_restarts: 1,
                last_restart_at_unix_ms: Some(1_700_000_000_000),
            },
            RoleHealth {
                role: "plain".into(),
                state: HealthState::Backoff,
                consecutive_fast_exits: 1,
                next_backoff_ms: 400,
                total_restarts: 3,
                last_restart_at_unix_ms: None,
            },
        ]
    }

    fn one_failed() -> Vec<RoleHealth> {
        let mut v = healthy();
        v.push(RoleHealth {
            role: "scanner".into(),
            state: HealthState::Failed,
            consecutive_fast_exits: 12,
            next_backoff_ms: 30_000,
            total_restarts: 12,
            last_restart_at_unix_ms: None,
        });
        v
    }

    /// Spin up the server on an ephemeral port, return its address + `JoinHandle` so the test can
    /// cancel it
    async fn spawn_health<F>(snapshot_fn: F) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: Fn() -> Vec<RoleHealth> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // run_health_server takes an addr to bind itself; for the test we bypass and run accept
        // loop directly so we can use the already-bound ephemeral port
        let snap = Arc::new(snapshot_fn);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let snap = snap.clone();
                tokio::spawn(async move {
                    let _ = handle(stream, snap.as_ref()).await;
                });
            }
        });
        (addr, handle)
    }

    async fn http_get(addr: std::net::SocketAddr) -> (u16, String) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    #[test]
    fn state_name_covers_all_variants() {
        assert_eq!(state_name(HealthState::Healthy), "healthy");
        assert_eq!(state_name(HealthState::Backoff), "backoff");
        assert_eq!(state_name(HealthState::Flapping), "flapping");
        assert_eq!(state_name(HealthState::Failed), "failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flapping_state_appears_in_health_body() {
        let snap = || {
            vec![RoleHealth {
                role: "tls".into(),
                state: HealthState::Flapping,
                consecutive_fast_exits: 5,
                next_backoff_ms: 16_000,
                total_restarts: 5,
                last_restart_at_unix_ms: None,
            }]
        };
        let (addr, handle) = spawn_health(snap).await;
        let (code, body) = http_get(addr).await;
        handle.abort();
        assert_eq!(code, 200, "flapping is not failed; body: {body}");
        assert!(body.contains("\"state\":\"flapping\""));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_request_still_gets_response() {
        // drain_headers fills its 4096-byte buffer before finding CRLFCRLF;
        // it should give up and let handle() respond normally.
        let (addr, handle) = spawn_health(healthy).await;
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        // 4096 bytes with no \r\n\r\n anywhere
        s.write_all(&vec![b'A'; 4096]).await.unwrap();
        // Flush / close write side so handle doesn't wait for more data
        s.shutdown().await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        handle.abort();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("HTTP/1.1 200"), "should still reply: {text}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn returns_200_when_all_roles_healthy_or_backoff() {
        let (addr, handle) = spawn_health(healthy).await;
        let (code, body) = http_get(addr).await;
        handle.abort();
        assert_eq!(code, 200, "body was: {body}");
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"role\":\"processor\""));
        assert!(body.contains("\"state\":\"backoff\""));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn returns_503_when_any_role_failed() {
        let (addr, handle) = spawn_health(one_failed).await;
        let (code, body) = http_get(addr).await;
        handle.abort();
        assert_eq!(code, 503, "body was: {body}");
        assert!(body.contains("\"status\":\"degraded\""));
        assert!(body.contains("\"state\":\"failed\""));
    }
}
