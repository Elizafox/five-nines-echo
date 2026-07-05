use std::sync::Arc;

use futures::StreamExt;
use tokio_util::codec::{Framed, LinesCodec};

use crate::{control::SessionMetadata, processor::SessionRegistry};

/// One persistent connection per scanner. Each line is a `SessionMetadata` frame. We store it keyed
/// by peer and log a per-session annotation.
pub(super) async fn run_sidecar(
    registry: Arc<std::sync::Mutex<SessionRegistry>>,
    mut framed: Framed<tokio::net::UnixStream, LinesCodec>,
) {
    while let Some(item) = framed.next().await {
        let line = match item {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "sidecar decode error");
                break;
            }
        };
        let meta: SessionMetadata = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, line = %line, "sidecar bad metadata");
                continue;
            }
        };
        let session_active = {
            let mut reg = registry.lock().unwrap();
            store_metadata_if_session_active(&mut reg, &meta)
        };
        tracing::info!(
            peer = %meta.peer,
            trace_id = %meta.trace_id,
            ident = ?meta.ident,
            session_active,
            "sidecar metadata received",
        );
    }
    tracing::info!("scanner sidecar disconnected");
}

fn store_metadata_if_session_active(reg: &mut SessionRegistry, meta: &SessionMetadata) -> bool {
    let active = reg.sessions.values().any(|h| h.peer == meta.peer);
    if active {
        reg.metadata.insert(meta.peer.clone(), meta.clone());
    }
    active
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;
    use crate::processor::SessionHandle;

    fn metadata(peer: &str) -> SessionMetadata {
        SessionMetadata {
            peer: peer.to_string(),
            ident: Some("client-ident".to_string()),
            trace_id: "trace-1".to_string(),
        }
    }

    fn insert_session(registry: &mut SessionRegistry, peer: &str) {
        let (cancel, _cancel_rx) = oneshot::channel();
        let (_handoff_tx, handoff) = oneshot::channel();
        registry.sessions.insert(
            1,
            SessionHandle {
                cancel,
                handoff,
                peer: peer.to_string(),
            },
        );
    }

    #[test]
    fn sidecar_metadata_for_inactive_peer_is_not_stored() {
        let mut registry = SessionRegistry::default();
        let meta = metadata("peer-a");

        let active = store_metadata_if_session_active(&mut registry, &meta);

        assert!(!active);
        assert!(!registry.metadata.contains_key("peer-a"));
    }

    #[test]
    fn sidecar_metadata_for_active_peer_is_stored() {
        let mut registry = SessionRegistry::default();
        insert_session(&mut registry, "peer-a");
        let meta = metadata("peer-a");

        let active = store_metadata_if_session_active(&mut registry, &meta);

        assert!(active);
        assert_eq!(
            registry
                .metadata
                .get("peer-a")
                .and_then(|m| m.ident.as_deref()),
            Some("client-ident")
        );
    }
}
