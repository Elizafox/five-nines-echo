//! Helpers shared by every worker (processor, scanner, plain/tls acceptors) for the bits of
//! plumbing they all repeat: dialing the supervisor's control socket with retry, and acquiring
//! their listener FD across the upgrade exec or from the supervisor's spawner socket via
//! `SCM_RIGHTS`.

mod dial;
mod listeners;
mod scm;

pub use dial::{SocketsDialer, dial_control_plane};
pub use listeners::{SpawnRequest, adopt_or_bind_tcp_listener, adopt_or_bind_uds_listener};
pub use scm::{recv_fd_via_scm, send_fd_via_scm};
