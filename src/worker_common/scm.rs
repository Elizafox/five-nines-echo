use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use nix::{
    cmsg_space,
    sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, recvmsg, sendmsg},
};
use tokio::io::Interest;

/// Synchronously send one FD plus a payload over a connected UDS.
///
/// Must be called when the socket is writable; the caller is responsible for awaiting tokio
/// readiness around it. The payload must fit in a single `sendmsg()` call.
fn send_fd_sync(sock_fd: RawFd, fd_to_send: RawFd, payload: &[u8]) -> io::Result<()> {
    let iov = [IoSlice::new(payload)];
    let fds = [fd_to_send];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    let sent =
        sendmsg::<()>(sock_fd, &iov, &cmsgs, MsgFlags::empty(), None).map_err(io::Error::from)?;
    if sent != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "short SCM_RIGHTS send: sent {sent} of {} payload bytes",
                payload.len()
            ),
        ));
    }
    Ok(())
}

/// First SCM_RIGHTS-passed FD in a received message, if any. The kernel mints
/// a fresh FD number in our process for each passed FD; we take ownership of
/// the first and ignore any others.
fn first_scm_rights_fd(msg: &RecvMsg<'_, '_, ()>) -> io::Result<Option<OwnedFd>> {
    for cmsg in msg.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&raw) = fds.first()
        {
            // SAFETY: kernel just minted this FD for us via recvmsg; we own it now.
            return Ok(Some(unsafe { OwnedFd::from_raw_fd(raw) }));
        }
    }
    Ok(None)
}

/// Synchronously receive an FD plus inline payload. Caller must ensure the socket is readable.
fn recv_fd_sync(sock_fd: RawFd) -> io::Result<(OwnedFd, Vec<u8>)> {
    if let Some(f) = fault_inject!("scm.recvmsg") {
        return Err(f.into_io_error());
    }
    let mut buf = vec![0u8; 256];
    let mut cmsg_buf = cmsg_space!([RawFd; 1]);
    let (bytes, owned) = {
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(sock_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(io::Error::from)?;
        if msg.bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "spawner closed before sending FD",
            ));
        }
        (msg.bytes, first_scm_rights_fd(&msg)?)
    };

    let owned = owned.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "spawner reply missing SCM_RIGHTS attachment",
        )
    })?;
    buf.truncate(bytes);
    Ok((owned, buf))
}

/// Async wrapper: wait for `stream` to be writable, then sendmsg.
pub async fn send_fd_via_scm(
    stream: &tokio::net::UnixStream,
    fd_to_send: RawFd,
    payload: &[u8],
) -> io::Result<()> {
    loop {
        stream.writable().await?;
        let result = stream.try_io(Interest::WRITABLE, || {
            send_fd_sync(stream.as_raw_fd(), fd_to_send, payload)
        });
        match result {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

/// Async wrapper: wait for `stream` to be readable, then `recvmsg()` one FD.
pub async fn recv_fd_via_scm(stream: &tokio::net::UnixStream) -> io::Result<(OwnedFd, Vec<u8>)> {
    loop {
        stream.readable().await?;
        let result = stream.try_io(Interest::READABLE, || recv_fd_sync(stream.as_raw_fd()));
        match result {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::fd::AsRawFd;

    use tokio::io::AsyncReadExt;

    /// Send an FD over a connected `UnixStream` pair and verify the receiver got an
    /// independently-usable handle on the same kernel object.
    #[tokio::test(flavor = "current_thread")]
    async fn scm_rights_roundtrip_passes_a_pipe_read_end() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        // The "thing being passed" is the read end of a pipe; we'll write to its writer side and
        // verify the receiver, holding the freshly-minted FD, sees the same bytes.
        let (pipe_reader, pipe_writer) = nix::unistd::pipe().expect("pipe");

        let send_task = tokio::spawn(async move {
            send_fd_via_scm(&a, pipe_reader.as_raw_fd(), b"ok")
                .await
                .unwrap();
            // Drop our copy so only the receiver's holds the read end.
            drop(pipe_reader);
        });

        let (owned_fd, payload) = recv_fd_via_scm(&b).await.unwrap();
        assert_eq!(&payload[..], b"ok");
        send_task.await.unwrap();

        // Write a sentinel into the pipe's write end; read from the SCM_RIGHTS-minted FD on the
        // receiver side.
        nix::unistd::write(&pipe_writer, b"X").unwrap();
        drop(pipe_writer);
        let mut buf = [0u8; 1];
        let std_reader: std::fs::File = owned_fd.into();
        let mut tokio_reader = tokio::fs::File::from_std(std_reader);
        tokio_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"X");
    }

    /// Peer closes before sending anything: `recvmsg` returns 0 bytes, which we surface as EOF
    /// rather than a spurious empty success.
    #[tokio::test(flavor = "current_thread")]
    async fn recv_fd_reports_eof_when_peer_closes_without_sending() {
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        drop(a);
        let err = recv_fd_via_scm(&b).await.expect_err("expected EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Peer sends a plain reply with no `SCM_RIGHTS` ancillary data: we must reject it as malformed
    /// instead of returning a bogus FD.
    #[tokio::test(flavor = "current_thread")]
    async fn recv_fd_errors_when_reply_has_no_scm_attachment() {
        use tokio::io::AsyncWriteExt;
        let (mut a, b) = tokio::net::UnixStream::pair().unwrap();
        a.write_all(b"ok\n").await.unwrap();
        let err = recv_fd_via_scm(&b)
            .await
            .expect_err("expected missing-attachment error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        drop(a);
    }
}
