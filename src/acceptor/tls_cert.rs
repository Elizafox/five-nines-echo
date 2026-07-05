use std::fs::File;
#[cfg_attr(
    not(target_os = "freebsd"),
    allow(unused_imports, reason = "only used in FreeBSD capability-mode blocks")
)]
use std::io;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use tokio_rustls::TlsAcceptor;

// The active TLS crypto backend, selected by the `ring` / `aws-lc-rs` crate features (see
// Cargo.toml). Exactly one is enabled; the mutually-exclusive guard lives in main.rs.
#[cfg(feature = "aws-lc-rs")]
use rustls::crypto::aws_lc_rs as crypto_backend;
#[cfg(feature = "ring")]
use rustls::crypto::ring as crypto_backend;

use crate::{config::TlsConfig, fault_inject};

/// Source for the TLS cert/key, encapsulating the per-OS reload strategy: the cert-file analog of
/// `worker_common::SocketsDialer`. On FreeBSD, it pre-opens the cert/key parent directories as
/// capability-rights-limited dir FDs (`CAP_LOOKUP | CAP_READ`) so SIGHUP/admin reload can
/// `openat(dir_fd, basename)` after `cap_enter()`. Elsewhere it just keeps the paths and reopens
/// them by path on reload.
///
/// Construct (`open`) *before* `apply_sandbox`, while the global path namespace is still reachable.
/// The cert and key may live in different directories; we open a dir FD per parent rather than
/// assuming a shared one.
pub(super) struct TlsCertSource {
    pub(super) cert_path: PathBuf,
    pub(super) key_path: PathBuf,
    #[cfg(target_os = "freebsd")]
    cert_dir_fd: std::os::fd::OwnedFd,
    #[cfg(target_os = "freebsd")]
    key_dir_fd: std::os::fd::OwnedFd,
    #[cfg(target_os = "freebsd")]
    cert_basename: std::ffi::OsString,
    #[cfg(target_os = "freebsd")]
    key_basename: std::ffi::OsString,
}

impl TlsCertSource {
    /// Prepare the per-OS reload strategy. Call before `apply_sandbox`.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Failable on FreeBSD, nowhere else"
    )]
    pub(super) fn open(tls: &TlsConfig) -> Result<Self> {
        #[cfg(target_os = "freebsd")]
        {
            use std::os::fd::{FromRawFd, OwnedFd};

            use crate::handoff::{ENV_CERT_DIR_FD, ENV_KEY_DIR_FD, env_raw_fd};

            // Basenames come from the paths (still in config); the dir FDs are
            // either pre-opened here or, in a cap-mode upgrade successor,
            // adopted from the FDs the parent handed over (path opens ECAPMODE).
            let cert_basename = cert_dir_basename(&tls.cert_path)?;
            let key_basename = cert_dir_basename(&tls.key_path)?;
            let cert_dir_fd = match env_raw_fd(ENV_CERT_DIR_FD) {
                // SAFETY: parent cleared CLOEXEC + passed the fd via env before
                // fexecve; already CAP_LOOKUP|CAP_READ-limited.
                Some(raw) => unsafe { OwnedFd::from_raw_fd(raw) },
                None => open_cert_dir_fd(&tls.cert_path).with_context(|| {
                    format!("pre-open cert dir for {}", tls.cert_path.display())
                })?,
            };
            let key_dir_fd = match env_raw_fd(ENV_KEY_DIR_FD) {
                // SAFETY: parent cleared CLOEXEC + passed the fd via env before
                // fexecve; already CAP_LOOKUP|CAP_READ-limited.
                Some(raw) => unsafe { OwnedFd::from_raw_fd(raw) },
                None => open_cert_dir_fd(&tls.key_path)
                    .with_context(|| format!("pre-open key dir for {}", tls.key_path.display()))?,
            };
            Ok(Self {
                cert_path: tls.cert_path.clone(),
                key_path: tls.key_path.clone(),
                cert_dir_fd,
                key_dir_fd,
                cert_basename,
                key_basename,
            })
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            Ok(Self {
                cert_path: tls.cert_path.clone(),
                key_path: tls.key_path.clone(),
            })
        }
    }

    /// (Re)load cert + key and assemble a fresh `TlsAcceptor`. Works under FreeBSD capability mode
    /// because the opens go through the pre-opened dir FDs rather than through the global path
    /// namespace.
    pub(super) fn build_acceptor(&self) -> Result<TlsAcceptor> {
        if let Some(f) = fault_inject!("tls.cert_load") {
            return Err(f.into_anyhow().context("synthetic cert load failure"));
        }
        let cert = self.open_cert().context("open TLS cert")?;
        let key = self.open_key().context("open TLS key")?;
        build_tls_acceptor_from_files(cert, key).with_context(|| {
            format!(
                "build TLS acceptor from {} / {}",
                self.cert_path.display(),
                self.key_path.display()
            )
        })
    }

    #[cfg(target_os = "freebsd")]
    fn open_cert(&self) -> Result<File> {
        openat_read(&self.cert_dir_fd, &self.cert_basename)
            .with_context(|| format!("openat cert {}", self.cert_path.display()))
    }

    #[cfg(target_os = "freebsd")]
    fn open_key(&self) -> Result<File> {
        openat_read(&self.key_dir_fd, &self.key_basename)
            .with_context(|| format!("openat key {}", self.key_path.display()))
    }

    #[cfg(not(target_os = "freebsd"))]
    fn open_cert(&self) -> Result<File> {
        File::open(&self.cert_path)
            .with_context(|| format!("open cert {}", self.cert_path.display()))
    }

    #[cfg(not(target_os = "freebsd"))]
    fn open_key(&self) -> Result<File> {
        File::open(&self.key_path).with_context(|| format!("open key {}", self.key_path.display()))
    }

    /// Raw fds of the pre-opened cert/key dirs, for cap-mode upgrade handoff.
    /// `None` off FreeBSD (no dir FDs held).
    pub(super) fn cert_dir_raw_fd(&self) -> Option<RawFd> {
        #[cfg(target_os = "freebsd")]
        {
            use std::os::unix::io::AsRawFd;

            Some(self.cert_dir_fd.as_raw_fd())
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            let _ = self;
            None
        }
    }

    pub(super) fn key_dir_raw_fd(&self) -> Option<RawFd> {
        #[cfg(target_os = "freebsd")]
        {
            use std::os::unix::io::AsRawFd;

            Some(self.key_dir_fd.as_raw_fd())
        }
        #[cfg(not(target_os = "freebsd"))]
        {
            let _ = self;
            None
        }
    }
}

/// The single-component basename of a TLS cert/key path, for `openat`.
#[cfg(target_os = "freebsd")]
fn cert_dir_basename(path: &std::path::Path) -> Result<std::ffi::OsString> {
    Ok(path
        .file_name()
        .ok_or_else(|| anyhow!("TLS path {} has no filename component", path.display()))?
        .to_os_string())
}

/// Open `path`'s parent directory as a capability-rights-limited dir FD, limited to `CAP_LOOKUP |
/// CAP_READ` so a later bug can't reuse it for writes or other fs operations; those are exactly the
/// rights `openat(..., O_RDONLY)` needs. Mirrors `worker_common::SocketsDialer::open`'s cap-rights
/// dance.
#[cfg(target_os = "freebsd")]
fn open_cert_dir_fd(path: &std::path::Path) -> Result<std::os::fd::OwnedFd> {
    use std::os::unix::io::AsRawFd;

    use nix::libc;

    // `Path::parent` is `Some("")` for a bare filename; treat that as ".".
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let f = File::open(&dir).with_context(|| format!("open cert dir {}", dir.display()))?;
    let dir_fd: std::os::fd::OwnedFd = f.into();

    #[allow(
        unused_unsafe,
        reason = "FreeBSD libc cap_rights helpers are unsafe on supported toolchains"
    )]
    // SAFETY: cap_rights_init/limit operate on a valid open dir FD; the varargs rights list is
    // terminated by the trailing `0u64` per the FreeBSD ABI. Mirrors the SocketsDialer pattern.
    unsafe {
        let mut rights = std::mem::MaybeUninit::<libc::cap_rights_t>::uninit();
        libc::__cap_rights_init(
            libc::CAP_RIGHTS_VERSION,
            rights.as_mut_ptr(),
            libc::CAP_LOOKUP,
            libc::CAP_READ,
            0u64,
        );
        let rights = rights.assume_init();
        if libc::cap_rights_limit(dir_fd.as_raw_fd(), &rights) != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cap_rights_limit on cert dir {}", dir.display()));
        }
    }
    Ok(dir_fd)
}

/// `openat(dir_fd, basename, O_RDONLY)` -> owned `File`. Permitted under capability mode because
/// the lookup is relative to a dir FD (with `CAP_LOOKUP | CAP_READ`) rather than the global path
/// namespace.
#[cfg(target_os = "freebsd")]
fn openat_read(dir_fd: &std::os::fd::OwnedFd, basename: &std::ffi::OsStr) -> io::Result<File> {
    use nix::libc;
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
    };

    let cpath = CString::new(basename.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cert basename has interior NUL",
        )
    })?;
    // SAFETY: dir_fd is a valid cap-limited (CAP_LOOKUP|CAP_READ) open dir FD; cpath is a
    // NULL-terminated single-component relative name. O_RDONLY needs no mode argument, so the
    // variadic `openat` is called with none.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat just minted this FD for us; we take sole ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Parse already-opened cert/key files into a `TlsAcceptor`. The platform-specific open step lives
/// in `TlsCertSource`; this is the platform-agnostic parse + assemble half.
fn build_tls_acceptor_from_files(cert: File, key: File) -> Result<TlsAcceptor> {
    if let Some(f) = fault_inject!("tls.cert_parse") {
        return Err(f.into_anyhow().context("synthetic cert parse failure"));
    }
    let _ = crypto_backend::default_provider().install_default();
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("ServerConfig::with_single_cert")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(file: File) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_reader_iter(file)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert")
}

fn load_key(file: File) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_reader(file)
        .map_err(|err| match err {
            rustls::pki_types::pem::Error::NoItemsFound => anyhow!("no private key in key file"),
            _ => anyhow!(err),
        })
        .context("parse key")
}
