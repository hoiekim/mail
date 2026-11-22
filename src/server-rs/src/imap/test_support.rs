//! Shared pieces of the IMAP unit tests: the lock around process-wide state
//! and a throwaway TLS certificate.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio_rustls::TlsAcceptor;

static PROCESS_WIDE: RwLock<()> = RwLock::const_new(());

/// Taken by every test that opens a session. Sessions register themselves
/// in the process-wide registries and IDLE manager, so they run alongside
/// each other but never alongside a sweep.
pub(crate) async fn shared() -> RwLockReadGuard<'static, ()> {
    PROCESS_WIDE.read().await
}

/// Taken by a test that sweeps every session (the shutdown sweep, the IDLE
/// manager's shutdown) or counts the registries.
pub(crate) async fn exclusive() -> RwLockWriteGuard<'static, ()> {
    PROCESS_WIDE.write().await
}

/// A self-signed certificate for `localhost`, made once per build directory
/// with the `openssl` command. `None` when the command is not there.
pub(crate) fn certificate() -> Option<&'static (PathBuf, PathBuf)> {
    static CERTIFICATE: OnceLock<Option<(PathBuf, PathBuf)>> = OnceLock::new();
    CERTIFICATE
        .get_or_init(|| {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join("test-tls");
            let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
            if cert.exists() && key.exists() {
                return Some((cert, key));
            }
            // Made beside the final place and moved in, so a test process
            // running at the same time never reads half a file.
            let staging = dir.join(format!("staging-{}", std::process::id()));
            std::fs::create_dir_all(&staging).ok()?;
            let made = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-keyout",
                    "key.pem",
                    "-out",
                    "cert.pem",
                    "-days",
                    "2",
                    "-subj",
                    "/CN=localhost",
                ])
                .current_dir(&staging)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .ok()?
                .success();
            if !made {
                return None;
            }
            std::fs::rename(staging.join("key.pem"), &key).ok()?;
            std::fs::rename(staging.join("cert.pem"), &cert).ok()?;
            let _ = std::fs::remove_dir_all(&staging);
            Some((cert, key))
        })
        .as_ref()
}

/// A TLS acceptor for the test certificate, built without the process
/// environment the server reads its own certificate from.
pub(crate) fn acceptor() -> Option<TlsAcceptor> {
    let (cert, key) = certificate()?;
    let mut cert_reader = std::io::BufReader::new(std::fs::File::open(cert).ok()?);
    let certificates: Vec<_> = rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>().ok()?;
    let mut key_reader = std::io::BufReader::new(std::fs::File::open(key).ok()?);
    let private_key = rustls_pemfile::private_key(&mut key_reader).ok()??;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .ok()?;
    Some(TlsAcceptor::from(Arc::new(config)))
}

/// The server name the test certificate is for.
pub(crate) fn server_name() -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::try_from("localhost").expect("a valid name")
}
