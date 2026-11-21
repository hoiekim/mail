//! Whether this process can serve TLS, from `SSL_CERTIFICATE` /
//! `SSL_CERTIFICATE_KEY`. Read per call: certificates are renewed under a
//! running process.

use std::fs::File;

use crate::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsCredentials {
    /// The pair is unset: a deliberate plaintext deployment.
    Unconfigured,
    /// The pair is set but names files this process cannot read.
    Unreadable { cert: String, key: String },
    Available { cert: String, key: String },
}

fn is_readable(path: &str) -> bool {
    File::open(path).is_ok()
}

pub fn get_tls_credentials() -> TlsCredentials {
    let (Some(cert), Some(key)) = (env::non_empty("SSL_CERTIFICATE"), env::non_empty("SSL_CERTIFICATE_KEY")) else {
        return TlsCredentials::Unconfigured;
    };
    if !is_readable(&cert) || !is_readable(&key) {
        return TlsCredentials::Unreadable { cert, key };
    }
    TlsCredentials::Available { cert, key }
}

pub fn is_tls_available() -> bool {
    matches!(get_tls_credentials(), TlsCredentials::Available { .. })
}
