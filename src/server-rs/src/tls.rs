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

/// A TLS client that accepts any certificate, for probing this server's own
/// listeners over loopback.
pub fn insecure_connector() -> tokio_rustls::TlsConnector {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions are valid")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}
