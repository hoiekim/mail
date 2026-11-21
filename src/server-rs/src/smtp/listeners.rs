//! The SMTP listeners of this server: which ports open, with which options,
//! and what becomes of the failures they report (the transport half of
//! `smtp.ts`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::json;

use super::registry::{register_smtp_server, unregister_smtp_server};
use super::server::{create_smtp_server, SmtpServer, SmtpServerError};
use super::types::{SharedSmtpHandler, SmtpServerOptions, SmtpTlsSource};
use crate::proxy_protocol::is_proxy_protocol_enabled;
use crate::tls::{get_tls_credentials, TlsCredentials};
use crate::{alarm, env, logger};

pub const SMTP_MAX_CLIENTS: usize = 100;

/// How long `SmtpServer::close` waits on open connections before it answers the
/// rest `421 Server shutting down` and returns. It has to fit inside compose's
/// 10s stop grace, which an idle client would otherwise hold for all of it —
/// long enough for the SIGKILL to land before the pool drains.
///
/// The window is for a transaction already in DATA: once `close` runs, any new
/// command is answered 421 on arrival, so only a message still streaming in
/// needs it. One cut off here gets a transient reply and is retried by the
/// sender, so the bound costs a redelivery, never a message.
pub const SMTP_CLOSE_TIMEOUT_MS: u64 = 5 * 1000;

/// The largest message accepted (`message-size.ts`): advertised as `SIZE` and
/// enforced against a `MAIL FROM ... SIZE=` declaration.
pub const MAX_MESSAGE_BYTES: u64 = 35 * 1024 * 1024;

// A peer rejecting our certificate (expired, wrong hostname, unknown CA) is a
// server-side defect even though it surfaces as a TLS-layer error, so it pages.
const PEER_CERT_REJECTION_ALERTS: [&str; 6] = [
    "ALERT_BAD_CERTIFICATE",
    "ALERT_UNSUPPORTED_CERTIFICATE",
    "ALERT_CERTIFICATE_REVOKED",
    "ALERT_CERTIFICATE_EXPIRED",
    "ALERT_CERTIFICATE_UNKNOWN",
    "ALERT_UNKNOWN_CA",
];

/// Whether the peer refused this server's certificate (`peer-cert-rejection.ts`).
pub fn is_peer_cert_rejection(error: &SmtpServerError) -> bool {
    let text = format!("{} {}", error.reason.as_deref().unwrap_or(""), error.message).to_uppercase().replace(' ', "_");
    PEER_CERT_REJECTION_ALERTS.iter().any(|alert| text.contains(alert))
}

// On an implicit-TLS server, handshake errors are tagged with meta.stage
// "connect" before the connection exists, so the tag means "before any SMTP
// command". A STARTTLS handshake carries the same tag but happens inside a
// session, so only the implicit-TLS listener treats it as scanner noise.
fn is_implicit_tls_handshake_failure(secure: bool, error: &SmtpServerError) -> bool {
    secure && error.meta.as_ref().is_some_and(|meta| meta.stage == "connect")
}

// Errors from the TLS layer carry library "SSL routines" and an ERR_SSL_* code.
fn is_tls_layer_error(error: &SmtpServerError) -> bool {
    error.library.as_deref() == Some("SSL routines")
        || error.code.as_deref().is_some_and(|code| code.starts_with("ERR_SSL_"))
}

// A remote client dropping or stalling its connection, matched by syscall and
// errno code because the message differs by runtime.
const PEER_DROP_SYSCALL_ERRORS: [&str; 5] =
    ["read ECONNRESET", "read ETIMEDOUT", "write ECONNRESET", "write EPIPE", "write EPROTO"];

fn is_peer_drop_error(error: &SmtpServerError) -> bool {
    let (Some(syscall), Some(code)) = (error.syscall.as_deref(), error.code.as_deref()) else {
        return false;
    };
    PEER_DROP_SYSCALL_ERRORS.contains(&format!("{syscall} {code}").as_str())
}

// Noise from external port scanners and misconfigured clients, by what the
// message says. The OpenSSL function names are what the Bun server matches on
// Node; they stay so an error worded that way is treated the same here.
const SUPPRESSED_MESSAGE_FRAGMENTS: [&str; 17] = [
    "tls_early_post_process_client_hello", // ClientHello stage rejections
    "tls_post_process_client_hello",       // post-ClientHello cipher/extension failures
    "tls_parse_ctos_",                     // malformed ClientHello extension
    "tls_collect_extensions",              // duplicate or malformed ClientHello extension block
    "tls_validate_record_header",          // malformed/wrong-protocol record header
    "extract_keyshares",                   // TLS 1.3 key exchange failure (bad key share)
    "final_key_share",                     // TLS 1.3 key exchange failure (no suitable key share)
    "tls_choose_sigalg",                   // signature algorithm negotiation failure
    "tls_get_more_records",                // oversized/malformed TLS record
    "Socket closed",                       // client disconnected before TLS handshake
    "Failed to establish TLS session",     // generic TLS failure wrapper
    "read ECONNRESET",                     // client dropped connection mid-handshake
    "read ETIMEDOUT",                      // client connected but stopped responding
    "write EPROTO",                        // protocol error writing to socket
    // The connection itself swallows a write ECONNRESET/EPIPE silently once a
    // transaction is complete (no open envelope), so by the time either
    // reaches here the client abandoned an in-flight transaction and reset
    // the socket before a pending write landed.
    "write ECONNRESET",
    "write EPIPE",
    "TLS handshake timeout", // implicit-TLS client connected but never completed the handshake
];

/// What a listener does about a failure it was told of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerErrorReport {
    /// A client's doing: logged at warn, nobody paged.
    Warn,
    /// Logged at error and sent to the alarm channel.
    Alarm { remote_address: Option<String>, detail: String },
}

/// Sorts a failure the listener on `port` reported: noise from the remote
/// side failing TLS negotiation or dropping its connection is only logged,
/// anything else pages.
pub fn classify_server_error(port: u16, secure: bool, error: &SmtpServerError) -> ServerErrorReport {
    let message = error.message.as_str();
    let suppressed = !is_peer_cert_rejection(error)
        && (is_implicit_tls_handshake_failure(secure, error)
            || is_tls_layer_error(error)
            || is_peer_drop_error(error)
            || SUPPRESSED_MESSAGE_FRAGMENTS.iter().any(|fragment| message.contains(fragment)));
    if suppressed {
        return ServerErrorReport::Warn;
    }
    // Handshake failures carry the peer in meta; session errors set it on the error.
    let remote_address = match error.meta.as_ref().and_then(|meta| meta.remote_address.clone()) {
        Some(address) => Some(address),
        None => error.remote_address.clone(),
    };
    let remote_line = remote_address.as_ref().map(|address| format!("**Remote:** {address}\n")).unwrap_or_default();
    let detail = format!("**Port:** {port}\n{remote_line}**Error:** Error: {message}");
    ServerErrorReport::Alarm { remote_address, detail }
}

fn report_server_error(port: u16, secure: bool, error: &SmtpServerError) {
    match classify_server_error(port, secure, error) {
        // Still logged (at warn, not error) so a real failure hiding in this
        // bucket leaves a trace — only the page is suppressed.
        ServerErrorReport::Warn => logger::warn_with(format!("SMTP Server({port}) Error"), json!({}), error),
        ServerErrorReport::Alarm { remote_address, detail } => {
            let context = match remote_address {
                Some(address) => json!({ "remoteAddress": address }),
                None => json!({}),
            };
            logger::error_with(format!("SMTP Server({port}) Error"), context, error);
            alarm::spawn_alarm("SMTP Server Error", detail);
        }
    }
}

/// Opens one listener on `port` and wires up its registry entry, error
/// handling and logging.
async fn start_listener(options: SmtpServerOptions, port: u16) -> Result<SmtpServer> {
    let secure = options.secure;
    let server = create_smtp_server(options);
    register_smtp_server(&server);
    server.on_error(move |error| report_server_error(port, secure, error));
    let registered = Arc::downgrade(server.shared());
    server.on_close(move || {
        if let Some(shared) = registered.upgrade() {
            unregister_smtp_server(&SmtpServer::from_shared(shared));
        }
        logger::info(format!("SMTP Server({port}) closed"), json!({}));
    });

    if let Err(error) = server.listen(port).await {
        // The Bun server reports a failed listen like any other server error.
        report_server_error(port, secure, &SmtpServerError::from_io("listen", &error));
        unregister_smtp_server(&server);
        return Err(anyhow!(error)).with_context(|| format!("SMTP server could not listen on port {port}"));
    }
    logger::info(format!("SMTP server listening on port {port}"), json!({}));
    Ok(server)
}

fn port_setting(name: &str, default: u16) -> Result<u16> {
    env::port(name, default).ok_or_else(|| anyhow!("{name} is not a port number"))
}

/// What [`initialize_smtp`] needs from the rest of the server.
#[derive(Clone)]
pub struct SmtpListeners {
    /// The mail handling behind every listener.
    pub handler: SharedSmtpHandler,
    /// Whether single sign-on is on. With it an app password is a full
    /// credential for the protocol, so the submission port too takes no AUTH
    /// before STARTTLS.
    pub single_sign_on: bool,
}

/// Starts the SMTP listeners: the cleartext port (`SMTP_PORT`, 25) always,
/// and with a readable certificate the implicit-TLS port (`SMTPS_PORT`, 465)
/// and the STARTTLS submission port (`SMTP_SUBMISSION_PORT`, 587).
pub async fn initialize_smtp(listeners: SmtpListeners) -> Result<Vec<SmtpServer>> {
    let mut servers = Vec::new();

    let credentials = get_tls_credentials();
    let tls: Option<SmtpTlsSource> = match &credentials {
        TlsCredentials::Unreadable { cert, key } => {
            // TLS was configured and cannot be served, so this is an operator
            // error that has to page rather than sit in a warn line while the
            // server accepts plaintext auth.
            logger::error(
                "SMTP: SSL certificate files not readable — starting without TLS",
                json!({ "cert": cert, "key": key }),
            );
            alarm::spawn_alarm_keyed(
                "TLS certificate not readable",
                format!(
                    "SMTP is configured for TLS but cannot read its certificate, and is serving cleartext only.\n**cert:** {cert}\n**key:** {key}"
                ),
                "tls-cert-unreadable-smtp",
            );
            None
        }
        TlsCredentials::Unconfigured => {
            logger::warn("SMTP: SSL certificate not configured.", json!({}));
            None
        }
        TlsCredentials::Available { .. } => {
            // The Bun server builds its TLS context here and does not start
            // with a certificate it cannot use. Each handshake then reads the
            // certificate again, so a renewed one is served without a restart.
            crate::tls::acceptor().context("SMTP: the SSL certificate could not be loaded")?;
            Some(Arc::new(crate::tls::acceptor))
        }
    };

    let options = SmtpServerOptions {
        secure: false,
        proxy_protocol: is_proxy_protocol_enabled(),
        allow_insecure_auth: false,
        name: None,
        tls,
        size: MAX_MESSAGE_BYTES,
        max_clients: SMTP_MAX_CLIENTS,
        close_timeout: Duration::from_millis(SMTP_CLOSE_TIMEOUT_MS),
        socket_timeout: None,
        handler: listeners.handler,
    };

    servers.push(start_listener(options.clone(), port_setting("SMTP_PORT", 25)?).await?);

    if options.tls.is_some() {
        let implicit = SmtpServerOptions { secure: true, ..options.clone() };
        servers.push(start_listener(implicit, port_setting("SMTPS_PORT", 465)?).await?);

        let submission = SmtpServerOptions { allow_insecure_auth: !listeners.single_sign_on, ..options };
        servers.push(start_listener(submission, port_setting("SMTP_SUBMISSION_PORT", 587)?).await?);
    }

    Ok(servers)
}

/// Closes every listener at once; done when the slowest has drained or hit
/// its close timeout.
pub async fn close_smtp_servers(servers: &[SmtpServer]) {
    futures_util::future::join_all(servers.iter().map(|server| server.close())).await;
}
