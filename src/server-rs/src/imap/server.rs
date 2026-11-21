//! The IMAP listeners (imap/index.ts): the plain port, with STARTTLS when a
//! certificate is readable, and the implicit-TLS port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::close_socket::CLOSE_FLUSH_TIMEOUT_MS;
use super::handler::serve_connection;
use super::idle_manager::idle_manager;
use super::session_registry::shutdown_imap_sessions;
use crate::alarm::spawn_alarm_keyed;
use crate::proxy_protocol::{is_proxy_protocol_enabled, read_proxy_header, unmapped, Peer, Prefixed};
use crate::tls::{get_tls_credentials, TlsCredentials};
use crate::{env, js, logger};

/// How long an implicit-TLS client behind a TCP proxy may take to complete
/// its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// The same for a direct client: the default the Bun server's TLS listener
/// applies.
const DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// Connections one port serves at once. One more is closed as it arrives,
/// without a greeting.
const IMAP_MAX_CONNECTIONS: u32 = 100;

/// How long shutdown waits for the IMAP listeners to close. Every session the
/// sweep reaches is destroyed by the flush timeout at the latest; the margin
/// lets those closes land. Anything still open after it belongs to no
/// session: a TLS handshake or a PROXY header still in flight.
pub const IMAP_SHUTDOWN_TIMEOUT_MS: u64 = CLOSE_FLUSH_TIMEOUT_MS + 1000;

/// `Number(value) || fallback`, as a port to listen on: unset, empty, zero
/// or not a number is the fallback. A number that is no port is an error, as
/// it is when the Bun server is told to listen on it.
fn port_setting(value: Option<&str>, fallback: u16) -> Result<u16> {
    let Some(value) = value else {
        return Ok(fallback);
    };
    let number = js::number_from_str(value);
    if number.is_nan() || number == 0.0 {
        return Ok(fallback);
    }
    if number.fract() != 0.0 || !(1.0..=65535.0).contains(&number) {
        bail!("{value} is not a port");
    }
    Ok(number as u16)
}

pub fn get_imap_port() -> Result<u16> {
    port_setting(env::var("IMAP_PORT").as_deref(), 143).context("IMAP_PORT")
}

pub fn get_imap_tls_port() -> Result<u16> {
    port_setting(env::var("IMAP_TLS_PORT").as_deref(), 993).context("IMAP_TLS_PORT")
}

struct ImapServer {
    stop: CancellationToken,
    /// One permit per connection the port may still take.
    connections: Arc<Semaphore>,
    accepting: JoinHandle<()>,
}

/// The running IMAP listeners, for [`close_imap_servers`].
pub struct ImapServers {
    servers: Vec<ImapServer>,
}

/// Takes one accepted connection to the point where IMAP is spoken on it —
/// the PROXY header when a TCP proxy is in front, then the TLS handshake on
/// the implicit-TLS port — and serves it.
async fn accept_connection(mut stream: TcpStream, address: SocketAddr, is_tls: bool, proxied: bool) {
    let _ = stream.set_nodelay(true);

    if !proxied {
        let peer = Peer { address: address.ip().to_string(), port: address.port() };
        if !is_tls {
            serve_connection(Box::new(stream), peer, false).await;
            return;
        }
        // The certificate is read now, so a renewed one is picked up
        // without a restart.
        let Ok(acceptor) = crate::tls::acceptor() else {
            return;
        };
        if let Ok(Ok(stream)) = tokio::time::timeout(DIRECT_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            serve_connection(Box::new(stream), peer, true).await;
        }
        return;
    }

    // Behind a TCP proxy: the header names the client, and whatever follows
    // it belongs to the handshake or to IMAP.
    let from = unmapped(&address.ip().to_string());
    let own = Peer { address: from.clone(), port: address.port() };
    let (peer, rest) = match read_proxy_header(&mut stream, &own).await {
        Ok(read) => read,
        Err(error) => {
            logger::warn(
                "IMAP: connection dropped before its PROXY header",
                json!({ "component": "imap", "from": from, "reason": error.to_string() }),
            );
            return;
        }
    };
    let stream = Prefixed::new(rest, stream);
    if !is_tls {
        serve_connection(Box::new(stream), peer, false).await;
        return;
    }
    let Ok(acceptor) = crate::tls::acceptor() else {
        return;
    };
    if let Ok(Ok(stream)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        serve_connection(Box::new(stream), peer, true).await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    is_tls: bool,
    proxied: bool,
    stop: CancellationToken,
    connections: Arc<Semaphore>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, address) = match accepted {
            Ok(connection) => connection,
            Err(_) => {
                // Out of descriptors, or the peer was gone before it was
                // accepted: nothing to serve, and no reason to spin.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = connections.clone().try_acquire_owned() else {
            // At the limit: closed at once, without a word.
            drop(stream);
            continue;
        };
        tokio::spawn(async move {
            accept_connection(stream, address, is_tls, proxied).await;
            drop(slot);
        });
    }
}

async fn listen(port: u16, is_tls: bool) -> Result<ImapServer> {
    let listener = crate::net::bind_all(port).await.with_context(|| format!("IMAP could not listen on port {port}"))?;
    let stop = CancellationToken::new();
    let connections = Arc::new(Semaphore::new(IMAP_MAX_CONNECTIONS as usize));
    let accepting =
        tokio::spawn(accept_loop(listener, is_tls, is_proxy_protocol_enabled(), stop.clone(), connections.clone()));
    Ok(ImapServer { stop, connections, accepting })
}

/// Opens the IMAP listeners: the plain port always, the implicit-TLS port
/// when a certificate is readable.
pub async fn initialize_imap() -> Result<ImapServers> {
    idle_manager().start_heartbeat();

    let mut servers = Vec::new();

    let port = get_imap_port()?;
    servers.push(listen(port, false).await?);
    logger::info("IMAP server listening", json!({ "component": "imap", "port": port }));

    match get_tls_credentials() {
        TlsCredentials::Unreadable { cert, key } => {
            // Loud, not a warn line: TLS was explicitly configured and cannot
            // be served, so the deployment is about to run cleartext-only
            // while believing it is encrypted. `/health` reports the TLS
            // ports as `not_configured` and stays 200, so nothing else pages
            // for this.
            logger::error(
                "IMAP: SSL certificate files not readable — TLS server not started",
                json!({ "component": "imap", "cert": cert, "key": key }),
            );
            spawn_alarm_keyed(
                "TLS certificate not readable",
                format!(
                    "IMAP is configured for TLS but cannot read its certificate, and is serving cleartext only.\n**cert:** {cert}\n**key:** {key}"
                ),
                "tls-cert-unreadable-imap",
            );
        }
        TlsCredentials::Available { .. } => {
            // A pair that is there but is not a key pair stops the start,
            // as it does when the Bun server builds its TLS listener.
            crate::tls::server_config().context("IMAP could not load its TLS certificate")?;
            let port = get_imap_tls_port()?;
            servers.push(listen(port, true).await?);
            logger::info("IMAP server listening over TLS", json!({ "component": "imap", "port": port }));
        }
        TlsCredentials::Unconfigured => {
            logger::warn(
                "IMAP: SSL certificate not configured, TLS server not started",
                json!({ "component": "imap" }),
            );
        }
    }

    Ok(ImapServers { servers })
}

/// Stops the IMAP listeners and ends every connection on them.
///
/// Every live session is sent an untagged BYE (RFC 3501 §7.1.5) and closed
/// through the flush-then-destroy teardown, so the listeners drain once the
/// flush window has run instead of once each client idles out. The wait is
/// still bounded: the process exit that follows takes down whatever the
/// sweep could not reach.
///
/// Returns whether every connection was gone within the bound.
pub async fn close_imap_servers(servers: ImapServers) -> bool {
    for server in &servers.servers {
        server.stop.cancel();
    }
    let sessions = shutdown_imap_sessions();
    logger::info("IMAP sessions closed for shutdown", json!({ "component": "imap", "sessions": sessions }));

    let all_closed = async {
        for server in servers.servers {
            let _ = server.accepting.await;
            let _ = server.connections.acquire_many(IMAP_MAX_CONNECTIONS).await;
        }
    };
    tokio::time::timeout(Duration::from_millis(IMAP_SHUTDOWN_TIMEOUT_MS), all_closed).await.is_ok()
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    use super::super::close_socket::CLOSE_FLUSH_TIMEOUT_MS;
    use super::*;

    const BYE: &str = "* BYE Server shutting down\r\n";

    /// A plain listener on an ephemeral loopback port.
    async fn serve(proxied: bool) -> (ImapServers, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = CancellationToken::new();
        let connections = Arc::new(Semaphore::new(IMAP_MAX_CONNECTIONS as usize));
        let accepting = tokio::spawn(accept_loop(listener, false, proxied, stop.clone(), connections.clone()));
        (ImapServers { servers: vec![ImapServer { stop, connections, accepting }] }, port)
    }

    async fn connect(port: u16) -> BufReader<TcpStream> {
        BufReader::new(TcpStream::connect(("127.0.0.1", port)).await.unwrap())
    }

    async fn line(client: &mut BufReader<TcpStream>) -> String {
        let mut line = String::new();
        client.read_line(&mut line).await.unwrap();
        line
    }

    // The shutdown sweep is process-wide, so the tests that run it take turns.
    static SWEEP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn greets_and_serves_a_connection() {
        let _sweep = SWEEP.lock().await;
        let (servers, port) = serve(false).await;
        let mut client = connect(port).await;
        assert!(line(&mut client).await.starts_with("* OK [CAPABILITY IMAP4rev1 "));
        client.get_mut().write_all(b"a1 NOOP\r\n").await.unwrap();
        assert_eq!(line(&mut client).await, "a1 OK NOOP completed\r\n");
        assert!(close_imap_servers(servers).await);
    }

    #[tokio::test]
    async fn shutdown_tells_an_idle_client_bye_and_closes_promptly() {
        let _sweep = SWEEP.lock().await;
        let (servers, port) = serve(false).await;
        let mut client = connect(port).await;
        assert!(line(&mut client).await.starts_with("* OK"));

        let started = std::time::Instant::now();
        let drained = close_imap_servers(servers).await;

        // Without the sweep the listener would wait out the inactivity
        // timeout and this would come back false at the bound.
        assert!(drained);
        // A client that closes on FIN goes as soon as the BYE lands.
        let mut rest = String::new();
        client.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, BYE);
        drop(client);
        assert!(started.elapsed() < Duration::from_millis(CLOSE_FLUSH_TIMEOUT_MS + 500));
        // The port is closed.
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_closes_within_the_flush_window_when_the_client_keeps_its_side_open() {
        let _sweep = SWEEP.lock().await;
        let (servers, port) = serve(false).await;
        let mut client = connect(port).await;
        assert!(line(&mut client).await.starts_with("* OK"));

        // The client reads the BYE but never closes its own side.
        let started = std::time::Instant::now();
        let drained = close_imap_servers(servers).await;
        assert!(drained);
        assert!(started.elapsed() < Duration::from_millis(IMAP_SHUTDOWN_TIMEOUT_MS));
        assert_eq!(line(&mut client).await, BYE);
    }

    #[tokio::test]
    async fn shutdown_stops_waiting_at_the_bound_on_a_connection_no_session_owns() {
        let _sweep = SWEEP.lock().await;
        // Behind a proxy a connection has no session until its PROXY header
        // arrives; this one never sends it.
        let (servers, port) = serve(true).await;
        let _silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        let drained = close_imap_servers(servers).await;
        assert!(!drained);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(IMAP_SHUTDOWN_TIMEOUT_MS - 50), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(IMAP_SHUTDOWN_TIMEOUT_MS + 1000), "{elapsed:?}");
    }

    #[tokio::test]
    async fn a_proxied_listener_waits_for_the_header_and_reports_its_client() {
        let _sweep = SWEEP.lock().await;
        let (servers, port) = serve(true).await;
        let mut client = connect(port).await;
        // Nothing is said before the header.
        let early = tokio::time::timeout(Duration::from_millis(100), line(&mut client)).await;
        assert!(early.is_err());
        client.get_mut().write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 143\r\nA1 NOOP\r\n").await.unwrap();
        assert!(line(&mut client).await.starts_with("* OK [CAPABILITY "));
        assert_eq!(line(&mut client).await, "A1 OK NOOP completed\r\n");

        // A connection that starts with anything else is dropped unanswered.
        let mut stranger = connect(port).await;
        stranger.get_mut().write_all(b"A1 CAPABILITY\r\n").await.unwrap();
        let mut said = String::new();
        stranger.read_to_string(&mut said).await.unwrap();
        assert_eq!(said, "");

        assert!(close_imap_servers(servers).await);
    }

    #[tokio::test]
    async fn the_connection_past_the_limit_is_closed_without_a_greeting() {
        let _sweep = SWEEP.lock().await;
        let (servers, port) = serve(false).await;
        let mut clients = Vec::new();
        for _ in 0..IMAP_MAX_CONNECTIONS {
            let mut client = connect(port).await;
            assert!(line(&mut client).await.starts_with("* OK"));
            clients.push(client);
        }
        let mut extra = connect(port).await;
        let mut said = String::new();
        // Closed at once: end of stream, or a reset, and not one octet.
        let _ = extra.read_to_string(&mut said).await;
        assert_eq!(said, "");

        // A slot comes back when a connection leaves.
        drop(clients.pop());
        let mut greeted = false;
        for _ in 0..50 {
            let mut next = connect(port).await;
            let mut greeting = String::new();
            if next.read_line(&mut greeting).await.is_ok() && greeting.starts_with("* OK") {
                greeted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(greeted);
        assert!(close_imap_servers(servers).await);
    }

    #[test]
    fn ports_follow_number_or_default() {
        assert_eq!(port_setting(None, 143).unwrap(), 143);
        assert_eq!(port_setting(Some("1143"), 143).unwrap(), 1143);
        assert_eq!(port_setting(Some(" 1143 "), 143).unwrap(), 1143);
        // Not a number at all, or zero: the default.
        assert_eq!(port_setting(Some("not-a-port"), 143).unwrap(), 143);
        assert_eq!(port_setting(Some("143abc"), 993).unwrap(), 993);
        assert_eq!(port_setting(Some(""), 993).unwrap(), 993);
        assert_eq!(port_setting(Some("0"), 143).unwrap(), 143);
        // A number that is no port cannot be listened on.
        assert!(port_setting(Some("70000"), 143).is_err());
        assert!(port_setting(Some("-1"), 143).is_err());
        assert!(port_setting(Some("143.5"), 143).is_err());
    }
}
