//! The HTTP server: the request pipeline, the `/api` routes, mail-client
//! autoconfig, and the built web client with its single-page fallback.

pub mod error_handler;
pub mod issue_session;
pub mod rate_limit;
pub mod request;
pub mod respond;
pub mod routes;
pub mod session;
pub mod session_secret;
pub mod sso_hooks;
pub mod static_files;
pub mod upload;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{stream, TryStreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use self::error_handler::{error_handler, report_middleware_error, FailedRequest};
use self::request::{
    has_body, is_secure_request, read_json_body, resolve_client_ip, trust_loopback_and_private, trust_no_proxy,
    HttpRequest, ProxyTrust, Query, RawBody,
};
use self::respond::{conditional, send, text, Body, Response};
use self::routes::auth::is_raw_body_path;
use self::routes::route::mounted_path;
use self::session::{HttpSession, SessionOptions};
use crate::postgres::repositories::sessions::PostgresSessionStore;
use crate::util::get_domain;
use crate::{env, logger};

type WireBody = BoxBody<Bytes, std::io::Error>;

/// Security response headers, applied to every response. This is the single
/// place they are defined.
fn security_headers(production: bool) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        (
            "Content-Security-Policy",
            [
                "default-src 'self'",
                "script-src 'self'",
                // 'unsafe-inline' for styles is required by React.
                "style-src 'self' 'unsafe-inline'",
                // blob: for inline email images, https: for external ones; plain http: is left out.
                "img-src 'self' data: blob: https:",
                "connect-src 'self'",
                // The sandboxed email iframes are same-origin documents.
                "frame-src 'self'",
                "font-src 'self' data:",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]
            .join("; "),
        ),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("X-Frame-Options", "DENY".to_string()),
        ("Referrer-Policy", "strict-origin-when-cross-origin".to_string()),
    ];
    if production {
        headers.push(("Strict-Transport-Security", "max-age=31536000; includeSubDomains".to_string()));
    }
    headers
}

fn is_autoconfig_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let lower = lower.strip_suffix('/').unwrap_or(&lower);
    lower == "/.well-known/autoconfig/mail/config-v1.1.xml"
}

/// IMAP/SMTP auto-discovery for mail clients (Thunderbird and others).
fn autoconfig() -> Response {
    let email_domain = get_domain();
    // The hostname clients connect to, which is not always the mail domain.
    let server_hostname = env::non_empty("APP_HOSTNAME").unwrap_or_else(|| email_domain.clone());
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{email_domain}">
    <domain>{email_domain}</domain>
    <displayName>{email_domain} Mail</displayName>
    <displayShortName>{email_domain}</displayShortName>
    <incomingServer type="imap">
      <hostname>{server_hostname}</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{server_hostname}</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#
    );
    send(xml, 200, "application/xml; charset=utf-8")
}

/// Everything the pipeline resolves once at boot.
pub struct HttpApp {
    store: PostgresSessionStore,
    session_secret: String,
    production: bool,
    trust: ProxyTrust,
    headers: Vec<(&'static str, String)>,
    client_path: PathBuf,
}

impl HttpApp {
    pub fn new(store: PostgresSessionStore) -> anyhow::Result<HttpApp> {
        let production = env::is_production();
        Ok(HttpApp {
            store,
            session_secret: session_secret::resolve_session_secret()?,
            production,
            // The proxy is trusted by address, not by hop count: a request
            // that reaches the port without passing the proxy cannot name
            // its own address through a forwarding header.
            trust: if production { trust_loopback_and_private } else { trust_no_proxy },
            headers: security_headers(production),
            client_path: env::non_empty("CLIENT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("build/client")),
        })
    }

    async fn route(&self, req: &mut HttpRequest) -> anyhow::Result<Response> {
        let path = req.path.clone();
        if let Some(api_path) = mounted_path(&path, "/api") {
            return routes::handle_api(req, api_path).await;
        }
        if req.method != "GET" && req.method != "HEAD" {
            return Ok(text("Not Found", 404));
        }
        if is_autoconfig_path(&path) {
            return Ok(autoconfig());
        }
        let ranged = req.headers.contains_key("range");
        if let Some(file) = static_files::serve_static(&self.client_path, &path, ranged).await {
            return Ok(file);
        }
        Ok(static_files::serve_index(&self.client_path, ranged)
            .await
            .unwrap_or_else(|| text("Not Found", 404)))
    }

    /// Handles one request; `peer_address` is the remote address of its connection.
    pub async fn handle(
        &self,
        method: String,
        target: RequestTarget,
        headers: http::HeaderMap,
        body: Incoming,
        peer_address: &str,
    ) -> Response {
        let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        let ip = resolve_client_ip(peer_address, header("x-forwarded-for"), self.trust);
        let secure = is_secure_request(peer_address, header("x-forwarded-proto"), self.trust);
        let request_has_body = has_body(&headers, &body);
        let failed = |session_id: Option<&str>, error: &anyhow::Error| {
            error_handler(error, &FailedRequest { method: &method, path: &target.pathname, session_id })
        };

        // The body is read before the session is loaded, as a client error
        // there must not cost a store round trip.
        let parsed = if is_raw_body_path(&target.pathname) {
            Ok(request::JsonBody { value: json!({}), raw: RawBody::Unread(body) })
        } else {
            read_json_body(&headers, body, request_has_body).await
        };
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => return self.finish(&method, &headers, failed(None, &error.into())),
        };

        let options = SessionOptions { secret: self.session_secret.clone(), secure: self.production };
        let mut session = match HttpSession::load(header("cookie"), self.store, options).await {
            Ok(session) => session,
            Err(error) => return self.finish(&method, &headers, failed(None, &error.into())),
        };

        let mut response = match sso_hooks::enforce_sso_session(&mut session).await {
            Err(error) => {
                let response = failed(Some(session.session_id()), &error);
                (response, session)
            }
            Ok(()) => {
                let mut req = HttpRequest {
                    method: method.clone(),
                    path: target.pathname.clone(),
                    url: format!("{}{}", target.pathname, target.search),
                    query: Query::parse(&target.search),
                    headers: headers.clone(),
                    params: Default::default(),
                    body: parsed.value,
                    files: None,
                    ip,
                    secure,
                    session,
                    raw: parsed.raw,
                    has_body: request_has_body,
                };
                let response = match self.route(&mut req).await {
                    Ok(response) => response,
                    Err(error) => failed(Some(req.session.session_id()), &error),
                };
                (response, req.session)
            }
        };
        let (response, session) = (&mut response.0, &mut response.1);

        let (cookie, save_error) = session.commit(secure).await;
        if let Some(error) = save_error {
            report_middleware_error(
                &error.into(),
                &FailedRequest { method: &method, path: &target.pathname, session_id: Some(session.session_id()) },
            );
        }
        if let Some(cookie) = cookie {
            response.append_header("Set-Cookie", cookie);
        }
        self.finish(&method, &headers, std::mem::replace(response, Response::empty()))
    }

    fn finish(&self, method: &str, request_headers: &http::HeaderMap, mut response: Response) -> Response {
        for (name, value) in &self.headers {
            response.set_header(name, value.clone());
        }
        conditional(method, request_headers, response)
    }
}

/// The path and query string a request asked for.
pub struct RequestTarget {
    pub pathname: String,
    pub search: String,
}

/// Normalizes the request target the way a URL parser does — dot segments
/// resolved, `%2e` treated as a dot, backslashes as slashes — and splits it
/// at the first `?`. The Host header plays no part in the result.
fn request_target(uri: &http::Uri) -> RequestTarget {
    let raw = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let normalized = url::Url::parse(&format!("http://localhost{raw}"))
        .ok()
        .map(|url| url.as_str()["http://localhost".len()..].to_string())
        .unwrap_or_else(|| raw.to_string());
    let (pathname, search) = match normalized.find('?') {
        Some(at) => (normalized[..at].to_string(), normalized[at..].to_string()),
        None => (normalized, String::new()),
    };
    RequestTarget { pathname: if pathname.is_empty() { "/".to_string() } else { pathname }, search }
}

/// One satisfiable byte range of a file of `size` bytes.
enum ByteRange {
    /// Not a single well-formed range: answer with the whole file.
    Ignore,
    Unsatisfiable,
    Partial { start: u64, end: u64 },
}

fn parse_range(header: &str, size: u64) -> ByteRange {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return ByteRange::Ignore;
    };
    if spec.contains(',') {
        return ByteRange::Ignore;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return ByteRange::Ignore;
    };
    let number = |text: &str| -> Option<u64> {
        (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
    };
    match (first.is_empty(), last.is_empty()) {
        (true, true) => ByteRange::Ignore,
        // The last `n` bytes.
        (true, false) => match number(last) {
            Some(0) | None => ByteRange::Ignore,
            Some(suffix) if size == 0 => {
                let _ = suffix;
                ByteRange::Unsatisfiable
            }
            Some(suffix) => ByteRange::Partial { start: size.saturating_sub(suffix), end: size - 1 },
        },
        (false, _) => {
            let Some(start) = number(first) else {
                return ByteRange::Ignore;
            };
            let end = if last.is_empty() {
                None
            } else {
                match number(last) {
                    Some(end) => Some(end),
                    None => return ByteRange::Ignore,
                }
            };
            if end.is_some_and(|end| end < start) {
                return ByteRange::Ignore;
            }
            if start >= size {
                return ByteRange::Unsatisfiable;
            }
            ByteRange::Partial { start, end: end.map_or(size - 1, |end| end.min(size - 1)) }
        }
    }
}

fn full(bytes: Bytes) -> WireBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

async fn file_body(path: PathBuf, start: u64, length: u64) -> std::io::Result<WireBody> {
    let mut file = tokio::fs::File::open(path).await?;
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let frames = ReaderStream::new(file.take(length)).map_ok(Frame::data);
    Ok(BodyExt::boxed(StreamBody::new(frames)))
}

/// Puts a response on the wire: explicit `Content-Length`, no body for HEAD,
/// and byte ranges for a file body.
async fn into_wire(
    method: &str,
    request_headers: &http::HeaderMap,
    mut response: Response,
) -> hyper::Response<WireBody> {
    let mut status = response.status;
    let mut length = response.body.len();
    let mut range = None;

    if let Body::File { size, .. } = &response.body {
        let requested = request_headers.get("range").and_then(|value| value.to_str().ok());
        if let (true, 200, Some(requested)) = (method == "GET", status, requested) {
            match parse_range(requested, *size) {
                ByteRange::Ignore => {}
                ByteRange::Unsatisfiable => {
                    status = 416;
                    length = 0;
                    response.set_header("Content-Range", format!("bytes */{size}"));
                    response.set_header("Accept-Ranges", "bytes");
                    response.body = Body::Empty;
                }
                ByteRange::Partial { start, end } => {
                    status = 206;
                    length = end - start + 1;
                    range = Some((start, length));
                    response.set_header("Content-Range", format!("bytes {start}-{end}/{size}"));
                    response.set_header("Accept-Ranges", "bytes");
                }
            }
        }
    }

    let body: WireBody = if method == "HEAD" || status == 304 {
        full(Bytes::new())
    } else {
        match response.body {
            Body::Empty => full(Bytes::new()),
            Body::Bytes(bytes) => full(bytes),
            Body::Chunks(chunks) => {
                let frames = stream::iter(chunks.into_iter().map(|chunk| Ok(Frame::data(chunk))));
                BodyExt::boxed(StreamBody::new(frames))
            }
            Body::File { path, size } => {
                let (start, take) = range.unwrap_or((0, size));
                match file_body(path, start, take).await {
                    Ok(body) => body,
                    Err(error) => {
                        // The file vanished between the stat and the open.
                        logger::error_with("Unhandled HTTP server error", json!({}), &error);
                        crate::alarm::spawn_alarm("Unhandled HTTP Server Error", format!("**Error:** {error}"));
                        let fallback = text("Internal server error", 500);
                        let Body::Bytes(bytes) = fallback.body else { unreachable!("text bodies are bytes") };
                        status = 500;
                        length = bytes.len() as u64;
                        response.headers = fallback.headers;
                        full(bytes)
                    }
                }
            }
        }
    };

    let mut builder = hyper::Response::builder().status(status);
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    if status != 304 {
        builder = builder.header("Content-Length", length);
    }
    builder.body(body).unwrap_or_else(|_| {
        let mut fallback = hyper::Response::new(full(Bytes::from_static(b"Internal server error")));
        *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

async fn serve(
    app: Arc<HttpApp>,
    request: hyper::Request<Incoming>,
    peer: SocketAddr,
) -> Result<hyper::Response<WireBody>, Infallible> {
    let (parts, body) = request.into_parts();
    // An HTTP/1.1 request without Host is refused outright.
    if parts.version == http::Version::HTTP_11 && !parts.headers.contains_key("host") {
        let mut response = hyper::Response::new(full(Bytes::new()));
        *response.status_mut() = http::StatusCode::BAD_REQUEST;
        response.headers_mut().insert("connection", http::HeaderValue::from_static("close"));
        return Ok(response);
    }
    let method = parts.method.as_str().to_string();
    let target = request_target(&parts.uri);
    let peer_address = match peer.ip() {
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| ip.to_string()),
        std::net::IpAddr::V4(ip) => ip.to_string(),
    };
    let response = app.handle(method.clone(), target, parts.headers.clone(), body, &peer_address).await;
    Ok(into_wire(&method, &parts.headers, response).await)
}

/// The running HTTP server.
pub struct HttpServer {
    shutdown: CancellationToken,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl HttpServer {
    /// Stops accepting connections and waits for in-flight requests to finish.
    pub async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.accept_loop.await;
    }
}

// How long an idle keep-alive connection is kept.
const IDLE_TIMEOUT: Duration = Duration::from_secs(255);

/// How long a stop waits for in-flight requests before dropping them.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Binds the HTTP port (`PORT`, default 3004) and starts serving.
pub async fn initialize_http() -> anyhow::Result<HttpServer> {
    let app = Arc::new(HttpApp::new(PostgresSessionStore::start())?);
    let port: u16 = match env::non_empty("PORT") {
        Some(value) => crate::js::number_from_str(&value) as u16,
        None => 3004,
    };
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    logger::info(format!("{} mail server is listening", get_domain()), json!({}));
    rate_limit::start_cleanup_scheduler();

    let shutdown = CancellationToken::new();
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let accept_loop = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.timer(TokioTimer::new()).header_read_timeout(IDLE_TIMEOUT).title_case_headers(true);
            loop {
                let (stream, peer) = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => continue,
                    },
                };
                let _ = stream.set_nodelay(true);
                let app = app.clone();
                let connection = builder
                    .serve_connection(TokioIo::new(stream), service_fn(move |request| serve(app.clone(), request, peer)));
                let connection = graceful.watch(connection);
                tokio::spawn(async move {
                    let _ = connection.await;
                });
            }
            drop(listener);
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await;
        }
    });
    Ok(HttpServer { shutdown, accept_loop })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(raw: &str) -> (String, String) {
        let target = request_target(&raw.parse().unwrap());
        (target.pathname, target.search)
    }

    #[test]
    fn targets_are_normalized_like_a_url() {
        assert_eq!(target("/api/users/../users/login"), ("/api/users/login".into(), "".into()));
        assert_eq!(target("/%2e%2e/package.json"), ("/package.json".into(), "".into()));
        assert_eq!(target("/api//ping?x=1&y"), ("/api//ping".into(), "?x=1&y".into()));
        assert_eq!(target("/a%20b"), ("/a%20b".into(), "".into()));
        assert_eq!(target("/"), ("/".into(), "".into()));
    }

    #[test]
    fn ranges() {
        assert!(matches!(parse_range("bytes=0-4", 67), ByteRange::Partial { start: 0, end: 4 }));
        assert!(matches!(parse_range("bytes=5-", 67), ByteRange::Partial { start: 5, end: 66 }));
        assert!(matches!(parse_range("bytes=-5", 67), ByteRange::Partial { start: 62, end: 66 }));
        assert!(matches!(parse_range("bytes=0-99999", 67), ByteRange::Partial { start: 0, end: 66 }));
        assert!(matches!(parse_range("bytes=9999-", 67), ByteRange::Unsatisfiable));
        assert!(matches!(parse_range("bytes=4-2", 67), ByteRange::Ignore));
        assert!(matches!(parse_range("bytes=0-0,2-3", 67), ByteRange::Ignore));
        assert!(matches!(parse_range("garbage", 67), ByteRange::Ignore));
    }

    #[test]
    fn autoconfig_paths() {
        assert!(is_autoconfig_path("/.well-known/autoconfig/mail/config-v1.1.xml"));
        assert!(is_autoconfig_path("/.WELL-KNOWN/autoconfig/mail/config-v1.1.xml/"));
        assert!(!is_autoconfig_path("/.well-known/autoconfig/mail/config-v1.1.xml/x"));
    }
}
