//! `/api/auth/*`: single sign-on. Public, and answered only while single
//! sign-on is on, so with it off they are unknown routes.

use crate::http::request::HttpRequest;
use crate::http::respond::Response;

/// The provider events route reads its own body: a request there is not
/// parsed as JSON, whatever content type it claims.
pub fn is_raw_body_path(pathname: &str) -> bool {
    let lower = pathname.to_ascii_lowercase();
    lower == "/api/auth/events" || lower == "/api/auth/events/"
}

/// `/api/auth/*`, with `path` relative to that mount.
pub async fn handle_auth(_req: &mut HttpRequest, _path: &str) -> anyhow::Result<Option<Response>> {
    Ok(None)
}
