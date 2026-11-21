//! `/api/mails/*`.

use crate::http::request::HttpRequest;
use crate::http::respond::Response;

/// `/api/mails/*`, with `path` relative to that mount.
pub async fn handle_mails(_req: &mut HttpRequest, _path: &str) -> anyhow::Result<Option<Response>> {
    Ok(None)
}
