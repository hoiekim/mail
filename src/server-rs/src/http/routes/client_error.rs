//! `POST /api/client-error`: frontend error reports, forwarded as an alarm.
//! No session is required (the beacon fires after page unload), so it is
//! rate-limited per address.

use std::sync::OnceLock;

use serde_json::{json, Value};

use crate::alarm::send_alarm;
use crate::http::rate_limit::{get_client_ip, RateLimiter};
use crate::http::request::HttpRequest;
use crate::http::respond::{json, Response};
use crate::js;

fn client_error_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(5, "Too many client error reports, try again later", false))
}

/// `/api/client-error`, with `path` relative to that mount.
pub async fn handle_client_error(req: &mut HttpRequest, path: &str) -> anyhow::Result<Option<Response>> {
    if req.method != "POST" || path != "/" {
        return Ok(None);
    }
    if let Some(refused) = client_error_limiter().check(req) {
        return Ok(Some(refused));
    }
    // The cap bounds report volume, so every accepted report takes a slot.
    client_error_limiter().record_failure(&get_client_ip(req), None);

    let string = |key: &str| req.body.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let number = |key: &str| req.body.get(key).filter(|value| value.is_number()).map(js_number);
    let message = req.body.get("message").and_then(Value::as_str).unwrap_or("(no message)").to_string();
    let (stack, url, filename) = (string("stack"), string("url"), string("filename"));
    let (lineno, colno) = (number("lineno"), number("colno"));

    // The column is only appended once a line is known.
    let location = if filename.is_empty() {
        String::new()
    } else {
        match (&lineno, &colno) {
            (Some(line), Some(column)) => format!("{filename}:{line}:{column}"),
            (Some(line), None) => format!("{filename}:{line}"),
            (None, _) => filename.clone(),
        }
    };

    eprintln!("Client error reported: {}", json!({ "url": url, "message": message, "location": location }));

    let mut detail = Vec::new();
    if !url.is_empty() {
        detail.push(format!("**URL:** {url}"));
    }
    detail.push(format!("**Message:** {message}"));
    if !location.is_empty() {
        detail.push(format!("**Source:** {location}"));
    }
    if !stack.is_empty() {
        detail.push(format!("```\n{}\n```", js::utf16_truncate(&stack, 1000)));
    }

    // A bucket of its own, so client-error volume cannot suppress other alarms.
    send_alarm("Client JS Error", &detail.join("\n"), Some("client-error")).await;
    Ok(Some(json(&json!({ "status": "success" }), 200)))
}

/// A JSON number the way JavaScript prints it in a template string.
fn js_number(value: &Value) -> String {
    match value.as_i64() {
        Some(integer) => integer.to_string(),
        None => js::number_to_string(value.as_f64().unwrap_or(f64::NAN)),
    }
}
