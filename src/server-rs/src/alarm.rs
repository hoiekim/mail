//! Discord alarms for server errors.
//!
//! One POST to `DISCORD_ALARM_WEBHOOK` per alarm key per minute, so a burst
//! from one source cannot flood the channel or starve another source.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::json;

use crate::{env, js};

const COOLDOWN_MS: i64 = 60_000;

fn last_alarm_at() -> &'static Mutex<HashMap<String, i64>> {
    static STATE: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}

/// The HTTP client every outbound request of this process shares.
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("the HTTP client builds")
    })
}

/// Sends one alarm and waits for the webhook to answer. `key` is the cooldown
/// bucket; `None` uses the title. Never fails: a delivery problem is logged.
pub async fn send_alarm(title: &str, detail: &str, key: Option<&str>) {
    let Some(webhook_url) = env::non_empty("DISCORD_ALARM_WEBHOOK") else {
        return;
    };

    let key = key.unwrap_or(title).to_string();
    let now = js::now_ms();
    {
        let mut last = last_alarm_at().lock().unwrap();
        if now - last.get(&key).copied().unwrap_or(0) < COOLDOWN_MS {
            return;
        }
        last.insert(key, now);
    }

    let body = json!({
        "embeds": [{
            "title": format!("🚨 Mail Server Error: {title}"),
            "description": js::utf16_truncate(detail, 4000),
            "color": 0xff0000,
            "timestamp": js::iso_from_ms(now),
        }]
    });

    let request = http_client()
        .post(webhook_url)
        .header("Content-Type", "application/json")
        .body(body.to_string());
    if let Err(error) = request.send().await {
        eprintln!("Failed to send Discord alarm: {error}");
    }
}

/// Sends an alarm without waiting for it: the caller's work does not depend
/// on the delivery.
pub fn spawn_alarm(title: impl Into<String>, detail: impl Into<String>) {
    let (title, detail) = (title.into(), detail.into());
    tokio::spawn(async move { send_alarm(&title, &detail, None).await });
}

/// Like [`spawn_alarm`], with an explicit cooldown bucket.
pub fn spawn_alarm_keyed(title: impl Into<String>, detail: impl Into<String>, key: impl Into<String>) {
    let (title, detail, key) = (title.into(), detail.into(), key.into());
    tokio::spawn(async move { send_alarm(&title, &detail, Some(&key)).await });
}
