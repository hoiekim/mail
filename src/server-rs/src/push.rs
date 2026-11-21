//! Web push notifications.

use std::sync::RwLock;
use std::time::Duration;

use anyhow::{bail, Result};
use base64::Engine;
use serde_json::json;

use crate::postgres::repositories::push_subscriptions as repo;
use crate::push_validation::{validate_push_subscription, PushSubscription};
use crate::{env, logger};

#[derive(Clone, Default)]
#[allow(dead_code)] // The private key and subject sign outgoing pushes.
struct Vapid {
    public_key: Option<String>,
    private_key: Option<String>,
    subject: String,
    configured: bool,
}

static VAPID: RwLock<Vapid> = RwLock::new(Vapid {
    public_key: None,
    private_key: None,
    subject: String::new(),
    configured: false,
});

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()
}

/// The checks the push library applies to its VAPID details.
fn validate_vapid_details(subject: &str, public_key: &str, private_key: &str) -> Result<()> {
    if subject.is_empty() {
        bail!("No subject set in vapidDetails.subject.");
    }
    if url::Url::parse(subject).is_err() {
        bail!("Vapid subject is not a valid URL. {subject}");
    }
    let is_url_safe = |value: &str| value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=');
    if !is_url_safe(public_key) {
        bail!("Vapid public key must be a URL safe Base 64 (without \"=\")");
    }
    if decode_base64url(public_key).map(|bytes| bytes.len()) != Some(65) {
        bail!("Vapid public key should be 65 bytes long when decoded.");
    }
    if !is_url_safe(private_key) {
        bail!("Vapid private key must be a URL safe Base 64 (without \"=\")");
    }
    if decode_base64url(private_key).map(|bytes| bytes.len()) != Some(32) {
        bail!("Vapid private key should be 32 bytes long when decoded.");
    }
    Ok(())
}

/// Reads the VAPID keys. Push is on only when both are set; a malformed pair
/// is a startup error.
pub fn init_push() -> Result<()> {
    let public_key = env::non_empty("PUSH_VAPID_PUBLIC_KEY");
    let private_key = env::non_empty("PUSH_VAPID_PRIVATE_KEY");
    let domain = env::non_empty("EMAIL_DOMAIN").unwrap_or_else(|| "mydomain".to_string());
    let subject = format!("mailto:admin@{domain}");
    let configured = public_key.is_some() && private_key.is_some();

    if let (Some(public_key), Some(private_key)) = (&public_key, &private_key) {
        validate_vapid_details(&subject, public_key, private_key)?;
    } else {
        logger::warn(
            "VAPID keys not configured - push notifications disabled",
            json!({
                "component": "push",
                "hint": "Set PUSH_VAPID_PUBLIC_KEY and PUSH_VAPID_PRIVATE_KEY to enable",
            }),
        );
    }
    *VAPID.write().unwrap() = Vapid { public_key, private_key, subject, configured };
    Ok(())
}

/// The VAPID public key a browser subscribes with, when one is set.
pub fn get_push_public_key() -> Option<String> {
    VAPID.read().unwrap().public_key.clone()
}

pub fn is_push_enabled() -> bool {
    VAPID.read().unwrap().configured
}

/// Stores a subscription for `user_id` and returns its id.
pub async fn store_subscription(user_id: &str, subscription: &PushSubscription) -> Option<String> {
    repo::store_subscription(user_id, subscription).await
}

/// Re-validates and stores a subscription given as untrusted JSON.
pub async fn store_untrusted_subscription(user_id: &str, input: Option<&serde_json::Value>) -> Option<String> {
    match validate_push_subscription(input) {
        Ok(subscription) => store_subscription(user_id, &subscription).await,
        Err(reason) => {
            logger::warn(
                "Refused to store an unusable push subscription",
                json!({ "component": "push", "reason": reason }),
            );
            None
        }
    }
}

pub async fn delete_subscription_for_user(push_subscription_id: &str, user_id: &str) -> bool {
    repo::delete_subscription_for_user(push_subscription_id, user_id).await
}

pub async fn refresh_subscription(push_subscription_id: &str) -> bool {
    repo::refresh_subscription(push_subscription_id).await
}

const ONE_DAY: Duration = Duration::from_secs(60 * 60 * 24);

/// Starts the daily sweep of subscriptions no browser has refreshed.
pub fn clean_subscriptions() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(ONE_DAY).await;
            logger::info("Cleaning old push subscriptions", json!({ "component": "push" }));
            let deleted = repo::clean_subscriptions().await;
            logger::info("Deleted old subscriptions", json!({ "component": "push", "count": deleted }));
        }
    });
}
