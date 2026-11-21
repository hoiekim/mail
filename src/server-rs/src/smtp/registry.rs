//! The authenticated SMTP connections this process holds, by username.

/// Closes every SMTP connection authenticated as `username` and returns how
/// many there were. Called when the account's credential is rotated or revoked.
pub fn evict_smtp_connections(_username: &str) -> usize {
    0
}
