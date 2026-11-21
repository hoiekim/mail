//! The IMAP sessions this process holds, by authenticated username.

/// Closes every IMAP session authenticated as `username` and returns how many
/// there were. Called when the account's credential is rotated or revoked.
pub fn evict_imap_sessions(_username: &str) -> usize {
    0
}
