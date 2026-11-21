//! IDLE sessions waiting for mailbox changes.

/// Tells IDLE sessions of these users that new mail arrived, optionally
/// limited to the given mailboxes.
pub async fn notify_new_mail(_usernames: &[String], _mailboxes: Option<&[String]>) {}

/// Tells IDLE sessions of these users that the flags of these mails changed.
pub async fn notify_flag_change(_usernames: &[String], _mail_ids: &[String]) {}
