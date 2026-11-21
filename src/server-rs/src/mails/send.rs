//! Sending a mail and recording it in Sent (mails/send.ts).

use crate::models::SignedUser;
use crate::users::AuthenticationMail;

/// Sends the sign-up / password-reset mail as `admin`, without a Sent record.
///
/// Not wired yet: the sender lands with the mail-sending port.
pub async fn send_authentication_mail(_admin: &SignedUser, _mail: AuthenticationMail) -> anyhow::Result<()> {
    anyhow::bail!("mail sending is not wired into the Rust server yet")
}
