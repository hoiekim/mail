//! The two ways an admitted DATA transaction goes: inbound mail stored for
//! the local recipients, and an authenticated user's submission sent out
//! (`onDataIncoming` / `onDataOutgoing` in `smtp.ts`).

use serde_json::json;

use super::bounded::BoundedMessage;
use super::handler::{refusals, CredentialStamp, DataFailure, MailDirectory, MailHandler};
use super::transaction_dir::{new_transaction_dir, remove_transaction_dir};
use super::types::SmtpSession;
use crate::logger;
use crate::mime::parser::{parse_message, ParseOptions, ParsedMessage};

/// The refusal a lane met while reading, as its answer.
fn refused(message: &mut BoundedMessage) -> Option<DataFailure> {
    let (error, coded) = message.refusal()?.to_hook_error();
    Some(if coded { DataFailure::Refused(error) } else { DataFailure::Failed(anyhow::anyhow!(error.message)) })
}

impl<D: MailDirectory> MailHandler<D> {
    pub(crate) async fn incoming(&self, mut message: BoundedMessage, session: &SmtpSession) -> Result<(), DataFailure> {
        let dir = new_transaction_dir();
        let outcome = async {
            let parsed = parse_message(&mut message, &ParseOptions { attachment_dir: dir.clone() }).await;
            if let Some(refusal) = refused(&mut message) {
                return Err(refusal);
            }
            let stored = match parsed {
                Ok(parsed) => store_incoming(parsed, session).await,
                Err(error) => Err(error),
            };
            let stored = match stored {
                Ok(stored) => stored,
                Err(error) => {
                    logger::error_with("Error parsing email", json!({}), &error);
                    return Err(DataFailure::Failed(error));
                }
            };
            // RCPT TO refuses the recipients this cannot store for, so a zero
            // here is a mailbox that went away mid-transaction.
            if stored == 0 {
                logger::warn(
                    "SMTP: accepted DATA that stored into no mailbox",
                    json!({ "remoteAddress": session.remote_address }),
                );
                return Err(refusals::mail_not_stored().into());
            }
            Ok(())
        }
        .await;
        drop(message);
        remove_transaction_dir(&dir).await;
        outcome
    }

    pub(crate) async fn outgoing(&self, mut message: BoundedMessage, session: &SmtpSession) -> Result<(), DataFailure> {
        let dir = new_transaction_dir();
        let outcome = async {
            let username = session.user.clone();
            let user = match username.as_deref() {
                Some(username) => match self.directory.get_user(username).await {
                    Ok(user) => user,
                    Err(error) => return Err(refused(&mut message).unwrap_or(DataFailure::Failed(error))),
                },
                None => None,
            };
            if let Some(refusal) = refused(&mut message) {
                return Err(refusal);
            }
            let signed = user.as_ref().and_then(|user| user.get_signed());
            let (Some(username), Some(user), Some(signed)) = (username, user, signed) else {
                logger::warn("SMTP: Unauthenticated user attempted to send email.", json!({}));
                return Err(DataFailure::Failed(anyhow::anyhow!("User not authenticated")));
            };

            // Credential-revocation fence at the send gate: a rotation that
            // landed after MAIL FROM / RCPT TO still loses the grant here.
            let stamped = session.state.get::<CredentialStamp>().map_or(1, |stamp| stamp.password_version);
            if user.password_version.unwrap_or(1) > stamped {
                logger::info(
                    "SMTP: refused an outgoing message on a rotated credential",
                    json!({ "authenticatedAs": username }),
                );
                return Err(refusals::credential_changed().into());
            }

            let parsed = parse_message(&mut message, &ParseOptions { attachment_dir: dir.clone() }).await;
            if let Some(refusal) = refused(&mut message) {
                return Err(refusal);
            }
            let parsed = parsed.map_err(DataFailure::Failed)?;
            send_outgoing(parsed, &username, signed, session).await.map_err(DataFailure::Failed)
        }
        .await;
        drop(message);
        remove_transaction_dir(&dir).await;
        outcome
    }
}

/// Stores an inbound message for its local recipients; how many mailboxes
/// it went into.
async fn store_incoming(_parsed: ParsedMessage, _session: &SmtpSession) -> anyhow::Result<usize> {
    anyhow::bail!("storing inbound mail is not wired yet")
}

/// Sends an authenticated submission through Mailgun and records it in Sent.
async fn send_outgoing(
    _parsed: ParsedMessage,
    _username: &str,
    _user: crate::models::SignedUser,
    _session: &SmtpSession,
) -> anyhow::Result<()> {
    anyhow::bail!("sending submissions is not wired yet")
}
