//! The two ways an admitted DATA transaction goes: inbound mail stored for
//! the local recipients, and an authenticated user's submission sent out
//! (`onDataIncoming` / `onDataOutgoing` in `smtp.ts`).

use serde_json::{json, Value};

use super::bounded::BoundedMessage;
use super::handler::{refusals, CredentialStamp, DataFailure, MailDirectory, MailHandler};
use super::outgoing::{address_list, resolve_outgoing_sender, split_envelope_recipients, EnvelopeRecipients, OutgoingSender};
use super::transaction_dir::{new_transaction_dir, remove_transaction_dir};
use super::types::{SmtpEnvelope, SmtpSession};
use crate::logger;
use crate::mails::receive::{incoming_mail_from_parsed, save_mail_handler, IncomingMailAddressValue, SaveMailHandlerOptions};
use crate::mails::send::{send_mail, MailDataToSend, SendMailOptions};
use crate::mails::text_to_html::plain_text_to_html;
use crate::mime::parser::{parse_message, ParseOptions, ParsedMessage};
use crate::models::SignedUser;
use crate::util::get_user_domain;

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
async fn store_incoming(parsed: ParsedMessage, session: &SmtpSession) -> anyhow::Result<usize> {
    let mut mail = incoming_mail_from_parsed(&parsed);
    // `envelope.mailFrom || undefined`: the null sender `<>` is an empty
    // address, which the save drops, leaving no envelope sender.
    mail.envelope_from =
        session.envelope.mail_from.as_ref().map(|from| vec![IncomingMailAddressValue::address(from.address.clone())]);
    mail.envelope_to = Some(
        session.envelope.rcpt_to.iter().map(|to| IncomingMailAddressValue::address(to.address.clone())).collect(),
    );
    // The client address, for the spam check's DNS blocklist lookups.
    let options = SaveMailHandlerOptions { remote_address: Some(session.remote_address.clone()) };
    save_mail_handler(&mail, &options).await
}

/// The first entry of the From header: its address and display name.
fn first_from(parsed: &ParsedMessage) -> (Option<&str>, Option<&str>) {
    let first = parsed.from.as_ref().and_then(|from| from.value.first());
    (first.and_then(|entry| entry.address.as_deref()), first.map(|entry| entry.name.as_str()))
}

/// What a submission is sent as, from the parsed message and the envelope.
pub(crate) fn outgoing_mail(parsed: &ParsedMessage, username: &str, user_domain: &str, envelope: &SmtpEnvelope) -> MailDataToSend {
    let (from_address, from_name) = first_from(parsed);
    let envelope_from = envelope.mail_from.as_ref().map(|from| from.address.as_str());
    let addressed_to = address_list(parsed.to.as_ref());
    let rcpt_to: Vec<String> = envelope.rcpt_to.iter().map(|to| to.address.clone()).collect();
    let OutgoingSender { sender, recipients } =
        resolve_outgoing_sender(username, user_domain, from_address, envelope_from, &rcpt_to, &addressed_to);
    let EnvelopeRecipients { to, cc, bcc } =
        split_envelope_recipients(&recipients, &addressed_to, &address_list(parsed.cc.as_ref()));

    let list = |addresses: Vec<String>| (!addresses.is_empty()).then(|| Value::String(addresses.join(",")));
    let non_empty = |text: Option<&str>| text.filter(|text| !text.is_empty()).map(str::to_string);
    // A text-only submission is sent as HTML, so convert it rather than let
    // the recipient's client collapse its line breaks.
    let html = non_empty(parsed.html.as_deref())
        .or_else(|| non_empty(parsed.text.as_deref()).map(|text| plain_text_to_html(&text)))
        .unwrap_or_default();
    let sender_full_name = non_empty(from_name).unwrap_or_else(|| sender.clone());
    MailDataToSend {
        // The model's defaults: a falsy subject is "No Subject".
        subject: Value::String(non_empty(parsed.subject.as_deref()).unwrap_or_else(|| "No Subject".to_string())),
        to: Value::String(to.join(",")),
        cc: list(cc),
        bcc: list(bcc),
        html: Value::String(html),
        sender_full_name: Value::String(sender_full_name),
        sender: Value::String(sender),
        // A reply written in a mail client keeps its place in the
        // conversation: the headers go out with it and onto the Sent copy.
        in_reply_to: parsed.in_reply_to.clone().map(Value::String),
        references: parsed.references.clone(),
    }
}

/// Sends an authenticated submission through Mailgun and records it in Sent.
/// Attachments are not carried, as the Bun server carries none.
async fn send_outgoing(parsed: ParsedMessage, username: &str, user: SignedUser, session: &SmtpSession) -> anyhow::Result<()> {
    let mail = outgoing_mail(&parsed, username, &get_user_domain(username), &session.envelope);
    send_mail(&user, mail, &[], SendMailOptions::default()).await.map_err(anyhow::Error::new)?;
    Ok(())
}
