//! Mailbox management operations (imap/mailbox-ops.ts): CREATE, DELETE,
//! RENAME, SUBSCRIBE, UNSUBSCRIBE, STATUS, LIST, LSUB and SELECT / EXAMINE.
//!
//! CREATE, DELETE, RENAME, SUBSCRIBE and UNSUBSCRIBE are whole: they need
//! only the mailbox repository. STATUS, LIST, LSUB and SELECT read through
//! the IMAP store, which is not ported yet: everything they answer before
//! touching it is here, and the rest of each is one function marked
//! `STORE SEAM` that answers the command's own failure line for now.

use serde_json::json;

use super::auth::strip_surrounding_quotes;
use super::session::ImapSession;
use super::types::StatusItem;
use super::util::{
    canonical_mailbox, is_accounts_folder, is_inbox, is_sent_messages_accounts_folder, is_utility_folder,
    quote_string, ACCOUNTS_FOLDER, SENT_MESSAGES_ACCOUNTS_FOLDER,
};
use crate::logger;
use crate::models::SignedUser;
use crate::postgres::repositories::mailboxes::{
    create_mailbox as db_create_mailbox, delete_mailbox_by_name, rename_mailbox as db_rename_mailbox,
    set_mailbox_subscribed, CreateMailboxInput, CreateMailboxResult, DeleteMailboxResult, RenameMailboxResult,
    MAILBOX_COUNT_MAX, MAILBOX_NAME_MAX_BYTES,
};

fn exceeds_name_limit(name: &str) -> bool {
    name.len() > MAILBOX_NAME_MAX_BYTES
}

// ---------------------------------------------------------------------------
// CREATE
// ---------------------------------------------------------------------------

pub async fn create_mailbox(tag: &str, mailbox: &str, user: &SignedUser, session: &ImapSession) {
    let clean_name = strip_surrounding_quotes(mailbox);
    if clean_name.is_empty() {
        session.write(&format!("{tag} NO Empty mailbox name\r\n"));
        return;
    }
    // RFC 3501 §6.3.3: "It is an error to attempt to create INBOX or a
    // mailbox with a name that refers to an existent mailbox." INBOX always
    // exists as a synthetic mailbox, in any casing. Without this guard the
    // insert would succeed and leave a phantom row that LIST de-duplicates
    // away but that lingers in the table.
    if is_inbox(clean_name) || is_utility_folder(clean_name) {
        session.write(&format!("{tag} NO [ALREADYEXISTS] Mailbox already exists\r\n"));
        return;
    }
    if exceeds_name_limit(clean_name) {
        session.write(&format!("{tag} NO [LIMIT] Mailbox name exceeds {MAILBOX_NAME_MAX_BYTES} bytes\r\n"));
        return;
    }
    let input = CreateMailboxInput { user_id: user.id.clone(), name: clean_name.to_string(), ..Default::default() };
    match db_create_mailbox(&input).await {
        Ok(CreateMailboxResult::Exists) => {
            session.write(&format!("{tag} NO [ALREADYEXISTS] Mailbox already exists\r\n"));
        }
        Ok(CreateMailboxResult::AtLimit) => {
            session.write(&format!("{tag} NO [LIMIT] Mailbox limit of {MAILBOX_COUNT_MAX} reached\r\n"));
        }
        Ok(CreateMailboxResult::Created(_)) => {
            logger::info("Mailbox created", json!({ "component": "imap", "mailbox": clean_name }));
            session.write(&format!("{tag} OK CREATE completed\r\n"));
        }
        Err(error) => {
            logger::error_with("Error creating mailbox", json!({ "component": "imap", "mailbox": clean_name }), &error);
            session.write(&format!("{tag} NO CREATE failed\r\n"));
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

pub async fn delete_mailbox(tag: &str, mailbox: &str, user: &SignedUser, session: &ImapSession) {
    let clean_name = strip_surrounding_quotes(mailbox);
    if clean_name.is_empty() {
        session.write(&format!("{tag} NO Empty mailbox name\r\n"));
        return;
    }
    // RFC 3501 §6.3.4: deletion of INBOX is forbidden, in every casing.
    // Without this guard the repository would report "not found" and the
    // client would get a misleading "does not exist".
    if is_inbox(clean_name) {
        session.write(&format!("{tag} NO [CANNOT] Cannot delete INBOX\r\n"));
        return;
    }
    // For the same reason: a utility folder is a server-defined view with
    // no row behind it.
    if is_utility_folder(clean_name) {
        session.write(&format!("{tag} NO [CANNOT] Cannot delete system mailbox\r\n"));
        return;
    }
    match delete_mailbox_by_name(&user.id, clean_name).await {
        Ok(DeleteMailboxResult::NotFound) => {
            session.write(&format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n"));
        }
        Ok(DeleteMailboxResult::Protected) => {
            session.write(&format!("{tag} NO [CANNOT] Cannot delete system mailbox\r\n"));
        }
        Ok(DeleteMailboxResult::Deleted) => {
            logger::info("Mailbox deleted", json!({ "component": "imap", "mailbox": clean_name }));
            session.write(&format!("{tag} OK DELETE completed\r\n"));
        }
        Err(error) => {
            logger::error_with("Error deleting mailbox", json!({ "component": "imap", "mailbox": clean_name }), &error);
            session.write(&format!("{tag} NO DELETE failed\r\n"));
        }
    }
}

// ---------------------------------------------------------------------------
// RENAME
// ---------------------------------------------------------------------------

pub async fn rename_mailbox(tag: &str, old_name: &str, new_name: &str, user: &SignedUser, session: &ImapSession) {
    let clean_old = strip_surrounding_quotes(old_name);
    let clean_new = strip_surrounding_quotes(new_name);
    if clean_old.is_empty() || clean_new.is_empty() {
        session.write(&format!("{tag} NO Empty mailbox name\r\n"));
        return;
    }
    // RFC 3501 §6.3.5 gives RENAME INBOX special semantics (move every
    // message to the new name, leave INBOX empty) which the backing store
    // does not support, so it is refused outright rather than answered
    // with the misleading "does not exist" the repository would produce.
    if is_inbox(clean_old) {
        session.write(&format!("{tag} NO [CANNOT] RENAME INBOX is not supported\r\n"));
        return;
    }
    if is_utility_folder(clean_old) {
        session.write(&format!("{tag} NO [CANNOT] Cannot rename system mailbox\r\n"));
        return;
    }
    // The target must not collide with a synthetic mailbox either.
    if is_inbox(clean_new) || is_utility_folder(clean_new) {
        session.write(&format!("{tag} NO [ALREADYEXISTS] Target mailbox already exists\r\n"));
        return;
    }
    if exceeds_name_limit(clean_new) {
        session.write(&format!("{tag} NO [LIMIT] Mailbox name exceeds {MAILBOX_NAME_MAX_BYTES} bytes\r\n"));
        return;
    }
    match db_rename_mailbox(&user.id, clean_old, clean_new).await {
        Ok(RenameMailboxResult::NotFound) => {
            session.write(&format!("{tag} NO [NONEXISTENT] Mailbox does not exist\r\n"));
        }
        Ok(RenameMailboxResult::Protected) => {
            session.write(&format!("{tag} NO [CANNOT] Cannot rename system mailbox\r\n"));
        }
        Ok(RenameMailboxResult::NameTaken) => {
            session.write(&format!("{tag} NO [ALREADYEXISTS] Target mailbox already exists\r\n"));
        }
        Ok(RenameMailboxResult::Renamed) => {
            logger::info("Mailbox renamed", json!({ "component": "imap", "from": clean_old, "to": clean_new }));
            session.write(&format!("{tag} OK RENAME completed\r\n"));
        }
        Err(error) => {
            logger::error_with("Error renaming mailbox", json!({ "component": "imap" }), &error);
            session.write(&format!("{tag} NO RENAME failed\r\n"));
        }
    }
}

// ---------------------------------------------------------------------------
// SUBSCRIBE / UNSUBSCRIBE
// ---------------------------------------------------------------------------

pub async fn subscribe_mailbox(tag: &str, mailbox: &str, user: &SignedUser, session: &ImapSession) {
    let clean_name = strip_surrounding_quotes(mailbox);
    if let Err(error) = set_mailbox_subscribed(&user.id, clean_name, true).await {
        logger::error_with("Error subscribing mailbox", json!({ "component": "imap", "mailbox": clean_name }), &error);
    }
    // Completes either way.
    session.write(&format!("{tag} OK SUBSCRIBE completed\r\n"));
}

pub async fn unsubscribe_mailbox(tag: &str, mailbox: &str, user: &SignedUser, session: &ImapSession) {
    let clean_name = strip_surrounding_quotes(mailbox);
    if let Err(error) = set_mailbox_subscribed(&user.id, clean_name, false).await {
        logger::error_with(
            "Error unsubscribing mailbox",
            json!({ "component": "imap", "mailbox": clean_name }),
            &error,
        );
    }
    session.write(&format!("{tag} OK UNSUBSCRIBE completed\r\n"));
}

// ---------------------------------------------------------------------------
// STATUS
// ---------------------------------------------------------------------------

pub async fn status_mailbox(
    tag: &str,
    mailbox_arg: &str,
    items: &[StatusItem],
    user: &SignedUser,
    session: &ImapSession,
) {
    // RFC 3501 §5.1: INBOX is case-insensitive. Canonicalize so the answer
    // (`* STATUS "INBOX" ...`) names the mailbox the same way whatever
    // casing the client used.
    let mailbox = canonical_mailbox(mailbox_arg);
    status_from_store(tag, &mailbox, items, user, session).await;
}

/// STORE SEAM (STATUS). Needs from the store: `mailbox_exists(mailbox)`,
/// `count_messages(mailbox) -> Option<{total, unread}>`, `get_highest_modseq`,
/// `get_uid_next`, and `get_imap_uid_validity(user.id)` from the users
/// repository. Answers `NO Mailbox does not exist`, or `* STATUS "<mailbox>"
/// (<item> <value> ...)` and `OK STATUS completed`; any fault is `NO STATUS
/// failed`.
async fn status_from_store(
    tag: &str,
    _mailbox: &str,
    _items: &[StatusItem],
    _user: &SignedUser,
    session: &ImapSession,
) {
    session.write(&format!("{tag} NO STATUS failed\r\n"));
}

// ---------------------------------------------------------------------------
// LIST / LSUB
// ---------------------------------------------------------------------------

pub async fn list_mailboxes(tag: &str, reference: &str, pattern: &str, user: &SignedUser, session: &ImapSession) {
    // An empty pattern asks for the hierarchy delimiter and the root name of
    // the reference (RFC 3501 §6.3.8); no mailboxes are returned.
    if pattern.is_empty() {
        session.write(&format!("* LIST (\\Noselect) \"/\" {}\r\n", quote_string(reference)));
        session.write(&format!("{tag} OK LIST completed\r\n"));
        return;
    }
    list_from_store(tag, reference, pattern, user, session).await;
}

/// STORE SEAM (LIST). Needs from the store: `list_mailboxes() -> Vec<String>`
/// (every listable name, in listing order). Answers one `* LIST (<attributes>)
/// "/" "<name>"` per name the reference and pattern match, then `OK LIST
/// completed`; any fault is `NO LIST failed`.
async fn list_from_store(tag: &str, _reference: &str, _pattern: &str, _user: &SignedUser, session: &ImapSession) {
    session.write(&format!("{tag} NO LIST failed\r\n"));
}

pub async fn list_subscribed_mailboxes(
    tag: &str,
    reference: &str,
    pattern: &str,
    user: &SignedUser,
    session: &ImapSession,
) {
    if pattern.is_empty() {
        session.write(&format!("* LSUB (\\Noselect) \"/\" {}\r\n", quote_string(reference)));
        session.write(&format!("{tag} OK LSUB completed\r\n"));
        return;
    }
    lsub_from_store(tag, reference, pattern, user, session).await;
}

/// STORE SEAM (LSUB). Needs from the store: `list_mailbox_entries() ->
/// Vec<{name, subscribed}>`. Answers one `* LSUB (<attributes>) "/" "<name>"`
/// per subscribed name that matches (and, for a `%` pattern, per ancestor of
/// one), then `OK LSUB completed`; any fault is `NO LSUB failed`.
async fn lsub_from_store(tag: &str, _reference: &str, _pattern: &str, _user: &SignedUser, session: &ImapSession) {
    session.write(&format!("{tag} NO LSUB failed\r\n"));
}

// ---------------------------------------------------------------------------
// SELECT / EXAMINE
// ---------------------------------------------------------------------------

pub async fn select_mailbox(
    tag: &str,
    name: &str,
    read_only: bool,
    command: &str,
    user: &SignedUser,
    session: &ImapSession,
) {
    let unquoted = strip_surrounding_quotes(name);

    if unquoted.is_empty() {
        session.write(&format!("{tag} NO Empty mailbox name\r\n"));
        return;
    }

    // RFC 3501 §5.1: INBOX is case-insensitive. Canonicalize so the selected
    // mailbox kept on the session, and every later response, say "INBOX"
    // rather than whatever casing the client sent.
    let clean_name = canonical_mailbox(unquoted);

    if is_accounts_folder(&clean_name) {
        session.write(&format!("{tag} NO [CANNOT] {ACCOUNTS_FOLDER} is not selectable\r\n"));
        return;
    }

    if is_sent_messages_accounts_folder(&clean_name) {
        session.write(&format!("{tag} NO [CANNOT] {SENT_MESSAGES_ACCOUNTS_FOLDER} is not selectable\r\n"));
        return;
    }

    select_from_store(tag, &clean_name, read_only, command, user, session).await;
}

/// STORE SEAM (SELECT / EXAMINE). Needs from the store:
/// `mailbox_exists(mailbox)`, `get_all_uids(mailbox)` (the sequence
/// mapping), `count_messages`, `get_first_unseen_uid`, `get_uid_next`,
/// `get_highest_modseq`, and `get_imap_uid_validity(user.id)`.
///
/// On success it records the selection with `session.set_selected(Some(name),
/// total)`, fills `session.state().seq_state`, and writes the untagged block
/// and `OK [READ-WRITE|READ-ONLY] <command> completed`. RFC 3501 §6.3.1: a
/// failed SELECT leaves no mailbox selected, which is what every failure
/// exit here does before it answers — `NO Mailbox does not exist`, `NO
/// Failed to read mailbox`, or for a fault `NO SELECT failed`.
async fn select_from_store(
    tag: &str,
    _mailbox: &str,
    _read_only: bool,
    _command: &str,
    _user: &SignedUser,
    session: &ImapSession,
) {
    session.set_selected(None, 0);
    session.clear_seq_state();
    session.write(&format!("{tag} NO SELECT failed\r\n"));
}
