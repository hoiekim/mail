//! Message operations (imap/message-ops.ts): FETCH, SEARCH, STORE, COPY,
//! MOVE, APPEND and EXPUNGE.
//!
//! Every one of these reads or writes through the IMAP store, which is not
//! ported yet. What each command answers before it touches the store is
//! here; the rest of each is one function marked `STORE SEAM` that answers
//! the command's own failure line for now.

use anyhow::Result;

use super::sequence_resolver::MailboxUids;
use super::session::ImapSession;
use super::types::{AppendRequest, CopyRequest, FetchRequest, MoveRequest, SearchCriterion, SearchRequest, StoreRequest};
use super::util::canonical_mailbox;
use crate::models::SignedUser;

// ---------------------------------------------------------------------------
// What IDLE notifications read
// ---------------------------------------------------------------------------

/// The flags of one mail in a mailbox's view, as a flag notification
/// reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFlagUpdate {
    pub uid: i64,
    pub read: bool,
    pub saved: bool,
    pub deleted: bool,
    pub draft: bool,
    pub answered: bool,
}

impl MailFlagUpdate {
    /// The system flags that are set, in the order every FLAGS list uses.
    pub fn flags(&self) -> Vec<&'static str> {
        [
            (self.read, "\\Seen"),
            (self.saved, "\\Flagged"),
            (self.deleted, "\\Deleted"),
            (self.draft, "\\Draft"),
            (self.answered, "\\Answered"),
        ]
        .into_iter()
        .filter_map(|(set, flag)| set.then_some(flag))
        .collect()
    }
}

/// STORE SEAM (sequence mapping). The UIDs of the session's selected
/// mailbox in ascending order: `store.get_all_uids(selected_mailbox)`.
/// `NotSelected` without a store or a selected mailbox, `Unreadable` when
/// the read failed. Used wherever the mapping is rebuilt: an IDLE
/// notification, and after EXPUNGE, MOVE and APPEND into the selected
/// mailbox.
pub async fn read_selected_mailbox_uids(session: &ImapSession) -> MailboxUids {
    let state = session.state();
    if state.user.is_none() || state.selected_mailbox.is_none() {
        return MailboxUids::NotSelected;
    }
    MailboxUids::Unreadable
}

/// STORE SEAM (flag notifications). The current flags of `mail_ids` as the
/// selected mailbox sees them: `store.get_mail_flag_updates(mailbox,
/// mail_ids)`. `None` when the mailbox could not be read.
pub async fn read_mail_flag_updates(
    _session: &ImapSession,
    _selected_mailbox: &str,
    _mail_ids: &[String],
) -> Result<Option<Vec<MailFlagUpdate>>> {
    Ok(None)
}

// ---------------------------------------------------------------------------
// FETCH
// ---------------------------------------------------------------------------

/// STORE SEAM (FETCH). Needs from the store: `get_messages(mailbox,
/// uid_start, uid_end, fields, use_uid, changed_since)`, and `mark_read`
/// from the mail repository unless `suppress_read_mark`. The per-command cap
/// (`count_sequence_set_messages` / `clamp_sequence_set_to_first`: 500 for a
/// header-only fetch, 50 for anything with a body, none for row metadata)
/// is applied first. Writes one `* n FETCH (...)` per message through
/// `session.write`, `write_chunked` and `write_stream`, then `OK FETCH
/// completed`; a fault is `NO FETCH failed`.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_messages_typed(
    tag: &str,
    _fetch_request: &FetchRequest,
    _is_uid_command: bool,
    _user: &SignedUser,
    _selected_mailbox: &str,
    session: &ImapSession,
    _condstore_enabled: bool,
    // Suppresses the automatic \Seen of a body fetch for a read-only
    // session, so reading a message never changes a flag another client is
    // looking at.
    _suppress_read_mark: bool,
) {
    session.write(&format!("{tag} NO FETCH failed\r\n"));
}

// ---------------------------------------------------------------------------
// SEARCH
// ---------------------------------------------------------------------------

pub async fn search_typed(
    tag: &str,
    search_request: &SearchRequest,
    is_uid_command: bool,
    user: &SignedUser,
    selected_mailbox: &str,
    session: &ImapSession,
) {
    if search_request.criteria.is_empty() {
        session.write(&format!("{tag} BAD Search criteria is required\r\n"));
        return;
    }

    // The explicit `UID <set>` key is only valid under the UID command; a
    // bare sequence set is valid in both.
    let has_uid_criteria = search_request.criteria.iter().any(|criterion| matches!(criterion, SearchCriterion::Uid(_)));
    if !is_uid_command && has_uid_criteria {
        session.write(&format!("{tag} NO Not supported\r\n"));
        return;
    }

    search_in_store(tag, search_request, is_uid_command, user, selected_mailbox, session).await;
}

/// STORE SEAM (SEARCH). Needs from the store: `search(mailbox, criteria) ->
/// Vec<uid>`, after the sequence-set keys are resolved against
/// `session.state().seq_state`. Answers `* SEARCH <numbers>` (UIDs, or
/// sequence numbers for a plain SEARCH) and `OK SEARCH completed`; a fault
/// is `NO SEARCH failed`.
async fn search_in_store(
    tag: &str,
    _search_request: &SearchRequest,
    _is_uid_command: bool,
    _user: &SignedUser,
    _selected_mailbox: &str,
    session: &ImapSession,
) {
    session.write(&format!("{tag} NO SEARCH failed\r\n"));
}

// ---------------------------------------------------------------------------
// STORE
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn store_flags_typed(
    tag: &str,
    store_request: &StoreRequest,
    is_uid_command: bool,
    user: &SignedUser,
    selected_mailbox: &str,
    mailbox_read_only: bool,
    session: &ImapSession,
    condstore_enabled: bool,
) {
    if mailbox_read_only {
        session.write(&format!("{tag} NO [READ-ONLY] Mailbox is read-only\r\n"));
        return;
    }
    store_flags_in_store(tag, store_request, is_uid_command, user, selected_mailbox, session, condstore_enabled).await;
}

/// STORE SEAM (STORE). Needs from the store: `set_flags(mailbox, uid_start,
/// uid_end, flags, use_uid, operation, unchanged_since) -> {updated,
/// failed}`, and `sync_mailbox_pivot` from the mail repository for `Starred`
/// and `Trash`. Answers `* n FETCH (FLAGS (...)[ MODSEQ (m)])` per changed
/// message unless silent, then `OK STORE completed` or `OK [MODIFIED <set>]
/// Conditional STORE failed`; a fault is `NO STORE failed`.
async fn store_flags_in_store(
    tag: &str,
    _store_request: &StoreRequest,
    _is_uid_command: bool,
    _user: &SignedUser,
    _selected_mailbox: &str,
    session: &ImapSession,
    _condstore_enabled: bool,
) {
    session.write(&format!("{tag} NO STORE failed\r\n"));
}

// ---------------------------------------------------------------------------
// COPY
// ---------------------------------------------------------------------------

/// STORE SEAM (COPY). Needs from the store: `mailbox_exists(destination)`,
/// `get_messages` for the source rows, `store_mail(mail, destination)`, the
/// UID counters (`get_domain_uid_next`, `get_account_uid_next`,
/// `get_mailbox_uid_next`) and `get_imap_uid_validity`. Answers `NO
/// [TRYCREATE] Mailbox does not exist`, `OK COPY completed` when nothing
/// matched, or `OK [COPYUID <validity> <source-set> <destination-set>] COPY
/// completed`; a fault is `NO COPY failed`.
pub async fn copy_message_typed(
    tag: &str,
    _copy_request: &CopyRequest,
    _is_uid_command: bool,
    _user: &SignedUser,
    _selected_mailbox: &str,
    session: &ImapSession,
) {
    session.write(&format!("{tag} NO COPY failed\r\n"));
}

// ---------------------------------------------------------------------------
// MOVE (RFC 6851)
// ---------------------------------------------------------------------------

pub async fn move_message_typed(
    tag: &str,
    move_request: &MoveRequest,
    is_uid_command: bool,
    user: &SignedUser,
    selected_mailbox: &str,
    mailbox_read_only: bool,
    session: &ImapSession,
) {
    if mailbox_read_only {
        session.write(&format!("{tag} NO [READ-ONLY] Mailbox is read-only\r\n"));
        return;
    }

    let dest_mailbox = canonical_mailbox(&move_request.mailbox);

    // RFC 6851 §3.4-§3.5: MOVE to the selected mailbox is a no-op, since the
    // messages are already where they would land. A bare OK: the same end
    // state with no UID churn and no surprise EXPUNGE.
    if dest_mailbox == selected_mailbox {
        session.write(&format!("{tag} OK MOVE completed\r\n"));
        return;
    }

    move_in_store(tag, move_request, &dest_mailbox, is_uid_command, user, selected_mailbox, session).await;
}

/// STORE SEAM (MOVE). The copy phase of COPY, then
/// `store.expunge_uids(selected_mailbox, source_uids)` and the sequence
/// mapping rebuilt (`read_selected_mailbox_uids` with
/// `reconcile_sequence_mapping`, which writes the `* n EXPUNGE` lines).
/// Answers as COPY does, with `MOVE` in place of `COPY`; a fault is `NO
/// MOVE failed`.
async fn move_in_store(
    tag: &str,
    _move_request: &MoveRequest,
    _dest_mailbox: &str,
    _is_uid_command: bool,
    _user: &SignedUser,
    _selected_mailbox: &str,
    session: &ImapSession,
) {
    session.write(&format!("{tag} NO MOVE failed\r\n"));
}

// ---------------------------------------------------------------------------
// APPEND
// ---------------------------------------------------------------------------

/// STORE SEAM (APPEND). `append_request.message` is the spooled literal: a
/// file the connection removes once this returns. Needs from the store:
/// `mailbox_exists(target)` and `store_mail(mail, target)`; the MIME parser
/// and the receive path's conversions to build the mail; the UID counters
/// and `get_imap_uid_validity`. When the target is the selected mailbox the
/// sequence mapping is rebuilt after storing. Answers `NO [TRYCREATE]
/// Mailbox does not exist`, `OK [APPENDUID <validity> <uid>] APPEND
/// completed` or `NO APPEND failed to store message`; a fault is `NO APPEND
/// failed`.
pub async fn append_message(
    tag: &str,
    _append_request: &AppendRequest,
    _user: &SignedUser,
    _selected_mailbox: Option<&str>,
    session: &ImapSession,
) {
    session.write(&format!("{tag} NO APPEND failed\r\n"));
}

// ---------------------------------------------------------------------------
// EXPUNGE
// ---------------------------------------------------------------------------

pub async fn expunge(
    tag: &str,
    user: &SignedUser,
    selected_mailbox: &str,
    mailbox_read_only: bool,
    session: &ImapSession,
) {
    if mailbox_read_only {
        session.write(&format!("{tag} NO [READ-ONLY] Mailbox is read-only\r\n"));
        return;
    }
    expunge_in_store(tag, user, selected_mailbox, session).await;
}

/// STORE SEAM (EXPUNGE). Needs from the store: `expunge(mailbox)`, then the
/// sequence mapping rebuilt, which writes the `* n EXPUNGE` lines. Answers
/// `OK EXPUNGE completed`; a fault is `NO EXPUNGE failed`.
async fn expunge_in_store(tag: &str, _user: &SignedUser, _selected_mailbox: &str, session: &ImapSession) {
    session.write(&format!("{tag} NO EXPUNGE failed\r\n"));
}
