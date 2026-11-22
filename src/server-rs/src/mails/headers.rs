//! Mail list rows: the per-account list, the unified list, their pages and
//! deltas (mails/headers.ts).

use serde_json::{json, Map, Value};

use super::snippet::build_snippet;
use crate::js;
use crate::models::SignedUser;
use crate::postgres::repositories::mails::http::{
    self as repository, GetMailHeadersOptions, ListCursor, MailHeaderResult, UnifiedMailHeadersOptions,
};
use crate::postgres::DbResult;

/// Which per-account list to read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetMailsOptions {
    pub sent: bool,
    pub saved: bool,
    pub spam: bool,
}

/// What a delta answers: rows changed since, ids gone since, and when to ask from next.
#[derive(Debug, Clone, Default)]
pub struct MailHeadersDelta {
    pub as_of: String,
    pub headers: Vec<Value>,
    pub expunged_ids: Vec<String>,
}

impl MailHeadersDelta {
    /// `{as_of, headers, expunged_ids}`, the route's body.
    pub fn to_json(&self) -> Value {
        json!({ "as_of": self.as_of, "headers": self.headers, "expunged_ids": self.expunged_ids })
    }
}

/// The full list's page size (the unpaged list's `Pagination`).
const FULL_LIST_SIZE: i64 = 10_000;

fn column<'a>(row: &'a Map<String, Value>, key: &str) -> &'a Value {
    row.get(key).unwrap_or(&Value::Null)
}

/// `{ value: <column>, text: <text column> || "" }` when the address column
/// is truthy, as the list rows carry it.
fn address_field(row: &Map<String, Value>, address: &str, text: &str) -> Option<Value> {
    let value = column(row, address);
    if !js::is_truthy(value) {
        return None;
    }
    let text = match column(row, text) {
        Value::String(text) => text.clone(),
        _ => String::new(),
    };
    Some(json!({ "value": value, "text": text }))
}

fn insert_some(target: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        target.insert(key.to_string(), value);
    }
}

/// `if (!value) default`: the fallback `MailHeaderData` puts in place of a
/// falsy field.
fn bool_or_false(value: &Value) -> Value {
    if js::is_truthy(value) {
        value.clone()
    } else {
        Value::Bool(false)
    }
}

fn subject_of(row: &Map<String, Value>) -> Value {
    let subject = column(row, "subject");
    if js::is_truthy(subject) {
        subject.clone()
    } else {
        Value::String(String::new())
    }
}

fn date_of(row: &Map<String, Value>) -> Value {
    let date = column(row, "date");
    if js::is_truthy(date) {
        date.clone()
    } else {
        Value::String(js::now_iso())
    }
}

fn snippet_of(row: &Map<String, Value>) -> Option<Value> {
    build_snippet(column(row, "text_prefix").as_str()).map(Value::String)
}

/// The `envelopeTo` field: the stored envelope with an empty text.
fn envelope_to_of(row: &Map<String, Value>) -> Option<Value> {
    let value = column(row, "envelope_to");
    js::is_truthy(value).then(|| json!({ "value": value, "text": "" }))
}

/// `value?.length` read as a truthy number: a non-empty list or string.
fn has_length(value: &Value) -> bool {
    match value {
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        _ => false,
    }
}

/// A list row in the shape and key order the client reads:
/// `id, subject, date, from?, to?, cc?, bcc?, envelopeTo?, read, saved, sent,
/// insight, snippet?, messageId?, inReplyTo?, references?`.
pub fn to_mail_header_data(row: &MailHeaderResult) -> Map<String, Value> {
    let mut header = Map::new();
    header.insert("id".into(), column(row, "mail_id").clone());
    header.insert("subject".into(), subject_of(row));
    header.insert("date".into(), date_of(row));
    insert_some(&mut header, "from", address_field(row, "from_address", "from_text"));
    insert_some(&mut header, "to", address_field(row, "to_address", "to_text"));
    insert_some(&mut header, "cc", address_field(row, "cc_address", "cc_text"));
    insert_some(&mut header, "bcc", address_field(row, "bcc_address", "bcc_text"));
    insert_some(&mut header, "envelopeTo", envelope_to_of(row));
    header.insert("read".into(), bool_or_false(column(row, "read")));
    header.insert("saved".into(), bool_or_false(column(row, "saved")));
    header.insert("sent".into(), bool_or_false(column(row, "sent")));
    header.insert("insight".into(), column(row, "insight").clone());
    insert_some(&mut header, "snippet", snippet_of(row));
    let message_id = column(row, "message_id");
    if js::is_truthy(message_id) {
        header.insert("messageId".into(), message_id.clone());
    }
    let in_reply_to = column(row, "in_reply_to");
    if js::is_truthy(in_reply_to) {
        header.insert("inReplyTo".into(), in_reply_to.clone());
    }
    let references = column(row, "reference_ids");
    if has_length(references) {
        header.insert("references".into(), references.clone());
    }
    header
}

/// A search row: `id, subject, date, from?, to?, read, saved, sent, insight,
/// cc?, bcc?, envelopeTo?, highlight, snippet?, spam?`, with no thread ids.
pub fn to_search_header_data(row: &MailHeaderResult, highlight: &Map<String, Value>) -> Map<String, Value> {
    let mut header = Map::new();
    header.insert("id".into(), column(row, "mail_id").clone());
    header.insert("subject".into(), subject_of(row));
    header.insert("date".into(), date_of(row));
    insert_some(&mut header, "from", address_field(row, "from_address", "from_text"));
    insert_some(&mut header, "to", address_field(row, "to_address", "to_text"));
    header.insert("read".into(), bool_or_false(column(row, "read")));
    header.insert("saved".into(), bool_or_false(column(row, "saved")));
    header.insert("sent".into(), bool_or_false(column(row, "sent")));
    header.insert("insight".into(), column(row, "insight").clone());
    insert_some(&mut header, "cc", address_field(row, "cc_address", "cc_text"));
    insert_some(&mut header, "bcc", address_field(row, "bcc_address", "bcc_text"));
    insert_some(&mut header, "envelopeTo", envelope_to_of(row));
    header.insert("highlight".into(), Value::Object(highlight.clone()));
    insert_some(&mut header, "snippet", snippet_of(row));
    if js::is_truthy(column(row, "is_spam")) {
        header.insert("spam".into(), Value::Bool(true));
    }
    header
}

fn header_options(options: GetMailsOptions) -> GetMailHeadersOptions {
    GetMailHeadersOptions { sent: options.sent, saved: options.saved, spam: options.spam, ..Default::default() }
}

/// The ordered ids of a whole per-account list (newest first, at most 10000).
pub async fn get_mail_header_ids(user: &SignedUser, address: &str, options: GetMailsOptions) -> DbResult<Vec<String>> {
    let options = GetMailHeadersOptions { from: Some(0), size: Some(FULL_LIST_SIZE), ..header_options(options) };
    repository::get_mail_header_ids(&user.id, address, &options).await
}

/// One page of ids and where the next page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailHeaderPage {
    pub ids: Vec<String>,
    pub next: Option<ListCursor>,
}

/// Up to `limit` ids of the list, starting after `after` (or at the top).
pub async fn get_mail_header_page(
    user: &SignedUser,
    address: &str,
    options: GetMailsOptions,
    limit: usize,
    after: Option<ListCursor>,
) -> DbResult<MailHeaderPage> {
    let options = GetMailHeadersOptions { after, ..header_options(options) };
    let page = repository::get_mail_header_id_page(&user.id, address, &options, limit).await?;
    Ok(MailHeaderPage { ids: page.ids, next: page.next })
}

/// The unified list's [`get_mail_header_page`].
pub async fn get_unified_mail_header_page(
    user: &SignedUser,
    addresses: &[String],
    limit: usize,
    after: Option<ListCursor>,
) -> DbResult<MailHeaderPage> {
    let options = UnifiedMailHeadersOptions { after, ..Default::default() };
    let page = repository::get_unified_mail_header_id_page(&user.id, addresses, &options, limit).await?;
    Ok(MailHeaderPage { ids: page.ids, next: page.next })
}

/// The ordered ids of the whole unified list (unread first, at most 10000).
pub async fn get_unified_mail_header_ids(user: &SignedUser, addresses: &[String]) -> DbResult<Vec<String>> {
    let options = UnifiedMailHeadersOptions { from: Some(0), size: Some(FULL_LIST_SIZE), ..Default::default() };
    repository::get_unified_mail_header_ids(&user.id, addresses, &options).await
}

/// The rows of `ids` in that order, a batch at a time, each mapped to its
/// list row and handed to `sink`.
pub async fn for_each_mail_header(user: &SignedUser, ids: &[String], mut sink: impl FnMut(Map<String, Value>)) -> DbResult<()> {
    repository::get_mail_headers_by_ids(&user.id, ids, |rows| {
        for row in &rows {
            sink(to_mail_header_data(row));
        }
    })
    .await
}

pub async fn get_mail_headers_delta(
    user: &SignedUser,
    address: &str,
    options: GetMailsOptions,
    since: &str,
) -> MailHeadersDelta {
    let delta = repository::get_mail_headers_delta(&user.id, address, &header_options(options), since).await;
    MailHeadersDelta {
        as_of: delta.as_of,
        headers: delta.headers.iter().map(|row| Value::Object(to_mail_header_data(row))).collect(),
        expunged_ids: delta.expunged_ids,
    }
}

pub async fn get_unified_mail_headers_delta(user: &SignedUser, addresses: &[String], since: &str) -> MailHeadersDelta {
    let delta = repository::get_unified_mail_headers_delta(&user.id, addresses, since).await;
    MailHeadersDelta {
        as_of: delta.as_of,
        headers: delta.headers.iter().map(|row| Value::Object(to_mail_header_data(row))).collect(),
        expunged_ids: delta.expunged_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(value: Value) -> MailHeaderResult {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn a_list_row_keeps_the_client_key_order_and_drops_absent_fields() {
        let header = to_mail_header_data(&row(json!({
            "mail_id": "m", "user_id": "u", "subject": "Hi", "date": "2026-01-01T00:00:00.000Z",
            "from_address": [{ "name": "A", "address": "a@x.test" }], "from_text": null,
            "to_address": null, "to_text": "ignored",
            "cc_address": [], "cc_text": "c",
            "bcc_address": null, "bcc_text": null,
            "envelope_to": [{ "address": "me@x.test" }],
            "read": true, "saved": false, "sent": false, "is_spam": false, "insight": null,
            "text_prefix": "Hello there\n> quoted",
            "message_id": "<m@x>", "in_reply_to": null, "reference_ids": [],
        })));
        assert_eq!(
            serde_json::to_string(&header).unwrap(),
            r#"{"id":"m","subject":"Hi","date":"2026-01-01T00:00:00.000Z","from":{"value":[{"name":"A","address":"a@x.test"}],"text":""},"cc":{"value":[],"text":"c"},"envelopeTo":{"value":[{"address":"me@x.test"}],"text":""},"read":true,"saved":false,"sent":false,"insight":null,"snippet":"Hello there","messageId":"<m@x>"}"#
        );
    }

    #[test]
    fn a_null_subject_and_flags_take_their_defaults() {
        let header = to_mail_header_data(&row(json!({
            "mail_id": "m", "subject": null, "date": "d", "read": null, "saved": null, "sent": null,
            "insight": { "summary": ["s"] }, "text_prefix": "", "message_id": "",
            "in_reply_to": "<p@x>", "reference_ids": ["<a>", "<b>"],
        })));
        assert_eq!(
            serde_json::to_string(&header).unwrap(),
            r#"{"id":"m","subject":"","date":"d","read":false,"saved":false,"sent":false,"insight":{"summary":["s"]},"inReplyTo":"<p@x>","references":["<a>","<b>"]}"#
        );
    }

    #[test]
    fn a_search_row_has_its_own_order_and_labels_spam() {
        let mut highlight = Map::new();
        highlight.insert("subject".into(), json!(["<em>Hi</em>"]));
        let header = to_search_header_data(
            &row(json!({
                "mail_id": "m", "subject": "Hi", "date": "d",
                "from_address": [{ "address": "a@x" }], "from_text": "a@x",
                "cc_address": [{ "address": "c@x" }], "cc_text": "c@x",
                "read": false, "saved": true, "sent": false, "is_spam": true, "insight": null,
                "text_prefix": "Body", "message_id": "<m@x>",
            })),
            &highlight,
        );
        let keys: Vec<&str> = header.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["id", "subject", "date", "from", "read", "saved", "sent", "insight", "cc", "highlight", "snippet", "spam"]
        );
    }
}
