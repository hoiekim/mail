//! Tests of the connection driver: handler-literal, handler-literal-cap,
//! handler-literal-chain-pacing, handler-append-spool, handler-throttle,
//! handler-serial-drain, handler-idle, handler-socket-error,
//! handler-command-diag, starttls-pipelining and session-close-flush.
//!
//! A connection runs over an in-memory duplex stream, with a dispatch that
//! records each parsed command instead of (or before) running it. What the
//! Bun fixtures read off a mock socket's `writes` is read here off the
//! client end of the stream.
//!
//! Where the Bun handler pauses its socket, this one stops reading: a fixture
//! sees that as the client's writes no longer being taken, so those tests
//! run over a small stream and watch how much a background writer got in.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::sync::{Notify, RwLockReadGuard};
use tokio::task::JoinHandle;

use super::*;
use crate::imap::literal_spool::{spool_dirs, spool_test_lock};
use crate::imap::test_support;
use crate::imap::types::{AppendRequest, LoginRequest, SearchCriterion, SearchRequest, SelectRequest};

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

static JOURNAL: Mutex<Vec<(String, String, Value)>> = Mutex::new(Vec::new());

/// Called by the handler's log helpers.
pub(super) fn journal(level: &str, message: &str, context: &Value) {
    JOURNAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push((
        level.to_string(),
        message.to_string(),
        context.clone(),
    ));
}

/// Everything journaled so far, as one text to search. Tests run side by
/// side, so each one looks for markers only it uses.
fn journal_text() -> String {
    let entries = JOURNAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.iter().map(|(level, message, context)| format!("{level} {message} {context}\n")).collect()
}

/// The journal entries of one connection, by the `remote` they name.
fn journal_of(remote: &str) -> Vec<(String, String, Value)> {
    let entries = JOURNAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.iter().filter(|(_, _, context)| context.get("remote").and_then(Value::as_str) == Some(remote)).cloned().collect()
}

/// The raw wire text the DEBUG lines carry (`input` of a parse failure,
/// `command` of a received command) that contains `marker`.
fn journaled_wire_text(marker: &str) -> Vec<String> {
    let entries = JOURNAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    entries
        .iter()
        .filter(|(level, _, _)| level == "debug")
        .flat_map(|(_, _, context)| {
            ["input", "command"].into_iter().filter_map(|field| context.get(field).and_then(Value::as_str).map(str::to_string))
        })
        .filter(|text| text.contains(marker))
        .collect()
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Recorded {
    tag: String,
    request: ImapRequest,
    /// The spooled APPEND message, read while the command is dispatched.
    message: Option<Vec<u8>>,
}

impl Recorded {
    fn message_text(&self) -> String {
        String::from_utf8_lossy(self.message.as_deref().expect("an APPEND message")).into_owned()
    }

    fn append(&self) -> &AppendRequest {
        match &self.request {
            ImapRequest::Append(append) => append,
            other => panic!("expected APPEND, got {other:?}"),
        }
    }
}

type Hook = Arc<dyn Fn(Arc<ImapSession>, String, ImapRequest) -> BoxFuture<'static, ()> + Send + Sync>;

/// Records every dispatched command; `real` also runs it on the session, and
/// `hook` stands in for the session (it runs after the recording, with the
/// spooled file still in place).
#[derive(Clone, Default)]
struct Recorder {
    dispatched: Arc<Mutex<Vec<Recorded>>>,
    real: bool,
    hook: Option<Hook>,
}

impl Recorder {
    fn real() -> Recorder {
        Recorder { real: true, ..Recorder::default() }
    }

    fn with_hook(
        hook: impl Fn(Arc<ImapSession>, String, ImapRequest) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> Recorder {
        Recorder { hook: Some(Arc::new(hook)), ..Recorder::default() }
    }
}

impl Dispatch for Recorder {
    async fn handle_request(&mut self, session: &Arc<ImapSession>, tag: &str, request: ImapRequest) {
        let message = match &request {
            ImapRequest::Append(append) => std::fs::read(&append.message.path).ok(),
            _ => None,
        };
        self.dispatched.lock().unwrap().push(Recorded { tag: tag.to_string(), request: request.clone(), message });
        if self.real {
            handle_request(session, tag, request.clone()).await;
        }
        if let Some(hook) = self.hook.clone() {
            hook(session.clone(), tag.to_string(), request).await;
        }
    }
}

/// A hook that parks the first command until released.
fn parking_hook() -> (Recorder, Arc<Notify>) {
    let release = Arc::new(Notify::new());
    let parked = Arc::new(AtomicBool::new(false));
    let recorder = Recorder::with_hook({
        let release = release.clone();
        move |_, _, _| {
            let release = release.clone();
            let first = !parked.swap(true, Ordering::SeqCst);
            Box::pin(async move {
                if first {
                    release.notified().await;
                }
            })
        }
    });
    (recorder, release)
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(20_000);

#[derive(Default)]
struct Setup {
    authenticated: bool,
    selected: Option<&'static str>,
    /// Octets the stream holds in each direction; small to see a stop.
    capacity: Option<usize>,
    /// Opened by a test that holds the process-wide lock exclusively.
    unlocked: bool,
}

/// One connection, seen from the client.
struct Wire {
    writer: Arc<tokio::sync::Mutex<WriteHalf<DuplexStream>>>,
    received: Arc<Mutex<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    greeting: usize,
    dispatched: Arc<Mutex<Vec<Recorded>>>,
    session: Arc<ImapSession>,
    remote: String,
    _shared: Option<RwLockReadGuard<'static, ()>>,
}

/// A writer that keeps sending in the background, counting what was taken.
struct Flood {
    written: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Flood {
    fn written(&self) -> usize {
        self.written.load(Ordering::SeqCst)
    }

    fn is_done(&self) -> bool {
        self.task.is_finished()
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(60)).await;
}

async fn tick() {
    tokio::time::sleep(Duration::from_millis(2)).await;
}

/// Polls `condition` until it holds or `timeout` ran out.
async fn wait_for(timeout: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

impl Wire {
    async fn open(recorder: Recorder) -> Wire {
        Wire::open_with(recorder, Setup::default()).await
    }

    async fn open_authenticated(recorder: Recorder) -> Wire {
        Wire::open_with(recorder, Setup { authenticated: true, ..Setup::default() }).await
    }

    async fn open_with(recorder: Recorder, setup: Setup) -> Wire {
        let shared = if setup.unlocked { None } else { Some(test_support::shared().await) };
        let (server, client) = tokio::io::duplex(setup.capacity.unwrap_or(4 << 20));
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let peer = Peer { address: "203.0.113.7".into(), port };
        let dispatched = recorder.dispatched.clone();
        let handler = ImapRequestHandler::with_dispatch(Box::new(server), peer, false, recorder);
        let session = handler.session().clone();
        if setup.authenticated {
            session.sign_in_for_test("tester", setup.selected);
        }
        tokio::spawn(handler.run());

        let (mut reader, writer) = tokio::io::split(client);
        let received = Arc::new(Mutex::new(Vec::new()));
        let closed = Arc::new(AtomicBool::new(false));
        tokio::spawn({
            let (received, closed) = (received.clone(), closed.clone());
            async move {
                let mut chunk = vec![0u8; 64 * 1024];
                loop {
                    match reader.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => received.lock().unwrap().extend_from_slice(&chunk[..read]),
                    }
                }
                closed.store(true, Ordering::SeqCst);
            }
        });

        let greeted = wait_for(Duration::from_secs(5), || received.lock().unwrap().windows(2).any(|w| w == b"\r\n")).await;
        assert!(greeted, "the server greets");
        let greeting = received.lock().unwrap().windows(2).position(|w| w == b"\r\n").unwrap() + 2;
        assert!(String::from_utf8_lossy(&received.lock().unwrap()[..greeting]).starts_with("* OK [CAPABILITY "));

        Wire {
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
            received,
            closed,
            greeting,
            dispatched,
            session,
            remote: format!("203.0.113.7:{port}"),
            _shared: shared,
        }
    }

    async fn send(&self, data: impl AsRef<[u8]>) {
        self.writer.lock().await.write_all(data.as_ref()).await.expect("the server reads");
    }

    /// Sends each piece in its own write, with a turn of the clock between.
    async fn send_pieces(&self, pieces: &[&[u8]]) {
        for piece in pieces {
            self.send(piece).await;
            tick().await;
        }
    }

    /// Keeps writing `chunks` in the background.
    fn flood(&self, chunks: Vec<Vec<u8>>) -> Flood {
        let written = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let (writer, written) = (self.writer.clone(), written.clone());
            async move {
                for chunk in chunks {
                    if writer.lock().await.write_all(&chunk).await.is_err() {
                        return;
                    }
                    written.fetch_add(chunk.len(), Ordering::SeqCst);
                }
            }
        });
        Flood { written, task }
    }

    /// The client closes its side.
    async fn hang_up(&self) {
        let _ = self.writer.lock().await.shutdown().await;
    }

    /// Everything the server wrote after its greeting.
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()[self.greeting..]).into_owned()
    }

    fn output_bytes(&self) -> Vec<u8> {
        self.received.lock().unwrap()[self.greeting..].to_vec()
    }

    /// The server's lines after its greeting.
    fn lines(&self) -> Vec<String> {
        self.output().split_inclusive("\r\n").map(str::to_string).collect()
    }

    fn dispatched(&self) -> Vec<Recorded> {
        self.dispatched.lock().unwrap().clone()
    }

    fn tags(&self) -> Vec<String> {
        self.dispatched().into_iter().map(|recorded| recorded.tag).collect()
    }

    /// The server ended the connection: the client read the end of it.
    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn wait_for_dispatches(&self, count: usize) {
        let dispatched = self.dispatched.clone();
        assert!(
            wait_for(Duration::from_secs(10), || dispatched.lock().unwrap().len() >= count).await,
            "{count} dispatches, got {:?}",
            self.tags()
        );
    }

    async fn wait_for_output(&self, text: &str) {
        let received = self.received.clone();
        let text = text.to_string();
        assert!(
            wait_for(Duration::from_secs(10), || String::from_utf8_lossy(&received.lock().unwrap()).contains(&text)).await,
            "waiting for {text:?}, got {:?}",
            self.output()
        );
    }

    async fn wait_for_close(&self) {
        let closed = self.closed.clone();
        assert!(wait_for(Duration::from_secs(10), || closed.load(Ordering::SeqCst)).await, "the server closes");
    }
}

fn login(username: &str, password: &str) -> ImapRequest {
    ImapRequest::Login(LoginRequest { username: username.into(), password: password.into() })
}

fn subject_from(subject: &str, from: &str) -> ImapRequest {
    ImapRequest::Search(SearchRequest {
        criteria: vec![SearchCriterion::Subject(subject.into()), SearchCriterion::From(from.into())],
    })
}

/// The spool directories created since `before`.
fn new_spool_dirs(before: &[String]) -> Vec<String> {
    spool_dirs().into_iter().filter(|dir| !before.contains(dir)).collect()
}

/// Waits for the spool directories created since `before` to be gone.
async fn assert_spool_cleaned(before: &[String]) {
    let before = before.to_vec();
    let cleaned = wait_for(Duration::from_secs(5), || new_spool_dirs(&before).is_empty()).await;
    assert!(cleaned, "spool directories left behind: {:?}", new_spool_dirs(&before));
}

// Mirrors the constants in handler.rs. Re-stated rather than imported: a test
// that reads the symbol it checks cannot catch a cap being widened.
const SMALL_CAP: usize = 8 * 1024;
const APPEND_CAP: usize = 35 * 1024 * 1024;
const UNCONSUMED_CAP: usize = 64 * 1024;
const CHAIN_CAP: usize = 64;
const PENDING_CAP: usize = APPEND_CAP + 64 * 1024;
// Mirrors the line cap in trace.rs.
const TRACE_LINE_CAP: usize = 512;
const TAG_CAP: usize = 128;

// ---------------------------------------------------------------------------
// Literal continuation (handler-literal.test.ts)
// ---------------------------------------------------------------------------

mod literal_continuation {
    use super::*;

    #[tokio::test]
    async fn reassembles_a_literal_plus_login_instead_of_parsing_its_credentials_as_commands() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 LOGIN {5+}\r\nadmin {8+}\r\npassword\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].tag, "A1");
        assert_eq!(dispatched[0].request, login("admin", "password"));
        // A non-synchronizing literal needs no continuation, and nothing about
        // this command is an error: the wire stays silent.
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn prompts_once_per_synchronizing_literal_and_still_reassembles() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 LOGIN {5}\r\n").await;
        settle().await;
        assert_eq!(wire.output(), "+ go ahead\r\n");

        wire.send("admin {8}\r\n").await;
        settle().await;
        assert_eq!(wire.output(), "+ go ahead\r\n+ go ahead\r\n");

        wire.send("password\r\n").await;
        settle().await;
        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin", "password"));
    }

    #[tokio::test]
    async fn reassembles_across_arbitrary_tcp_segmentation() {
        let wire = Wire::open(Recorder::default()).await;
        for octet in b"A1 LOGIN {5+}\r\nadmin {8+}\r\npassword\r\n" {
            wire.send([*octet]).await;
            tick().await;
        }
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin", "password"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn keeps_octets_a_quoted_string_could_not_carry() {
        let wire = Wire::open(Recorder::default()).await;
        // 12 octets: quotes, a backslash, a brace, a space.
        wire.send("A1 LOGIN {5+}\r\nadmin {12+}\r\np@ss \"w\\d {}\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin", "p@ss \"w\\d {}"));
    }

    #[tokio::test]
    async fn answers_an_unparseable_literal_command_on_its_own_tag_never_on_the_payload() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 FOOBAR {5+}\r\nadmin\r\n").await;
        settle().await;

        assert!(wire.dispatched().is_empty());
        assert_eq!(wire.output(), "A1 BAD Unknown command: FOOBAR\r\n");
    }

    #[tokio::test]
    async fn still_reassembles_an_append_literal() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        wire.send("a1 APPEND INBOX (\\Seen) {11}\r\n").await;
        settle().await;
        assert_eq!(wire.output(), "+ go ahead\r\n");

        wire.send("Hello World\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].tag, "a1");
        assert_eq!(dispatched[0].append().mailbox, "INBOX");
        assert_eq!(dispatched[0].message_text(), "Hello World");
    }

    #[tokio::test]
    async fn counts_a_literal_in_octets_not_utf16_code_units() {
        let wire = Wire::open(Recorder::default()).await;
        // "pässword" is 8 code units and 9 octets. A code-unit count takes 8
        // characters, the password loses its last letter and swallows the
        // CR, and the pipelined A2 is never answered.
        let payload = "pässword".as_bytes();
        assert_eq!(payload.len(), 9);
        wire.send([b"A1 LOGIN {5+}\r\nadmin {9+}\r\n".as_slice(), payload, b"\r\nA2 NOOP\r\n"].concat()).await;
        settle().await;

        assert_eq!(wire.tags(), ["A1", "A2"]);
        assert_eq!(wire.dispatched()[0].request, login("admin", "pässword"));
    }

    #[tokio::test]
    async fn reassembles_a_multi_byte_character_split_across_tcp_segments() {
        let wire = Wire::open(Recorder::default()).await;
        let payload = "café".as_bytes(); // 5 octets, 4 code units
        wire.send_pieces(&[b"A1 SELECT {5+}\r\n", &payload[..4], &[payload[4], b'\r', b'\n']]).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, ImapRequest::Select(SelectRequest { mailbox: "café".into() }));
    }

    #[tokio::test]
    async fn carries_an_append_payload_through_byte_for_byte_trailing_crlf_included() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        let message = "Subject: x\r\n\r\nbody\r\n";
        wire.send(format!("a1 APPEND INBOX {{{}+}}\r\n", message.len())).await;
        tick().await;
        wire.send(format!("{message}\r\n")).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].message_text(), message);
    }

    #[tokio::test]
    async fn dispatches_when_the_payload_consumed_its_own_terminator_instead_of_wedging() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        // The client counted the CRLF into {N} and sent nothing after it.
        wire.send("a1 APPEND INBOX {13+}\r\nHello World\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].message_text(), "Hello World\r\n");
    }

    #[tokio::test]
    async fn accepts_a_zero_length_literal() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        wire.send("a1 APPEND INBOX {0+}\r\n\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].message_text(), "");
    }

    #[tokio::test]
    async fn does_not_read_a_trailing_brace_number_inside_an_argument_as_a_literal_declaration() {
        let wire = Wire::open(Recorder::default()).await;
        // `p@ss{5}` is a password that happens to end in brace-digits.
        wire.send("A1 LOGIN admin p@ss{5}\r\nA2 NOOP\r\n").await;
        settle().await;

        assert_eq!(wire.tags(), ["A1", "A2"]);
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn waits_for_the_rest_of_the_line_when_a_non_final_payload_is_flushed_on_its_own() {
        let wire = Wire::open(Recorder::default()).await;
        // An empty buffer means "nothing more has arrived YET": `admin` is not
        // the last argument, so the tail is still in flight.
        wire.send_pieces(&[b"A1 LOGIN {5+}\r\n", b"admin"]).await;
        settle().await;
        assert!(wire.dispatched().is_empty());
        wire.send(" \"hunter2\"\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin", "hunter2"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn reassembles_two_literals_when_the_first_payload_is_flushed_on_its_own() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 LOGIN {5+}\r\n", b"admin", b" {8+}\r\n", b"password\r\n"]).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin", "password"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn emits_exactly_one_continuation_per_synchronizing_declaration() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 LOGIN {5}\r\n", b"admin", b" {8}\r\n", b"password\r\n"]).await;
        settle().await;

        assert_eq!(wire.output(), "+ go ahead\r\n+ go ahead\r\n");
        assert_eq!(wire.tags(), ["A1"]);
    }

    #[tokio::test]
    async fn reassembles_a_two_literal_rename_whose_first_payload_is_flushed_on_its_own() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 RENAME {5+}\r\n", b"Oldie", b" {5+}\r\n", b"Newie\r\n"]).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, ImapRequest::Rename { old_name: "Oldie".into(), new_name: "Newie".into() });
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn keeps_a_final_append_payload_dispatching_when_its_trailing_crlf_arrives_separately() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        let message = "Subject: x\r\n\r\nbody";
        let header = format!("a1 APPEND INBOX {{{}+}}\r\n", message.len());
        wire.send_pieces(&[header.as_bytes(), message.as_bytes(), b"\r\n"]).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].message_text(), message);
    }

    #[tokio::test]
    async fn waits_for_the_tail_when_a_non_final_payloads_own_octets_end_in_crlf() {
        let wire = Wire::open(Recorder::default()).await;
        // A literal carries octets a quoted string cannot, CRLF included, so a
        // payload ending in CRLF says nothing about whether the command is
        // over. The parser does: `A1 LOGIN {7+}` + ["admin\r\n"] does not parse.
        wire.send_pieces(&[b"A1 LOGIN {7+}\r\n", b"admin\r\n"]).await;
        settle().await;
        assert!(wire.dispatched().is_empty());
        wire.send(" \"hunter2-crlf-tail\"\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, login("admin\r\n", "hunter2-crlf-tail"));
        assert_eq!(wire.output(), "");
        assert!(!journal_text().contains("hunter2-crlf-tail"));
    }

    #[tokio::test]
    async fn emits_no_extra_continuation_for_a_crlf_ending_payload_in_the_synchronizing_form() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 LOGIN {7}\r\n", b"admin\r\n", b" {8}\r\n", b"password\r\n"]).await;
        settle().await;

        assert_eq!(wire.output(), "+ go ahead\r\n+ go ahead\r\n");
        assert_eq!(wire.tags(), ["A1"]);
    }

    #[tokio::test]
    async fn waits_for_the_tail_of_a_rename_whose_first_payload_ends_in_crlf() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 RENAME {7+}\r\n", b"Oldie\r\n", b" {5+}\r\n", b"Newie\r\n"]).await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].request, ImapRequest::Rename { old_name: "Oldie\r\n".into(), new_name: "Newie".into() });
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn answers_a_command_pipelined_behind_a_payload_that_consumed_its_own_terminator() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        // RFC 3501 §7 requires a tagged completion for every command.
        wire.send("a1 APPEND INBOX {13+}\r\nHello World\r\na2 NOOP\r\n").await;
        settle().await;

        let dispatched = wire.dispatched();
        assert_eq!(wire.tags(), ["a1", "a2"]);
        assert_eq!(dispatched[0].message_text(), "Hello World\r\n");
        assert_eq!(dispatched[1].request, ImapRequest::Noop);
    }

    #[tokio::test]
    async fn answers_a_literal_declaring_command_pipelined_behind_a_self_terminated_payload() {
        let _spool = spool_test_lock().await;
        let wire = Wire::open(Recorder::default()).await;
        wire.send("a1 APPEND INBOX {13+}\r\nHello World\r\na2 SELECT {5+}\r\nINBOX\r\n").await;
        settle().await;

        assert_eq!(wire.tags(), ["a1", "a2"]);
        assert_eq!(wire.dispatched()[1].request, ImapRequest::Select(SelectRequest { mailbox: "INBOX".into() }));
    }

    #[tokio::test]
    async fn still_chains_a_separated_literal_onto_a_command_that_already_parses() {
        let wire = Wire::open(Recorder::default()).await;
        // `SEARCH SUBJECT {3+}` + ["foo"] is complete on its own; the
        // separating SP is what marks the tail as its continuation.
        wire.send("A1 SEARCH SUBJECT {3+}\r\nfoo FROM {3+}\r\nbar\r\n").await;
        settle().await;

        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.dispatched()[0].request, subject_from("foo", "bar"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn still_chains_a_separated_literal_when_the_first_payload_arrives_alone() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 SEARCH SUBJECT {3+}\r\nfoo", b" FROM {3+}\r\nbar\r\n"]).await;
        settle().await;

        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.dispatched()[0].request, subject_from("foo", "bar"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn draws_one_continuation_per_declaration_for_a_chained_search_flushed_alone() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 SEARCH SUBJECT {3}\r\n", b"foo", b" FROM {3}\r\n", b"bar\r\n"]).await;
        settle().await;

        assert_eq!(wire.output(), "+ go ahead\r\n+ go ahead\r\n");
        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.dispatched()[0].request, subject_from("foo", "bar"));
    }

    #[tokio::test]
    async fn chains_a_separated_literal_onto_a_search_whose_payload_spans_two_segments() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 SEARCH SUBJECT {6+}\r\nfoo", b"bar", b" FROM {3+}\r\nbaz\r\n"]).await;
        settle().await;

        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.dispatched()[0].request, subject_from("foobar", "baz"));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn chains_through_the_uid_wrapper_when_the_payload_arrives_alone() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send_pieces(&[b"A1 UID SEARCH SUBJECT {3+}\r\nfoo", b" FROM {3+}\r\nbar\r\n"]).await;
        settle().await;

        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.dispatched()[0].request, ImapRequest::Uid(UidRequest::new("SEARCH", subject_from("foo", "bar"))));
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn keeps_an_unseparated_literal_tail_chaining_while_the_command_is_incomplete() {
        let wire = Wire::open(Recorder::default()).await;
        // `A1 LOGIN {5+}` + ["admin"] does not parse yet, so this tail is still
        // an argument even though it sits flush against the buffer start.
        wire.send("A1 LOGIN {5+}\r\nadminA2 LOGIN {8+}\r\nhunter22\r\n").await;
        settle().await;

        assert_eq!(wire.tags(), ["A1"]);
        assert_eq!(wire.output(), "");
    }

    #[tokio::test]
    async fn processes_a_command_pipelined_behind_a_literal_command() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 LOGIN {5+}\r\nadmin {8+}\r\npassword\r\nA2 NOOP\r\n").await;
        settle().await;

        assert_eq!(wire.tags(), ["A1", "A2"]);
        assert_eq!(wire.dispatched()[1].request, ImapRequest::Noop);
    }
}

// ---------------------------------------------------------------------------
// Credential logging (handler-literal.test.ts)
// ---------------------------------------------------------------------------

mod credential_logging {
    use super::*;

    #[tokio::test]
    async fn never_writes_a_literal_credential_to_the_journal() {
        let wire = Wire::open(Recorder::default()).await;
        // Missing password: forces the parse-failure line.
        wire.send("A1 LOGIN {11+}\r\nadmin-lit-1\r\n").await;
        settle().await;

        let journal = journal_text();
        assert!(!journal.contains("admin-lit-1"));
        assert!(journal.contains("A1 LOGIN [REDACTED]"));
        assert!(wire.dispatched().is_empty());
    }

    #[tokio::test]
    async fn never_writes_a_plain_argument_password_to_the_journal() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 LOGIN admin hunter2-plain-1\r\n").await;
        settle().await;

        let journal = journal_text();
        assert!(!journal.contains("hunter2-plain-1"));
        assert!(journal.contains("A1 LOGIN [REDACTED]"));
    }

    #[tokio::test]
    async fn redacts_an_untagged_login_which_only_ever_reaches_the_failure_log() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("LOGIN admin hunter2-untagged-1\r\n").await;
        settle().await;

        let journal = journal_text();
        assert!(!journal.contains("hunter2-untagged-1"));
        assert!(journal.contains("LOGIN [REDACTED]"));
    }

    // A credential that non-conformant framing strands on a line of its own is
    // a bare astring, with no LOGIN prefix for the anchored redactor to key
    // on, so it reaches the journal and the wire verbatim. Pinned as the Bun
    // server has it.
    #[tokio::test]
    async fn leaves_a_credential_stranded_on_its_own_line_un_redacted() {
        let wire = Wire::open(Recorder::default()).await;
        wire.send("A1 LOGIN {5+}\r\nadmin\r\nhunter2-stranded-1\r\n").await;
        settle().await;

        assert!(journal_text().contains("hunter2-stranded-1"));
        assert!(wire.output().contains("hunter2-stranded-1 BAD Invalid command\r\n"));
    }
}
