import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createUser, type TestServer, type TestUser } from "../harness";
import { ImapClient, lit, openSession } from "../harness/imap";
import { deliver, mailDomain, startImapServer, type DeliveredMail } from "./support";

let server: TestServer;
let userCount = 0;

interface Box {
  user: TestUser;
  imap: ImapClient;
  mails: DeliveredMail[];
  domain: string;
}

/** A fresh account with `count` mails (odd ones for `hello@`, even ones for `work@`) and INBOX selected. */
const inbox = async (count: number): Promise<Box> => {
  const user = await createUser(server, `exp${++userCount}`);
  const domain = mailDomain(server, user.username);
  const mails: DeliveredMail[] = [];
  for (let i = 1; i <= count; i++) {
    mails.push(await deliver(server, { to: `${i % 2 ? "hello" : "work"}@${domain}`, subject: `Mail ${i}` }));
  }
  const imap = await openSession(server, user.username, user.password, "INBOX");
  return { user, imap, mails, domain };
};

const uids = async (imap: ImapClient, command = "FETCH 1:* (UID)") => (await imap.command(command)).untagged;

beforeAll(async () => {
  server = await startImapServer();
}, 90_000);

afterAll(async () => {
  await server?.stop();
});

describe("EXPUNGE", () => {
  test("with nothing flagged \\Deleted just completes", async () => {
    const { imap } = await inbox(2);
    expect((await imap.command("EXPUNGE")).lines).toEqual(["A3 OK EXPUNGE completed"]);
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 1)", "* 2 FETCH (UID 2)"]);
    imap.close();
  });

  test("removes every \\Deleted message, announcing each from the highest sequence number down", async () => {
    const { imap } = await inbox(6);
    await imap.command("STORE 2,4,5 +FLAGS.SILENT (\\Deleted)");
    const result = await imap.command("EXPUNGE");
    expect(result.lines).toEqual(["* 5 EXPUNGE", "* 4 EXPUNGE", "* 2 EXPUNGE", "A4 OK EXPUNGE completed"]);
    // The rest are renumbered and keep their UIDs.
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 1)", "* 2 FETCH (UID 3)", "* 3 FETCH (UID 6)"]);
    expect((await imap.command("EXPUNGE")).lines).toEqual(["A6 OK EXPUNGE completed"]);
    imap.close();
  });

  test("expunging the only message, and every message", async () => {
    const one = await inbox(1);
    await one.imap.command("STORE 1 +FLAGS.SILENT (\\Deleted)");
    expect((await one.imap.command("EXPUNGE")).lines).toEqual(["* 1 EXPUNGE", "A4 OK EXPUNGE completed"]);
    expect((await one.imap.command("FETCH 1:* (UID)")).lines).toEqual(["A5 OK FETCH completed"]);
    one.imap.close();

    const three = await inbox(3);
    await three.imap.command("STORE 1:* +FLAGS.SILENT (\\Deleted)");
    expect((await three.imap.command("EXPUNGE")).lines).toEqual([
      "* 3 EXPUNGE",
      "* 2 EXPUNGE",
      "* 1 EXPUNGE",
      "A4 OK EXPUNGE completed",
    ]);
    expect((await three.imap.command("STATUS INBOX (MESSAGES UIDNEXT)")).untagged).toEqual([
      '* STATUS "INBOX" (MESSAGES 0 UIDNEXT 4)',
    ]);
    three.imap.close();
  });

  test("marks the rows expunged rather than deleting them, under one new mod-sequence", async () => {
    const { imap, user } = await inbox(3);
    await imap.command("STORE 1,3 +FLAGS.SILENT (\\Deleted)");
    const before = await server.db.query("SELECT modseq FROM mails WHERE user_id = $1 ORDER BY uid_domain", [user.id]);
    await imap.command("EXPUNGE");
    const rows = await server.db.query(
      "SELECT uid_domain, deleted, expunged, modseq FROM mails WHERE user_id = $1 ORDER BY uid_domain",
      [user.id]
    );
    const highest = Math.max(...before.map((row) => Number(row.modseq)));
    expect(rows).toEqual([
      { uid_domain: 1, deleted: true, expunged: true, modseq: String(highest + 1) },
      { uid_domain: 2, deleted: false, expunged: false, modseq: before[1]!.modseq },
      { uid_domain: 3, deleted: true, expunged: true, modseq: String(highest + 1) },
    ]);
    imap.close();
  });

  test("an expunged UID is never given out again", async () => {
    const { imap, domain } = await inbox(2);
    await imap.command("STORE 2 +FLAGS.SILENT (\\Deleted)");
    await imap.command("EXPUNGE");
    await deliver(server, { to: `hello@${domain}`, subject: "After" });
    await imap.command("SELECT INBOX");
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 1)", "* 2 FETCH (UID 3)"]);
    imap.close();
  });

  test("a message expunged in INBOX is gone from its per-address mailbox and from Trash too", async () => {
    const { imap } = await inbox(4);
    await imap.command("STORE 2 +FLAGS.SILENT (\\Deleted)");
    expect((await imap.command("STATUS Trash (MESSAGES)")).untagged).toEqual(['* STATUS "Trash" (MESSAGES 1)']);
    await imap.command("EXPUNGE");
    expect((await imap.command("STATUS Trash (MESSAGES UIDNEXT)")).untagged).toEqual([
      '* STATUS "Trash" (MESSAGES 0 UIDNEXT 2)',
    ]);
    expect((await imap.command('STATUS "INBOX/accounts/work" (MESSAGES UIDNEXT)')).untagged).toEqual([
      '* STATUS "INBOX/accounts/work" (MESSAGES 1 UIDNEXT 3)',
    ]);
    imap.close();
  });

  test("in a per-address mailbox it expunges that mailbox's \\Deleted messages, which leave INBOX as well", async () => {
    const { imap } = await inbox(4);
    // Flag one message of each address, then expunge from inside "work".
    await imap.command("STORE 1,2 +FLAGS.SILENT (\\Deleted)");
    await imap.command('SELECT "INBOX/accounts/work"');
    expect((await imap.command("EXPUNGE")).lines).toEqual(["* 1 EXPUNGE", "A5 OK EXPUNGE completed"]);
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 2)"]);
    // The \Deleted message of the other address was not touched.
    await imap.command("SELECT INBOX");
    expect(await uids(imap, "FETCH 1:* (UID FLAGS)")).toEqual([
      "* 1 FETCH (UID 1 FLAGS (\\Deleted))",
      "* 2 FETCH (UID 3 FLAGS ())",
      "* 3 FETCH (UID 4 FLAGS ())",
    ]);
    imap.close();
  });

  test("in Trash it removes the messages for good, from INBOX too", async () => {
    const { imap } = await inbox(2);
    await imap.command("STORE 1 +FLAGS.SILENT (\\Deleted)");
    await imap.command("SELECT Trash");
    expect((await imap.command("EXPUNGE")).lines).toEqual(["* 1 EXPUNGE", "A5 OK EXPUNGE completed"]);
    expect((await imap.command("STATUS INBOX (MESSAGES)")).untagged).toEqual(['* STATUS "INBOX" (MESSAGES 1)']);
    imap.close();
  });

  test("is refused on an examined mailbox and without a selected mailbox", async () => {
    const { imap } = await inbox(1);
    await imap.command("STORE 1 +FLAGS.SILENT (\\Deleted)");
    await imap.command("EXAMINE INBOX");
    expect((await imap.command("EXPUNGE")).lines).toEqual(["A5 NO [READ-ONLY] Mailbox is read-only"]);
    await imap.command("CLOSE");
    expect((await imap.command("EXPUNGE")).lines).toEqual(["A7 BAD No mailbox selected"]);
    expect((await imap.command("STATUS INBOX (MESSAGES)")).untagged).toEqual(['* STATUS "INBOX" (MESSAGES 1)']);
    imap.close();
  });

  test("UID EXPUNGE is not supported, with or without a selected mailbox", async () => {
    // COPYUID and APPENDUID are sent, but UIDPLUS is neither advertised nor complete.
    const { imap } = await inbox(1);
    await imap.command("STORE 1 +FLAGS.SILENT (\\Deleted)");
    expect((await imap.command("UID EXPUNGE 1")).lines).toEqual(["A4 BAD UID EXPUNGE not supported"]);
    expect((await imap.command("UID EXPUNGE 1:*")).lines).toEqual(["A5 BAD UID EXPUNGE not supported"]);
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 1)"]);
    imap.close();
  });

  test("ignores arguments", async () => {
    const { imap } = await inbox(1);
    expect((await imap.command("EXPUNGE 1:*")).lines).toEqual(["A3 OK EXPUNGE completed"]);
    imap.close();
  });
});

describe("EXPUNGE: what another connection on the mailbox sees", () => {
  /** Two sessions on one INBOX of six mails; `first` then expunges messages 2, 4 and 5. */
  const pair = async () => {
    const box = await inbox(6);
    const second = await openSession(server, box.user.username, box.user.password, "INBOX");
    await box.imap.command("STORE 2,4,5 +FLAGS.SILENT (\\Deleted)");
    await box.imap.command("EXPUNGE");
    return { ...box, first: box.imap, second };
  };

  test("NOOP and CHECK announce nothing", async () => {
    // NOTE: RFC 3501 has the server report expunges (and new mail) to other
    // sessions when they send a command such as NOOP. Here nothing is sent
    // outside IDLE; the second session keeps its old numbering.
    const { first, second } = await pair();
    expect((await second.command("NOOP")).lines).toEqual(["A3 OK NOOP completed"]);
    expect((await second.command("CHECK")).lines).toEqual(["A4 OK CHECK completed"]);
    first.close();
    second.close();
  });

  test("its sequence numbers go stale: surviving messages keep their old numbers and the gaps answer nothing", async () => {
    // NOTE: looks like a bug. Until it re-selects, the second session still
    // counts six messages: FETCH 1:* answers numbers 1, 3 and 6, a STORE on an
    // expunged number completes OK with no effect, and SEARCH returns the old
    // numbers. A client that trusts sequence numbers is now off by the gaps.
    const { first, second } = await pair();
    expect(await uids(second)).toEqual(["* 1 FETCH (UID 1)", "* 3 FETCH (UID 3)", "* 6 FETCH (UID 6)"]);
    expect((await second.command("FETCH 2 (UID)")).lines).toEqual(["A4 OK FETCH completed"]);
    expect((await second.command("STORE 2 +FLAGS (\\Seen)")).lines).toEqual(["A5 OK STORE completed"]);
    expect((await second.command("STORE 3 +FLAGS (\\Seen)")).lines).toEqual([
      "* 3 FETCH (FLAGS (\\Seen))",
      "A6 OK STORE completed",
    ]);
    expect((await second.command("SEARCH ALL")).untagged).toEqual(["* SEARCH 1 3 6"]);
    expect((await second.command("UID SEARCH ALL")).untagged).toEqual(["* SEARCH 1 3 6"]);
    expect((await second.command("UID FETCH 1:* (UID)")).untagged).toEqual([
      "* 1 FETCH (UID 1)",
      "* 3 FETCH (UID 3)",
      "* 6 FETCH (UID 6)",
    ]);
    first.close();
    second.close();
  });

  test("its own EXPUNGE first announces what the other session removed", async () => {
    const { first, second } = await pair();
    expect((await second.command("EXPUNGE")).lines).toEqual([
      "* 5 EXPUNGE",
      "* 4 EXPUNGE",
      "* 2 EXPUNGE",
      "A3 OK EXPUNGE completed",
    ]);
    expect(await uids(second)).toEqual(["* 1 FETCH (UID 1)", "* 2 FETCH (UID 3)", "* 3 FETCH (UID 6)"]);
    first.close();
    second.close();
  });

  test("an APPEND to the selected mailbox announces them too", async () => {
    const { first, second } = await pair();
    const result = await second.command(["APPEND INBOX ", lit("Subject: appended\r\n\r\nx\r\n")]);
    expect(result.lines).toEqual([
      "+ go ahead",
      "* 5 EXPUNGE",
      "* 4 EXPUNGE",
      "* 2 EXPUNGE",
      expect.stringMatching(/^A3 OK \[APPENDUID \d+ 7\] APPEND completed$/),
    ]);
    first.close();
    second.close();
  });

  test("a MOVE announces them along with its own", async () => {
    const { first, second } = await pair();
    await second.command("CREATE folder");
    const result = await second.command("MOVE 1 folder");
    expect(result.untagged).toEqual(["* 5 EXPUNGE", "* 4 EXPUNGE", "* 2 EXPUNGE", "* 1 EXPUNGE"]);
    expect(result.status).toBe("OK");
    first.close();
    second.close();
  });

  test("selecting the mailbox again shows the current state", async () => {
    const { first, second } = await pair();
    expect((await second.command("SELECT INBOX")).untagged[0]).toBe("* 3 EXISTS");
    expect(await uids(second)).toEqual(["* 1 FETCH (UID 1)", "* 2 FETCH (UID 3)", "* 3 FETCH (UID 6)"]);
    first.close();
    second.close();
  });

  test("mail that arrives is not announced on NOOP either, and is not addressable until a re-select", async () => {
    const { imap, domain } = await inbox(1);
    await deliver(server, { to: `hello@${domain}`, subject: "New" });
    expect((await imap.command("NOOP")).lines).toEqual(["A3 OK NOOP completed"]);
    expect(await uids(imap)).toEqual(["* 1 FETCH (UID 1)"]);
    expect((await imap.command("FETCH 2 (UID)")).untagged).toEqual([]);
    // Not even by its UID: a message the session has no number for is skipped.
    expect((await imap.command("UID FETCH 2 (UID)")).untagged).toEqual([]);
    expect((await imap.command("UID FETCH 1:* (UID)")).untagged).toEqual(["* 1 FETCH (UID 1)"]);
    expect((await imap.command("UID SEARCH ALL")).untagged).toEqual(["* SEARCH 1 2"]);
    expect((await imap.command("SEARCH ALL")).untagged).toEqual(["* SEARCH 1"]);
    expect((await imap.command("STATUS INBOX (MESSAGES)")).untagged).toEqual(['* STATUS "INBOX" (MESSAGES 2)']);
    expect((await imap.command("SELECT INBOX")).untagged[0]).toBe("* 2 EXISTS");
    imap.close();
  });
});
