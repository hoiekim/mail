import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { startServer, type TestServer } from "../harness";
import type { SmtpClient } from "../harness/smtp";
import { closeClients, mailByMessageId, mailsByMessageId, messageId, plain, session } from "./support";

// Only so many DATA transactions run at once: SMTP_DATA_CONCURRENCY, two by
// default. One more waits in line for up to twenty seconds, then is refused.
let single: TestServer;
let byDefault: TestServer;
let invalid: TestServer;

beforeAll(async () => {
  [single, byDefault, invalid] = await Promise.all([
    startServer({ env: { SMTP_DATA_CONCURRENCY: "1" } }),
    startServer(),
    startServer({ env: { SMTP_DATA_CONCURRENCY: "none" } }),
  ]);
}, 90_000);

afterEach(closeClients);

afterAll(async () => {
  await Promise.all([single?.stop(), byDefault?.stop(), invalid?.stop()]);
});

const QUEUED = "250 OK: message queued";

/** Opens a transaction and sends DATA with the start of a message, which holds a slot until it ends. */
const hold = async (server: TestServer, id: string): Promise<SmtpClient> => {
  const smtp = await session(server);
  await smtp.send("MAIL FROM:<bounce@remote.example>");
  await smtp.send("RCPT TO:<held@mail.test>");
  expect((await smtp.send("DATA")).raw).toBe("354 End data with <CR><LF>.<CR><LF>");
  await smtp.writeFlushed(plain({ messageId: id, subject: "Held open", body: "first half" }));
  return smtp;
};

/** Sends a whole message, terminator included, without waiting for the reply to it. */
const sendWhole = async (server: TestServer, id: string): Promise<SmtpClient> => {
  const smtp = await session(server);
  await smtp.send("MAIL FROM:<bounce@remote.example>");
  await smtp.send("RCPT TO:<queued@mail.test>");
  expect((await smtp.send("DATA")).raw).toBe("354 End data with <CR><LF>.<CR><LF>");
  await smtp.writeFlushed(`${plain({ messageId: id, subject: "Waiting in line" })}.\r\n`);
  return smtp;
};

const finish = async (smtp: SmtpClient) => {
  smtp.write("second half\r\n.\r\n");
  return (await smtp.read()).raw;
};

describe("with room for one", () => {
  test("a second transaction gets its 354 at once but its answer only when the first is done", async () => {
    const [first, second] = [messageId("slot"), messageId("slot")];
    const holder = await hold(single, first);
    const waiting = await sendWhole(single, second);
    expect(await waiting.staysQuiet(500)).toBe(true);
    expect(await mailsByMessageId(single, second)).toEqual([]);

    expect(await finish(holder)).toBe(QUEUED);
    expect((await waiting.read()).raw).toBe(QUEUED);
    expect((await mailByMessageId(single, first)).text).toBe("first half\nsecond half\n");
    expect((await mailByMessageId(single, second)).subject).toBe("Waiting in line");
  });

  test("transactions in line are served in the order they asked", async () => {
    const ids = [messageId("line"), messageId("line"), messageId("line")];
    const holder = await hold(single, messageId("slot"));
    const waiting: SmtpClient[] = [];
    for (const id of ids) waiting.push(await sendWhole(single, id));
    expect(await finish(holder)).toBe(QUEUED);
    for (const smtp of waiting) expect((await smtp.read()).raw).toBe(QUEUED);
    const order = await single.db.query<{ message_id: string }>("SELECT message_id FROM mails WHERE message_id = ANY($1) ORDER BY uid_domain", [
      `{${ids.map((id) => `"${id}"`).join(",")}}`,
    ]);
    expect(order.map((row) => row.message_id)).toEqual(ids);
  });

  test("a transaction dropped mid-message gives its slot to the next in line", async () => {
    const id = messageId("slot");
    const holder = await hold(single, messageId("slot"));
    const waiting = await sendWhole(single, id);
    expect(await waiting.staysQuiet(300)).toBe(true);
    holder.close();
    expect((await waiting.read()).raw).toBe(QUEUED);
    expect((await mailByMessageId(single, id)).subject).toBe("Waiting in line");
  });

  test("a transaction that is refused outright never takes a slot", async () => {
    const holder = await hold(single, messageId("slot"));
    const relay = await session(single);
    const result = await relay.transaction({ from: "a@remote.example", to: ["b@elsewhere.example"], data: plain() });
    expect(result.final.raw).toBe("550 Error: relay access denied");
    expect(await finish(holder)).toBe(QUEUED);
  });

  test("after twenty seconds in line a transaction is refused 421 and disconnected", async () => {
    const held = messageId("slot");
    const refused = messageId("slot");
    const holder = await hold(single, held);
    const started = Date.now();
    const waiting = await sendWhole(single, refused);
    const reply = await waiting.read(30_000);
    expect(reply.raw).toBe("421 4.3.2 Error: too many concurrent deliveries, try again later");
    const waited = Date.now() - started;
    expect(waited).toBeGreaterThanOrEqual(19_000);
    expect(waited).toBeLessThan(25_000);
    expect(await waiting.waitForClose(5000)).toBe(true);
    expect(await mailsByMessageId(single, refused)).toEqual([]);

    // The transaction that held the slot all along is unharmed.
    expect(await finish(holder)).toBe(QUEUED);
    expect((await mailByMessageId(single, held)).text).toBe("first half\nsecond half\n");
  }, 45_000);
});

describe("how many run at once", () => {
  /** With two transactions held open, a third waits; with one, it does not. */
  const expectRoomForTwo = async (server: TestServer) => {
    const one = await hold(server, messageId("slot"));
    const beside = await sendWhole(server, messageId("slot"));
    expect((await beside.read()).raw).toBe(QUEUED);

    const two = await hold(server, messageId("slot"));
    const third = await sendWhole(server, messageId("slot"));
    expect(await third.staysQuiet(500)).toBe(true);
    expect(await finish(one)).toBe(QUEUED);
    expect((await third.read()).raw).toBe(QUEUED);
    expect(await finish(two)).toBe(QUEUED);
  };

  test("two when SMTP_DATA_CONCURRENCY is not set", async () => {
    await expectRoomForTwo(byDefault);
  });

  test("two when SMTP_DATA_CONCURRENCY is not a positive number", async () => {
    await expectRoomForTwo(invalid);
  });
});
