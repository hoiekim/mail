import { describe, it, expect, mock, beforeEach, afterAll } from "bun:test";
import { SignedUser } from "common";
import type { DomainAccess } from "../postgres/repositories/domains";

type Stat = { address: string; count: number; unread: number; saved: number; latest: Date };

const mockGetAccountStats = mock(
  (..._args: unknown[]): Promise<Stat[]> => Promise.resolve([])
);
const mockSearchAccountStats = mock(
  (..._args: unknown[]): Promise<Stat[]> => Promise.resolve([])
);
const mockListDomainAccess = mock(
  (_userId: string): Promise<DomainAccess[]> => Promise.resolve([])
);

mock.module("../postgres/repositories/mails", () => ({
  getAccountStats: mockGetAccountStats,
  searchAccountStats: mockSearchAccountStats,
}));

const realDomainRepository = { ...(await import("../postgres/repositories/domains")) };

mock.module("../postgres/repositories/domains", () => ({
  ...realDomainRepository,
  listDomainAccess: mockListDomainAccess,
}));

// `mock.module` is process-global with no unmock API: hand the real module
// back so the next file in the same run does not inherit the stub.
afterAll(() => {
  mock.module("../postgres/repositories/domains", () => realDomainRepository);
});

import { getAccounts, searchAccounts } from "./accounts";

const user = new SignedUser({
  id: "user-123",
  username: "testuser",
  email: "testuser@testuser.example.com",
});

const access = (overrides: Partial<DomainAccess>): DomainAccess => ({
  domainId: "d-1",
  name: "testuser.example.com",
  ownerId: "user-123",
  ownerUsername: "testuser",
  role: "owner",
  verifiedAt: null,
  ...overrides,
});

const stat = (address: string, overrides: Partial<Stat> = {}): Stat => ({
  address,
  count: 3,
  unread: 1,
  saved: 0,
  latest: new Date("2026-01-01T00:00:00.000Z"),
  ...overrides,
});

describe("getAccounts", () => {
  beforeEach(() => {
    mockGetAccountStats.mockReset();
    mockGetAccountStats.mockResolvedValue([]);
    mockListDomainAccess.mockReset();
    mockListDomainAccess.mockResolvedValue([
      access({}),
      access({ domainId: "d-2", name: "example.org" }),
    ]);
  });

  it("lists the user's own accounts on every domain they own", async () => {
    await getAccounts(user);
    const owned = ["testuser.example.com", "example.org"];
    expect(mockGetAccountStats).toHaveBeenCalledTimes(3);
    expect(mockGetAccountStats).toHaveBeenCalledWith("user-123", false, owned);
    expect(mockGetAccountStats).toHaveBeenCalledWith("user-123", true, owned);
    // Spam groups by receiving account, so it queries received-style with the
    // spamOnly flag set.
    expect(mockGetAccountStats).toHaveBeenCalledWith("user-123", false, owned, true);
  });

  it("maps received, sent and spam stats to Account objects", async () => {
    mockGetAccountStats.mockImplementation(async (_id, sent, _domains, spamOnly) => {
      if (spamOnly) return [stat("junk@example.org")];
      return sent ? [stat("me@example.org", { unread: 0 })] : [stat("hi@example.org")];
    });

    const result = await getAccounts(user);

    expect(result.received.map((a) => a.key)).toEqual(["hi@example.org"]);
    expect(result.received[0].unread_doc_count).toBe(1);
    expect(result.sent.map((a) => a.key)).toEqual(["me@example.org"]);
    expect(result.spam.map((a) => a.key)).toEqual(["junk@example.org"]);
    expect(result.shared).toEqual([]);
  });

  it("lists a viewed domain apart, from its owner's mail filtered to that domain", async () => {
    mockListDomainAccess.mockResolvedValue([
      access({}),
      access({
        domainId: "d-3",
        name: "example.com",
        ownerId: "owner-1",
        ownerUsername: "owner",
        role: "viewer",
      }),
    ]);
    mockGetAccountStats.mockImplementation(async (id, sent) =>
      id === "owner-1" && !sent ? [stat("info@example.com")] : []
    );

    const result = await getAccounts(user);

    // Owned accounts never include the viewed domain.
    expect(mockGetAccountStats).toHaveBeenCalledWith("user-123", false, ["testuser.example.com"]);
    // The owner's rows, both the address filter and the mail filtered to it.
    expect(mockGetAccountStats).toHaveBeenCalledWith(
      "owner-1",
      false,
      ["example.com"],
      false,
      ["example.com"]
    );
    expect(mockGetAccountStats).toHaveBeenCalledWith(
      "owner-1",
      true,
      ["example.com"],
      false,
      ["example.com"]
    );
    expect(result.received).toEqual([]);
    expect(result.shared).toHaveLength(1);
    expect(result.shared[0].domain).toBe("example.com");
    expect(result.shared[0].owner).toBe("owner");
    expect(result.shared[0].received.map((a) => a.key)).toEqual(["info@example.com"]);
  });
});

describe("searchAccounts", () => {
  beforeEach(() => {
    mockSearchAccountStats.mockReset();
    mockSearchAccountStats.mockResolvedValue([]);
    mockListDomainAccess.mockReset();
    mockListDomainAccess.mockResolvedValue([
      access({}),
      access({ name: "example.com", ownerId: "owner-1", role: "viewer" }),
    ]);
  });

  it("short-circuits an empty or whitespace term without querying", async () => {
    expect(await searchAccounts(user, "   ")).toEqual([]);
    expect(mockSearchAccountStats).not.toHaveBeenCalled();
  });

  it("searches the user's own mail on the domains they own, with the trimmed term", async () => {
    await searchAccounts(user, "  invoice ");
    expect(mockSearchAccountStats).toHaveBeenCalledWith("user-123", "invoice", [
      "testuser.example.com",
    ]);
  });

  it("maps matching stats to Account objects", async () => {
    mockSearchAccountStats.mockResolvedValue([stat("hi@testuser.example.com", { count: 2 })]);
    const result = await searchAccounts(user, "invoice");
    expect(result.map((a) => a.key)).toEqual(["hi@testuser.example.com"]);
    expect(result[0].doc_count).toBe(2);
  });
});
