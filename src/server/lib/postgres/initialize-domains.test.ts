/**
 * `initializeDomains`: the boot step that replaced the admin and read-only
 * admin seeding. Every boot it deletes the retired read-only login's sessions
 * and backfills each account's own domain; once (behind its marker) it gives
 * `admin` the bare served domain and retires `admin-ro`.
 *
 * The repositories and the marker are spied, so the assertions are on what
 * the step asks of them.
 */
import { afterAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import * as domainRepo from "./repositories/domains";
import * as sessionRepo from "./repositories/sessions";
import * as userRepo from "./repositories/users";
import * as migration from "./migration";
import { User } from "common";
import { initializeDomains } from "./initialize";

const spies = {
  deleteReadOnlySessions: spyOn(sessionRepo, "deleteReadOnlySessions"),
  deleteSessionsForUser: spyOn(sessionRepo, "deleteSessionsForUser"),
  searchUser: spyOn(userRepo, "searchUser"),
  writeUser: spyOn(userRepo, "writeUser"),
  assignDomain: spyOn(domainRepo, "assignDomain"),
  backfillAccountDomains: spyOn(domainRepo, "backfillAccountDomains"),
  checkSchemaAtTarget: spyOn(migration, "checkSchemaAtTarget"),
  writeSchemaMarker: spyOn(migration, "writeSchemaMarker"),
};

const originalDomain = process.env.EMAIL_DOMAIN;

afterAll(() => {
  for (const spy of Object.values(spies)) spy.mockRestore();
  if (originalDomain === undefined) delete process.env.EMAIL_DOMAIN;
  else process.env.EMAIL_DOMAIN = originalDomain;
});

const user = (username: string, id: string) =>
  new User({ id, username, email: `${username}@example.com`, password: "$2b$10$x", passwordVersion: 3 });

beforeEach(() => {
  process.env.EMAIL_DOMAIN = "Example.com";
  for (const spy of Object.values(spies)) spy.mockReset();
  spies.deleteReadOnlySessions.mockResolvedValue(0);
  spies.deleteSessionsForUser.mockResolvedValue(2);
  spies.searchUser.mockResolvedValue(undefined);
  spies.writeUser.mockResolvedValue({ _id: "u-ro" });
  spies.assignDomain.mockResolvedValue(true);
  spies.backfillAccountDomains.mockResolvedValue(0);
  spies.checkSchemaAtTarget.mockResolvedValue(true);
  spies.writeSchemaMarker.mockResolvedValue(undefined);
});

describe("initializeDomains", () => {
  it("every boot: ends the retired login's sessions and backfills the accounts' own domains", async () => {
    await initializeDomains();

    expect(spies.deleteReadOnlySessions).toHaveBeenCalledTimes(1);
    expect(spies.backfillAccountDomains).toHaveBeenCalledWith("example.com");
    // The marker is present: the one-time part does not run again, so a role
    // the owner changed afterwards is never undone at a restart.
    expect(spies.checkSchemaAtTarget).toHaveBeenCalledWith("1", "domains_migration");
    expect(spies.assignDomain).not.toHaveBeenCalled();
    expect(spies.writeUser).not.toHaveBeenCalled();
    expect(spies.writeSchemaMarker).not.toHaveBeenCalled();
  });

  it("once: gives admin the bare served domain and retires admin-ro, then writes its marker", async () => {
    spies.checkSchemaAtTarget.mockResolvedValue(false);
    spies.searchUser.mockImplementation((async ({ username }: { username?: string }) => {
      if (username === "admin") return { ...user("admin", "u-admin"), user_id: "u-admin" };
      if (username === "admin-ro")
        return { ...user("admin-ro", "u-ro"), user_id: "u-ro", password_version: 3, email: "admin-ro@example.com" };
      return undefined;
    }) as never);

    await initializeDomains();

    expect(spies.assignDomain).toHaveBeenCalledWith("u-admin", "example.com");
    // The read-only login's password becomes one nobody knows, in the same
    // write that moves its credential generation, and its sessions end.
    const [retired] = spies.writeUser.mock.calls[0] as unknown as [
      { user_id: string; username: string; password: string; password_version: number },
    ];
    expect(retired.user_id).toBe("u-ro");
    expect(retired.username).toBe("admin-ro");
    expect(retired.password).toMatch(/^[0-9a-f]{64}$/);
    expect(retired.password_version).toBe(4);
    expect(spies.deleteSessionsForUser).toHaveBeenCalledWith("u-ro");
    expect(spies.writeSchemaMarker).toHaveBeenCalledWith("1", "domains_migration");
    // Ordered so a failure before the marker is retried at the next boot.
    const markerOrder = spies.writeSchemaMarker.mock.invocationCallOrder[0];
    expect(spies.deleteSessionsForUser.mock.invocationCallOrder[0]).toBeLessThan(markerOrder);
  });

  it("once, on a server with neither account: assigns nothing and writes its marker", async () => {
    spies.checkSchemaAtTarget.mockResolvedValue(false);

    await initializeDomains();

    expect(spies.assignDomain).not.toHaveBeenCalled();
    expect(spies.writeUser).not.toHaveBeenCalled();
    expect(spies.writeSchemaMarker).toHaveBeenCalledTimes(1);
  });

  it("writes no marker when the one-time part fails, so the next boot retries it", async () => {
    spies.checkSchemaAtTarget.mockResolvedValue(false);
    spies.searchUser.mockImplementation((async ({ username }: { username?: string }) =>
      username === "admin-ro" ? { ...user("admin-ro", "u-ro"), user_id: "u-ro" } : undefined) as never);
    spies.writeUser.mockResolvedValue(undefined);

    await expect(initializeDomains()).rejects.toThrow();
    expect(spies.writeSchemaMarker).not.toHaveBeenCalled();
  });
});
