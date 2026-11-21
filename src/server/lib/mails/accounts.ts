import { Account, SignedUser } from "common";
import {
  getAccountStats,
  searchAccountStats,
} from "../postgres/repositories/mails";
import { listDomainAccess } from "../postgres/repositories/domains";

export interface AccountsGetResponse {
  received: Account[];
  sent: Account[];
  // Spam is grouped per receiving account, like received/sent — each entry
  // carries that account's spam doc/unread counts for the sidebar list + badge.
  spam: Account[];
  /**
   * The domains the user holds the viewer role on, each with its accounts.
   * Their mail is the owner's, read-only, so they are listed apart from the
   * user's own.
   */
  shared: SharedDomainAccounts[];
}

export interface SharedDomainAccounts {
  domain: string;
  owner: string;
  received: Account[];
  sent: Account[];
}

const toAccount = (stat: {
  address: string;
  count: number;
  unread: number;
  saved: number;
  latest: Date;
}): Account =>
  new Account({
    key: stat.address,
    doc_count: stat.count,
    unread_doc_count: stat.unread,
    saved_doc_count: stat.saved,
    updated: stat.latest,
  });

export const getAccounts = async (
  user: SignedUser
): Promise<AccountsGetResponse> => {
  const access = await listDomainAccess(user.id);
  const owned = access.filter((domain) => domain.role === "owner").map((domain) => domain.name);
  const viewed = access.filter((domain) => domain.role === "viewer");

  const [receivedStats, sentStats, spamStats, shared] = await Promise.all([
    getAccountStats(user.id, false, owned),
    getAccountStats(user.id, true, owned),
    getAccountStats(user.id, false, owned, true),
    Promise.all(
      viewed.map(async ({ name, ownerId, ownerUsername }) => {
        const [received, sent] = await Promise.all([
          getAccountStats(ownerId, false, [name], false, [name]),
          getAccountStats(ownerId, true, [name], false, [name]),
        ]);
        return {
          domain: name,
          owner: ownerUsername,
          received: received.map(toAccount),
          sent: sent.map(toAccount),
        };
      })
    ),
  ]);

  return {
    received: receivedStats.map(toAccount),
    sent: sentStats.map(toAccount),
    spam: spamStats.map(toAccount),
    shared,
  };
};

// Received accounts that own at least one mail matching `value`. Backs the
// search side-tab: the user types a keyword, this lists the accounts whose mail
// appears in the results, and clicking one jumps to that account's All view.
// Search covers the user's own mail only.
export const searchAccounts = async (
  user: SignedUser,
  value: string
): Promise<Account[]> => {
  value = value.trim();
  if (!value) return [];

  const owned = (await listDomainAccess(user.id))
    .filter((domain) => domain.role === "owner")
    .map((domain) => domain.name);
  const stats = await searchAccountStats(user.id, value, owned);

  return stats.map(toAccount);
};
