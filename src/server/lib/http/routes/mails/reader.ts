import { SignedUser } from "common";
import { domainOfAddress } from "../../../domains";
import { getDomainAccess } from "../../../postgres/repositories/domains";

/** Whose mail rows a request reads, and which of their domains it may see. */
export interface MailReader {
  /** The store the rows are keyed by: the user, or the owner of a viewed domain. */
  store: Pick<SignedUser, "id">;
  /** Undefined reads the whole store (the user's own); set, only those domains. */
  domains?: string[];
}

/**
 * The reader for an account (an address): the user's own store for a domain
 * they own, its owner's filtered to the domain for one they view, and null
 * for a domain they hold no role on. The role is read in the same request, so
 * a revoked one stops the next read.
 */
export const resolveMailReader = async (
  user: SignedUser,
  account: string
): Promise<MailReader | null> => {
  const domain = domainOfAddress(account);
  if (!domain) return null;
  const access = await getDomainAccess(user.id, domain);
  if (!access) return null;
  if (access.role === "owner") return { store: user };
  return { store: { id: access.ownerId }, domains: [access.name] };
};
