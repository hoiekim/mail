import { push } from "server";
import { Route } from "../route";

export type RefreshGetResponse = undefined;

// Public, but user-scoped: the service worker's same-origin fetch carries the
// session cookie, and only the caller's own subscription is kept alive (the
// :id alone is a bearer capability, as for the delete). An anonymous caller
// has no subscription of its own, and neither has a read-only session, which
// may not subscribe: its id is admin's, whose subscriptions it must not touch.
export const getRefreshRoute = new Route<RefreshGetResponse>(
  "GET",
  "/refresh/:id",
  async (req) => {
    const user = req.session.user;
    const result =
      !!user &&
      !user.isReadOnly &&
      (await push.refreshSubscription(req.params.id, user.id));
    if (result) {
      return { status: "success" };
    } else {
      return { status: "failed", message: "No subscription found" };
    }
  }
);
