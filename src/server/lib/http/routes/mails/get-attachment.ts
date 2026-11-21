import { AUTH_ERROR_MESSAGE, getAttachmentFile, mailsTable } from "server";
import { Route } from "../route";
import { findViewableMail } from "../../../postgres/repositories/mails";

export const getAttachmentRoute = new Route<Bun.BunFile>(
  "GET",
  "/attachment/:id",
  async (req) => {
    const { user } = req.session;
    if (!user) return { status: "failed", message: AUTH_ERROR_MESSAGE };

    const attachmentId = req.params.id;
    // A mail of a domain the user views carries its id, so the client can ask
    // for the attachments of exactly that mail.
    const mailId = typeof req.query.mail === "string" ? req.query.mail : undefined;

    // Single query: verify ownership AND confirm attachment exists on this user's mail.
    // mailsTable.queryOne uses JSONB @> containment for the attachments filter.
    let mail = await mailsTable.queryOne({
      user_id: user.id,
      attachments: [{ content: { data: attachmentId } }],
    });
    if (!mail && mailId) {
      const viewable = await findViewableMail(user.id, mailId);
      mail = viewable
        ? await mailsTable.queryOne({
            mail_id: mailId,
            user_id: viewable.ownerId,
            attachments: [{ content: { data: attachmentId } }],
          })
        : null;
    }
    if (!mail) return { status: "failed", message: "Not found" };

    const attachment = await getAttachmentFile(attachmentId);
    if (attachment === undefined) return { status: "failed" };
    return attachment;
  }
);
