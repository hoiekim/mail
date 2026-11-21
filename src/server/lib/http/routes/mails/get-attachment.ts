import { AUTH_ERROR_MESSAGE, getAttachmentFile, mailsTable } from "server";
import { Route } from "../route";
import { canViewAttachment } from "../../../postgres/repositories/mails";

export const getAttachmentRoute = new Route<Bun.BunFile>(
  "GET",
  "/attachment/:id",
  async (req) => {
    const { user } = req.session;
    if (!user) return { status: "failed", message: AUTH_ERROR_MESSAGE };

    const attachmentId = req.params.id;

    // Single query: verify ownership AND confirm attachment exists on this user's mail.
    // mailsTable.queryOne uses JSONB @> containment for the attachments filter.
    const own = await mailsTable.queryOne({
      user_id: user.id,
      attachments: [{ content: { data: attachmentId } }],
    });
    // Otherwise a mail of a domain the user views has to carry it.
    if (!own && !(await canViewAttachment(user.id, attachmentId))) {
      return { status: "failed", message: "Not found" };
    }

    const attachment = await getAttachmentFile(attachmentId);
    if (attachment === undefined) return { status: "failed" };
    return attachment;
  }
);
