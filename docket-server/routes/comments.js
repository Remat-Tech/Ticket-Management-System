const express = require('express');
const db = require('../db/connection');
const { removeAttachmentFiles, uploadIncomingAttachments, insertAttachmentRows } = require('../utils/attachment-storage');
const { requireAuth } = require('../middleware/authenticate');
const { requireTicketAccess } = require('../middleware/authorize');
const { asyncHandler } = require('../utils/async-handler');
const { markRead } = require('../utils/unread');

// mergeParams so this router can read :ticketId from the parent
// tickets router it's mounted under (see server.js).
const router = express.Router({ mergeParams: true });

// Every ticket-access route below allows the same three actors: the
// customer who owns the ticket, the agent currently assigned to it, or
// any admin. Internal-visibility gating (agents/admins only) is handled
// separately inside each handler, since it depends on more than "does
// this actor have access to the ticket at all".
const TICKET_ACCESS = { allowCustomer: true, allowAssignedAgent: true, allowAdmin: true };

// The auth layer's role names ('user'/'agent'/'admin') predate and differ
// slightly from the ticket_comments schema's author_type naming
// ('customer'/'agent'/'admin') — this is the single place that maps
// between them, instead of scattering the mapping across handlers.
const ROLE_TO_AUTHOR_TYPE = { user: 'customer', agent: 'agent', admin: 'admin' };

// Looks up a display name for author_name from the actor's own account
// record — never from anything the client sent. Falls back to a generic
// label rather than erroring if the row is somehow missing, since a
// missing display name shouldn't block posting a comment.
async function lookupActorName(actor) {
  const table = { user: 'users', agent: 'agents', admin: 'admins' }[actor.role];
  if (!table) return { user: 'Customer', agent: 'Agent', admin: 'Admin' }[actor.role];
  const result = await db.query(`SELECT full_name FROM ${table} WHERE id = $1`, [actor.id]);
  return result.rows[0] ? result.rows[0].full_name : { user: 'Customer', agent: 'Agent', admin: 'Admin' }[actor.role];
}

// Comment rows with their files attached, in one query. Files carry an id
// (so the client can build a download link) and filename only —
// stored_path never goes to the client. Callers append WHERE (on alias c)
// and ORDER BY.
const COMMENT_SELECT = `
  SELECT c.*, COALESCE(f.files, '[]'::json) AS files
  FROM ticket_comments c
  LEFT JOIN LATERAL (
    SELECT json_agg(json_build_object('id', ta.id, 'filename', ta.filename) ORDER BY ta.id) AS files
    FROM ticket_attachments ta
    WHERE ta.comment_id = c.id
  ) f ON true`;

// GET /api/tickets/:ticketId/comments?visibility=public|internal
// requireTicketAccess already 401s (no/invalid token), 404s (no such
// ticket), and 403s (wrong actor for this ticket) before this handler
// ever runs, so it only has to worry about visibility filtering.
router.get('/', requireAuth(), requireTicketAccess(TICKET_ACCESS), asyncHandler(async (req, res) => {
  const { visibility } = req.query;
  const canSeeInternal = req.actor.role === 'agent' || req.actor.role === 'admin';

  // A customer explicitly requesting ?visibility=internal gets an empty
  // list, not a 403 — same shape as "there happen to be no internal
  // comments", so it doesn't confirm or deny their existence.
  if (visibility === 'internal' && !canSeeInternal) {
    return res.json([]);
  }

  let where = 'WHERE c.ticket_id = $1';
  const params = [req.params.ticketId];

  if (visibility) {
    params.push(visibility);
    where += ` AND c.visibility = $${params.length}`;
  } else if (!canSeeInternal) {
    // No filter requested: a customer's unfiltered view still never
    // includes internal notes.
    where += " AND c.visibility = 'public'";
  }

  const commentsResult = await db.query(`${COMMENT_SELECT} ${where} ORDER BY c.created_at ASC, c.id ASC`, params);
  res.json(commentsResult.rows);
}));

// POST /api/tickets/:ticketId/comments
// { visibility?: 'public'|'internal', body, files?: [{ filename, content_base64, mime_type? }, ...] }
// author_type and author_name are NOT read from the body — they come
// entirely from req.actor, set by requireAuth() from the verified token.
// A message needs text or at least one file — matches the chat composer,
// which blocks sending an empty message with no attachment.
router.post('/', requireAuth(), requireTicketAccess(TICKET_ACCESS), asyncHandler(async (req, res) => {
  const { visibility, body, files } = req.body || {};
  const authorType = ROLE_TO_AUTHOR_TYPE[req.actor.role];
  const authorName = await lookupActorName(req.actor);

  // Validate everything that doesn't depend on the files BEFORE uploading,
  // so a rejected request never leaves orphaned objects in storage.
  const vis = visibility || 'public';
  if (!['public', 'internal'].includes(vis)) {
    return res.status(400).json({ error: "visibility must be 'public' or 'internal'" });
  }
  // Only agents/admins can post internal notes — checked against the
  // authenticated role, so a customer can no longer get an internal note
  // recorded just by sending author_type: 'agent' in the body.
  if (authorType === 'customer' && vis === 'internal') {
    return res.status(400).json({ error: 'customer comments cannot be marked internal' });
  }
  if (body != null && typeof body !== 'string') {
    return res.status(400).json({ error: 'body must be a string' });
  }

  // requireTicketAccess has already confirmed the ticket exists and this
  // actor may act on it, so attachment writes below only ever happen for
  // an authorized caller.
  let normalizedFiles;
  try {
    normalizedFiles = await uploadIncomingAttachments(req.params.ticketId, files);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  // Needs the upload result, so it can't move above. An empty message
  // means no files were uploaded, so there's nothing to clean up here.
  if ((!body || !body.trim()) && !normalizedFiles.length) {
    return res.status(400).json({ error: 'a message needs body text or at least one file' });
  }

  let commentId;
  try {
    commentId = await db.withTransaction(async (client) => {
      const insertResult = await client.query(
        `INSERT INTO ticket_comments (ticket_id, author_type, author_id, author_name, visibility, body)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [req.params.ticketId, authorType, req.actor.id, authorName, vis, (body || '').trim()]
      );
      const newCommentId = insertResult.rows[0].id;

      await insertAttachmentRows(client, { commentId: newCommentId }, normalizedFiles);

      await client.query('UPDATE tickets SET updated_at = now() WHERE id = $1', [req.params.ticketId]);
      // Replying means you've seen the conversation up to here.
      await markRead(req.params.ticketId, authorType, req.actor.id, newCommentId, client);
      return newCommentId;
    });
  } catch (err) {
    console.error('POST /api/tickets/:ticketId/comments: failed to persist comment', err);
    // The comment never committed, so nothing references these files.
    removeAttachmentFiles(normalizedFiles.map((f) => f.stored_path))
      .catch((cleanupErr) => console.error('POST /api/tickets/:ticketId/comments: storage cleanup failed', cleanupErr));
    return res.status(500).json({ error: 'failed to post comment' });
  }

  const createdResult = await db.query(`${COMMENT_SELECT} WHERE c.id = $1`, [commentId]);
  res.status(201).json(createdResult.rows[0]);
}));

// POST /api/tickets/:ticketId/comments/read  { up_to_id? }
// Called by the chat page while the conversation is on screen. Marks
// everything up to up_to_id (default: the newest message) as read for the
// caller, which clears their unread badge and cancels any pending email
// reminder for those messages.
router.post('/read', requireAuth(), requireTicketAccess(TICKET_ACCESS), asyncHandler(async (req, res) => {
  const upToId = Number((req.body || {}).up_to_id);
  await markRead(req.params.ticketId, ROLE_TO_AUTHOR_TYPE[req.actor.role], req.actor.id, Number.isInteger(upToId) ? upToId : null);
  res.status(204).end();
}));

module.exports = router;
