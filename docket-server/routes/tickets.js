const express = require('express');
const db = require('../db/connection');
const { nextId } = require('../utils/ids');
const { saveAttachmentFile } = require('../utils/attachment-storage');
const { requireAuth } = require('../middleware/authenticate');
const { requireTicketAccess } = require('../middleware/authorize');
const { asyncHandler } = require('../utils/async-handler');
const { recordAuditLog, resolveActorName } = require('../utils/audit');

const router = express.Router();

const VALID_CATEGORIES = ['Network', 'Application', 'Hardware', 'Access & Identity'];
const VALID_PRIORITIES = ['Low', 'Medium', 'High', 'Critical'];

// Pulled directly from app.js's teamByCategory / slaByPriority — the server
// is now the single source of truth for these, so the client no longer
// needs (or should keep) its own copies once it's wired to this API.
const TEAM_BY_CATEGORY = {
  Network: 'Network Support',
  Application: 'Application Support',
  Hardware: 'Infrastructure',
  'Access & Identity': 'Access & Identity'
};

const SLA_BY_PRIORITY = {
  Critical: { response: '15 min', resolution: '4 hrs' },
  High: { response: '30 min', resolution: '8 hrs' },
  Medium: { response: '4 hrs', resolution: '2 days' },
  Low: { response: '1 day', resolution: '5 days' }
};

function slaSummary(priority) {
  const sla = SLA_BY_PRIORITY[priority] || SLA_BY_PRIORITY.Medium;
  return `${sla.response} response / ${sla.resolution} resolution`;
}

// Matches app.js's STATUS_TRANSITIONS exactly:
// - No entry for 'Created' — a ticket must be assigned before any status
//   move is available (see /:id/assign).
// - Resolved -> Closed/Reopened are the *customer's* moves (confirm fix /
//   reopen on the portal), not an agent action, but they're still just
//   ordinary entries in the same graph.
const STATUS_TRANSITIONS = {
  Created: [],
  Assigned: ['In Progress'],
  'In Progress': ['Waiting', 'Escalated', 'Resolved'],
  Waiting: ['In Progress'],
  Escalated: ['In Progress'],
  Reopened: ['In Progress'],
  Resolved: ['Closed', 'Reopened'],
  Closed: []
};

function canTransition(from, to) {
  return (STATUS_TRANSITIONS[from] || []).includes(to);
}

// Customer-visible attachment count: creation-time attachments always
// count; chat attachments only count if they were posted on a public
// comment. ticket_attachments enforces ticket_id XOR comment_id (see
// schema.sql), so a comment's attachment never carries the ticket_id
// directly — reach its owning ticket through comment_id ->
// ticket_comments.ticket_id.
async function attachmentCount(ticketId) {
  const result = await db.query(
    `SELECT COUNT(*) AS n FROM ticket_attachments ta
     LEFT JOIN ticket_comments tc ON ta.comment_id = tc.id
     WHERE ta.ticket_id = $1 OR (tc.ticket_id = $1 AND tc.visibility = 'public')`,
    [ticketId]
  );
  return Number(result.rows[0].n);
}

// Creation-time attachments only (comment_id IS NULL) — chat attachments
// travel with their comment instead (see comments.js). stored_path is
// never sent to the client — it only ever needs the id, to build a
// GET /api/attachments/:id download link.
async function ticketAttachments(ticketId) {
  const result = await db.query(
    `SELECT id, filename, mime_type, size_bytes FROM ticket_attachments
     WHERE ticket_id = $1 AND comment_id IS NULL
     ORDER BY id ASC`,
    [ticketId]
  );
  return result.rows;
}

// LEFT JOIN (not JOIN) so a ticket never disappears from a queue just
// because its requester's user record is missing/inconsistent — requester_email
// simply comes back null in that case, same as any other optional field.
async function ticketWithComments(id) {
  const ticketResult = await db.query(
    'SELECT t.*, u.email AS requester_email FROM tickets t LEFT JOIN users u ON u.id = t.user_id WHERE t.id = $1',
    [id]
  );
  const ticket = ticketResult.rows[0];
  if (!ticket) return null;
  const commentsResult = await db.query(
    'SELECT * FROM ticket_comments WHERE ticket_id = $1 ORDER BY created_at ASC',
    [id]
  );
  const [count, attachments] = await Promise.all([attachmentCount(id), ticketAttachments(id)]);
  return { ...ticket, attachment_count: count, attachments, comments: commentsResult.rows };
}

// Validates one incoming attachment payload and — if it carries content —
// uploads it immediately, before any DB row exists for it. Accepts the
// { filename, content_base64, mime_type? } shape the client sends; also
// tolerates a bare filename string or an object with no content_base64
// (nothing to upload, so stored_path stays null).
async function normalizeIncomingAttachment(ticketId, a) {
  if (!a) return null;
  if (typeof a === 'string') {
    const filename = a.trim();
    return filename ? { filename, mime_type: null, size_bytes: null, stored_path: null } : null;
  }
  const filename = a.filename && String(a.filename).trim();
  if (!filename) return null;
  if (!a.content_base64) {
    return { filename, mime_type: a.mime_type || null, size_bytes: null, stored_path: null };
  }
  const { storedPath, sizeBytes } = await saveAttachmentFile(ticketId, filename, a.content_base64);
  return { filename, mime_type: a.mime_type || null, size_bytes: sizeBytes, stored_path: storedPath };
}

// POST /api/tickets
// body: { user_id?, subject, description, category, priority, affected_service?,
//         attachments?: [{ filename, content_base64, mime_type? }, ...] }
// user_id comes from the authenticated actor when they're a customer —
// the body's user_id is only honored when an admin is creating a ticket
// on a customer's behalf (e.g. phone-in tickets). Agents cannot create
// tickets at all, per the authorization matrix.
router.post('/', requireAuth(['user', 'admin']), asyncHandler(async (req, res) => {
  const { subject, description, category, priority, affected_service, attachments } = req.body || {};

  const user_id = req.actor.role === 'user' ? req.actor.id : req.body?.user_id;

  if (!user_id) return res.status(400).json({ error: 'user_id is required' });
  if (!subject || !subject.trim()) return res.status(400).json({ error: 'subject is required' });
  if (!description || !description.trim()) return res.status(400).json({ error: 'description is required' });
  if (!VALID_CATEGORIES.includes(category)) {
    return res.status(400).json({ error: `category must be one of: ${VALID_CATEGORIES.join(', ')}` });
  }
  if (!VALID_PRIORITIES.includes(priority)) {
    return res.status(400).json({ error: `priority must be one of: ${VALID_PRIORITIES.join(', ')}` });
  }

  const userResult = await db.query('SELECT id FROM users WHERE id = $1', [user_id]);
  if (!userResult.rows[0]) return res.status(404).json({ error: 'user_id does not exist' });

  const id = await nextId(db, 'tickets', 'TKT');
  const team = TEAM_BY_CATEGORY[category];
  const sla = slaSummary(priority);

  // Files are uploaded before the ticket row exists — a size-cap failure
  // here means the ticket is never created at all, rather than ending up
  // with a ticket that references a half-written attachment list.
  let normalizedAttachments;
  try {
    normalizedAttachments = Array.isArray(attachments)
      ? (await Promise.all(attachments.map((a) => normalizeIncomingAttachment(id, a)))).filter(Boolean)
      : [];
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  try {
    await db.withTransaction(async (client) => {
      await client.query(
        `INSERT INTO tickets
           (id, user_id, subject, description, category, priority, status,
            affected_service, assigned_team, sla_summary)
         VALUES ($1, $2, $3, $4, $5, $6, 'Created', $7, $8, $9)`,
        [id, user_id, subject.trim(), description.trim(), category, priority, affected_service || null, team, sla]
      );

      for (const a of normalizedAttachments) {
        await client.query(
          `INSERT INTO ticket_attachments (ticket_id, filename, mime_type, size_bytes, stored_path)
           VALUES ($1, $2, $3, $4, $5)`,
          [id, a.filename, a.mime_type, a.size_bytes, a.stored_path]
        );
      }
    });
  } catch (err) {
    console.error('POST /api/tickets: failed to persist ticket', err);
    return res.status(500).json({ error: 'failed to create ticket' });
  }

  recordAuditLog({
    actorType: req.actor.role,
    actorId: req.actor.id,
    actorName: await resolveActorName(req.actor),
    action: 'ticket.created',
    entityType: 'ticket',
    entityId: id,
    details: { subject: subject.trim(), category, priority }
  });

  res.status(201).json(await ticketWithComments(id));
}));

// GET /api/tickets?user_id=...&assigned_agent_id=...&status=...
// user_id/assigned_agent_id in the query string are only advisory now —
// for 'user' and 'agent' actors the filter is forced to their own id
// server-side, regardless of what the query string says, so no actor can
// list another customer's or another agent's tickets by editing the URL.
// Admins may filter by whatever they like, including neither (all tickets).
router.get('/', requireAuth(), asyncHandler(async (req, res) => {
  const { status } = req.query;
  let sql = 'SELECT t.*, u.email AS requester_email FROM tickets t LEFT JOIN users u ON u.id = t.user_id WHERE 1=1';
  const params = [];

  if (req.actor.role === 'user') {
    params.push(req.actor.id); sql += ` AND t.user_id = $${params.length}`;
  } else if (req.actor.role === 'agent') {
    params.push(req.actor.id); sql += ` AND t.assigned_agent_id = $${params.length}`;
  } else if (req.actor.role === 'admin') {
    if (req.query.user_id) { params.push(req.query.user_id); sql += ` AND t.user_id = $${params.length}`; }
    if (req.query.assigned_agent_id) { params.push(req.query.assigned_agent_id); sql += ` AND t.assigned_agent_id = $${params.length}`; }
  }
  if (status) { params.push(status); sql += ` AND t.status = $${params.length}`; }

  sql += ' ORDER BY t.created_at DESC';

  try {
    const result = await db.query(sql, params);
    const rows = await Promise.all(result.rows.map(async (t) => ({
      ...t,
      attachment_count: await attachmentCount(t.id),
      attachments: await ticketAttachments(t.id)
    })));
    res.json(rows);
  } catch (err) {
    console.error('GET /api/tickets error:', err);
    res.status(500).json({ error: 'failed to load tickets' });
  }
}));

// GET /api/tickets/:id  (includes comments + attachment_count + attachments)
router.get(
  '/:id',
  requireAuth(),
  requireTicketAccess({ allowCustomer: true, allowAssignedAgent: true, allowAdmin: true }),
  asyncHandler(async (req, res) => {
    // req.ticket was already fetched and permission-checked by
    // requireTicketAccess; ticketWithComments re-fetches so it can attach
    // comments/attachments in the same shape as every other response.
    try {
      res.json(await ticketWithComments(req.params.id));
    } catch (err) {
      console.error('GET /api/tickets/:id error:', err);
      res.status(500).json({ error: 'failed to load ticket' });
    }
  })
);

// PATCH /api/tickets/:id/assign
// body: { assigned_agent_id }  — pass null/omit to unassign.
// Mirrors app.js's reassign handler: claiming an unassigned Created ticket
// bumps it to Assigned; sending it back to Unassigned resets it to Created
// (unless it's Resolved/Closed, which stays put either way).
// Admin-only for now.
router.patch('/:id/assign', requireAuth(['admin']), asyncHandler(async (req, res) => {
  const ticketResult = await db.query('SELECT * FROM tickets WHERE id = $1', [req.params.id]);
  const ticket = ticketResult.rows[0];
  if (!ticket) return res.status(404).json({ error: 'not found' });

  // Resolved means it's sitting with the customer awaiting their confirm-fix/
  // reopen decision, and Closed is the end of the line — swapping the owning
  // agent on either doesn't make sense, same as the agent-side reassign panel
  // (app.js's canReassign) already refuses to open for these two statuses.
  if (ticket.status === 'Closed' || ticket.status === 'Resolved') {
    return res.status(400).json({ error: `cannot reassign a ${ticket.status.toLowerCase()} ticket` });
  }

  const assignedAgentId = req.body && req.body.assigned_agent_id ? req.body.assigned_agent_id : null;

  if (assignedAgentId) {
    const agentResult = await db.query('SELECT id FROM agents WHERE id = $1', [assignedAgentId]);
    if (!agentResult.rows[0]) return res.status(404).json({ error: 'assigned_agent_id does not exist' });
  }

  let newStatus = ticket.status;
  if (assignedAgentId) {
    if (ticket.status === 'Created') newStatus = 'Assigned';
  } else if (ticket.status !== 'Resolved' && ticket.status !== 'Closed') {
    newStatus = 'Created';
  }

  try {
    // Assigning (by anyone — this route is admin-only) consumes any
    // pending suggested_agent_id an agent left behind while escalating,
    // whether or not the admin actually went with that suggestion.
    await db.query(
      `UPDATE tickets SET assigned_agent_id = $1, status = $2, suggested_agent_id = NULL, updated_at = now() WHERE id = $3`,
      [assignedAgentId, newStatus, req.params.id]
    );
  } catch (err) {
    console.error('PATCH /:id/assign error:', err);
    return res.status(500).json({ error: 'failed to update assignment' });
  }

  recordAuditLog({
    actorType: req.actor.role,
    actorId: req.actor.id,
    actorName: await resolveActorName(req.actor),
    action: assignedAgentId ? 'ticket.assigned' : 'ticket.unassigned',
    entityType: 'ticket',
    entityId: req.params.id,
    details: { from_agent_id: ticket.assigned_agent_id, to_agent_id: assignedAgentId, status: newStatus }
  });

  res.json(await ticketWithComments(req.params.id));
}));

// PATCH /api/tickets/:id/status
// body: { status, resolution_summary?, escalated_to?, escalation_reason?, suggested_agent_id? }
// Resolving requires resolution_summary; escalating requires both
// escalated_to and escalation_reason — same hard requirements app.js's
// resolve/escalate panels enforce client-side.
//
// suggested_agent_id is optional and only meaningful on an Escalated
// transition: an agent still can't assign/reassign a ticket themselves
// (PATCH /:id/assign stays admin-only), but they can leave a recommendation
// here for the admin console to pre-fill instead of showing a blank
// reassign dropdown.
router.patch(
  '/:id/status',
  requireAuth(),
  // allowCustomer is scoped down further below: STATUS_TRANSITIONS lets
  // Resolved move to Closed/Reopened (the "confirm fix" / "reopen" buttons
  // on the customer portal), but that's the *only* move a customer should
  // ever be able to trigger through this route — every other transition
  // stays agent/admin-only even though the graph would technically allow it.
  requireTicketAccess({ allowCustomer: true, allowAssignedAgent: true, allowAdmin: true }),
  asyncHandler(async (req, res) => {
    const ticket = req.ticket;

    const { status, resolution_summary, escalated_to, escalation_reason, suggested_agent_id } = req.body || {};
    if (!status || !canTransition(ticket.status, status)) {
      return res.status(400).json({
        error: `cannot move ticket from "${ticket.status}" to "${status}"`,
        allowed_next_states: STATUS_TRANSITIONS[ticket.status] || []
      });
    }

    if (req.actor.role === 'user' && !(ticket.status === 'Resolved' && (status === 'Closed' || status === 'Reopened'))) {
      return res.status(403).json({ error: 'Not authorized to make this change' });
    }

    if (status === 'Resolved' && (!resolution_summary || !resolution_summary.trim())) {
      return res.status(400).json({ error: 'resolution_summary is required to resolve a ticket' });
    }
    if (status === 'Escalated' && (!escalated_to || !escalation_reason || !escalation_reason.trim())) {
      return res.status(400).json({ error: 'escalated_to and escalation_reason are both required to escalate a ticket' });
    }

    let suggestedAgentId = null;
    if (status === 'Escalated' && suggested_agent_id) {
      const agentResult = await db.query('SELECT id FROM agents WHERE id = $1', [suggested_agent_id]);
      if (!agentResult.rows[0]) return res.status(404).json({ error: 'suggested_agent_id does not exist' });
      suggestedAgentId = suggested_agent_id;
    }

    try {
      await db.query(
        `UPDATE tickets
         SET status = $1,
             resolution_summary = COALESCE($2, resolution_summary),
             escalated_to = COALESCE($3, escalated_to),
             escalation_reason = COALESCE($4, escalation_reason),
             suggested_agent_id = CASE WHEN $5 = 'Escalated' THEN $6 ELSE suggested_agent_id END,
             updated_at = now()
         WHERE id = $7`,
        [status, resolution_summary || null, escalated_to || null, escalation_reason || null, status, suggestedAgentId, req.params.id]
      );
    } catch (err) {
      console.error('PATCH /:id/status error:', err);
      return res.status(500).json({ error: 'failed to update status' });
    }

    recordAuditLog({
      actorType: req.actor.role,
      actorId: req.actor.id,
      actorName: await resolveActorName(req.actor),
      action: 'ticket.status_changed',
      entityType: 'ticket',
      entityId: req.params.id,
      details: {
        from_status: ticket.status,
        to_status: status,
        resolution_summary: resolution_summary || undefined,
        escalated_to: escalated_to || undefined,
        escalation_reason: escalation_reason || undefined
      }
    });

    res.json(await ticketWithComments(req.params.id));
  })
);

// PATCH /api/tickets/:id/csat  { csat_rating (1-5), csat_comment? }
// Only valid once a ticket is Closed and not already rated — mirrors the
// portal's csatPanel/csatDone toggle. Customer-only per the authorization
// matrix: agents and admins never submit CSAT on a customer's behalf.
router.patch(
  '/:id/csat',
  requireAuth(),
  requireTicketAccess({ allowCustomer: true }),
  asyncHandler(async (req, res) => {
    const ticket = req.ticket;

    if (ticket.status !== 'Closed') {
      return res.status(400).json({ error: 'ticket must be Closed before it can be rated' });
    }
    if (ticket.csat_rating != null) {
      return res.status(400).json({ error: 'ticket has already been rated' });
    }

    const rating = Number(req.body && req.body.csat_rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'csat_rating must be an integer 1-5' });
    }
    const comment = (req.body && req.body.csat_comment) || null;

    try {
      await db.query(
        `UPDATE tickets SET csat_rating = $1, csat_comment = $2, updated_at = now() WHERE id = $3`,
        [rating, comment, req.params.id]
      );
    } catch (err) {
      console.error('PATCH /:id/csat error:', err);
      return res.status(500).json({ error: 'failed to submit feedback' });
    }

    recordAuditLog({
      actorType: req.actor.role,
      actorId: req.actor.id,
      actorName: await resolveActorName(req.actor),
      action: 'ticket.csat_submitted',
      entityType: 'ticket',
      entityId: req.params.id,
      details: { rating, comment: comment || undefined }
    });

    res.json(await ticketWithComments(req.params.id));
  })
);

module.exports = router;
