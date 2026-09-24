const express = require('express');
const db = require('../db/connection');
const { nextId } = require('../utils/ids');
const { verifyToken } = require('../middleware/authenticate');
const { recordAuditLog } = require('../utils/audit');
const { createChallenge, MfaError, sendMfaError } = require('../utils/mfa');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VALID_CREATED_BY = ['seed', 'self-signup', 'admin'];

// GET /api/agents
router.get('/', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM agents ORDER BY full_name ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/agents error:', err);
    res.status(500).json({ error: 'failed to load agents' });
  }
});

// GET /api/agents/:id
router.get('/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM agents WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('GET /api/agents/:id error:', err);
    res.status(500).json({ error: 'failed to load agent' });
  }
});

// POST /api/agents
// Two real callers with different rules, same endpoint:
//  1. Agent self-sign-in (agent-login.html) — agents have no password, so
//     the emailed MFA code is the credential. Responds
//     { mfaRequired, challengeId }; the token (and, for a new email, the
//     agent row itself) comes from POST /api/auth/mfa/verify.
//  2. Admin "add an agent" (admin-dashboard.html) — created_by: 'admin',
//     requires an admin token, and a duplicate email is a hard error. No
//     token is returned: the new agent signs in themselves, via MFA.
router.post('/', async (req, res) => {
  const { full_name, email, created_by } = req.body || {};
  const createdBy = VALID_CREATED_BY.includes(created_by) ? created_by : 'self-signup';

  if (createdBy !== 'self-signup') {
    const header = req.headers.authorization || '';
    const payload = verifyToken(header.startsWith('Bearer ') ? header.slice(7) : null);
    if (!payload || payload.ownerType !== 'admin') {
      return res.status(403).json({ error: 'Only an admin can add agents' });
    }
  }

  if (!full_name || !full_name.trim()) {
    return res.status(400).json({ error: 'full_name is required' });
  }
  if (!email || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: 'a valid email is required' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  try {
    const existingResult = await db.query('SELECT * FROM agents WHERE email = $1', [normalizedEmail]);
    const existing = existingResult.rows[0];

    if (createdBy === 'self-signup') {
      const challenge = existing
        ? await createChallenge({ ownerType: 'agent', ownerId: existing.id, email: normalizedEmail, fullName: existing.full_name })
        : await createChallenge({
            ownerType: 'agent',
            email: normalizedEmail,
            fullName: full_name.trim(),
            context: { pending: { full_name: full_name.trim() } }
          });

      recordAuditLog({
        actorType: 'agent',
        actorId: existing ? existing.id : null,
        actorName: existing ? existing.full_name : full_name.trim(),
        action: 'auth.mfa_sent',
        details: { email: normalizedEmail, new_account: !existing }
      });

      return res.json(challenge);
    }

    if (existing) {
      return res.status(409).json({ error: 'an agent with this email already exists' });
    }

    const id = await nextId(db, 'agents', 'AGT');
    const insertResult = await db.query(
      'INSERT INTO agents (id, full_name, email, created_by) VALUES ($1, $2, $3, $4) RETURNING *',
      [id, full_name.trim(), normalizedEmail, createdBy]
    );

    recordAuditLog({
      actorType: 'admin',
      actorName: 'Admin console',
      action: 'agent.created',
      entityType: 'agent',
      entityId: id,
      details: { email: normalizedEmail, created_by: createdBy }
    });

    res.status(201).json(insertResult.rows[0]);
  } catch (err) {
    if (err instanceof MfaError) return sendMfaError(res, err);
    console.error('POST /api/agents error:', err);
    res.status(500).json({ error: 'failed to save agent' });
  }
});

// GET /api/agents/:id/tickets — tickets currently assigned to this agent
router.get('/:id/tickets', async (req, res) => {
  try {
    const agentResult = await db.query('SELECT id FROM agents WHERE id = $1', [req.params.id]);
    if (!agentResult.rows[0]) return res.status(404).json({ error: 'not found' });

    const ticketsResult = await db.query(
      'SELECT * FROM tickets WHERE assigned_agent_id = $1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json(ticketsResult.rows);
  } catch (err) {
    console.error('GET /api/agents/:id/tickets error:', err);
    res.status(500).json({ error: 'failed to load tickets' });
  }
});

module.exports = router;
