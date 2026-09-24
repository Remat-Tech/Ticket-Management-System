const express = require('express');
const db = require('../db/connection');
const { recordAuditLog } = require('../utils/audit');
const { createChallenge, MfaError, sendMfaError } = require('../utils/mfa');

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// POST /api/users
// Sign-in / sign-up for customers, who have no password: the emailed MFA
// code is the credential. Either way (new or returning email) this only
// starts a challenge and responds { mfaRequired, challengeId } — the token
// and the user record come from POST /api/auth/mfa/verify. A new user's
// row isn't created until then, so nobody can register someone else's
// email.
router.post('/', async (req, res) => {
  const { full_name, email, phone, department, organization } = req.body || {};

  if (!full_name || !full_name.trim()) {
    return res.status(400).json({ error: 'full_name is required' });
  }
  if (!email || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: 'a valid email is required' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  try {
    const existingResult = await db.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const existing = existingResult.rows[0];

    const challenge = existing
      ? await createChallenge({ ownerType: 'user', ownerId: existing.id, email: normalizedEmail, fullName: existing.full_name })
      : await createChallenge({
          ownerType: 'user',
          email: normalizedEmail,
          fullName: full_name.trim(),
          context: {
            pending: {
              full_name: full_name.trim(),
              phone: phone || null,
              department: department || null,
              organization: organization || null
            }
          }
        });

    recordAuditLog({
      actorType: 'user',
      actorId: existing ? existing.id : null,
      actorName: existing ? existing.full_name : full_name.trim(),
      action: 'auth.mfa_sent',
      details: { email: normalizedEmail, new_account: !existing }
    });

    res.json(challenge);
  } catch (err) {
    if (err instanceof MfaError) return sendMfaError(res, err);
    console.error('POST /api/users error:', err);
    res.status(500).json({ error: 'failed to save profile' });
  }
});

// GET /api/users/by-email/:email
router.get('/by-email/:email', async (req, res) => {
  const email = req.params.email.trim().toLowerCase();
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!result.rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('GET /api/users/by-email error:', err);
    res.status(500).json({ error: 'failed to load user' });
  }
});

// GET /api/users/:id
router.get('/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('GET /api/users/:id error:', err);
    res.status(500).json({ error: 'failed to load user' });
  }
});

// GET /api/users
router.get('/', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM users ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/users error:', err);
    res.status(500).json({ error: 'failed to load users' });
  }
});

module.exports = router;
