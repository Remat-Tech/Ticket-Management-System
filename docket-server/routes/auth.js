// POST /api/auth/login
//
// Deliberately generic: this route knows nothing about "admin login" vs
// "agent login" vs "user login" — it just authenticates an (email,
// password) pair against whichever row in users/agents/admins owns that
// email, using auth_credentials for the actual credential check.
// Authorization (what an admin vs agent vs user is *allowed to do* once
// logged in) is a separate concern, handled by requireAuth(role) in
// middleware/authenticate.js on individual routes — not by having three
// separate login endpoints.
//
// A correct password doesn't log you in by itself: it starts an email MFA
// challenge (see utils/mfa.js) and the token is issued by POST /mfa/verify.

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { signToken } = require('../middleware/authenticate');
const { recordAuditLog } = require('../utils/audit');
const { nextId } = require('../utils/ids');
const { createChallenge, verifyChallenge, resendChallenge, MfaError, sendMfaError } = require('../utils/mfa');

const router = express.Router();

// (table, owner_type) pairs to search for the email. Order doesn't imply
// priority — an email existing in more than one table is treated as a
// data problem (see below), not resolved by "first match wins".
const OWNER_TABLES = [
  { table: 'users', ownerType: 'user' },
  { table: 'agents', ownerType: 'agent' },
  { table: 'admins', ownerType: 'admin' }
];

async function findOwnerByEmail(email, roleHint) {
  const candidates = [];
  for (const { table, ownerType } of OWNER_TABLES) {
    if (roleHint && ownerType !== roleHint) continue;
    const result = await db.query(`SELECT id, email, full_name FROM ${table} WHERE email = $1`, [email]);
    if (result.rows[0]) candidates.push({ ownerType, ...result.rows[0] });
  }
  return candidates;
}

router.post('/login', async (req, res) => {
  const { email, password, role } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (role && !OWNER_TABLES.some((t) => t.ownerType === role)) {
    return res.status(400).json({ error: `role must be one of: ${OWNER_TABLES.map((t) => t.ownerType).join(', ')}` });
  }

  try {
    const matches = await findOwnerByEmail(email, role);

    if (matches.length === 0) {
      recordAuditLog({
        actorType: role || 'unknown',
        action: 'auth.login_failed',
        details: { email, reason: 'no such account' }
      });
      // Same response as a wrong password — don't reveal whether the email
      // exists at all.
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (matches.length > 1) {
      // The same email exists as e.g. both a user and an agent. That's a
      // data-integrity issue, not something the login route should silently
      // guess its way through — ask the caller to disambiguate.
      console.error(`Login: email ${email} matches multiple owner types: ${matches.map((m) => m.ownerType).join(', ')}`);
      return res.status(409).json({
        error: 'This email is associated with more than one account type. Specify which one to log in as.',
        roles: matches.map((m) => m.ownerType)
      });
    }

    const owner = matches[0];
    const credResult = await db.query(
      'SELECT * FROM auth_credentials WHERE owner_type = $1 AND owner_id = $2',
      [owner.ownerType, owner.id]
    );
    const cred = credResult.rows[0];

    if (!cred || cred.auth_provider !== 'local' || !cred.password_hash) {
      recordAuditLog({
        actorType: owner.ownerType,
        actorId: owner.id,
        actorName: owner.full_name,
        action: 'auth.login_failed',
        details: { email, reason: 'no local credentials' }
      });
      // No credentials row at all (never set a password), or an SSO-only
      // account trying to use password login.
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const ok = bcrypt.compareSync(password, cred.password_hash);
    if (!ok) {
      recordAuditLog({
        actorType: owner.ownerType,
        actorId: owner.id,
        actorName: owner.full_name,
        action: 'auth.login_failed',
        details: { email, reason: 'wrong password' }
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Password is right — but no token yet. The token only comes out of
    // POST /mfa/verify once the emailed code is entered.
    const challenge = await createChallenge({
      ownerType: owner.ownerType,
      ownerId: owner.id,
      email: owner.email,
      fullName: owner.full_name
    });

    recordAuditLog({
      actorType: owner.ownerType,
      actorId: owner.id,
      actorName: owner.full_name,
      action: 'auth.mfa_sent',
      details: { email }
    });

    res.json(challenge);
  } catch (err) {
    if (err instanceof MfaError) return sendMfaError(res, err);
    console.error('POST /api/auth/login error:', err);
    res.status(500).json({ error: 'failed to log in' });
  }
});

// Finds the account a verified challenge belongs to — or, for a first-time
// user/agent sign-in, creates it now that the email is proven. Returns
// { record, created }.
async function resolveChallengeOwner(challenge) {
  const table = OWNER_TABLES.find((t) => t.ownerType === challenge.owner_type).table;

  if (challenge.owner_id) {
    const result = await db.query(`SELECT * FROM ${table} WHERE id = $1`, [challenge.owner_id]);
    return { record: result.rows[0], created: false };
  }

  const pending = challenge.context.pending;
  if (!pending || table === 'admins') return { record: null, created: false };

  // Two sign-ups for the same new email can both reach here; the second one
  // just picks up the row the first created.
  const existing = await db.query(`SELECT * FROM ${table} WHERE email = $1`, [challenge.email]);
  if (existing.rows[0]) return { record: existing.rows[0], created: false };

  let inserted;
  if (table === 'users') {
    const id = await nextId(db, 'users', 'USR');
    inserted = await db.query(
      `INSERT INTO users (id, full_name, email, phone, department, organization)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (email) DO NOTHING RETURNING *`,
      [id, pending.full_name, challenge.email, pending.phone || null, pending.department || null, pending.organization || null]
    );
  } else {
    const id = await nextId(db, 'agents', 'AGT');
    inserted = await db.query(
      `INSERT INTO agents (id, full_name, email, created_by) VALUES ($1, $2, $3, 'self-signup')
       ON CONFLICT (email) DO NOTHING RETURNING *`,
      [id, pending.full_name, challenge.email]
    );
    if (inserted.rows[0]) {
      recordAuditLog({
        actorType: 'agent',
        actorName: pending.full_name,
        action: 'agent.created',
        entityType: 'agent',
        entityId: inserted.rows[0].id,
        details: { email: challenge.email, created_by: 'self-signup' }
      });
    }
  }

  if (inserted.rows[0]) return { record: inserted.rows[0], created: true };
  const raced = await db.query(`SELECT * FROM ${table} WHERE email = $1`, [challenge.email]);
  return { record: raced.rows[0], created: false };
}

// POST /api/auth/mfa/verify  { challengeId, code }
// The only route that issues a session token. Response:
//   { token, actor: { id, email, full_name, role }, record, returning }
// where `record` is the full users/agents/admins row.
router.post('/mfa/verify', async (req, res) => {
  const { challengeId, code } = req.body || {};

  try {
    const challenge = await verifyChallenge(challengeId, code);
    const { record, created } = await resolveChallengeOwner(challenge);

    if (!record) {
      // The account was deleted between login and verify.
      return res.status(401).json({ error: 'This account no longer exists.', restart: true });
    }

    await db.query(
      `UPDATE auth_credentials SET last_login_at = now(), updated_at = now()
       WHERE owner_type = $1 AND owner_id = $2`,
      [challenge.owner_type, record.id]
    );

    const token = signToken({ ownerType: challenge.owner_type, ownerId: record.id });

    recordAuditLog({
      actorType: challenge.owner_type,
      actorId: record.id,
      actorName: record.full_name,
      action: 'auth.login_success',
      details: { email: record.email, mfa: 'email' }
    });

    res.json({
      token,
      actor: {
        id: record.id,
        email: record.email,
        full_name: record.full_name,
        role: challenge.owner_type
      },
      record,
      returning: !created
    });
  } catch (err) {
    if (err instanceof MfaError) {
      const challenge = err.extra.challenge;
      recordAuditLog({
        actorType: challenge ? challenge.owner_type : 'unknown',
        actorId: challenge ? challenge.owner_id : null,
        action: 'auth.mfa_failed',
        details: { email: challenge ? challenge.email : null, reason: err.message }
      });
      return sendMfaError(res, err);
    }
    console.error('POST /api/auth/mfa/verify error:', err);
    res.status(500).json({ error: 'failed to verify code' });
  }
});

// POST /api/auth/mfa/resend  { challengeId }
router.post('/mfa/resend', async (req, res) => {
  try {
    res.json(await resendChallenge((req.body || {}).challengeId));
  } catch (err) {
    if (err instanceof MfaError) return sendMfaError(res, err);
    console.error('POST /api/auth/mfa/resend error:', err);
    res.status(500).json({ error: 'failed to resend code' });
  }
});

module.exports = router;
