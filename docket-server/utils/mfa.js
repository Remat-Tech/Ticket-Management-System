// Email MFA: every sign-in (user, agent, admin) ends with a 5-digit code
// emailed to the account's address, and no session token is issued until
// it's entered. The routes that used to mint a token directly
// (POST /api/auth/login, POST /api/users, POST /api/agents) now call
// createChallenge() instead; POST /api/auth/mfa/verify is the one place a
// token comes out.
//
// A 5-digit code has only 100,000 values, so the limits below are what make
// it safe, not the code length:
//   - MAX_ATTEMPTS wrong guesses burn the challenge (start over from login)
//   - MAX_CHALLENGES_PER_WINDOW new challenges per email per window, so an
//     attacker can't just keep requesting fresh codes to guess against
//   - a new challenge expires any older unused one for the same email
//   - codes expire after CODE_TTL_MINUTES and are single-use
// Only an HMAC of the code is stored — a database leak doesn't expose
// live codes.

const crypto = require('crypto');
const db = require('../db/connection');
const { sendEmail } = require('./email');

const CODE_TTL_MINUTES = 10;
const MAX_ATTEMPTS = 5;
const MAX_SENDS = 3;                 // initial send + 2 resends
const RESEND_COOLDOWN_SECONDS = 60;
const MAX_CHALLENGES_PER_WINDOW = 5;
const CHALLENGE_WINDOW_MINUTES = 15;

const SECRET = process.env.AUTH_TOKEN_SECRET;

// Thrown for anything the route should turn into a specific HTTP status
// rather than a generic 500.
class MfaError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.extra = extra || {};
  }
}

function generateCode() {
  return String(crypto.randomInt(0, 100000)).padStart(5, '0');
}

// Salted with the challenge id so the same code on two challenges never
// hashes the same.
function hashCode(challengeId, code) {
  return crypto.createHmac('sha256', SECRET).update(`${challengeId}:${code}`).digest('hex');
}

function codesMatch(challengeId, code, storedHash) {
  const a = Buffer.from(hashCode(challengeId, code), 'hex');
  const b = Buffer.from(storedHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function sendCodeEmail(email, fullName, code) {
  const greeting = fullName ? `Hi ${fullName.split(' ')[0]},` : 'Hi,';
  await sendEmail({
    to: email,
    subject: `Your Docket sign-in code: ${code}`,
    text:
      `${greeting}\n\nYour Docket sign-in code is ${code}. It expires in ${CODE_TTL_MINUTES} minutes.\n\n` +
      `If you didn't try to sign in, you can ignore this email — no one can get in without this code.`,
    html:
      `<p>${greeting}</p>` +
      `<p>Your Docket sign-in code is:</p>` +
      `<p style="font-size:28px;font-weight:700;letter-spacing:6px;margin:16px 0">${code}</p>` +
      `<p>It expires in ${CODE_TTL_MINUTES} minutes.</p>` +
      `<p style="color:#6B6A61">If you didn't try to sign in, you can ignore this email — no one can get in without this code.</p>`
  });
}

// ownerId is null for a first-time sign-up; context.pending then carries
// the profile to create once the code is verified.
async function createChallenge({ ownerType, ownerId, email, fullName, context }) {
  const recent = await db.query(
    `SELECT COUNT(*) AS n FROM mfa_challenges
     WHERE owner_type = $1 AND email = $2 AND created_at > now() - make_interval(mins => $3)`,
    [ownerType, email, CHALLENGE_WINDOW_MINUTES]
  );
  if (Number(recent.rows[0].n) >= MAX_CHALLENGES_PER_WINDOW) {
    throw new MfaError(429, `Too many sign-in attempts. Try again in ${CHALLENGE_WINDOW_MINUTES} minutes.`);
  }

  // Housekeeping, and invalidate any code still outstanding for this email.
  await db.query(`DELETE FROM mfa_challenges WHERE created_at < now() - interval '1 day'`);
  await db.query(
    `UPDATE mfa_challenges SET expires_at = now()
     WHERE owner_type = $1 AND email = $2 AND consumed_at IS NULL AND expires_at > now()`,
    [ownerType, email]
  );

  const id = crypto.randomUUID();
  const code = generateCode();
  await db.query(
    `INSERT INTO mfa_challenges (id, owner_type, owner_id, email, code_hash, context, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(mins => $7))`,
    [id, ownerType, ownerId || null, email, hashCode(id, code), JSON.stringify({ ...context, full_name: fullName || null }), CODE_TTL_MINUTES]
  );

  try {
    await sendCodeEmail(email, fullName, code);
  } catch (err) {
    console.error('MFA: failed to send code email:', err);
    await db.query('UPDATE mfa_challenges SET expires_at = now() WHERE id = $1', [id]);
    throw new MfaError(502, "We couldn't send your sign-in code. Please try again shortly.");
  }

  return { mfaRequired: true, challengeId: id, expiresInSeconds: CODE_TTL_MINUTES * 60 };
}

// Returns the challenge row on success; throws MfaError otherwise.
async function verifyChallenge(challengeId, code) {
  if (typeof challengeId !== 'string' || typeof code !== 'string' || !/^\d{5}$/.test(code.trim())) {
    throw new MfaError(400, 'Enter the 5-digit code from your email.');
  }

  // Count the attempt atomically before checking it, so parallel guesses
  // can't slip past MAX_ATTEMPTS.
  const claimed = await db.query(
    `UPDATE mfa_challenges SET attempts = attempts + 1
     WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < $2
     RETURNING *`,
    [challengeId, MAX_ATTEMPTS]
  );
  const challenge = claimed.rows[0];

  if (!challenge) {
    const existing = await db.query('SELECT attempts, consumed_at, expires_at FROM mfa_challenges WHERE id = $1', [challengeId]);
    const row = existing.rows[0];
    if (row && !row.consumed_at && row.attempts >= MAX_ATTEMPTS) {
      throw new MfaError(429, 'Too many incorrect codes. Please sign in again.', { restart: true });
    }
    throw new MfaError(401, 'This code has expired. Please sign in again.', { restart: true });
  }

  if (!codesMatch(challengeId, code.trim(), challenge.code_hash)) {
    const attemptsRemaining = MAX_ATTEMPTS - challenge.attempts;
    if (attemptsRemaining <= 0) {
      throw new MfaError(429, 'Too many incorrect codes. Please sign in again.', { restart: true, challenge });
    }
    throw new MfaError(401, 'Incorrect code.', { attemptsRemaining, challenge });
  }

  const consumed = await db.query(
    'UPDATE mfa_challenges SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL RETURNING id',
    [challengeId]
  );
  if (!consumed.rows[0]) {
    throw new MfaError(401, 'This code has already been used. Please sign in again.', { restart: true });
  }

  return challenge;
}

async function resendChallenge(challengeId) {
  if (typeof challengeId !== 'string') throw new MfaError(400, 'challengeId is required');

  const result = await db.query(
    `SELECT *, EXTRACT(EPOCH FROM (now() - last_sent_at)) AS seconds_since_send
     FROM mfa_challenges
     WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() AND attempts < $2`,
    [challengeId, MAX_ATTEMPTS]
  );
  const challenge = result.rows[0];
  if (!challenge) {
    throw new MfaError(401, 'This sign-in has expired. Please sign in again.', { restart: true });
  }
  if (challenge.send_count >= MAX_SENDS) {
    throw new MfaError(429, "You've requested too many codes. Please sign in again.", { restart: true });
  }
  const wait = Math.ceil(RESEND_COOLDOWN_SECONDS - Number(challenge.seconds_since_send));
  if (wait > 0) {
    throw new MfaError(429, `Please wait ${wait}s before requesting another code.`, { retryAfterSeconds: wait });
  }

  // A fresh code (the old one stops working) and a fresh expiry. The
  // send_count guard makes two simultaneous resend clicks send only once.
  const code = generateCode();
  const updated = await db.query(
    `UPDATE mfa_challenges
     SET code_hash = $2, send_count = send_count + 1, last_sent_at = now(),
         expires_at = now() + make_interval(mins => $3)
     WHERE id = $1 AND send_count = $4
     RETURNING id`,
    [challengeId, hashCode(challengeId, code), CODE_TTL_MINUTES, challenge.send_count]
  );
  if (!updated.rows[0]) {
    throw new MfaError(429, 'A new code is already on its way.');
  }

  try {
    await sendCodeEmail(challenge.email, challenge.context.full_name, code);
  } catch (err) {
    console.error('MFA: failed to resend code email:', err);
    throw new MfaError(502, "We couldn't send your sign-in code. Please try again shortly.");
  }

  return { challengeId, expiresInSeconds: CODE_TTL_MINUTES * 60 };
}

// Shared by every route that can throw MfaError.
function sendMfaError(res, err) {
  const { challenge, ...extra } = err.extra;
  return res.status(err.status).json({ error: err.message, ...extra });
}

module.exports = { createChallenge, verifyChallenge, resendChallenge, MfaError, sendMfaError };
