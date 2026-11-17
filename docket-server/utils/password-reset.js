// Password reset by emailed link. Only accounts with local credentials
// (auth_credentials.password_hash) have a password to reset — today that's
// the seeded admin; customers and agents sign in with the emailed MFA code
// alone.
//
// Flow: requestReset() emails a single-use link to
// APP_URL/reset-password.html#token=...; completeReset() takes that token
// plus the new password. The token rides in the URL fragment so it never
// reaches server access logs or a Referer header.
//
// Limits:
//   - links expire after TOKEN_TTL_MINUTES and are single-use
//   - a new link (or a completed reset) kills any older unused link
//   - MAX_REQUESTS_PER_WINDOW links per account per window; extra requests
//     are silently dropped, so the response never reveals whether the
//     email has an account

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { sendEmail, escapeHtml, appLink, greetingFor, buttonHtml, MUTED } = require('./email');
const { revokeSessions } = require('../middleware/authenticate');

const TOKEN_TTL_MINUTES = 30;
const MAX_REQUESTS_PER_WINDOW = 3;
const REQUEST_WINDOW_MINUTES = 60;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 72; // bcrypt ignores everything past 72 bytes

const OWNER_TABLES = { user: 'users', agent: 'agents', admin: 'admins' };

class PasswordResetError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_LENGTH) {
    return `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

async function sendResetEmail(owner, link) {
  const greeting = greetingFor(owner.full_name);
  await sendEmail({
    to: owner.email,
    subject: 'Reset your Docket password',
    text:
      `${greeting}\n\nSomeone (hopefully you) asked to reset your Docket password. ` +
      `Open this link to choose a new one — it expires in ${TOKEN_TTL_MINUTES} minutes and works once:\n\n${link}\n\n` +
      `If you didn't ask for this, ignore this email — your password stays the same.`,
    html:
      `<p>${escapeHtml(greeting)}</p>` +
      `<p>Someone (hopefully you) asked to reset your Docket password.</p>` +
      buttonHtml(link, 'Choose a new password') +
      `<p>The link expires in ${TOKEN_TTL_MINUTES} minutes and works once.</p>` +
      `<p style="color:${MUTED}">If you didn't ask for this, ignore this email — your password stays the same.</p>`
  });
}

async function sendPasswordChangedEmail(owner) {
  const greeting = greetingFor(owner.full_name);
  await sendEmail({
    to: owner.email,
    subject: 'Your Docket password was changed',
    text:
      `${greeting}\n\nThe password for your Docket account was just changed using a reset link.\n\n` +
      `If this wasn't you, contact your administrator right away.`,
    html:
      `<p>${escapeHtml(greeting)}</p>` +
      `<p>The password for your Docket account was just changed using a reset link.</p>` +
      `<p style="color:${MUTED}">If this wasn't you, contact your administrator right away.</p>`
  });
}

// `owner` is { ownerType, id, email, full_name }. Returns true if a link was
// sent. Callers must respond identically whatever this returns.
async function requestReset(owner) {
  const cred = await db.query(
    `SELECT 1 FROM auth_credentials
     WHERE owner_type = $1 AND owner_id = $2 AND auth_provider = 'local' AND password_hash IS NOT NULL`,
    [owner.ownerType, owner.id]
  );
  if (!cred.rows[0]) return false;

  const recent = await db.query(
    `SELECT COUNT(*) AS n FROM password_reset_tokens
     WHERE owner_type = $1 AND owner_id = $2 AND created_at > now() - make_interval(mins => $3)`,
    [owner.ownerType, owner.id, REQUEST_WINDOW_MINUTES]
  );
  if (Number(recent.rows[0].n) >= MAX_REQUESTS_PER_WINDOW) return false;

  await db.query(`DELETE FROM password_reset_tokens WHERE created_at < now() - interval '1 day'`);
  await db.query(
    `UPDATE password_reset_tokens SET expires_at = now()
     WHERE owner_type = $1 AND owner_id = $2 AND used_at IS NULL AND expires_at > now()`,
    [owner.ownerType, owner.id]
  );

  const token = crypto.randomBytes(32).toString('base64url');
  await db.query(
    `INSERT INTO password_reset_tokens (owner_type, owner_id, token_hash, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(mins => $4))`,
    [owner.ownerType, owner.id, hashToken(token), TOKEN_TTL_MINUTES]
  );

  await sendResetEmail(owner, appLink(`reset-password.html#token=${token}`));
  return true;
}

// Returns the owner row ({ ownerType, id, email, full_name }) whose
// password was changed; throws PasswordResetError otherwise.
async function completeReset(token, newPassword) {
  if (typeof token !== 'string' || !token) {
    throw new PasswordResetError(400, 'This reset link is invalid or has expired.');
  }
  const passwordProblem = validatePassword(newPassword);
  if (passwordProblem) throw new PasswordResetError(400, passwordProblem);

  const hashedToken = hashToken(token);
  const available = await db.query(
    `SELECT 1 FROM password_reset_tokens
     WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`,
    [hashedToken]
  );
  if (!available.rows[0]) {
    throw new PasswordResetError(400, 'This reset link is invalid or has expired.');
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);

  return db.withTransaction(async (client) => {
    // Claim the token first, atomically, so two submissions of the same
    // link can't both succeed.
    const claimed = await client.query(
      `UPDATE password_reset_tokens SET used_at = now()
       WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
       RETURNING owner_type, owner_id`,
      [hashedToken]
    );
    const row = claimed.rows[0];
    if (!row) throw new PasswordResetError(400, 'This reset link is invalid or has expired.');

    const updated = await client.query(
      `UPDATE auth_credentials SET password_hash = $1, updated_at = now()
       WHERE owner_type = $2 AND owner_id = $3 AND auth_provider = 'local'
       RETURNING id`,
      [passwordHash, row.owner_type, row.owner_id]
    );
    if (!updated.rows[0]) throw new PasswordResetError(400, 'This reset link is invalid or has expired.');

    await client.query(
      `UPDATE password_reset_tokens SET expires_at = now()
       WHERE owner_type = $1 AND owner_id = $2 AND used_at IS NULL`,
      [row.owner_type, row.owner_id]
    );

    // A reset usually means the old password can't be trusted — end every
    // session that was signed in with it, in the same transaction.
    await revokeSessions(row.owner_type, row.owner_id, client);

    const ownerResult = await client.query(
      `SELECT id, email, full_name FROM ${OWNER_TABLES[row.owner_type]} WHERE id = $1`,
      [row.owner_id]
    );
    return { ownerType: row.owner_type, ...ownerResult.rows[0] };
  });
}

module.exports = {
  requestReset,
  completeReset,
  sendPasswordChangedEmail,
  PasswordResetError,
  MIN_PASSWORD_LENGTH
};
