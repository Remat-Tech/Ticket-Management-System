// Seeds the starting admin account.
//
// Agents are not seeded — they come from the admin "Add an agent" form or
// self-sign-in on the agent login page instead.
//
// Safe to re-run: the admin insert is ON CONFLICT DO NOTHING against the
// unique email, so running this twice does not create duplicates.

const bcrypt = require('bcryptjs');
const db = require('./connection');

async function seedAdmin() {
  // The initial password comes from ADMIN_PASSWORD, never from source —
  // this repo is on GitHub, so anything hardcoded here is public. It's only
  // used to create the credentials row the first time; after that the row
  // is left alone (ON CONFLICT DO NOTHING below), so changing the password
  // through the reset flow sticks across restarts.
  const initialPassword = process.env.ADMIN_PASSWORD;
  const adminId = 'ADM-2026-000001';
  // Must be a mailbox someone can read: the login MFA code and password
  // reset links are sent here.
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (!adminEmail) {
    console.warn('ADMIN_EMAIL is not set — skipping admin seed; existing admin account is unchanged.');
    return;
  }

  // DO UPDATE on email so re-running the seed with a new ADMIN_EMAIL fixes
  // the existing row instead of silently keeping the old address.
  await db.query(
    `INSERT INTO admins (id, email, full_name) VALUES ($1, $2, $3)
     ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email`,
    [adminId, adminEmail, 'System Administrator']
  );

  // Credentials live in auth_credentials, not on admins directly — see
  // db/schema.sql. ON CONFLICT against the (owner_type, owner_id) unique
  // constraint keeps this safe to re-run.
  if (initialPassword) {
    if (initialPassword.length < 12) {
      throw new Error('ADMIN_PASSWORD must be at least 12 characters');
    }
    await db.query(
      `INSERT INTO auth_credentials (owner_type, owner_id, auth_provider, password_hash)
       VALUES ('admin', $1, 'local', $2)
       ON CONFLICT (owner_type, owner_id) DO NOTHING`,
      [adminId, await bcrypt.hash(initialPassword, 10)]
    );
  } else {
    const existing = await db.query(
      `SELECT 1 FROM auth_credentials WHERE owner_type = 'admin' AND owner_id = $1`,
      [adminId]
    );
    if (!existing.rows[0]) {
      console.warn('ADMIN_PASSWORD is not set and the admin has no password yet — admin sign-in will fail until it is.');
    }
  }

  console.log(`Seeded admin account ${adminEmail} (or confirmed it already exists).`);
}

async function seed() {
  await db.ensureSchema();
  await seedAdmin();
  console.log('Seed complete.');
}

if (require.main === module) {
  seed().catch((err) => { console.error('Seed failed:', err); process.exit(1); });
}

module.exports = { seed };
