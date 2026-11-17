const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const db = require('../db/connection');
const { completeReset } = require('../utils/password-reset');

const resetToken = 'synthetic-reset-link';
const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

test('invalid reset links fail before hashing or starting a transaction', async (t) => {
  const query = t.mock.method(db, 'query', async () => ({ rows: [] }));
  const transaction = t.mock.method(db, 'withTransaction', async () => {
    throw new Error('should not open transaction');
  });
  const hash = t.mock.method(bcrypt, 'hash', async () => {
    throw new Error('should not hash an invalid link');
  });
  t.mock.method(bcrypt, 'hashSync', () => {
    throw new Error('synchronous hashing is forbidden');
  });

  await assert.rejects(completeReset(resetToken, 'strong-passphrase'), {
    status: 400,
    message: 'This reset link is invalid or has expired.'
  });
  assert.match(query.mock.calls[0].arguments[0], /used_at IS NULL AND expires_at > now\(\)/);
  assert.deepEqual(query.mock.calls[0].arguments[1], [tokenHash]);
  assert.equal(hash.mock.callCount(), 0);
  assert.equal(transaction.mock.callCount(), 0);
});

test('valid reset links hash asynchronously and remain single-use', async (t) => {
  let lookupCount = 0;
  const query = t.mock.method(db, 'query', async () => ({
    rows: lookupCount++ === 0 ? [{ owner_type: 'admin', owner_id: 'a1' }] : []
  }));
  const hash = t.mock.method(bcrypt, 'hash', async () => 'asynchronous-hash');
  t.mock.method(bcrypt, 'hashSync', () => {
    throw new Error('synchronous hashing is forbidden');
  });
  const statements = [];
  let alreadyClaimed = false;
  const transaction = t.mock.method(db, 'withTransaction', async (callback) => callback({
    query: async (sql, values) => {
      statements.push({ sql, values });
      if (sql.includes('UPDATE password_reset_tokens SET used_at')) {
        if (alreadyClaimed) return { rows: [] };
        alreadyClaimed = true;
        return { rows: [{ owner_type: 'admin', owner_id: 'a1' }] };
      }
      if (sql.includes('UPDATE auth_credentials')) return { rows: [{ id: 'a1' }] };
      if (sql.includes('SELECT id, email, full_name')) {
        return { rows: [{ id: 'a1', email: 'sample@example.org', full_name: 'Sample' }] };
      }
      return { rows: [] };
    }
  }));

  assert.deepEqual(await completeReset(resetToken, 'strong-passphrase'), {
    ownerType: 'admin', id: 'a1', email: 'sample@example.org', full_name: 'Sample'
  });
  assert.deepEqual(hash.mock.calls[0].arguments, ['strong-passphrase', 10]);
  assert.equal(statements[1].values[0], 'asynchronous-hash');
  assert.match(statements[3].sql, /token_version = token_version \+ 1/);
  assert.equal(query.mock.callCount(), 1);

  await assert.rejects(completeReset(resetToken, 'strong-passphrase'), {
    status: 400,
    message: 'This reset link is invalid or has expired.'
  });
  assert.equal(query.mock.callCount(), 2);
  assert.equal(hash.mock.callCount(), 1);
  assert.equal(transaction.mock.callCount(), 1);
});
