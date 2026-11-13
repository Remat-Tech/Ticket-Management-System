const test = require('node:test');
const assert = require('node:assert/strict');
const { mock } = require('node:test');
const db = require('../db/connection');
const { seed } = require('../db/seed');

test('missing ADMIN_EMAIL skips all admin queries without failing startup', async () => {
  const previousEmail = process.env.ADMIN_EMAIL;
  const previousPassword = process.env.ADMIN_PASSWORD;
  const ensureSchema = mock.method(db, 'ensureSchema', async () => {});
  const query = mock.method(db, 'query', async () => { throw new Error('unexpected admin query'); });
  const warn = mock.method(console, 'warn', () => {});
  const log = mock.method(console, 'log', () => {});

  try {
    delete process.env.ADMIN_EMAIL;
    delete process.env.ADMIN_PASSWORD;
    await seed();
    assert.equal(ensureSchema.mock.callCount(), 1);
    assert.equal(query.mock.callCount(), 0);
    assert.match(warn.mock.calls[0].arguments[0], /ADMIN_EMAIL is not set/);
  } finally {
    if (previousEmail === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = previousEmail;
    if (previousPassword === undefined) delete process.env.ADMIN_PASSWORD;
    else process.env.ADMIN_PASSWORD = previousPassword;
    ensureSchema.mock.restore();
    query.mock.restore();
    warn.mock.restore();
    log.mock.restore();
  }
});

test('configured ADMIN_EMAIL is trimmed, normalized, and seeded', async () => {
  const previousEmail = process.env.ADMIN_EMAIL;
  const previousPassword = process.env.ADMIN_PASSWORD;
  const ensureSchema = mock.method(db, 'ensureSchema', async () => {});
  const query = mock.method(db, 'query', async () => ({ rows: [{ '?column?': 1 }] }));
  const log = mock.method(console, 'log', () => {});

  try {
    process.env.ADMIN_EMAIL = '  Admin@Example.org  ';
    delete process.env.ADMIN_PASSWORD;
    await seed();
    assert.equal(ensureSchema.mock.callCount(), 1);
    assert.equal(query.mock.callCount(), 2);
    assert.deepEqual(query.mock.calls[0].arguments[1], [
      'ADM-2026-000001', 'admin@example.org', 'System Administrator'
    ]);
  } finally {
    if (previousEmail === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = previousEmail;
    if (previousPassword === undefined) delete process.env.ADMIN_PASSWORD;
    else process.env.ADMIN_PASSWORD = previousPassword;
    ensureSchema.mock.restore();
    query.mock.restore();
    log.mock.restore();
  }
});
