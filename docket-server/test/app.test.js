const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../app');

// app.locals.ready is never set here, so the server behaves as it does
// before database setup has finished. Nothing below reaches the database.
let server;
let baseUrl;

test.before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => new Promise((resolve) => server.close(resolve)));

test('responses do not reveal Express through X-Powered-By', async () => {
  const res = await fetch(`${baseUrl}/`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.has('x-powered-by'), false);
});

test('/api/health returns 503 before the server is ready', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { status: 'error', error: 'server is not ready' });
});

test('other /api routes return 503 before the server is ready', async () => {
  for (const path of ['/api/tickets', '/api/users', '/api/reports']) {
    const res = await fetch(`${baseUrl}${path}`);
    assert.equal(res.status, 503, path);
    const body = await res.json();
    assert.equal(typeof body.error, 'string', path);
  }
});

test('malformed JSON returns 400 in the { error } shape', async () => {
  const res = await fetch(`${baseUrl}/api/tickets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"subject": '
  });
  assert.equal(res.status, 400);
  assert.match(res.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await res.json(), { error: 'Malformed request body.' });
});
