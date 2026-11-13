const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const clientDirectory = join(__dirname, '..', '..', 'client');
const headers = readFileSync(join(clientDirectory, '_headers'), 'utf8');
const app = readFileSync(join(clientDirectory, 'app.js'), 'utf8');

test('Netlify sends security headers for every frontend path', () => {
  assert.match(headers, /^\/\*\s*$/m);
  assert.match(headers, /^  X-Frame-Options: DENY$/m);
  assert.match(headers, /^  X-Content-Type-Options: nosniff$/m);
  assert.match(headers, /^  Referrer-Policy: strict-origin-when-cross-origin$/m);
  assert.match(headers, /^  Permissions-Policy: geolocation=\(\), camera=\(\), microphone=\(\)$/m);
});

test('CSP permits the app dependencies and local attachment previews', () => {
  const policy = headers.match(/^  Content-Security-Policy: (.+)$/m)?.[1];
  assert.ok(policy, 'Content-Security-Policy header is required');

  for (const rule of [
    "default-src 'self'",
    "script-src 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    'https://fonts.googleapis.com',
    'https://fonts.gstatic.com',
    'img-src \'self\' data: blob:',
    "media-src 'self' blob:",
    'frame-src blob:',
  ]) {
    assert.ok(policy.includes(rule), `Missing CSP restriction or app dependency: ${rule}`);
  }

  assert.doesNotMatch(policy, /script-src[^;]*'unsafe-inline'/);
  const apiOrigin = app.match(/'https:\/\/ticket-management-system-[^']+onrender\.com'/)?.[0].slice(1, -1);
  assert.ok(apiOrigin, 'Could not determine the API host from client/app.js');
  assert.ok(policy.includes(`connect-src 'self' ${apiOrigin}`), 'CSP connect-src must allow the production API');
});
