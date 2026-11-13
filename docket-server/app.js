// The Express app, kept apart from server.js so it can be loaded without
// starting the server or touching the database.

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const db = require('./db/connection');

const app = express();
// Avoid disclosing the API framework in HTTP response headers.
app.disable('x-powered-by');

// Set by server.js once database setup has succeeded. Until then the server
// is up but can't serve anything that needs the database.
app.locals.ready = false;

// Render terminates TLS in one proxy hop in front of us. Trusting exactly
// one hop makes req.ip the real client address (so the rate limits below
// are per visitor, not one shared bucket for the proxy) without letting a
// caller spoof it with their own X-Forwarded-For header.
app.set('trust proxy', 1);

// Only the frontend may call the API from a browser. Allowed origins come
// from CORS_ORIGINS (comma-separated), else APP_URL's origin; localhost is
// always allowed for local dev. With neither configured we fall back to
// allowing any origin, loudly, rather than breaking a deploy.
const allowedOrigins = (process.env.CORS_ORIGINS || process.env.APP_URL || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => { try { return new URL(s).origin; } catch { return null; } })
  .filter(Boolean);
const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

if (!allowedOrigins.length) {
  console.warn('CORS_ORIGINS/APP_URL not set — the API accepts browser requests from any origin.');
}
app.use(cors({
  origin(origin, callback) {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin) || LOCALHOST_RE.test(origin)) {
      return callback(null, true);
    }
    callback(null, false);
  },
  // Paged GET /api/tickets reports the full match count here.
  exposedHeaders: ['X-Total-Count']
}));

// Attachments are served with whatever MIME type the uploader claimed —
// stop browsers from second-guessing that into something executable.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Per-IP limit on everything that sends a sign-in code, checks a password
// or code, or starts a password reset. The per-account limits in
// utils/mfa.js and utils/password-reset.js stop guessing against one
// account; this stops one client hammering many accounts (or the email
// quota). Generous enough for an office of people behind one NAT address.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts from this network. Please wait a few minutes and try again.' }
});
app.use('/api/auth', authLimiter);
app.post('/api/users', authLimiter);
app.post('/api/users/sign-in', authLimiter);
app.post('/api/agents', authLimiter);
// The public "Find my account" form (routes/account-help.js) writes a row
// an admin has to read, so it gets a far tighter cap than sign-in: a real
// person sends one, maybe two.
const accountHelpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests from this network. Please try again in an hour.' }
});
app.post('/api/account-help', accountHelpLimiter);
// Attachments travel as base64 inline in the JSON body (see
// attachment-storage.js's 5MB-per-file cap) — base64 inflates that by
// ~33%, and a ticket/comment can carry more than one file, so the
// default 100kb express.json() limit rejects any real attachment with a
// 413 long before the app's own size check ever runs.
app.use(express.json({ limit: '10mb' }));

// A body-parser failure (oversized payload, malformed JSON) would
// otherwise fall through to Express's default HTML error page — the
// frontend's response.json() then throws a confusing
// "unexpected character at line 1 column 1" instead of showing the
// actual problem. Reply in the same { error } shape every route already
// uses so the client can surface a real message.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request too large — attachments are capped at 5MB each.' });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed request body.' });
  }
  next(err);
});

// Root route — just so opening the bare Render URL in a browser doesn't
// look like the server is down. The frontend never calls this directly.
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Docket API is running' });
});

// Health check — confirms the server is up and the database is reachable.
// Public, so it deliberately reports nothing about what's in the database.
// The uptime monitor watches this, so it must not report ok before setup
// has finished.
app.get('/api/health', async (req, res) => {
  if (!app.locals.ready) {
    return res.status(503).json({ status: 'error', error: 'server is not ready' });
  }
  try {
    await db.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('GET /api/health error:', err);
    res.status(500).json({ status: 'error', error: 'database unreachable' });
  }
});

// Every route below needs the database, so answer in the usual { error }
// shape until setup has succeeded instead of letting each one fail.
app.use('/api', (req, res, next) => {
  if (app.locals.ready) return next();
  res.status(503).json({ error: 'The service is starting up. Please try again in a minute.' });
});

app.use('/api/users', require('./routes/users'));
app.use('/api/agents', require('./routes/agents'));
app.use('/api/admins', require('./routes/admins'));
app.use('/api/tickets', require('./routes/tickets'));
app.use('/api/auth', require('./routes/auth'));
// Comments are nested under a ticket: /api/tickets/:ticketId/comments
app.use('/api/tickets/:ticketId/comments', require('./routes/comments'));
app.use('/api/attachments', require('./middleware/attachments'));
app.use('/api/audit-logs', require('./routes/audit-logs'));
app.use('/api/reports', require('./routes/reports'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/account-help', require('./routes/account-help'));

// Catch-all: anything forwarded via next(err) — including every rejected
// promise from an asyncHandler-wrapped route — lands here instead of
// crashing the process or falling through to Express's default HTML error
// page. Must be registered after every other app.use()/route.
app.use((err, req, res, next) => {
  console.error('Unhandled request error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'internal server error' });
});

module.exports = app;
