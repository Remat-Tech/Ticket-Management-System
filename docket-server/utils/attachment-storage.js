const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'attachments';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
}

// Service-role client — bypasses RLS, since Docket's own server is the
// security boundary (auth + ticket-access checks happen in
// attachments.js/comments.js/tickets.js before this module is ever
// called). This key must never reach the frontend.
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Matches app.js's own cap in readFileAsAttachment — kept in sync manually
// since the client and server run in different processes.
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_REQUEST = 5;
const ALLOWED_ATTACHMENT_EXTENSIONS = new Set([
  'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'txt', 'csv', 'log', 'doc', 'docx', 'xls', 'xlsx'
]);

// Strips path separators and ".." so a crafted filename (e.g.
// "../../etc/passwd") can't escape the ticket's attachment folder. Only
// used to build the storage key — the original filename the user chose
// is preserved as-is in the `filename` column for display/download.
function sanitizeFilename(name) {
  return String(name).replace(/[/\\]/g, '_').replace(/\.\./g, '_').trim() || 'file';
}

// Decodes base64, enforces the size cap, and uploads the file to
// <ticketId>/<random>-<filename> in the Supabase Storage bucket. The
// random prefix avoids collisions between attachments that share a
// filename on the same ticket, without needing a database round trip
// first to learn the row's id. Returns { storedPath, sizeBytes }; throws
// if the decoded file is over the cap or the upload fails. storedPath is
// now a bucket-relative key rather than a filesystem path, but it's still
// just an opaque string to everything downstream.
async function saveAttachmentFile(ticketId, filename, contentBase64) {
  const buffer = Buffer.from(contentBase64, 'base64');
  if (buffer.length > MAX_ATTACHMENT_BYTES) {
    throw new Error(`"${filename}" is larger than 5MB — attachments are capped at 5MB each.`);
  }

  const diskName = crypto.randomBytes(6).toString('hex') + '-' + sanitizeFilename(filename);
  const storedPath = `${ticketId}/${diskName}`;

  const { error } = await supabase.storage.from(BUCKET).upload(storedPath, buffer, { upsert: false });
  if (error) {
    throw new Error(`failed to upload "${filename}" to storage: ${error.message}`);
  }

  return { storedPath, sizeBytes: buffer.length };
}

// Fetches a file's bytes back out of Storage so attachments.js can proxy
// them to the client. Returns a Buffer, or null if the object is missing
// (deleted from the bucket out-of-band, storedPath is stale, etc.).
async function fetchAttachmentFile(storedPath) {
  const { data, error } = await supabase.storage.from(BUCKET).download(storedPath);
  if (error || !data) return null;
  return Buffer.from(await data.arrayBuffer());
}

// For backups, where "the file is gone" and "Storage didn't answer" must not
// look the same: null only when the object really doesn't exist, and a throw
// for anything else.
async function fetchAttachmentForBackup(storedPath) {
  const { data, error } = await supabase.storage.from(BUCKET).download(storedPath);
  if (error) {
    if (error.status === 404 || String(error.statusCode) === '404') return null;
    throw new Error(`failed to download "${storedPath}" from storage: ${error.message}`);
  }
  return Buffer.from(await data.arrayBuffer());
}

// Puts a file back at its original path during a restore, so the restored
// ticket_attachments rows still point at it. Upsert so a restore can be rerun.
async function restoreAttachmentFile(storedPath, buffer) {
  const { error } = await supabase.storage.from(BUCKET).upload(storedPath, buffer, { upsert: true });
  if (error) {
    throw new Error(`failed to restore "${storedPath}" to storage: ${error.message}`);
  }
}

// Best-effort removal of stored files when their ticket is deleted. The DB
// rows are already gone by the time this runs, so a failure here only
// leaves an orphaned object in the bucket — logged, never thrown.
async function removeAttachmentFiles(storedPaths) {
  const paths = storedPaths.filter(Boolean);
  if (!paths.length) return;
  const { error } = await supabase.storage.from(BUCKET).remove(paths);
  if (error) console.error('removeAttachmentFiles: failed to remove from storage', error);
}

// Uploads every item with `upload` (which resolves to an attachment record
// with a stored_path, or null to skip). All or nothing: if any one fails —
// say the third file is over the size cap — the ones that already made it
// to Storage are removed again before the error is rethrown, instead of
// being left orphaned in the bucket.
async function uploadAllOrNone(items, upload) {
  const results = await Promise.allSettled(items.map(upload));
  const failure = results.find((r) => r.status === 'rejected');
  if (failure) {
    const uploaded = results.filter((r) => r.status === 'fulfilled' && r.value).map((r) => r.value.stored_path);
    await removeAttachmentFiles(uploaded).catch((err) => console.error('uploadAllOrNone: cleanup failed', err));
    throw failure.reason;
  }
  return results.map((r) => r.value).filter(Boolean);
}

// Validate the entire request before any storage write. A bad sixth file must
// not cause the first five files to be uploaded and then cleaned up.
function validateIncomingAttachments(items) {
  if (items == null) return [];
  if (!Array.isArray(items)) throw new Error('Attachments must be an array.');
  if (items.length > MAX_ATTACHMENTS_PER_REQUEST) {
    throw new Error(`A request may include at most ${MAX_ATTACHMENTS_PER_REQUEST} attachments.`);
  }
  for (const [index, item] of items.entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item) ||
        typeof item.filename !== 'string' || !item.filename.trim()) {
      throw new Error(`Attachment ${index + 1} must have a filename.`);
    }
    const extension = item.filename.trim().split('.').pop().toLowerCase();
    if (!ALLOWED_ATTACHMENT_EXTENSIONS.has(extension)) {
      throw new Error(`Attachment "${item.filename}" has a file type that is not allowed.`);
    }
    if (typeof item.content_base64 !== 'string' || !item.content_base64.trim() ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(item.content_base64)) {
      throw new Error(`Attachment "${item.filename}" must have valid base64 file content.`);
    }
  }
  return items;
}

// Upload one validated { filename, content_base64, mime_type? } payload.
async function normalizeIncomingAttachment(ticketId, a) {
  const filename = a.filename.trim();
  const { storedPath, sizeBytes } = await saveAttachmentFile(ticketId, filename, a.content_base64);
  return { filename, mime_type: a.mime_type || null, size_bytes: sizeBytes, stored_path: storedPath };
}

// The request body's attachment list (ticket attachments or chat files),
// validated and uploaded all-or-nothing. Anything that isn't an array is
// treated as no attachments. Throws a user-facing error (e.g. over the size
// cap) for the route to return as a 400.
async function uploadIncomingAttachments(ticketId, items) {
  const validated = validateIncomingAttachments(items);
  return uploadAllOrNone(validated, (a) => normalizeIncomingAttachment(ticketId, a));
}

// Inserts the rows for already-uploaded attachments, inside the caller's
// transaction. `parent` is exactly one of { ticketId } or { commentId } —
// ticket_attachments' CHECK constraint requires one and only one (see
// schema.sql); a comment's attachment reaches its ticket through
// comment_id -> ticket_comments.ticket_id.
async function insertAttachmentRows(client, parent, attachments) {
  for (const a of attachments) {
    await client.query(
      `INSERT INTO ticket_attachments (ticket_id, comment_id, filename, mime_type, size_bytes, stored_path)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [parent.ticketId || null, parent.commentId || null, a.filename, a.mime_type, a.size_bytes, a.stored_path]
    );
  }
}

module.exports = {
  saveAttachmentFile,
  fetchAttachmentFile,
  fetchAttachmentForBackup,
  restoreAttachmentFile,
  removeAttachmentFiles,
  uploadAllOrNone,
  validateIncomingAttachments,
  uploadIncomingAttachments,
  insertAttachmentRows,
  sanitizeFilename,
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS_PER_REQUEST,
  BUCKET
};
