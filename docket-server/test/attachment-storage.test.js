const test = require('node:test');
const assert = require('node:assert/strict');

// Stub Storage before loading the module: tests must not need Supabase or
// production credentials, and must observe whether any upload was attempted.
const supabaseModule = require('@supabase/supabase-js');
const actualCreateClient = supabaseModule.createClient;
const uploaded = [];
supabaseModule.createClient = () => ({
  storage: {
    from: () => ({
      upload: async (path, bytes) => {
        uploaded.push({ path, bytes });
        return { error: null };
      },
      remove: async () => ({ error: null })
    })
  }
});
const { validateIncomingAttachments, uploadIncomingAttachments } = require('../utils/attachment-storage');
supabaseModule.createClient = actualCreateClient;

const file = (name = 'evidence.PDF') => ({
  filename: name,
  content_base64: Buffer.from('valid test content').toString('base64'),
  mime_type: 'application/pdf'
});

test('requires actual base64 content and an allowed filename', () => {
  for (const bad of ['report.exe', 'image.svg', 'no-extension']) {
    assert.throws(() => validateIncomingAttachments([file(bad)]), /file type/);
  }
  for (const content of ['', '  ', '!!!']) {
    assert.throws(() => validateIncomingAttachments([{ ...file(), content_base64: content }]), /base64/);
  }
  assert.throws(() => validateIncomingAttachments(['report.pdf']), /filename/);
  assert.throws(() => validateIncomingAttachments([{ content_base64: 'YWJj' }]), /filename/);
  assert.throws(() => validateIncomingAttachments({ filename: 'report.pdf' }), /array/);
});

test('rejects a sixth file before contacting Storage', async () => {
  uploaded.length = 0;
  await assert.rejects(uploadIncomingAttachments('TKT-1', Array.from({ length: 6 }, () => file())), /at most 5/);
  assert.equal(uploaded.length, 0);
});

test('a rejected item never partially uploads an otherwise valid batch', async () => {
  uploaded.length = 0;
  await assert.rejects(uploadIncomingAttachments('TKT-1', [file(), file('payload.exe')]), /file type/);
  assert.equal(uploaded.length, 0);
});

test('valid types upload for ticket creation and comments', async () => {
  uploaded.length = 0;
  for (const ticketId of ['TKT-1', 'TKT-2']) {
    const records = await uploadIncomingAttachments(ticketId, [file(), file('trace.LOG')]);
    assert.equal(records.length, 2);
    assert.equal(records[0].filename, 'evidence.PDF');
    assert.ok(records.every((record) => record.stored_path.startsWith(`${ticketId}/`)));
    assert.ok(records.every((record) => record.size_bytes > 0));
  }
  assert.equal(uploaded.length, 4);
});
