// Transactional email via Resend's REST API (https://resend.com/docs/api-reference/emails/send-email).
// Called with Node's built-in fetch rather than the `resend` SDK — it's one
// POST, not worth a dependency.
//
// RESEND_API_KEY   — required in production.
// EMAIL_FROM       — verified sender, e.g. "Docket <no-reply@yourdomain.com>".
//                    Falls back to Resend's shared test sender, which can only
//                    deliver to the email address that owns the Resend account.
//
// With no RESEND_API_KEY outside production, emails are printed to the
// console instead of sent, so local dev works without a Resend account —
// with a loud warning so it can't go unnoticed.

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || 'Docket <onboarding@resend.dev>';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!RESEND_API_KEY && IS_PRODUCTION) {
  throw new Error('RESEND_API_KEY is not set');
}

async function sendEmail({ to, subject, text, html }) {
  if (!RESEND_API_KEY) {
    console.warn(`[email] RESEND_API_KEY not set — NOT sending. To: ${to} | Subject: ${subject}\n${text}`);
    return;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from: EMAIL_FROM, to: [to], subject, text, html })
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Resend send failed (${response.status}): ${body}`);
  }
}

module.exports = { sendEmail };
