/**
 * /api/contact — the public contact form.
 *
 * THE POINT OF THIS FILE
 * ----------------------
 * The homepage sells "Forms That Don't Lose Submissions", and describes the
 * failure mode precisely: a form that sends an email and reports success only
 * if the send worked will silently destroy enquiries the day a credential
 * expires. This function is that claim, implemented. If it did it the other way
 * round the site would be selling a discipline it does not practise on its own
 * contact path.
 *
 * So the order is not negotiable:
 *
 *   1. Write the submission to durable storage. This needs no credential and no
 *      third party, so there is almost nothing that can stop it.
 *   2. THEN attempt a notification, best-effort.
 *   3. Report success on the strength of step 1 alone.
 *
 * A notification failure is therefore an alert, never a deletion. With no mail
 * provider configured at all, submissions are still captured and still
 * retrievable — the form degrades to "we have it, you just were not paged".
 *
 * CONFIGURATION (Netlify env vars — scope them to Functions, not just Builds)
 *   RESEND_API_KEY    optional. Without it, nothing is emailed and the
 *                     submission is stored anyway. That is a deliberate
 *                     degradation, not a bug.
 *   CONTACT_TO        optional, defaults to info@siegestack.com.
 *   CONTACT_FROM      optional. Must be a domain the mail provider has verified.
 */

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

export const config = { path: ['/api/contact'] };

const MAX = { name: 120, email: 200, company: 160, message: 5000 };
const store = () => getStore({ name: 'siegestack-contact', consistency: 'strong' });

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

/**
 * Monotonic, zero-padded, with a random suffix. Two submissions in the same
 * millisecond must not overwrite each other, and keys must sort into
 * chronological order so the newest can be read off the end of a sorted list.
 */
let last = 0;
function key() {
  last = Math.max(Date.now(), last + 1);
  return `msg/${String(last).padStart(16, '0')}-${crypto.randomBytes(4).toString('hex')}`;
}

const clean = (v, max) => String(v ?? '').trim().slice(0, max);

// Deliberately permissive. Rejecting a valid address is a lost enquiry, which
// costs more than accepting a malformed one that a human can read anyway.
const looksLikeEmail = (v) => /^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(v);

export default async (req) => {
  if (req.method !== 'POST') return json({ ok: false, error: 'method' }, 405);

  const body = await req.json().catch(() => null);
  if (!body) return json({ ok: false, error: 'bad_request' }, 400);

  // Honeypot. A real person never fills a field they cannot see; accept and
  // discard rather than reject, so a bot learns nothing from the response.
  if (clean(body.website, 200)) return json({ ok: true });

  const submission = {
    name: clean(body.name, MAX.name),
    email: clean(body.email, MAX.email),
    company: clean(body.company, MAX.company),
    message: clean(body.message, MAX.message),
    at: new Date().toISOString(),
    ua: clean(req.headers.get('user-agent'), 300),
  };

  if (!submission.message) return json({ ok: false, error: 'message_required' }, 400);
  if (!looksLikeEmail(submission.email)) return json({ ok: false, error: 'email_invalid' }, 400);

  // ---- 1. Durable write. Everything below this line is optional. ----
  const id = key();
  try {
    await store().setJSON(id, submission);
  } catch (err) {
    // The only genuine failure. Say so honestly rather than reporting a success
    // that did not happen — the whole point is not pretending.
    console.error(JSON.stringify({ event: 'CONTACT_STORE_FAILED', detail: String(err?.message || err).slice(0, 200) }));
    return json({ ok: false, error: 'store_failed' }, 503);
  }

  // ---- 2. Best-effort notification. Never allowed to fail the request. ----
  let notified = false;
  const apiKey = process.env.RESEND_API_KEY;
  if (apiKey) {
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          from: process.env.CONTACT_FROM || 'SiegeStack <info@siegestack.com>',
          to: [process.env.CONTACT_TO || 'info@siegestack.com'],
          reply_to: submission.email,
          subject: `Enquiry from ${submission.name || submission.email}`,
          text: [
            `Name:    ${submission.name || '(not given)'}`,
            `Email:   ${submission.email}`,
            `Company: ${submission.company || '(not given)'}`,
            `Stored:  ${id}`,
            '',
            submission.message,
          ].join('\n'),
        }),
      });
      notified = res.ok;
      if (!res.ok) console.error(JSON.stringify({ event: 'CONTACT_NOTIFY_HTTP', status: res.status }));
    } catch (err) {
      console.error(JSON.stringify({ event: 'CONTACT_NOTIFY_ERROR', detail: String(err?.message || err).slice(0, 200) }));
    }
  } else {
    console.log(JSON.stringify({ event: 'CONTACT_NOTIFY_SKIPPED', reason: 'no RESEND_API_KEY' }));
  }

  // Stored is what success means here. `notified` is reported for observability,
  // and the page does not change its message based on it — the sender's
  // enquiry arrived either way, and telling them otherwise would be a lie about
  // our own plumbing.
  console.log(JSON.stringify({ event: 'CONTACT_RECEIVED', id, notified }));
  return json({ ok: true, notified });
};
