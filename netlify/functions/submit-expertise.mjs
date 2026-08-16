/**
 * /api/expertise -- the consultant expertise matrix on /consultant-expertise.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * It did not, and the form had been posting to a function that was never
 * written. Every submission got a 404, hit the client's catch branch, and
 * showed "There was an error submitting your form" -- with nothing stored, no
 * log line, and no email. A consultant filling in two hundred dropdowns was
 * told it failed, and was right.
 *
 * That is the precise failure the homepage sells against, so the ordering here
 * is the same as contact-api.mjs and is not negotiable:
 *
 *   1. Write the submission to durable storage.
 *   2. THEN attempt a notification, best-effort.
 *   3. Report success on the strength of step 1 alone.
 *
 * DELIBERATE COPY
 * ---------------
 * The notification block below is a copy of the one in contact-api.mjs, not a
 * shared import. That is the same call already made for jesse-api/nicole-api in
 * this repo, and it carries the same obligation: A FIX TO ONE MUST BE APPLIED
 * TO THE OTHER. The alternative -- extracting a module -- meant editing the
 * contact path on the same deploy that first makes this one exist, and that
 * path had just been verified working end to end. Both files carry this notice.
 *
 * Env vars are shared with contact-api.mjs and documented in MAIL.md:
 * SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS, CONTACT_FROM, CONTACT_TO.
 * Nothing new needs setting for this function to work.
 */

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';

export const config = { path: ['/api/expertise'] };

// Kept identical to contact-api.mjs on purpose. 8s is the measured ceiling:
// ImprovMX handshakes have been observed at 8.6s against Netlify's 10s function
// limit, so this must not go higher. See MAIL.md, "Option A".
const NOTIFY_BUDGET_MS = 8000;

const withBudget = (promise, ms, label) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms).unref?.()),
]);

// The identity fields on the form. Everything else posted is a skill rating.
const MAX = { consultantName: 120, erpExperience: 200, languagesSpoken: 200 };

// The form generates roughly 200 skill selects today and will grow as the
// categories do. The cap is a sanity bound against a crafted payload, not a
// business rule, so it sits well above the real field count -- tripping it on a
// legitimate submission would lose exactly the data this file exists to keep.
const MAX_FIELDS = 600;
const MAX_KEY_LEN = 80;

const RATINGS = ['No Experience', 'Basic', 'Intermediate', 'Proficient', 'Expert'];

const store = () => getStore({ name: 'siegestack-expertise', consistency: 'strong' });

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

// Monotonic, zero-padded, random suffix -- two submissions in the same
// millisecond must not overwrite each other, and keys must sort chronologically.
let last = 0;
function key() {
  last = Math.max(Date.now(), last + 1);
  return `matrix/${String(last).padStart(16, '0')}-${crypto.randomBytes(4).toString('hex')}`;
}

const domainOf = (a) => String(a || '').split('@')[1] || '';
const addr = (v) => (String(v || '').match(/<([^>]+)>/)?.[1] || String(v || '')).trim().toLowerCase();
const clean = (v, max) => String(v ?? '').trim().slice(0, max);

// Turns the flat form field name back into something readable. The client
// builds these with skill.replace(/[^a-zA-Z0-9]/g, '_'), which is lossy -- the
// original punctuation is gone and cannot be recovered here. Underscores back
// to spaces is as close as it gets, and it is only used for the email summary;
// the stored record keeps the raw field names exactly as submitted.
const label = (field) => field.replace(/_+/g, ' ').trim();

export default async (req) => {
  if (req.method !== 'POST') return json({ ok: false, error: 'method' }, 405);

  const body = await req.json().catch(() => null);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  const entries = Object.entries(body);
  if (entries.length > MAX_FIELDS) return json({ ok: false, error: 'too_many_fields' }, 400);

  const consultantName = clean(body.consultantName, MAX.consultantName);
  // The only field the form marks required. Everything else is genuinely
  // optional -- a partly-filled matrix from someone real is worth keeping.
  if (!consultantName) return json({ ok: false, error: 'name_required' }, 400);

  // yearsInDistribution is <input type="number">, but a number input still
  // posts a string and still posts "" when left blank. Store a number or null
  // rather than an empty string, so the stored records stay sortable.
  const yearsRaw = clean(body.yearsInDistribution, 10);
  const years = yearsRaw === '' || !Number.isFinite(Number(yearsRaw)) ? null : Number(yearsRaw);

  const identity = new Set(['consultantName', 'erpExperience', 'languagesSpoken', 'yearsInDistribution']);

  // Skills arrive as { Field_Name: "0".."4" }. Anything outside that range is
  // dropped rather than rejected: a single unexpected value must not cost the
  // whole submission, and the raw payload is preserved below regardless.
  const skills = {};
  for (const [k, v] of entries) {
    if (identity.has(k)) continue;
    if (k.length > MAX_KEY_LEN) continue;
    const n = Number(String(v ?? '').trim());
    if (!Number.isInteger(n) || n < 0 || n > 4) continue;
    skills[k] = n;
  }

  const submission = {
    consultantName,
    erpExperience: clean(body.erpExperience, MAX.erpExperience),
    languagesSpoken: clean(body.languagesSpoken, MAX.languagesSpoken),
    yearsInDistribution: years,
    skills,
    // The unparsed payload, capped. The parser above is opinionated and the
    // form's field list changes over time; keeping the original means a future
    // question about an old submission is answerable without a migration.
    raw: JSON.stringify(body).slice(0, 60000),
    at: new Date().toISOString(),
    ua: clean(req.headers.get('user-agent'), 300),
  };

  // ---- 1. Durable write. Everything below this line is optional. ----
  const id = key();
  try {
    await store().setJSON(id, submission);
  } catch (err) {
    console.error(JSON.stringify({ event: 'EXPERTISE_STORE_FAILED', detail: String(err?.message || err).slice(0, 200) }));
    return json({ ok: false, error: 'store_failed' }, 503);
  }

  // ---- 2. Best-effort notification. Never allowed to fail the request. ----
  let notified = false;
  let reason = null;
  let smtpSaid = null;
  const from = process.env.CONTACT_FROM;
  const to = process.env.CONTACT_TO;   // No default. See contact-api.mjs and MAIL.md.

  const rated = Object.entries(skills).filter(([, n]) => n > 0);
  const strongest = rated
    .filter(([, n]) => n >= 3)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 25)
    .map(([k, n]) => `  ${RATINGS[n]}: ${label(k)}`);

  const subject = `Expertise matrix from ${consultantName}`;
  const text = [
    `Name:       ${consultantName}`,
    `ERP exp:    ${submission.erpExperience || '(not given)'}`,
    `Languages:  ${submission.languagesSpoken || '(not given)'}`,
    `Years:      ${years === null ? '(not given)' : years}`,
    `Stored:     ${id}`,
    '',
    `Rated above "No Experience": ${rated.length} of ${Object.keys(skills).length}`,
    '',
    strongest.length ? 'Proficient or Expert:' : 'Nothing rated Proficient or Expert.',
    ...strongest,
    rated.filter(([, n]) => n >= 3).length > 25 ? '  ...and more; see the stored record.' : '',
    '',
    // Said plainly because it is the first thing you will want and the form does
    // not ask for it.
    'This form collects no email address, so there is no way to reply from here.',
  ].filter(Boolean).join('\n');

  const smtpHost = process.env.SMTP_HOST;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const apiKey = process.env.RESEND_API_KEY;

  if ((smtpHost || apiKey) && !to) {
    reason = 'no_to';
    console.error(JSON.stringify({
      event: 'EXPERTISE_NOTIFY_MISCONFIGURED',
      detail: 'A mail provider is configured but CONTACT_TO is not set. The submission was stored regardless.',
    }));
  } else if ((smtpHost || apiKey) && !from) {
    reason = 'no_from';
    console.error(JSON.stringify({
      event: 'EXPERTISE_NOTIFY_MISCONFIGURED',
      detail: 'A mail provider is configured but CONTACT_FROM is not. The submission was stored regardless.',
    }));
  } else if (smtpHost && smtpUser && smtpPass && addr(to) && domainOf(addr(to)) === domainOf(addr(from))) {
    // Same forwarder loop as contact-api.mjs -- ImprovMX rejects being asked to
    // feed its own forwarder with a 550, and refusing here is more useful than
    // letting it fail at the provider.
    reason = 'to_equals_from';
    console.error(JSON.stringify({
      event: 'EXPERTISE_NOTIFY_LOOP',
      detail: 'CONTACT_TO is on the same domain as CONTACT_FROM. The submission was stored regardless.',
    }));
  } else if (smtpHost && smtpUser && smtpPass) {
    let transport;
    try {
      const port = Number(process.env.SMTP_PORT || 587);
      transport = nodemailer.createTransport({
        host: smtpHost,
        port,
        secure: port === 465,
        auth: { user: smtpUser, pass: smtpPass },
        connectionTimeout: NOTIFY_BUDGET_MS,
        greetingTimeout: NOTIFY_BUDGET_MS,
        socketTimeout: NOTIFY_BUDGET_MS,
      });
      await withBudget(transport.sendMail({ from, to, subject, text }), NOTIFY_BUDGET_MS, 'smtp');
      notified = true;
    } catch (err) {
      // The outer race rejects with a plain Error carrying no .code, so a
      // timeout surfaces as smtp_unknown rather than smtp_etimedout. That is
      // expected and documented in MAIL.md; it is latency, not a credential.
      reason = 'smtp_' + String(err?.code || 'unknown').toLowerCase() + (err?.responseCode ? '_' + err.responseCode : '');
      // \s, not s -- see the matching note in contact-api.mjs. The character
      // class has to exclude whitespace; excluding the letter s makes the
      // redaction match nothing, because addresses are full of s.
      smtpSaid = String(err?.response || err?.message || '').replace(/[^\s<>@]+@[^\s<>@]+/g, '[address]').slice(0, 160);
      console.error(JSON.stringify({ event: 'EXPERTISE_NOTIFY_SMTP_FAILED', code: err?.code || null, responseCode: err?.responseCode || null, detail: String(err?.message || err).slice(0, 300) }));
    } finally {
      try { transport?.close(); } catch { /* nothing useful to do */ }
    }
  } else if (apiKey) {
    try {
      const res = await withBudget(fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from, to: [to], subject, text }),
      }), NOTIFY_BUDGET_MS, 'resend');
      notified = res.ok;
      if (!res.ok) { reason = 'http_' + res.status; console.error(JSON.stringify({ event: 'EXPERTISE_NOTIFY_HTTP', status: res.status })); }
    } catch (err) {
      reason = 'resend_failed';
      console.error(JSON.stringify({ event: 'EXPERTISE_NOTIFY_ERROR', detail: String(err?.message || err).slice(0, 200) }));
    }
  } else {
    reason = 'no_provider';
    console.log(JSON.stringify({ event: 'EXPERTISE_NOTIFY_SKIPPED', reason: 'no SMTP_HOST and no RESEND_API_KEY visible to the function runtime' }));
  }

  // Stored is what success means. The client only reads response.ok, and the
  // consultant is told it worked because it did.
  console.log(JSON.stringify({ event: 'EXPERTISE_RECEIVED', id, name: consultantName, rated: rated.length, notified, reason }));
  return json({ ok: true, notified, ...(reason ? { reason } : {}), ...(smtpSaid ? { smtpSaid } : {}) });
};
