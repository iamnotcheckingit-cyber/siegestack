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
 * The notification itself is in ../lib/notify.mjs, shared with contact-api.mjs
 * and notify-sweep.mjs. It was briefly a deliberate copy of the contact
 * function's block; the third caller ended that argument, and a redaction bug
 * that had to be fixed twice in one day made the case.
 *
 * Env vars are shared with contact-api.mjs and documented in docs/MAIL.md:
 * SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS, CONTACT_FROM, CONTACT_TO.
 * Nothing new needs setting for this function to work.
 */

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import { notify } from '../lib/notify.mjs';
import { markNotified } from '../lib/pending.mjs';

export const config = { path: ['/api/expertise'] };

// The identity fields on the form. Everything else posted is a skill rating.
const MAX = { consultantName: 120, email: 200, phone: 40, bestTimeToCall: 40, timeZone: 20, erpExperience: 200, languagesSpoken: 200 };

// Deliberately permissive, matching contact-api.mjs. Rejecting a valid address
// costs a consultant who just filled in two hundred dropdowns their whole
// submission, which is far worse than accepting an odd-looking one a human can
// read. The browser's type="email" is the first pass; this is the backstop.
const looksLikeEmail = (v) => /^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(v);

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
  if (!consultantName) return json({ ok: false, error: 'name_required' }, 400);

  // Required since 2026-08-16. Before that the form collected no address at
  // all, so a completed matrix arrived with no way to answer it.
  const email = clean(body.email, MAX.email);
  if (!email) return json({ ok: false, error: 'email_required' }, 400);
  if (!looksLikeEmail(email)) return json({ ok: false, error: 'email_invalid' }, 400);

  // Optional, and stored as given. No normalising: international formats,
  // extensions and "text me first" notes are all things a person might type,
  // and mangling one is worse than storing it verbatim for a human to read.
  const phone = clean(body.phone, MAX.phone);
  const bestTimeToCall = clean(body.bestTimeToCall, MAX.bestTimeToCall);
  const timeZone = clean(body.timeZone, MAX.timeZone);

  // yearsInDistribution is <input type="number">, but a number input still
  // posts a string and still posts "" when left blank. Store a number or null
  // rather than an empty string, so the stored records stay sortable.
  const yearsRaw = clean(body.yearsInDistribution, 10);
  const years = yearsRaw === '' || !Number.isFinite(Number(yearsRaw)) ? null : Number(yearsRaw);

  // Anything not named here is treated as a skill rating, so a new form field
  // MUST be added to this set. A phone number that happened to parse as 0-4
  // would otherwise be filed as a skill.
  const identity = new Set([
    'consultantName', 'email', 'phone', 'bestTimeToCall', 'timeZone',
    'erpExperience', 'languagesSpoken', 'yearsInDistribution',
  ]);

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
    email,
    phone,
    bestTimeToCall,
    timeZone,
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


  const rated = Object.entries(skills).filter(([, n]) => n > 0);
  const strongest = rated
    .filter(([, n]) => n >= 3)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 25)
    .map(([k, n]) => `  ${RATINGS[n]}: ${label(k)}`);

  // Only shown when a number was actually given -- a call window with no phone
  // number is noise, and so is a time zone with no window.
  const reachBy = [phone, bestTimeToCall && `best ${bestTimeToCall}`, timeZone]
    .filter(Boolean)
    .join(', ');

  const subject = `Expertise matrix from ${consultantName}`;
  const text = [
    `Name:       ${consultantName}`,
    `Email:      ${email}`,
    phone ? `Phone:      ${reachBy}` : 'Phone:      (not given)',
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
  ].filter(Boolean).join('\n');

  const { notified, reason, smtpSaid } = await notify({
    subject,
    text,
    replyTo: email,
    event: 'EXPERTISE_NOTIFY',
  });

  // Tells notify-sweep this one is done; see contact-api.mjs.
  if (notified) await markNotified(store(), id, 'EXPERTISE');

  console.log(JSON.stringify({ event: 'EXPERTISE_RECEIVED', id, name: consultantName, rated: rated.length, notified, reason }));
  return json({ ok: true, notified, ...(reason ? { reason } : {}), ...(smtpSaid ? { smtpSaid } : {}) });
};
