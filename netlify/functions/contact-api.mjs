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
 * The notification itself is in ../lib/notify.mjs, shared with
 * submit-expertise.mjs and notify-sweep.mjs. A notification that loses the race
 * against the 8s budget is retried by the sweep, which is why this function
 * writes a "sent" marker on success -- see ../lib/pending.mjs.
 *
 * CONFIGURATION (Netlify env vars — scope them to Functions, not just Builds)
 *   SMTP_HOST         optional, and the preferred route when set. ImprovMX
 *   SMTP_USER         already handles this domain's mail and its SPF and DKIM
 *   SMTP_PASS         already cover it, so a notification sent this way can
 *   SMTP_PORT         legitimately come FROM info@siegestack.com rather than a
 *                     third party's sending address, and needs no new DNS and
 *                     no second vendor.
 *                       SMTP_HOST = the provider's SMTP hostname
 *                       SMTP_PORT = 587   (465 also works; 465 is implicit TLS)
 *                       SMTP_USER = the full alias the provider authenticates
 *                       SMTP_PASS = the SMTP password from the ImprovMX console
 *
 *   RESEND_API_KEY    optional alternative, used only when SMTP is not
 *                     configured. With neither set, nothing is emailed and the
 *                     submission is stored anyway. That is a deliberate
 *                     degradation, not a bug.
 *   CONTACT_TO        REQUIRED once EITHER provider is set, and it has NO
 *                     default. It is the mailbox that receives the
 *                     notification.
 *
 *                     On the SMTP route it must not be an address on the
 *                     sending domain at all -- not just the alias itself. A
 *                     forwarder relays mail addressed to its domain onward, so
 *                     sending there asks it to feed its own forwarder and is
 *                     rejected with 550. The check below is therefore
 *                     domain-to-domain; `to_equals_from` names it more narrowly
 *                     than it behaves. Use a mailbox somewhere else entirely,
 *                     which is where the alias forwards anyway.
 *   CONTACT_FROM      REQUIRED once EITHER provider is set -- SMTP_HOST or
 *                     RESEND_API_KEY. There is deliberately no default, and
 *                     that is worth explaining, because the right value differs
 *                     by route and the wrong one fails in a confusing way.
 *
 *                     On the SMTP route it SHOULD be info@siegestack.com: that
 *                     is the alias ImprovMX authenticates, and this domain's
 *                     SPF and DKIM already cover it. This is what ships today.
 *
 *                     On the Resend route that same address is wrong. ImprovMX
 *                     owns the MX record on the root domain, so a third-party
 *                     sender has to be verified on a SUBDOMAIN
 *                     (send.siegestack.com) or its bounce MX collides with
 *                     ImprovMX and breaks inbound forwarding -- and the
 *                     provider then rejects any from-address outside the domain
 *                     it verified. A root-domain default would produce a 403
 *                     that looks like a mystery, on the one code path whose
 *                     entire purpose is not failing quietly.
 *
 *                     No default can be right for both, so there is none. Set
 *                     it explicitly to match the route in use.
 *
 * Scope all of these to Functions in Netlify. "Builds" is the default and a
 * build seeing a value says nothing about whether process.env here does.
 */

import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import { notify } from '../lib/notify.mjs';
import { markNotified } from '../lib/pending.mjs';

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
  //
  // The send lives in ../lib/notify.mjs, shared with submit-expertise and
  // notify-sweep. `reason` is a coarse code naming which branch was taken and
  // nothing else -- no hostnames, no addresses, no credentials -- so a
  // misconfiguration is diagnosable from outside instead of needing dashboard
  // access. "notified:false" alone says something is wrong but not what, which
  // is the same unhelpful shape as a form that fails silently.
  const subject = `Enquiry from ${submission.name || submission.email}`;
  const text = [
    `Name:    ${submission.name || '(not given)'}`,
    `Email:   ${submission.email}`,
    `Company: ${submission.company || '(not given)'}`,
    `Stored:  ${id}`,
    '',
    submission.message,
  ].join('\n');

  const { notified, reason, smtpSaid } = await notify({
    subject,
    text,
    replyTo: submission.email,
    event: 'CONTACT_NOTIFY',
  });

  // The marker is what tells notify-sweep this one is done. Without it the
  // sweep sends a duplicate an hour later; without the sweep, a send that loses
  // the race against the 8s budget is never retried at all.
  if (notified) await markNotified(store(), id, 'CONTACT');

  // Stored is what success means here. `notified` is reported for observability,
  // and the page does not change its message based on it — the sender's
  // enquiry arrived either way, and telling them otherwise would be a lie about
  // our own plumbing.
  console.log(JSON.stringify({ event: 'CONTACT_RECEIVED', id, notified, reason }));
  return json({ ok: true, notified, ...(reason ? { reason } : {}), ...(smtpSaid ? { smtpSaid } : {}) });
};
