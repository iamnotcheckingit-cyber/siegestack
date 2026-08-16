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
 * DELIBERATE COPY
 * ---------------
 * The notification block below (from "Best-effort notification" to the end) is
 * duplicated in netlify/functions/submit-expertise.mjs, deliberately, the same
 * way jesse-api and nicole-api are copies rather than a shared module. A FIX
 * HERE MUST BE APPLIED THERE. Both files carry this notice. The env vars are
 * shared, so the two are configured together and fail together.
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
import nodemailer from 'nodemailer';

export const config = { path: ['/api/contact'] };

/**
 * The notification gets a hard budget well under the function's own ceiling.
 *
 * Netlify synchronous functions are killed at 10s by default and nothing here
 * raises that. SMTP is a multi-round-trip handshake and can sit there; if it
 * outlives the function, the request dies AFTER the submission was already
 * stored, and the page tells the visitor it failed when it did not. Lying to a
 * sender about a message we are holding is the worst outcome available.
 *
 * A timeout at or above the platform ceiling can never fire, which is precisely
 * how this went wrong on another site.
 *
 * Started at 6s, raised to 8s once measured: ImprovMX intermittently takes
 * longer than six seconds to complete a handshake on a cold connection, so the
 * tighter budget was dropping perfectly good notifications. Eight still leaves
 * roughly 1.5s of headroom after the durable write, and a timeout here costs a
 * missed page, never a lost submission -- the write has already happened.
 */
const NOTIFY_BUDGET_MS = 8000;

const withBudget = (promise, ms, label) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms).unref?.()),
]);

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

// Pulls the bare address out of either "Name <a@b.c>" or "a@b.c".
const domainOf = (a) => String(a || '').split('@')[1] || '';

const addr = (v) => (String(v || '').match(/<([^>]+)>/)?.[1] || String(v || '')).trim().toLowerCase();

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
  // Coarse reason code returned alongside `notified`. It names which branch was
  // taken and nothing else -- no hostnames, no addresses, no credentials -- so
  // a misconfiguration is diagnosable from the outside instead of requiring
  // dashboard access. "notified:false" on its own says something is wrong but
  // not what, which is the same unhelpful shape as a form that fails silently.
  let reason = null;
  let smtpSaid = null;
  const from = process.env.CONTACT_FROM;
  // No default. The obvious one -- the same alias CONTACT_FROM sends as -- is a
  // loop through a forwarding provider and is exactly what produced a 550 here.
  // An unset CONTACT_TO is a missing setting and should say so, not quietly
  // construct a destination that cannot work.
  const to = process.env.CONTACT_TO;
  const subject = `Enquiry from ${submission.name || submission.email}`;
  const text = [
    `Name:    ${submission.name || '(not given)'}`,
    `Email:   ${submission.email}`,
    `Company: ${submission.company || '(not given)'}`,
    `Stored:  ${id}`,
    '',
    submission.message,
  ].join('\n');

  // SMTP is preferred when configured: it is the mail vendor already paid for
  // and already covered by this domain's SPF and DKIM, so the notification can
  // legitimately come from the domain rather than a third party's sending
  // address. Resend stays as the alternative.
  const smtpHost = process.env.SMTP_HOST;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const apiKey = process.env.RESEND_API_KEY;

  if ((smtpHost || apiKey) && !to) {
    reason = 'no_to';
    console.error(JSON.stringify({
      event: 'CONTACT_NOTIFY_MISCONFIGURED',
      detail: 'A mail provider is configured but CONTACT_TO is not set. It must be the mailbox that receives the notification -- on the SMTP route, an address NOT on the same domain CONTACT_FROM sends from, because a forwarder rejects being asked to feed itself. The submission was stored regardless.',
    }));
  } else if ((smtpHost || apiKey) && !from) {
    // Misconfiguration, not a runtime failure. Say exactly what is wrong and
    // how to fix it, because the alternative is a rejection that reads as
    // "email is broken" and costs an afternoon.
    reason = 'no_from';
    console.error(JSON.stringify({
      event: 'CONTACT_NOTIFY_MISCONFIGURED',
      detail: 'A mail provider is configured but CONTACT_FROM is not. Set it to an address the provider will accept, e.g. "SiegeStack <info@siegestack.com>" for ImprovMX SMTP. The submission was stored regardless.',
    }));
  } else if (smtpHost && smtpUser && smtpPass && addr(to) && domainOf(addr(to)) === domainOf(addr(from))) {
    // Refusing this is correct behaviour, not just diagnosis. ImprovMX is a
    // FORWARDER: mail sent to the alias is relayed onward, so asking it to send
    // FROM the alias TO the same alias asks it to feed its own forwarder. It
    // rejects with 550, and it is right to. CONTACT_TO must be the mailbox the
    // alias forwards to, not the alias.
    reason = 'to_equals_from';
    console.error(JSON.stringify({
      event: 'CONTACT_NOTIFY_LOOP',
      detail: 'CONTACT_TO is on the same domain as CONTACT_FROM. Through a forwarding provider that is a loop and is rejected. Set CONTACT_TO to the real destination mailbox. The submission was stored regardless.',
    }));
  } else if (smtpHost && smtpUser && smtpPass) {
    let transport;
    try {
      const port = Number(process.env.SMTP_PORT || 587);
      transport = nodemailer.createTransport({
        host: smtpHost,
        port,
        secure: port === 465,               // 465 is implicit TLS; 587 upgrades via STARTTLS
        auth: { user: smtpUser, pass: smtpPass },
        // Every socket stage gets its own bound. Without these nodemailer will
        // happily wait longer than the function is allowed to live.
        connectionTimeout: NOTIFY_BUDGET_MS,
        greetingTimeout: NOTIFY_BUDGET_MS,
        socketTimeout: NOTIFY_BUDGET_MS,
      });
      await withBudget(
        transport.sendMail({ from, to, replyTo: submission.email, subject, text }),
        NOTIFY_BUDGET_MS,
        'smtp',
      );
      notified = true;
    } catch (err) {
      // Surface nodemailer's own error code and the server's response code.
      // EAUTH means the credentials were rejected; ESOCKET/ECONNECTION means the
      // port never opened; ETIMEDOUT means it opened and then sat there. Codes
      // only -- the message can echo the host and the envelope back at us.
      reason = 'smtp_' + String(err?.code || 'unknown').toLowerCase() + (err?.responseCode ? '_' + err.responseCode : '');
      // The server's own words are the only thing that distinguishes one 550
      // from another. Addresses are stripped before it leaves the building.
      // \s, not s. Written as [^s<>@] this excluded the LETTER s rather than
      // whitespace, and since real addresses are full of s the redaction
      // matched nothing at all -- scott@siegestack.com went out verbatim in a
      // response anyone can request. Caught by the submit-expertise suite.
      smtpSaid = String(err?.response || err?.message || '').replace(/[^\s<>@]+@[^\s<>@]+/g, '[address]').slice(0, 160);
      console.error(JSON.stringify({ event: 'CONTACT_NOTIFY_SMTP_FAILED', code: err?.code || null, responseCode: err?.responseCode || null, detail: String(err?.message || err).slice(0, 300) }));
    } finally {
      // Leaving the pool open holds the Lambda alive past the response.
      try { transport?.close(); } catch { /* nothing useful to do */ }
    }
  } else if (apiKey) {
    try {
      const res = await withBudget(fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from, to: [to], reply_to: submission.email, subject, text }),
      }), NOTIFY_BUDGET_MS, 'resend');
      notified = res.ok;
      if (!res.ok) { reason = 'http_' + res.status; console.error(JSON.stringify({ event: 'CONTACT_NOTIFY_HTTP', status: res.status })); }
    } catch (err) {
      reason = 'resend_failed';
      console.error(JSON.stringify({ event: 'CONTACT_NOTIFY_ERROR', detail: String(err?.message || err).slice(0, 200) }));
    }
  } else {
    reason = 'no_provider';
    console.log(JSON.stringify({ event: 'CONTACT_NOTIFY_SKIPPED', reason: 'no SMTP_HOST and no RESEND_API_KEY visible to the function runtime' }));
  }

  // Stored is what success means here. `notified` is reported for observability,
  // and the page does not change its message based on it — the sender's
  // enquiry arrived either way, and telling them otherwise would be a lie about
  // our own plumbing.
  console.log(JSON.stringify({ event: 'CONTACT_RECEIVED', id, notified, reason }));
  return json({ ok: true, notified, ...(reason ? { reason } : {}), ...(smtpSaid ? { smtpSaid } : {}) });
};
