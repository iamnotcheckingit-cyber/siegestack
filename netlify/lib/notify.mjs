/**
 * The one implementation of "send a notification about a form submission".
 *
 * WHY THIS IS NOW A MODULE
 * ------------------------
 * It began as a block inside contact-api.mjs, was copied into
 * submit-expertise.mjs, and a third caller (notify-sweep.mjs) is what ended the
 * argument. Two copies can be kept in step by a comment; three cannot. The
 * copy-with-a-notice convention used for jesse-api/nicole-api stays where it
 * is -- those files differ in more than a subject line -- but this logic is
 * genuinely identical for every caller, and the bug that made the case was a
 * redaction typo that had to be fixed twice on the same day.
 *
 * CONFIGURATION -- see MAIL.md. Scope every one of these to Functions in
 * Netlify, not just Builds:
 *
 *   SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS   preferred route (ImprovMX)
 *   RESEND_API_KEY                                  alternative, used only if
 *                                                   SMTP_HOST is absent
 *   CONTACT_FROM   REQUIRED once either provider is set. No default: the right
 *                  value differs by route and a wrong one fails confusingly.
 *   CONTACT_TO     REQUIRED once either provider is set. No default: the
 *                  obvious one loops a forwarder back into itself and is
 *                  rejected with 550.
 */

import nodemailer from 'nodemailer';

/**
 * A hard budget well under the platform's own ceiling.
 *
 * Netlify kills a synchronous function at 10s. SMTP is a multi-round-trip
 * handshake and can sit there; if the send outlives the function the request
 * dies AFTER the submission was stored, and the page tells the visitor it
 * failed when it did not. A timeout at or above the ceiling can never fire.
 *
 * 8s, not 6s: ImprovMX handshakes were measured at up to 8.6s and 6s was
 * dropping good notifications. It must not go higher either -- 8.6s already
 * leaves under 1.4s of headroom. The remedy for the misses is the sweep in
 * notify-sweep.mjs, not a bigger number here.
 */
export const NOTIFY_BUDGET_MS = 8000;

export const withBudget = (promise, ms, label) => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms).unref?.()),
]);

const domainOf = (a) => String(a || '').split('@')[1] || '';
const addr = (v) => (String(v || '').match(/<([^>]+)>/)?.[1] || String(v || '')).trim().toLowerCase();

/**
 * Attempts one notification. NEVER THROWS -- every caller has already written
 * the submission to durable storage by the time it gets here, and a
 * notification failure must not turn a stored submission into an error.
 *
 * Returns { notified, reason, smtpSaid }. `reason` is a coarse code naming
 * which branch was taken and nothing else: no hostnames, no addresses, no
 * credentials, because callers return it in a public HTTP response.
 */
export async function notify({ subject, text, replyTo = null, event = 'NOTIFY' }) {
  const from = process.env.CONTACT_FROM;
  const to = process.env.CONTACT_TO;
  const smtpHost = process.env.SMTP_HOST;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const apiKey = process.env.RESEND_API_KEY;

  if ((smtpHost || apiKey) && !to) {
    console.error(JSON.stringify({
      event: `${event}_MISCONFIGURED`,
      detail: 'A mail provider is configured but CONTACT_TO is not set. It must be the mailbox that receives the notification -- on the SMTP route, an address NOT on the same domain CONTACT_FROM sends from, because a forwarder rejects being asked to feed itself. The submission was stored regardless.',
    }));
    return { notified: false, reason: 'no_to', smtpSaid: null };
  }

  if ((smtpHost || apiKey) && !from) {
    console.error(JSON.stringify({
      event: `${event}_MISCONFIGURED`,
      detail: 'A mail provider is configured but CONTACT_FROM is not. Set it to an address the provider will accept, e.g. "SiegeStack <info@siegestack.com>" for ImprovMX SMTP. The submission was stored regardless.',
    }));
    return { notified: false, reason: 'no_from', smtpSaid: null };
  }

  if (smtpHost && smtpUser && smtpPass && addr(to) && domainOf(addr(to)) === domainOf(addr(from))) {
    // Refusing this is correct behaviour, not merely diagnosis. ImprovMX is a
    // FORWARDER: mail addressed to the domain is relayed onward, so sending
    // from it to it asks the forwarder to feed itself. It answers 550, rightly.
    console.error(JSON.stringify({
      event: `${event}_LOOP`,
      detail: 'CONTACT_TO is on the same domain as CONTACT_FROM. Through a forwarding provider that is a loop and is rejected. Set CONTACT_TO to the real destination mailbox. The submission was stored regardless.',
    }));
    return { notified: false, reason: 'to_equals_from', smtpSaid: null };
  }

  if (smtpHost && smtpUser && smtpPass) {
    let transport;
    try {
      const port = Number(process.env.SMTP_PORT || 587);
      transport = nodemailer.createTransport({
        host: smtpHost,
        port,
        secure: port === 465,               // 465 implicit TLS; 587 upgrades via STARTTLS
        auth: { user: smtpUser, pass: smtpPass },
        // Every socket stage bounded. Without these nodemailer will happily
        // wait longer than the function is allowed to live.
        connectionTimeout: NOTIFY_BUDGET_MS,
        greetingTimeout: NOTIFY_BUDGET_MS,
        socketTimeout: NOTIFY_BUDGET_MS,
      });
      await withBudget(
        transport.sendMail({ from, to, ...(replyTo ? { replyTo } : {}), subject, text }),
        NOTIFY_BUDGET_MS,
        'smtp',
      );
      return { notified: true, reason: null, smtpSaid: null };
    } catch (err) {
      // EAUTH: credentials rejected. ESOCKET/ECONNECTION: the port never
      // opened. ETIMEDOUT: it opened and then sat there. A timeout from the
      // outer race arrives as a plain Error with no .code and therefore reads
      // as smtp_unknown -- that is the common one, and it is latency.
      const reason = 'smtp_' + String(err?.code || 'unknown').toLowerCase() + (err?.responseCode ? '_' + err.responseCode : '');
      // \s, not s. Written [^s<>@] this excluded the LETTER s rather than
      // whitespace, so it matched nothing and the server's response -- addresses
      // and all -- went out in a body any anonymous caller can request.
      const smtpSaid = String(err?.response || err?.message || '').replace(/[^\s<>@]+@[^\s<>@]+/g, '[address]').slice(0, 160);
      console.error(JSON.stringify({ event: `${event}_SMTP_FAILED`, code: err?.code || null, responseCode: err?.responseCode || null, detail: String(err?.message || err).slice(0, 300) }));
      return { notified: false, reason, smtpSaid };
    } finally {
      // Leaving the pool open holds the Lambda alive past the response.
      try { transport?.close(); } catch { /* nothing useful to do */ }
    }
  }

  if (apiKey) {
    try {
      const res = await withBudget(fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from, to: [to], ...(replyTo ? { reply_to: replyTo } : {}), subject, text }),
      }), NOTIFY_BUDGET_MS, 'resend');
      if (res.ok) return { notified: true, reason: null, smtpSaid: null };
      console.error(JSON.stringify({ event: `${event}_HTTP`, status: res.status }));
      return { notified: false, reason: 'http_' + res.status, smtpSaid: null };
    } catch (err) {
      console.error(JSON.stringify({ event: `${event}_ERROR`, detail: String(err?.message || err).slice(0, 200) }));
      return { notified: false, reason: 'resend_failed', smtpSaid: null };
    }
  }

  console.log(JSON.stringify({ event: `${event}_SKIPPED`, reason: 'no SMTP_HOST and no RESEND_API_KEY visible to the function runtime' }));
  return { notified: false, reason: 'no_provider', smtpSaid: null };
}
