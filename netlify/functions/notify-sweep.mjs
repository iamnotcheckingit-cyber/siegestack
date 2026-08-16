/**
 * notify-sweep -- the safety net under both form notifications.
 *
 * THE PROBLEM IT SOLVES
 * ---------------------
 * A form notification is sent inside the request, under an 8-second budget,
 * because the visitor is waiting. ImprovMX's handshake latency is variable:
 * measured live at 2.5s, 7.4s and 8.6s on 2026-08-16, so roughly one send in
 * three exceeds the budget and is abandoned. Nothing is lost when that happens
 * -- the submission was written to durable storage first, which is the entire
 * design -- but nobody is paged, and an unread submission sits until someone
 * goes looking.
 *
 * The budget cannot simply be raised. 8.6s against Netlify's 10s ceiling leaves
 * under 1.4s, and exceeding the ceiling kills the request AFTER the write, so
 * the page would tell the sender it failed when it did not. That is strictly
 * worse than a late notification.
 *
 * So this runs hourly and sends what the request path could not. A missed
 * notification becomes at most an hour late rather than indefinitely silent.
 *
 * WHY HOURLY, AND NOT A BACKGROUND FUNCTION
 * -----------------------------------------
 * Netlify's minimum schedule IS hourly -- there is no faster cron. A background
 * function would notify immediately instead, but it is invoked over HTTP, which
 * in a public repo means a publicly reachable endpoint plus a shared secret to
 * guard it, and it cannot report `notified` in the response the form returns,
 * which is what makes the whole thing diagnosable with one curl. For a
 * consultancy contact form, an hour is cheap and that complexity is not. If
 * immediacy ever matters more, docs/MAIL.md has the trade written up.
 *
 * Scheduled functions get 30 seconds, not 10 -- but that is still a real
 * ceiling, and each send can take 8 of it. See BUDGET below.
 */

import { getStore } from '@netlify/blobs';
import { notify, NOTIFY_BUDGET_MS } from '../lib/notify.mjs';
import { SENT_PREFIX, WATERMARK_KEY, markNotified, stampOf } from '../lib/pending.mjs';

export const config = { schedule: '@hourly' };

// Netlify allows a scheduled function 30s. Stop starting new sends with less
// than a full budget plus a margin left, so the function finishes on its own
// terms rather than being killed mid-send -- a kill after a successful send but
// before its marker is written is exactly how a duplicate happens.
const RUN_BUDGET_MS = 30000;
const MARGIN_MS = 4000;

// A bound on how many notifications one run will send. Not a business rule:
// insurance against a pathological backlog turning one cron tick into a
// mail flood. Whatever it defers is logged and picked up an hour later.
const MAX_PER_RUN = 8;

const STORES = [
  { name: 'siegestack-contact', prefix: 'msg/', label: 'contact', event: 'SWEEP_CONTACT' },
  { name: 'siegestack-expertise', prefix: 'matrix/', label: 'expertise', event: 'SWEEP_EXPERTISE' },
];

const line = (k, v) => `${k}${' '.repeat(Math.max(1, 12 - k.length))}${v}`;

/** Rebuilds a readable notification from a stored record of either shape. */
function describe(store, key, rec) {
  if (store.label === 'contact') {
    return {
      subject: `Enquiry from ${rec.name || rec.email || 'unknown'}`,
      replyTo: rec.email || null,
      text: [
        line('Name:', rec.name || '(not given)'),
        line('Email:', rec.email || '(not given)'),
        line('Company:', rec.company || '(not given)'),
        line('Stored:', key),
        '',
        rec.message || '(no message)',
      ].join('\n'),
    };
  }
  const skills = rec.skills || {};
  const rated = Object.entries(skills).filter(([, n]) => n > 0);
  return {
    subject: `Expertise matrix from ${rec.consultantName || 'unknown'}`,
    replyTo: rec.email || null,
    text: [
      line('Name:', rec.consultantName || '(not given)'),
      line('Email:', rec.email || '(not given)'),
      line('Phone:', [rec.phone, rec.bestTimeToCall && `best ${rec.bestTimeToCall}`, rec.timeZone].filter(Boolean).join(', ') || '(not given)'),
      line('ERP exp:', rec.erpExperience || '(not given)'),
      line('Years:', rec.yearsInDistribution ?? '(not given)'),
      line('Stored:', key),
      '',
      `Rated above "No Experience": ${rated.length} of ${Object.keys(skills).length}`,
    ].join('\n'),
  };
}

export default async () => {
  const startedAt = Date.now();
  const summary = [];

  for (const spec of STORES) {
    const store = getStore({ name: spec.name, consistency: 'strong' });

    let submissions = [];
    let sent = new Set();
    try {
      const [subs, marks] = await Promise.all([
        store.list({ prefix: spec.prefix }),
        store.list({ prefix: SENT_PREFIX }),
      ]);
      submissions = (subs?.blobs || []).map((b) => b.key);
      sent = new Set((marks?.blobs || []).map((b) => b.key.slice(SENT_PREFIX.length)));
    } catch (err) {
      console.error(JSON.stringify({ event: `${spec.event}_LIST_FAILED`, detail: String(err?.message || err).slice(0, 200) }));
      summary.push(`${spec.label}: list failed`);
      continue;
    }

    const pending = submissions.filter((k) => !sent.has(k)).sort();

    /**
     * FIRST RUN ESTABLISHES A WATERMARK AND SENDS NOTHING.
     *
     * Every submission that predates this feature has no marker, so it is
     * indistinguishable from one the request path just failed to notify. On the
     * day this ships that is the entire history of the store -- and mailing all
     * of it at once, hours or months late, would be a worse bug than the one
     * being fixed. So the first run records the time, declares everything older
     * already handled, and says in the log how many it passed over.
     */
    let watermark = null;
    try {
      watermark = await store.get(WATERMARK_KEY, { type: 'json' });
    } catch { /* treated as absent */ }

    if (!watermark || typeof watermark.at !== 'number') {
      const at = Date.now();
      await store.setJSON(WATERMARK_KEY, { at, note: 'Submissions older than this were present when the sweep was first deployed and are deliberately not notified.' });
      console.log(JSON.stringify({ event: `${spec.event}_INITIALISED`, at, skipped: pending.length }));
      summary.push(`${spec.label}: initialised, ${pending.length} pre-existing left alone`);
      continue;
    }

    // Anything older than the watermark was accounted for at initialisation.
    // A key with no parseable stamp cannot be judged, and is left alone rather
    // than guessed at -- an unexplained mail is worse than a missing one here.
    const due = pending.filter((k) => {
      const s = stampOf(k);
      return s !== null && s > watermark.at;
    });

    let notifiedCount = 0;
    let deferred = 0;
    for (const k of due) {
      if (notifiedCount >= MAX_PER_RUN || Date.now() - startedAt > RUN_BUDGET_MS - NOTIFY_BUDGET_MS - MARGIN_MS) {
        deferred = due.length - notifiedCount;
        break;
      }
      let rec;
      try {
        rec = await store.get(k, { type: 'json' });
      } catch {
        rec = null;
      }
      if (!rec) {
        console.error(JSON.stringify({ event: `${spec.event}_UNREADABLE`, key: k }));
        continue;
      }

      const { subject, text, replyTo } = describe(spec, k, rec);
      const { notified, reason } = await notify({ subject: `[late] ${subject}`, text, replyTo, event: spec.event });
      if (notified) {
        await markNotified(store, k, spec.event);
        notifiedCount++;
      } else {
        // Left unmarked on purpose, so the next run tries again. A permanent
        // misconfiguration (no_to, no_from) will retry hourly and do nothing
        // but log -- which is the correct noise level for something that needs
        // a human to fix a setting.
        console.error(JSON.stringify({ event: `${spec.event}_RETRY_FAILED`, key: k, reason }));
        break;   // If one fails, the rest will too. Stop and wait an hour.
      }
    }

    // Never let a cap be silent: a truncated run that says nothing reads
    // exactly like a run with nothing to do.
    if (deferred > 0) console.log(JSON.stringify({ event: `${spec.event}_DEFERRED`, deferred }));
    console.log(JSON.stringify({ event: `${spec.event}_DONE`, pending: due.length, notified: notifiedCount, deferred }));
    summary.push(`${spec.label}: ${notifiedCount} sent, ${deferred} deferred, ${due.length} due`);
  }

  console.log(JSON.stringify({ event: 'SWEEP_COMPLETE', ms: Date.now() - startedAt, summary }));
};
