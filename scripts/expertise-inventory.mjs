/**
 * What the siegestack-expertise blob store holds -- WITHOUT reading a single
 * submission.
 *
 *   NETLIFY_SITE_ID=... NETLIFY_AUTH_TOKEN=... node scripts/expertise-inventory.mjs
 *
 * WHY THIS EXISTS AS A SCRIPT RATHER THAN A DASHBOARD LOOK. The question asked
 * was count, date range and field names -- explicitly no values. The Netlify
 * blobs UI cannot answer it that way: opening a record to see its shape shows
 * you the record. This reads keys only.
 *
 * HOW IT AVOIDS THE VALUES. submit-expertise.mjs writes keys as
 *
 *     matrix/<16-digit epoch ms, zero padded>-<8 hex>
 *
 * so the key alone carries the submission time. `store.list()` returns keys and
 * never fetches bodies, so the count and the full date range are derivable from
 * metadata that is already in the key. NOTHING IN THIS FILE CALLS get() OR
 * getJSON(), and that is the point of it rather than an implementation detail.
 *
 * The field names below are read out of submit-expertise.mjs, not out of the
 * data. They are what the function WRITES, which is the honest answer to "what
 * fields does the store hold" and does not require opening a record to learn.
 *
 * WHAT IT CANNOT TELL YOU: whether a stored record is a real consultant or a
 * test submission. That needs a value, so it is deliberately out of scope here.
 */
import { getStore } from '@netlify/blobs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const siteID = process.env.NETLIFY_SITE_ID || process.env.SITE_ID;
const token = process.env.NETLIFY_AUTH_TOKEN || process.env.NETLIFY_API_TOKEN;

if (!siteID || !token) {
  console.error('CANNOT VERIFY: no Netlify credentials in the environment.');
  console.error('');
  console.error('  NETLIFY_SITE_ID    (Site configuration -> General -> Site ID)');
  console.error('  NETLIFY_AUTH_TOKEN (User settings -> Applications -> Personal access token)');
  console.error('');
  console.error('Exiting 2 rather than 0. A store inventory that reports "nothing found"');
  console.error('because it could not authenticate is worse than no inventory at all.');
  process.exit(2);
}

const store = getStore({ name: 'siegestack-expertise', siteID, token, consistency: 'strong' });

// list() returns keys and etags. It does not fetch bodies.
const { blobs } = await store.list({ prefix: 'matrix/' });

const stamps = [];
let unparsable = 0;
for (const b of blobs) {
  const m = /^matrix\/(\d{16})-[0-9a-f]{8}$/.exec(b.key);
  if (!m) { unparsable++; continue; }
  stamps.push(Number(m[1]));
}
stamps.sort((a, b) => a - b);

const iso = (ms) => new Date(ms).toISOString();
const day = (ms) => iso(ms).slice(0, 10);

console.log('siegestack-expertise  (prefix matrix/)');
console.log('');
console.log('  submissions stored : ' + blobs.length);
if (unparsable) console.log('  keys not matching the expected format: ' + unparsable);

if (stamps.length) {
  console.log('  earliest           : ' + iso(stamps[0]));
  console.log('  latest             : ' + iso(stamps[stamps.length - 1]));
  const byDay = new Map();
  for (const s of stamps) byDay.set(day(s), (byDay.get(day(s)) ?? 0) + 1);
  console.log('');
  console.log('  by day:');
  for (const [d, n] of [...byDay].sort()) console.log('    ' + d + '  ' + n);
} else {
  console.log('  earliest/latest    : n/a, the store is empty');
}

// Notification bookkeeping lives under a different prefix; counting it says
// how many were emailed without opening anything.
const sent = await store.list({ prefix: 'sent/' }).catch(() => ({ blobs: [] }));
console.log('');
console.log('  notification markers under sent/: ' + sent.blobs.length);

// ---- field names, read from the writer rather than from the data ----------
const src = fs.readFileSync(path.join(ROOT, 'netlify/functions/submit-expertise.mjs'), 'utf8');
const ident = /const identity = new Set\(\[([\s\S]*?)\]\);/.exec(src);
if (!ident) {
  console.error('');
  console.error('REFUSING TO GUESS: the identity field set in submit-expertise.mjs no longer');
  console.error('matches the shape this script reads. Update this script rather than');
  console.error('inferring the field list from a stored record.');
  process.exit(3);
}
const fields = [...ident[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);

console.log('');
console.log('  identity fields the function writes (from source, not from data):');
for (const f of fields) console.log('    ' + f);
console.log('    skills              (object: form field name -> integer 0-4)');
console.log('    raw                 (the unparsed POST body, capped at 60000 chars)');
console.log('    at                  (ISO timestamp)');
console.log('    ua                  (user agent, capped at 300 chars)');
console.log('');
console.log('  NOTE: `raw` holds the whole original payload, so a deletion request');
console.log('  is satisfied only by deleting the record, not by clearing a field.');
