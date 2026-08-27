/**
 * Deletes every record in the siegestack-expertise blob store.
 *
 *   node scripts/expertise-purge.mjs                  # dry run, lists nothing but counts
 *   node scripts/expertise-purge.mjs --confirm        # actually deletes
 *
 * Requires NETLIFY_SITE_ID and NETLIFY_AUTH_TOKEN.
 *
 * WHY THIS EXISTS AND WHY IT IS SEPARATE FROM THE INVENTORY. The form was
 * closed to submissions on 2026-08-26 and the decision was to delete what it
 * had collected rather than retain it, so that the privacy policy can say the
 * store no longer exists. That sentence must not be published until this has
 * actually run: a policy describing a deletion that did not happen is worse
 * than a policy that describes retention honestly.
 *
 * IT DOES NOT READ VALUES. list() then delete() by key. Nothing calls get() or
 * getJSON(), so running this does not put any submission in front of anybody,
 * including whoever runs it. The count comes from keys.
 *
 * IT REFUSES TO RUN WHILE THE FORM CAN STILL ACCEPT WRITES. Purging a live
 * endpoint is a race: a submission landing between the list and the delete
 * survives the purge and is then undisclosed AND unaccounted for. The guard
 * reads the deployed source rather than trusting the operator to have deployed
 * the closure first.
 *
 * DRY RUN BY DEFAULT. --confirm is required, and the deletion is not
 * recoverable: there is no backup of this store, which is the same fact that
 * makes the deletion right in the privacy policy honest.
 */
import { getStore } from '@netlify/blobs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONFIRM = process.argv.includes('--confirm');

const siteID = process.env.NETLIFY_SITE_ID || process.env.SITE_ID;
const token = process.env.NETLIFY_AUTH_TOKEN || process.env.NETLIFY_API_TOKEN;

if (!siteID || !token) {
  console.error('CANNOT RUN: no Netlify credentials in the environment.');
  console.error('  NETLIFY_SITE_ID, NETLIFY_AUTH_TOKEN');
  process.exit(2);
}

// ---- refuse while the endpoint can still write -----------------------------
const fnSrc = fs.readFileSync(path.join(ROOT, 'netlify/functions/submit-expertise.mjs'), 'utf8');
if (!/^const CLOSED = true;$/m.test(fnSrc)) {
  console.error('REFUSING TO PURGE: submit-expertise.mjs does not have `const CLOSED = true`.');
  console.error('');
  console.error('The form can still accept writes, so a submission landing between the');
  console.error('listing and the deletion would survive this purge -- leaving a record that');
  console.error('is both undisclosed and unaccounted for. Close the form, deploy it, then');
  console.error('run this.');
  process.exit(3);
}

const store = getStore({ name: 'siegestack-expertise', siteID, token, consistency: 'strong' });

const all = [];
for (const prefix of ['matrix/', 'sent/']) {
  const { blobs } = await store.list({ prefix });
  for (const b of blobs) all.push(b.key);
}

// Anything not under a known prefix is reported rather than silently left
// behind: "the store no longer exists" has to be true of the whole store.
const { blobs: everything } = await store.list();
const known = new Set(all);
const stray = everything.map((b) => b.key).filter((k) => !known.has(k));

console.log('siegestack-expertise');
console.log('  records under matrix/ and sent/ : ' + all.length);
if (stray.length) console.log('  OTHER keys, also to be deleted : ' + stray.length);
console.log('  total to delete                 : ' + (all.length + stray.length));

if (!all.length && !stray.length) {
  console.log('');
  console.log('Store is already empty. Nothing to do.');
  console.log('The policy may state that no expertise submissions are retained.');
  process.exit(0);
}

if (!CONFIRM) {
  console.log('');
  console.log('DRY RUN. Nothing deleted. Re-run with --confirm to delete.');
  console.log('This is not recoverable: there is no backup of this store.');
  process.exit(0);
}

let done = 0;
const failed = [];
for (const key of [...all, ...stray]) {
  try { await store.delete(key); done++; }
  catch (err) { failed.push(key + ': ' + String(err?.message || err).slice(0, 120)); }
}

// Verify by re-listing rather than trusting the loop.
const { blobs: after } = await store.list();

console.log('');
console.log('  deleted   : ' + done);
console.log('  remaining : ' + after.length);
if (failed.length) {
  console.log('  FAILED    : ' + failed.length);
  for (const f of failed) console.log('    ' + f);
}

if (after.length === 0 && !failed.length) {
  // The receipt SS-205 requires. Written only here: after the delete loop, after
  // re-listing, and only when the re-list came back empty. It is deliberately
  // not written by the loop itself -- the whole point is that it is evidence the
  // store IS empty, not evidence that a deletion was attempted.
  fs.mkdirSync(path.join(ROOT, 'data/receipts'), { recursive: true });
  fs.writeFileSync(
    path.join(ROOT, 'data/receipts/expertise-purge.json'),
    JSON.stringify({
      _readme: [
        'Evidence that the siegestack-expertise blob store was emptied, required by SS-205',
        'before any page may publish a claim marked data-requires-receipt="expertise-purge".',
        'Written by scripts/expertise-purge.mjs only after re-listing the store and finding',
        'it empty. Commit it: CI reads this file, not the live store.',
      ],
      store: 'siegestack-expertise',
      // Re-tested by SS-205 on every validate run. A receipt is evidence about
      // the past; this is what lets the present revoke it. Reopen the form and
      // the receipt is void, so the page cannot keep claiming an empty store.
      voidIf: {
        description: 'The expertise endpoint was closed to writes when this purge ran. If it is reopened, the store can be written to again and this receipt no longer describes the present.',
        file: 'netlify/functions/submit-expertise.mjs',
        mustContain: 'const CLOSED = true;',
      },
      verified: true,
      verifiedBy: 'scripts/expertise-purge.mjs re-listed the store after deleting and found 0 keys',
      deleted: done,
      remaining: after.length,
      purgedAt: new Date().toISOString(),
    }, null, 2) + '\n'
  );
  console.log('');
  console.log('  receipt written: data/receipts/expertise-purge.json');
  console.log('  COMMIT IT. SS-205 reads that file, not the live store, and the privacy');
  console.log('  policy sentence about deletion cannot publish until it is in the repo.');

  console.log('');
  console.log('Store is empty, verified by re-listing after the deletion.');
  console.log('The policy may now state that no expertise submissions are retained.');
  process.exit(0);
}

console.log('');
console.log('NOT COMPLETE. Do not publish a policy sentence saying the store is empty.');
process.exit(1);
