/**
 * notify-sweep: the hourly retry for notifications the request path could not
 * send inside its 8-second budget.
 *
 * The case that matters most here is the FIRST RUN. Every submission that
 * predates the sweep has no "sent" marker and is therefore indistinguishable
 * from one that just failed, so a naive implementation mails the entire history
 * of the store the moment it deploys. That is a worse bug than the one being
 * fixed, and it is the reason for the watermark.
 */
import { load, reset, blobs, mailer, SMTP_ENV, eq, truthy, runner, report, cleanup } from './harness.mjs';

const DEFECTS = {
  // Without a watermark the first run mails everything already in the store.
  watermark_ignored: {
    file: 'sweep',
    re: /if \(!watermark \|\| typeof watermark\.at !== 'number'\) \{/,
    to: 'if (false) {',
  },
  // Sending without marking means the same notification goes out every hour.
  marker_not_written_after_send: {
    file: 'sweep',
    re: /await markNotified\(store, k, spec\.event\);/,
    to: '',
  },
  // Dropping the age filter re-notifies everything the watermark excluded.
  watermark_not_applied_to_pending: {
    file: 'sweep',
    re: /return s !== null && s > watermark\.at;/,
    to: 'return true;',
  },
  // A missing prefix filter treats markers and the watermark as submissions.
  markers_counted_as_submissions: {
    file: 'sweep',
    re: /submissions\.filter\(\(k\) => !sent\.has\(k\)\)/,
    to: 'submissions.filter(() => true)',
  },
  per_run_cap_removed: { file: 'sweep', re: /notifiedCount >= MAX_PER_RUN \|\|/, to: 'false &&' },
};

const STORE = 'siegestack-expertise';
const PREFIX = 'matrix/';

const store = () => blobs.__state.stores.get(STORE);
const keysOf = (prefix) => [...(store()?.keys() ?? [])].filter((k) => k.startsWith(prefix));

// Keys carry a zero-padded millisecond stamp; the sweep reads ages from them.
const keyAt = (ms, tag = 'aaaaaaaa') => `${PREFIX}${String(ms).padStart(16, '0')}-${tag}`;

const record = (name) => ({ consultantName: name, email: `${name}@example.org`, skills: { A: 4, B: 0 }, at: new Date().toISOString() });

function seed(keys) {
  const m = new Map();
  for (const [k, v] of keys) m.set(k, v);
  blobs.__state.stores.set(STORE, m);
  blobs.__state.stores.set('siegestack-contact', new Map());
}

const r = runner();

async function suite(opts = {}) {
  r.reset();
  const { check } = r;

  await check('the first run sends nothing and records a watermark', async () => {
    reset(SMTP_ENV);
    seed([[keyAt(1000), record('old-one')], [keyAt(2000), record('old-two')]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 0, 'nothing mailed on the first run');
    const wm = store().get('sweep/watermark');
    truthy(wm && typeof wm.at === 'number', 'watermark written');
    eq(keysOf('sent/').length, 0, 'no markers invented');
  });

  await check('a submission newer than the watermark is sent and marked', async () => {
    reset(SMTP_ENV);
    seed([['sweep/watermark', { at: 5000 }], [keyAt(6000), record('new-one')]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 1, 'one sent');
    truthy(/new-one/.test(mailer.__mail.sent[0].text), 'the right one');
    truthy(/^\[late\]/.test(mailer.__mail.sent[0].subject), 'subject marked late, got: ' + mailer.__mail.sent[0].subject);
    eq(keysOf('sent/').length, 1, 'marker written');
  });

  await check('an already-marked submission is left alone', async () => {
    reset(SMTP_ENV);
    const k = keyAt(6000);
    seed([['sweep/watermark', { at: 5000 }], [k, record('already')], [`sent/${k}`, { at: 'x' }]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 0, 'nothing re-sent');
  });

  await check('a submission older than the watermark is left alone', async () => {
    reset(SMTP_ENV);
    seed([['sweep/watermark', { at: 5000 }], [keyAt(4000), record('ancient')]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('running twice does not send the same notification twice', async () => {
    reset(SMTP_ENV);
    seed([['sweep/watermark', { at: 5000 }], [keyAt(6000), record('once-only')]]);
    const fn = await load('sweep', opts);
    await fn();
    await fn();
    eq(mailer.__mail.sent.length, 1, 'sent exactly once across two runs');
  });

  await check('a failing send leaves the submission unmarked so it retries', async () => {
    reset(SMTP_ENV);
    mailer.__mail.mode = 'throw';
    seed([['sweep/watermark', { at: 5000 }], [keyAt(6000), record('will-fail')]]);
    await (await load('sweep', opts))();
    eq(keysOf('sent/').length, 0, 'no marker');
    // ...and the next run, with mail working, sends it.
    mailer.__mail.mode = 'ok';
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 1, 'sent on the retry');
    eq(keysOf('sent/').length, 1, 'marked this time');
  });

  await check('one run sends at most MAX_PER_RUN and says what it deferred', async () => {
    reset(SMTP_ENV);
    const rows = [['sweep/watermark', { at: 5000 }]];
    for (let i = 0; i < 12; i++) rows.push([keyAt(6000 + i, 'k' + i), record('bulk' + i)]);
    seed(rows);
    const logged = [];
    const realLog = console.log;
    console.log = (...a) => { logged.push(String(a[0])); };
    try {
      await (await load('sweep', opts))();
    } finally {
      console.log = realLog;
    }
    eq(mailer.__mail.sent.length, 8, 'capped at 8');
    truthy(logged.some((l) => /_DEFERRED/.test(l) && /"deferred":4/.test(l)), 'deferred count logged, got: ' + logged.join(' | '));
  });

  await check('with no provider configured it sends nothing and marks nothing', async () => {
    reset({});
    seed([['sweep/watermark', { at: 5000 }], [keyAt(6000), record('no-provider')]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
    eq(keysOf('sent/').length, 0, 'nothing marked');
  });

  await check('a key with no parseable timestamp is left alone rather than guessed at', async () => {
    reset(SMTP_ENV);
    seed([['sweep/watermark', { at: 5000 }], [`${PREFIX}not-a-stamp`, record('odd')]]);
    await (await load('sweep', opts))();
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('it is scheduled hourly, which is the fastest Netlify allows', async () => {
    const src = (await import('node:fs')).readFileSync(new URL('../../netlify/functions/notify-sweep.mjs', import.meta.url), 'utf8');
    truthy(/schedule: '@hourly'/.test(src), 'schedule declared');
  });

  return { failures: r.failures, results: r.results };
}

try {
  if (process.argv.includes('--defects')) {
    let missed = 0;
    for (const [name, defect] of Object.entries(DEFECTS)) {
      const out = await suite({ defect });
      const caught = out.failures > 0;
      console.log(`${caught ? 'CAUGHT ' : 'MISSED '} ${name}  (${out.failures} case(s) failed)`);
      if (!caught) missed++;
    }
    console.log(missed === 0 ? '\nEvery defect was caught; a pass from this suite means something.' : `\n${missed} defect(s) went unnoticed -- fix the suite before trusting it.`);
    process.exit(missed === 0 ? 0 : 1);
  } else {
    const out = await suite();
    report(out.results, out.failures);
    process.exit(out.failures === 0 ? 0 : 1);
  }
} finally {
  cleanup();
}
