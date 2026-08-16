/**
 * Tests netlify/functions/submit-expertise.mjs without deploying it.
 *
 *   node scripts/test/submit-expertise.test.mjs            run the suite
 *   node scripts/test/submit-expertise.test.mjs --defects  prove it bites
 *
 * WHY IT IS SHAPED LIKE THIS
 * --------------------------
 * `netlify dev` does not run on the machine this was written on -- the CLI
 * fails with EBUSY spawning its bundled deno.exe -- so the function is driven
 * directly instead, with real Request objects against in-memory stubs.
 *
 * Two rules keep that honest:
 *
 * 1. THE REAL SOURCE IS COPIED IN AT RUN TIME and its imports rewritten to
 *    point at the stubs. The suite therefore cannot go stale against a
 *    snapshot, and the import lines it rewrites are asserted first, so
 *    renaming a dependency fails loudly instead of silently testing nothing.
 *    (Rewriting is used rather than a stub node_modules because node_modules is
 *    gitignored, and a rig that cannot be committed gets rebuilt from scratch
 *    every time -- which is exactly what happened to the jesse/nicole one.)
 *
 * 2. A PASS MEANS NOTHING UNTIL THE SUITE IS PROVEN TO FAIL. `--defects`
 *    applies each substitution in DEFECTS to the source and asserts the suite
 *    notices. Add a defect whenever you add a case that matters.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SRC = path.join(REPO, 'netlify', 'functions', 'submit-expertise.mjs');

const STUB_BLOBS = pathToFileURL(path.join(HERE, 'stub-blobs.mjs')).href;
const STUB_MAILER = pathToFileURL(path.join(HERE, 'stub-nodemailer.mjs')).href;

// The import lines the rewrite depends on. If the function changes how it
// imports either dependency, these stop matching and the suite refuses to run
// rather than quietly exercising the real modules or nothing at all.
const IMPORTS = [
  [/from '@netlify\/blobs'/, `from '${STUB_BLOBS}'`],
  [/from 'nodemailer'/, `from '${STUB_MAILER}'`],
];

const DEFECTS = {
  store_failure_reported_as_success: [
    /return json\(\{ ok: false, error: 'store_failed' \}, 503\);/,
    'return json({ ok: true }, 200);',
  ],
  budget_race_disabled: [/Promise\.race\(\[/, 'Promise.all(['],
  contact_to_default_restored: [
    /const to = process\.env\.CONTACT_TO;/,
    "const to = process.env.CONTACT_TO || 'info@siegestack.com';",
  ],
  loop_guard_narrowed_to_address: [
    /domainOf\(addr\(to\)\) === domainOf\(addr\(from\)\)/,
    'addr(to) === addr(from)',
  ],
  name_not_required: [
    /if \(!consultantName\) return json\(\{ ok: false, error: 'name_required' \}, 400\);/,
    '',
  ],
  redaction_class_excludes_the_letter_s: [
    /\[\^\\s<>@\]\+@\[\^\\s<>@\]\+/,
    '[^s<>@]+@[^s<>@]+',
  ],
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'expertise-suite-'));
let seq = 0;

async function load({ defect = null, fastBudget = false } = {}) {
  let src = fs.readFileSync(SRC, 'utf8');

  for (const [re, to] of IMPORTS) {
    if (!re.test(src)) throw new Error(`the source no longer matches ${re} -- this suite is stale, fix the rewrite`);
    src = src.replace(re, to);
  }
  // The real budget is 8s. Waiting that long per timing case is not worth it,
  // and a separate case asserts the shipped constant is still 8000.
  if (fastBudget) src = src.replace(/const NOTIFY_BUDGET_MS = 8000;/, 'const NOTIFY_BUDGET_MS = 300;');
  if (defect) {
    const [re, to] = DEFECTS[defect];
    if (!re.test(src)) throw new Error(`defect "${defect}" did not match the source -- this suite is stale, fix it`);
    src = src.replace(re, to);
  }

  const file = path.join(TMP, `subject-${++seq}.mjs`);
  fs.writeFileSync(file, src);
  return (await import(pathToFileURL(file).href)).default;
}

const blobs = await import(STUB_BLOBS);
const mailer = await import(STUB_MAILER);

function reset(env = {}) {
  blobs.reset();
  mailer.reset();
  for (const k of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'CONTACT_FROM', 'CONTACT_TO', 'RESEND_API_KEY']) {
    delete process.env[k];
  }
  Object.assign(process.env, env);
}

const SMTP_ENV = {
  SMTP_HOST: 'smtp.example.net',
  SMTP_PORT: '587',
  SMTP_USER: 'info@siegestack.com',
  SMTP_PASS: 'not-a-real-password',
  CONTACT_FROM: 'SiegeStack <info@siegestack.com>',
  CONTACT_TO: 'someone@example.com',
};

const post = (body) =>
  new Request('https://siegestack.com/api/expertise', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'suite' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

const FORM = {
  consultantName: 'A Consultant',
  erpExperience: 'P21 17 Years',
  languagesSpoken: 'English',
  yearsInDistribution: '12',
  Bank_Reconciliation: '4',
  Cash_Receipts: '3',
  Sales_Tax: '0',
  Widgets: '2',
};

const store = () => blobs.__state.stores.get('siegestack-expertise');
const eq = (a, b, what) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
};
const truthy = (v, what) => { if (!v) throw new Error(`${what}: expected truthy, got ${JSON.stringify(v)}`); };

let failures = 0;
const results = [];
async function check(name, fn) {
  try {
    await Promise.race([fn(), new Promise((_, r) => setTimeout(() => r(new Error('case timed out after 20s')), 20000))]);
    results.push(['PASS', name, '']);
  } catch (e) {
    failures++;
    results.push(['FAIL', name, e.message]);
  }
}

async function suite(opts = {}) {
  failures = 0;
  results.length = 0;

  await check('a valid submission is stored and reported ok', async () => {
    reset(SMTP_ENV);
    const res = await (await load(opts))(post(FORM));
    const j = await res.json();
    eq(res.status, 200, 'status');
    eq(j.ok, true, 'ok');
    eq(j.notified, true, 'notified');
    eq(store().size, 1, 'stored count');
    const rec = [...store().values()][0];
    eq(rec.consultantName, 'A Consultant', 'name');
    eq(rec.yearsInDistribution, 12, 'years coerced to a number');
    eq(rec.skills, { Bank_Reconciliation: 4, Cash_Receipts: 3, Sales_Tax: 0, Widgets: 2 }, 'skills');
    truthy(rec.raw, 'raw payload kept');
    eq(blobs.__state.calls[0].opts.consistency, 'strong', 'strong consistency requested');
  });

  await check('the durable write happens BEFORE the notification', async () => {
    reset(SMTP_ENV);
    const order = [];
    const realStore = blobs.__state.calls.push.bind(blobs.__state.calls);
    const realSent = mailer.__mail.sent.push.bind(mailer.__mail.sent);
    blobs.__state.calls.push = (v) => { order.push('store'); return realStore(v); };
    mailer.__mail.sent.push = (v) => { order.push('mail'); return realSent(v); };
    await (await load(opts))(post(FORM));
    blobs.__state.calls.push = realStore;
    mailer.__mail.sent.push = realSent;
    eq(order, ['store', 'mail'], 'ordering');
  });

  await check('a store failure is reported honestly as a 503', async () => {
    reset(SMTP_ENV);
    blobs.__state.failNext = true;
    const res = await (await load(opts))(post(FORM));
    const j = await res.json();
    eq(res.status, 503, 'status');
    eq(j.ok, false, 'ok');
    eq(j.error, 'store_failed', 'error');
  });

  await check('GET is rejected', async () => {
    reset(SMTP_ENV);
    const res = await (await load(opts))(new Request('https://siegestack.com/api/expertise'));
    eq(res.status, 405, 'status');
  });

  await check('malformed JSON is a 400', async () => {
    reset(SMTP_ENV);
    eq((await (await load(opts))(post('{not json'))).status, 400, 'status');
  });

  await check('a missing name is a 400 and stores nothing', async () => {
    reset(SMTP_ENV);
    const res = await (await load(opts))(post({ ...FORM, consultantName: '   ' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'name_required', 'error');
    eq(store()?.size ?? 0, 0, 'nothing stored');
  });

  await check('out-of-range ratings are dropped, not fatal', async () => {
    reset(SMTP_ENV);
    const res = await (await load(opts))(post({ ...FORM, Bad_High: '9', Bad_Neg: '-1', Bad_Text: 'expert', Bad_Float: '2.5' }));
    eq(res.status, 200, 'status');
    eq(Object.keys([...store().values()][0].skills).sort(), ['Bank_Reconciliation', 'Cash_Receipts', 'Sales_Tax', 'Widgets'], 'skills kept');
  });

  await check('a blank years field stores null, not an empty string', async () => {
    reset(SMTP_ENV);
    await (await load(opts))(post({ ...FORM, yearsInDistribution: '' }));
    eq([...store().values()][0].yearsInDistribution, null, 'years');
  });

  await check('an oversized payload is refused', async () => {
    reset(SMTP_ENV);
    const big = { ...FORM };
    for (let i = 0; i < 700; i++) big['Skill_' + i] = '1';
    const res = await (await load(opts))(post(big));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'too_many_fields', 'error');
  });

  await check('no provider: stored anyway, reason no_provider', async () => {
    reset({});
    const j = await (await (await load(opts))(post(FORM))).json();
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    eq(j.reason, 'no_provider', 'reason');
    eq(store().size, 1, 'still stored');
  });

  await check('CONTACT_TO unset: no_to, and no default is invented', async () => {
    reset(SMTP_ENV);
    delete process.env.CONTACT_TO;
    const j = await (await (await load(opts))(post(FORM))).json();
    eq(j.reason, 'no_to', 'reason');
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('CONTACT_FROM unset: no_from', async () => {
    reset(SMTP_ENV);
    delete process.env.CONTACT_FROM;
    eq((await (await (await load(opts))(post(FORM))).json()).reason, 'no_from', 'reason');
  });

  await check('a same-DOMAIN destination is refused, not just the same address', async () => {
    reset({ ...SMTP_ENV, CONTACT_TO: 'scott@siegestack.com' });
    const j = await (await (await load(opts))(post(FORM))).json();
    eq(j.reason, 'to_equals_from', 'reason');
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('an SMTP failure keeps the submission, names the code, and redacts the address', async () => {
    reset(SMTP_ENV);
    mailer.__mail.mode = 'throw';
    const j = await (await (await load(opts))(post(FORM))).json();
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    eq(j.reason, 'smtp_eauth_535', 'reason');
    truthy(j.smtpSaid, 'smtpSaid present');
    // The response is public. Anyone can POST here and read this field.
    if (/@/.test(j.smtpSaid)) throw new Error('smtpSaid leaked an address: ' + j.smtpSaid);
    eq(mailer.__mail.closed, 1, 'transport closed');
    eq(store().size, 1, 'stored despite the failure');
  });

  await check('a hanging send gives up at the budget and still returns 200', async () => {
    reset(SMTP_ENV);
    mailer.__mail.mode = 'hang';
    const t0 = Date.now();
    const j = await (await (await load({ ...opts, fastBudget: true }))(post(FORM))).json();
    const ms = Date.now() - t0;
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    // The outer race rejects with a plain Error carrying no .code, so this is
    // smtp_unknown rather than smtp_etimedout. MAIL.md documents the same.
    eq(j.reason, 'smtp_unknown', 'reason');
    truthy(/exceeded 300ms/.test(j.smtpSaid || ''), 'smtpSaid names the budget, got: ' + j.smtpSaid);
    if (ms > 5000) throw new Error('did not give up at the budget; took ' + ms + 'ms');
    eq(mailer.__mail.closed, 1, 'transport closed');
    eq(store().size, 1, 'stored despite the timeout');
  });

  await check('the shipped budget is still 8000ms', async () => {
    truthy(/const NOTIFY_BUDGET_MS = 8000;/.test(fs.readFileSync(SRC, 'utf8')), 'source declares 8000');
  });

  return { failures, results };
}

try {
  if (process.argv.includes('--defects')) {
    let missed = 0;
    for (const name of Object.keys(DEFECTS)) {
      const r = await suite({ defect: name });
      const caught = r.failures > 0;
      console.log(`${caught ? 'CAUGHT ' : 'MISSED '} ${name}  (${r.failures} case(s) failed)`);
      if (!caught) missed++;
    }
    console.log(missed === 0 ? '\nEvery defect was caught; a pass from this suite means something.' : `\n${missed} defect(s) went unnoticed -- fix the suite before trusting it.`);
    process.exit(missed === 0 ? 0 : 1);
  } else {
    const r = await suite();
    for (const [s, n, m] of r.results) console.log(`  ${s}  ${n}${m ? '\n        ' + m : ''}`);
    console.log(`\n  ${r.results.length - r.failures}/${r.results.length} passed`);
    process.exit(r.failures === 0 ? 0 : 1);
  }
} finally {
  fs.rmSync(TMP, { recursive: true, force: true });
}
