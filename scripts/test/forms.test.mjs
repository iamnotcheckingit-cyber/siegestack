/**
 * The two public form endpoints: /api/expertise and /api/contact.
 *
 * See harness.mjs for how the functions are loaded and why a pass here is
 * worth something. Run with --defects to prove the suite still bites.
 */
import { load, readSource, reset, blobs, mailer, SMTP_ENV, post, eq, truthy, runner, report, cleanup } from './harness.mjs';

const DEFECTS = {
  store_failure_reported_as_success: {
    file: 'expertise',
    re: /return json\(\{ ok: false, error: 'store_failed' \}, 503\);/,
    to: 'return json({ ok: true }, 200);',
  },
  budget_race_disabled: { file: 'notify', re: /Promise\.race\(\[/, to: 'Promise.all([' },
  contact_to_default_restored: {
    file: 'notify',
    re: /const to = process\.env\.CONTACT_TO;/,
    to: "const to = process.env.CONTACT_TO || 'info@siegestack.com';",
  },
  loop_guard_narrowed_to_address: {
    file: 'notify',
    re: /domainOf\(addr\(to\)\) === domainOf\(addr\(from\)\)/,
    to: 'addr(to) === addr(from)',
  },
  redaction_class_excludes_the_letter_s: {
    file: 'notify',
    re: /\[\^\\s<>@\]\+@\[\^\\s<>@\]\+/,
    to: '[^s<>@]+@[^s<>@]+',
  },
  name_not_required: {
    file: 'expertise',
    re: /if \(!consultantName\) return json\(\{ ok: false, error: 'name_required' \}, 400\);/,
    to: '',
  },
  email_not_required: {
    file: 'expertise',
    re: /if \(!email\) return json\(\{ ok: false, error: 'email_required' \}, 400\);/,
    to: '',
  },
  contact_fields_treated_as_skills: {
    file: 'expertise',
    re: /'consultantName', 'email', 'phone', 'bestTimeToCall', 'timeZone',/,
    to: "'consultantName',",
  },
  reply_to_dropped: { file: 'expertise', re: /replyTo: email,/, to: '' },
  // The marker is what stops notify-sweep sending a duplicate of every
  // notification that already went out.
  expertise_marker_not_written: { file: 'expertise', re: /if \(notified\) await markNotified/, to: 'if (false) await markNotified' },
  contact_marker_not_written: { file: 'contact', re: /if \(notified\) await markNotified/, to: 'if (false) await markNotified' },
};

const EXP_URL = 'https://siegestack.com/api/expertise';
const CON_URL = 'https://siegestack.com/api/contact';

const FORM = {
  consultantName: 'A Consultant',
  email: 'consultant@example.org',
  phone: '',
  bestTimeToCall: '',
  timeZone: '',
  erpExperience: 'P21 17 Years',
  languagesSpoken: 'English',
  yearsInDistribution: '12',
  Bank_Reconciliation: '4',
  Cash_Receipts: '3',
  Sales_Tax: '0',
  Widgets: '2',
};

const ENQUIRY = { name: 'A Visitor', email: 'visitor@example.org', company: 'Some Co', message: 'Hello there' };

const expStore = () => blobs.__state.stores.get('siegestack-expertise');
const conStore = () => blobs.__state.stores.get('siegestack-contact');
const keysOf = (s, prefix) => [...(s?.keys() ?? [])].filter((k) => k.startsWith(prefix));

const r = runner();

async function suite(opts = {}) {
  r.reset();
  const { check } = r;

  // ---------------- /api/expertise ----------------

  await check('expertise: a valid submission is stored and reported ok', async () => {
    reset(SMTP_ENV);
    const res = await (await load('expertise', opts))(post(EXP_URL, FORM));
    const j = await res.json();
    eq(res.status, 200, 'status');
    eq(j.ok, true, 'ok');
    eq(j.notified, true, 'notified');
    eq(keysOf(expStore(), 'matrix/').length, 1, 'stored count');
    // Without this marker notify-sweep would send a duplicate an hour later.
    eq(keysOf(expStore(), 'sent/').length, 1, 'marker written');
    const rec = [...expStore().values()][0];
    eq(rec.consultantName, 'A Consultant', 'name');
    eq(rec.email, 'consultant@example.org', 'email');
    eq(rec.yearsInDistribution, 12, 'years coerced to a number');
    eq(rec.skills, { Bank_Reconciliation: 4, Cash_Receipts: 3, Sales_Tax: 0, Widgets: 2 }, 'skills');
    truthy(rec.raw, 'raw payload kept');
    eq(blobs.__state.calls[0].opts.consistency, 'strong', 'strong consistency requested');
  });

  await check('expertise: the durable write happens BEFORE the notification', async () => {
    reset(SMTP_ENV);
    const order = [];
    const realStore = blobs.__state.calls.push.bind(blobs.__state.calls);
    const realSent = mailer.__mail.sent.push.bind(mailer.__mail.sent);
    blobs.__state.calls.push = (v) => { if (v.key.startsWith('matrix/')) order.push('store'); return realStore(v); };
    mailer.__mail.sent.push = (v) => { order.push('mail'); return realSent(v); };
    await (await load('expertise', opts))(post(EXP_URL, FORM));
    blobs.__state.calls.push = realStore;
    mailer.__mail.sent.push = realSent;
    eq(order, ['store', 'mail'], 'ordering');
  });

  await check('expertise: a store failure is reported honestly as a 503', async () => {
    reset(SMTP_ENV);
    blobs.__state.failNext = true;
    const res = await (await load('expertise', opts))(post(EXP_URL, FORM));
    eq(res.status, 503, 'status');
    eq((await res.json()).error, 'store_failed', 'error');
  });

  await check('expertise: GET is rejected', async () => {
    reset(SMTP_ENV);
    eq((await (await load('expertise', opts))(new Request(EXP_URL))).status, 405, 'status');
  });

  await check('expertise: malformed JSON is a 400', async () => {
    reset(SMTP_ENV);
    eq((await (await load('expertise', opts))(post(EXP_URL, '{not json'))).status, 400, 'status');
  });

  await check('expertise: a missing name is a 400 and stores nothing', async () => {
    reset(SMTP_ENV);
    const res = await (await load('expertise', opts))(post(EXP_URL, { ...FORM, consultantName: '   ' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'name_required', 'error');
    eq(keysOf(expStore(), 'matrix/').length, 0, 'nothing stored');
  });

  await check('expertise: a missing email is a 400 and stores nothing', async () => {
    reset(SMTP_ENV);
    const res = await (await load('expertise', opts))(post(EXP_URL, { ...FORM, email: '' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'email_required', 'error');
    eq(keysOf(expStore(), 'matrix/').length, 0, 'nothing stored');
  });

  await check('expertise: a malformed email is a 400', async () => {
    reset(SMTP_ENV);
    const res = await (await load('expertise', opts))(post(EXP_URL, { ...FORM, email: 'not-an-address' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'email_invalid', 'error');
  });

  await check('expertise: a reply reaches the consultant, and From stays the alias', async () => {
    reset(SMTP_ENV);
    await (await load('expertise', opts))(post(EXP_URL, FORM));
    const sent = mailer.__mail.sent[0];
    eq(sent.replyTo, 'consultant@example.org', 'replyTo');
    // Sending as the consultant's own domain would fail SPF.
    eq(sent.from, SMTP_ENV.CONTACT_FROM, 'from');
    truthy(sent.text.includes('consultant@example.org'), 'address in the body too');
  });

  await check('expertise: phone, call window and time zone travel together', async () => {
    reset(SMTP_ENV);
    await (await load('expertise', opts))(post(EXP_URL, { ...FORM, phone: '+1 555 0134 x22', bestTimeToCall: 'Morning (8-11)', timeZone: 'CT' }));
    const rec = [...expStore().values()].find((v) => v.consultantName);
    eq(rec.phone, '+1 555 0134 x22', 'phone stored verbatim');
    eq(rec.bestTimeToCall, 'Morning (8-11)', 'window');
    eq(rec.timeZone, 'CT', 'time zone');
    const line = mailer.__mail.sent[0].text.split('\n').find((l) => l.startsWith('Phone:'));
    truthy(/\+1 555 0134 x22/.test(line), 'number in the summary, got: ' + line);
    truthy(/best Morning \(8-11\)/.test(line), 'window in the summary, got: ' + line);
    truthy(/CT/.test(line), 'time zone in the summary, got: ' + line);
  });

  await check('expertise: contact fields are never filed as skill ratings', async () => {
    reset(SMTP_ENV);
    // "2" is a valid rating, so a contact field carrying it is exactly how one
    // would leak into the matrix if it fell out of the identity set.
    await (await load('expertise', opts))(post(EXP_URL, { ...FORM, phone: '2', timeZone: '3' }));
    const rec = [...expStore().values()].find((v) => v.consultantName);
    eq(Object.keys(rec.skills).sort(), ['Bank_Reconciliation', 'Cash_Receipts', 'Sales_Tax', 'Widgets'], 'skills');
    eq(rec.phone, '2', 'phone kept as a contact field');
  });

  await check('expertise: an omitted phone reads as not given', async () => {
    reset(SMTP_ENV);
    await (await load('expertise', opts))(post(EXP_URL, FORM));
    truthy(mailer.__mail.sent[0].text.includes('Phone:      (not given)'), 'phone line');
  });

  await check('expertise: out-of-range ratings are dropped, not fatal', async () => {
    reset(SMTP_ENV);
    const res = await (await load('expertise', opts))(post(EXP_URL, { ...FORM, Bad_High: '9', Bad_Neg: '-1', Bad_Text: 'expert', Bad_Float: '2.5' }));
    eq(res.status, 200, 'status');
    const rec = [...expStore().values()].find((v) => v.consultantName);
    eq(Object.keys(rec.skills).sort(), ['Bank_Reconciliation', 'Cash_Receipts', 'Sales_Tax', 'Widgets'], 'skills kept');
  });

  await check('expertise: a blank years field stores null, not an empty string', async () => {
    reset(SMTP_ENV);
    await (await load('expertise', opts))(post(EXP_URL, { ...FORM, yearsInDistribution: '' }));
    eq([...expStore().values()].find((v) => v.consultantName).yearsInDistribution, null, 'years');
  });

  await check('expertise: an oversized payload is refused', async () => {
    reset(SMTP_ENV);
    const big = { ...FORM };
    for (let i = 0; i < 700; i++) big['Skill_' + i] = '1';
    const res = await (await load('expertise', opts))(post(EXP_URL, big));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'too_many_fields', 'error');
  });

  // ---------------- /api/contact ----------------

  await check('contact: a valid enquiry is stored, notified and marked', async () => {
    reset(SMTP_ENV);
    const res = await (await load('contact', opts))(post(CON_URL, ENQUIRY));
    const j = await res.json();
    eq(res.status, 200, 'status');
    eq(j.ok, true, 'ok');
    eq(j.notified, true, 'notified');
    eq(keysOf(conStore(), 'msg/').length, 1, 'stored');
    eq(keysOf(conStore(), 'sent/').length, 1, 'marker written');
    eq(mailer.__mail.sent[0].replyTo, ENQUIRY.email, 'replyTo');
  });

  await check('contact: the honeypot is accepted and discarded', async () => {
    reset(SMTP_ENV);
    const res = await (await load('contact', opts))(post(CON_URL, { ...ENQUIRY, website: 'http://spam' }));
    eq(res.status, 200, 'status');
    eq((await res.json()).ok, true, 'ok, so a bot learns nothing');
    eq(keysOf(conStore(), 'msg/').length, 0, 'nothing stored');
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('contact: a missing message is a 400', async () => {
    reset(SMTP_ENV);
    const res = await (await load('contact', opts))(post(CON_URL, { ...ENQUIRY, message: '' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'message_required', 'error');
  });

  await check('contact: an invalid email is a 400', async () => {
    reset(SMTP_ENV);
    const res = await (await load('contact', opts))(post(CON_URL, { ...ENQUIRY, email: 'nope' }));
    eq(res.status, 400, 'status');
    eq((await res.json()).error, 'email_invalid', 'error');
  });

  await check('contact: a store failure is reported honestly as a 503', async () => {
    reset(SMTP_ENV);
    blobs.__state.failNext = true;
    const res = await (await load('contact', opts))(post(CON_URL, ENQUIRY));
    eq(res.status, 503, 'status');
    eq((await res.json()).error, 'store_failed', 'error');
  });

  // ---------------- shared notification behaviour ----------------

  await check('no provider: stored anyway, reason no_provider, no marker', async () => {
    reset({});
    const j = await (await (await load('expertise', opts))(post(EXP_URL, FORM))).json();
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    eq(j.reason, 'no_provider', 'reason');
    eq(keysOf(expStore(), 'matrix/').length, 1, 'still stored');
    // No marker, so the sweep will pick it up rather than assume it went.
    eq(keysOf(expStore(), 'sent/').length, 0, 'no marker');
  });

  await check('CONTACT_TO unset: no_to, and no default is invented', async () => {
    reset(SMTP_ENV);
    delete process.env.CONTACT_TO;
    const j = await (await (await load('expertise', opts))(post(EXP_URL, FORM))).json();
    eq(j.reason, 'no_to', 'reason');
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('CONTACT_FROM unset: no_from', async () => {
    reset(SMTP_ENV);
    delete process.env.CONTACT_FROM;
    eq((await (await (await load('expertise', opts))(post(EXP_URL, FORM))).json()).reason, 'no_from', 'reason');
  });

  await check('a same-DOMAIN destination is refused, not just the same address', async () => {
    reset({ ...SMTP_ENV, CONTACT_TO: 'scott@siegestack.com' });
    const j = await (await (await load('expertise', opts))(post(EXP_URL, FORM))).json();
    eq(j.reason, 'to_equals_from', 'reason');
    eq(mailer.__mail.sent.length, 0, 'nothing sent');
  });

  await check('an SMTP failure keeps the submission, names the code, redacts the address', async () => {
    reset(SMTP_ENV);
    mailer.__mail.mode = 'throw';
    const j = await (await (await load('expertise', opts))(post(EXP_URL, FORM))).json();
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    eq(j.reason, 'smtp_eauth_535', 'reason');
    truthy(j.smtpSaid, 'smtpSaid present');
    // This response is public: anyone can POST and read the field.
    if (/@/.test(j.smtpSaid)) throw new Error('smtpSaid leaked an address: ' + j.smtpSaid);
    eq(mailer.__mail.closed, 1, 'transport closed');
    eq(keysOf(expStore(), 'sent/').length, 0, 'not marked, so the sweep retries it');
  });

  await check('a hanging send gives up at the budget and still returns 200', async () => {
    reset(SMTP_ENV);
    mailer.__mail.mode = 'hang';
    const t0 = Date.now();
    const j = await (await (await load('expertise', { ...opts, fastBudget: true }))(post(EXP_URL, FORM))).json();
    const ms = Date.now() - t0;
    eq(j.ok, true, 'ok');
    eq(j.notified, false, 'notified');
    // The outer race rejects with a plain Error carrying no .code, so this is
    // smtp_unknown rather than smtp_etimedout. MAIL.md documents the same.
    eq(j.reason, 'smtp_unknown', 'reason');
    truthy(/exceeded 300ms/.test(j.smtpSaid || ''), 'smtpSaid names the budget, got: ' + j.smtpSaid);
    if (ms > 5000) throw new Error('did not give up at the budget; took ' + ms + 'ms');
    eq(mailer.__mail.closed, 1, 'transport closed');
    eq(keysOf(expStore(), 'matrix/').length, 1, 'stored despite the timeout');
    eq(keysOf(expStore(), 'sent/').length, 0, 'unmarked, so the sweep will retry it');
  });

  await check('the shipped budget is still 8000ms', async () => {
    truthy(/export const NOTIFY_BUDGET_MS = 8000;/.test(readSource('notify')), 'notify.mjs declares 8000');
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
