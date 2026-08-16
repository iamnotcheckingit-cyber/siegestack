/**
 * Shared loader for the function tests.
 *
 * `netlify dev` does not run on the machine this was written on -- the CLI
 * fails with EBUSY spawning its bundled deno.exe -- so functions are driven
 * directly instead, with real Request objects against in-memory stubs.
 *
 * Two rules keep that honest, and both are enforced here rather than trusted:
 *
 * 1. THE REAL SOURCE IS COPIED IN AT RUN TIME and its import specifiers
 *    rewritten to point at stubs, so a suite can never go stale against a
 *    snapshot. Every rewrite is asserted before it is applied: if a file stops
 *    importing what this expects, the suite REFUSES TO RUN rather than quietly
 *    exercising nothing. That check is the whole reason to trust a pass.
 *
 *    (Rewriting is used rather than a stub node_modules because node_modules is
 *    gitignored, and a rig that cannot be committed gets rebuilt from scratch
 *    every time -- which is what kept happening to the jesse/nicole one.)
 *
 * 2. A PASS MEANS NOTHING UNTIL THE SUITE IS PROVEN TO FAIL. Defects are regex
 *    substitutions applied to the source before import, so "the suite fails on
 *    broken code" is one flag rather than a manual edit. Each defect names the
 *    file it targets, because the notification logic now lives in lib/notify.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..');

const SRC = {
  notify: path.join(REPO, 'netlify', 'lib', 'notify.mjs'),
  pending: path.join(REPO, 'netlify', 'lib', 'pending.mjs'),
  contact: path.join(REPO, 'netlify', 'functions', 'contact-api.mjs'),
  expertise: path.join(REPO, 'netlify', 'functions', 'submit-expertise.mjs'),
  sweep: path.join(REPO, 'netlify', 'functions', 'notify-sweep.mjs'),
};

const STUB_BLOBS = pathToFileURL(path.join(HERE, 'stub-blobs.mjs')).href;
const STUB_MAILER = pathToFileURL(path.join(HERE, 'stub-nodemailer.mjs')).href;

export const blobs = await import(STUB_BLOBS);
export const mailer = await import(STUB_MAILER);

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'siegestack-suite-'));
let seq = 0;

const write = (name, src) => {
  const file = path.join(TMP, `${name}-${++seq}.mjs`);
  fs.writeFileSync(file, src);
  return file;
};

/** Applies a substitution, refusing to continue if it does not match. */
function must(src, re, to, what) {
  if (!re.test(src)) throw new Error(`${what}: ${re} no longer matches the source -- this suite is stale, fix the rewrite`);
  return src.replace(re, to);
}

/**
 * Builds a runnable copy of one function with its whole import graph rewritten
 * onto the stubs, and returns its default export.
 *
 * defects: { file: 'notify'|'pending'|<fn>, re, to } applied before import.
 */
export async function load(which, { defect = null, fastBudget = false } = {}) {
  const patch = (fileKey, src) => {
    if (defect && defect.file === fileKey) {
      if (!defect.re.test(src)) throw new Error(`defect did not match ${fileKey} -- this suite is stale`);
      src = src.replace(defect.re, defect.to);
    }
    return src;
  };

  // pending.mjs imports nothing, so it needs no rewriting -- only patching.
  const pendingFile = write('pending', patch('pending', fs.readFileSync(SRC.pending, 'utf8')));

  let notifySrc = fs.readFileSync(SRC.notify, 'utf8');
  notifySrc = must(notifySrc, /from 'nodemailer'/, `from '${STUB_MAILER}'`, 'notify.mjs nodemailer import');
  // The real budget is 8s. Waiting that long per timing case is not worth it,
  // and a separate case asserts the shipped constant is still 8000.
  if (fastBudget) notifySrc = must(notifySrc, /export const NOTIFY_BUDGET_MS = 8000;/, 'export const NOTIFY_BUDGET_MS = 300;', 'notify.mjs budget');
  const notifyFile = write('notify', patch('notify', notifySrc));

  let fnSrc = fs.readFileSync(SRC[which], 'utf8');
  fnSrc = must(fnSrc, /from '@netlify\/blobs'/, `from '${STUB_BLOBS}'`, `${which} blobs import`);
  fnSrc = must(fnSrc, /from '\.\.\/lib\/notify\.mjs'/, `from '${pathToFileURL(notifyFile).href}'`, `${which} notify import`);
  fnSrc = must(fnSrc, /from '\.\.\/lib\/pending\.mjs'/, `from '${pathToFileURL(pendingFile).href}'`, `${which} pending import`);
  const fnFile = write(which, patch(which, fnSrc));

  return (await import(pathToFileURL(fnFile).href)).default;
}

export const readSource = (which) => fs.readFileSync(SRC[which], 'utf8');

export function reset(env = {}) {
  blobs.reset();
  mailer.reset();
  for (const k of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'CONTACT_FROM', 'CONTACT_TO', 'RESEND_API_KEY']) {
    delete process.env[k];
  }
  Object.assign(process.env, env);
}

export const SMTP_ENV = {
  SMTP_HOST: 'smtp.example.net',
  SMTP_PORT: '587',
  SMTP_USER: 'info@siegestack.com',
  SMTP_PASS: 'not-a-real-password',
  CONTACT_FROM: 'SiegeStack <info@siegestack.com>',
  CONTACT_TO: 'someone@example.com',
};

export const post = (url, body) =>
  new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'suite' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });

export const eq = (a, b, what) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
};
export const truthy = (v, what) => { if (!v) throw new Error(`${what}: expected truthy, got ${JSON.stringify(v)}`); };

export function runner() {
  let failures = 0;
  const results = [];
  return {
    async check(name, fn) {
      try {
        await Promise.race([fn(), new Promise((_, r) => setTimeout(() => r(new Error('case timed out after 20s')), 20000))]);
        results.push(['PASS', name, '']);
      } catch (e) {
        failures++;
        results.push(['FAIL', name, e.message]);
      }
    },
    get failures() { return failures; },
    results,
    reset() { failures = 0; results.length = 0; },
  };
}

export function report(results, failures) {
  for (const [s, n, m] of results) console.log(`  ${s}  ${n}${m ? '\n        ' + m : ''}`);
  console.log(`\n  ${results.length - failures}/${results.length} passed`);
}

export const cleanup = () => fs.rmSync(TMP, { recursive: true, force: true });
