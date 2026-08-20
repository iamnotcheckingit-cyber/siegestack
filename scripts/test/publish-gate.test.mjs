/**
 * publish-gate: deny-by-default for the published surface.
 *
 * This gate runs on every request to the site. A bug in it is not a bad page,
 * it is the whole site returning 404 — so it is driven here against its real
 * source before it is ever deployed, and every published route is asserted
 * individually rather than spot-checked.
 *
 * The allow-list is cross-checked against sitemap.xml rather than hand-listed:
 * a route added to the sitemap and forgotten in the gate would 404 in
 * production, and that is exactly the failure this file exists to catch.
 *
 * The source is TypeScript for Deno, so the type annotations are stripped
 * before import. Every strip is asserted — if the file changes shape the suite
 * refuses to run rather than testing something that is no longer the gate.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC_PATH = path.join(ROOT, 'netlify', 'edge-functions', 'publish-gate.ts');
const RAW = fs.readFileSync(SRC_PATH, 'utf8');

const STRIPS = [
  [/\(request: Request, context: any\)/, '(request, context)'],
  [/\(_context\?: unknown\)/, '(_context)'],
  [/\(err as Error\)/, 'err'],
  [/function isAllowed\(rawPath: string\): boolean/, 'function isAllowed(rawPath)'],
];

let js = RAW;
for (const [re, to] of STRIPS) {
  if (!re.test(js)) {
    console.error(`FATAL: ${re} no longer matches publish-gate.ts — this suite is stale, fix the strip.`);
    process.exit(1);
  }
  js = js.replace(re, to);
}

const mod = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
const gate = mod.default;

const PASS = Symbol('passed-through');
const ctx = { next: async () => PASS };
const ask = async (p) => {
  const out = await gate(new Request(`https://siegestack.com${p}`), ctx);
  return out === PASS ? 'ALLOW' : `DENY(${out.status})`;
};

// Every route the sitemap publishes must be reachable. Built from the file, so
// adding a route to the sitemap without allow-listing it fails here.
const sitemapRoutes = [...fs.readFileSync(path.join(ROOT, 'sitemap.xml'), 'utf8')
  .matchAll(/<loc>https:\/\/siegestack\.com([^<]*)<\/loc>/g)]
  .map((m) => m[1] || '/');

const MUST_ALLOW = [
  ...sitemapRoutes,
  // Reachable on purpose, deliberately absent from the sitemap.
  '/audit', '/consultant-expertise', '/jesse', '/nicole', '/secret',
  '/epicor-p21-kinetic-reporting',            // must reach its 301
  '/prophet-21.html',                          // must reach its 301
  // Crawl and citation layer.
  '/robots.txt', '/sitemap.xml', '/llms.txt', '/llms-full.txt',
  // Search Console verification. A 404 here silently unverifies the domain.
  '/googleeaab9608ff5e7c66.html',
  // Assets and PWA surface.
  '/favicon.svg', '/favicon.ico', '/favicon.png', '/favicon-sw.svg',
  '/og-card.jpg', '/og-image.png', '/og-working-with-claude-card.jpg',
  '/consultant-form.js', '/jesse-sw.js', '/nicole-sw.js', '/label-tool-xlsx.js',
  '/jesse-manifest.json', '/nicole-manifest.json',
  '/private-icon-192.png', '/private-icon-maskable-512.png', '/private-badge-96.png',
  '/apple-touch-icon.png',
  // Function surface.
  '/api/contact', '/api/expertise',
];

const MUST_DENY = [
  '/MAIL.md', '/DNS-SNAPSHOT.md', '/README.md',
  '/docs/MAIL.md', '/docs/DNS-SNAPSHOT.md', '/docs/audit-2026-08-16.md',
  '/package.json', '/package-lock.json',
  '/scripts/build-llms-full.mjs', '/scripts/test/harness.mjs',
  '/netlify/functions/contact-api.mjs', '/netlify/lib/notify.mjs',
  '/netlify/edge-functions/publish-gate.ts',
  '/_readme_for_zip.txt', '/LICENSE',
  '/private-files/ram-report.bat',
  // The class that started this: a new document dropped in the root.
  '/NOTES.md', '/TODO.md', '/secrets.txt', '/backup.sql', '/config.yaml',
];

let failures = 0;
const line = (verdict, p, want) => {
  const ok = verdict.startsWith(want);
  if (!ok) failures++;
  return `  ${ok ? 'PASS' : 'FAIL'}  ${want.padEnd(5)} ${p}${ok ? '' : `  -> got ${verdict}`}`;
};

const out = [];
out.push(`ALLOW (${MUST_ALLOW.length}, of which ${sitemapRoutes.length} read from sitemap.xml)`);
for (const p of MUST_ALLOW) out.push(line(await ask(p), p, 'ALLOW'));
out.push(`\nDENY (${MUST_DENY.length})`);
for (const p of MUST_DENY) out.push(line(await ask(p), p, 'DENY'));

// Only print failures unless everything passed, so a green run stays readable.
if (failures) console.log(out.filter((l) => l.includes('FAIL') || !l.startsWith('  ')).join('\n'));
console.log(`\n  publish-gate: ${MUST_ALLOW.length + MUST_DENY.length - failures}/${MUST_ALLOW.length + MUST_DENY.length} decisions correct`);

/**
 * Malformed percent-encoding must NOT crash the gate. It is judged on its raw
 * form and denied, which is correct — an unparseable path is not a published
 * route, and failing open there would serve nothing that exists anyway.
 */
const malformed = await ask('/%E0%A4%A');
if (malformed.startsWith('DENY')) {
  console.log('  PASS  a malformed path is judged without throwing');
} else {
  console.error(`  FAIL  malformed path returned ${malformed}`);
  failures++;
}

/**
 * The gate must fail OPEN when its own decision logic breaks, because a gate on
 * /* that fails closed is a sitewide outage caused by its own bug. Exercised by
 * making the request unreadable, which is the only way to reach that catch.
 */
const hostile = { get url() { throw new Error('unreadable request'); } };
const failOpen = await gate(hostile, ctx);
if (failOpen === PASS) {
  console.log('  PASS  fails open when the decision itself throws');
} else {
  console.error(`  FAIL  the gate denied (${failOpen?.status}) instead of failing open`);
  failures++;
}

/**
 * A downstream failure is NOT this gate's to absorb. Retrying context.next()
 * inside a catch just throws again — an earlier version did exactly that and
 * its fail-open only worked when nothing was wrong. The exception must
 * propagate so the platform handles it.
 */
let propagated = false;
await gate(new Request('https://siegestack.com/'), {
  next: () => { throw new Error('simulated downstream failure'); },
}).catch(() => { propagated = true; });
if (!propagated) {
  console.error('  FAIL  a downstream throw was swallowed instead of propagating');
  failures++;
} else {
  console.log('  PASS  a downstream throw propagates rather than being retried');
}

process.exit(failures ? 1 : 0);
