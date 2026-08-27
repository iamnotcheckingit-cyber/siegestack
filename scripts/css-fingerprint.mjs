/**
 * Proves a CSS change altered nothing, by comparing what actually applies to
 * each page rather than by reading the diff.
 *
 *   node scripts/css-fingerprint.mjs            # write data/css-fingerprint.json
 *   node scripts/css-fingerprint.mjs --check    # compare against the committed one
 *
 * WHY THIS IS IN THE REPOSITORY AND NOT IN SOMEONE'S SCRATCH DIRECTORY.
 * /delivery-config-audit and the homepage both sell this exact discipline: "for
 * a large mechanical change, 'the diff looks equivalent' is not evidence. We
 * measure the old and new versions side by side and compare what actually
 * renders." The Phase 5 consolidation was measured that way, the tool caught two
 * real bugs doing it -- a 768px .hero h1/.content hoist that changed the article
 * pages' mobile rendering, and an emitter reading only each page's largest
 * <style> block when /contact keeps a nav rule in its second -- and then the
 * tool was thrown away with the temp directory. A verification you cannot re-run
 * is an anecdote.
 *
 * It matters more now than it did before Phase 5. One stylesheet backs 22 pages,
 * so every future CSS edit is a 22-page change, and the blast radius of a
 * mistake grew by exactly the amount the consolidation was worth.
 *
 * WHAT THE FINGERPRINT IS. For each page: every (media query, selector) pair
 * that applies to it, with its declarations resolved the way the cascade
 * resolves them -- later blocks overriding earlier ones property by property,
 * across the linked stylesheets and the page's own <style> in document order.
 * Hashed per page. It deliberately does NOT include the HTML: the point is to
 * detect CSS that changed under markup that did not.
 *
 * WHAT IT IS NOT. It does not run a browser, so it does not know about
 * specificity conflicts between different selectors, inheritance, or layout. It
 * answers one question exactly: does the same rule set, with the same values,
 * still reach this page. That question is the one a consolidation gets wrong.
 *
 * Values are compared normalised -- .9rem and 0.9rem are the same declaration
 * written twice -- because reporting those as changes trains people to ignore it.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = 'data/css-fingerprint.json';
const CHECK = process.argv.includes('--check');

const rd = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const has = (p) => fs.existsSync(path.join(ROOT, p));

/**
 * A deliberately small CSS reader. It handles what this site actually uses:
 * rule blocks, one level of @media/@supports nesting, and comments. It does not
 * handle @import (this site has none) and would need extending for nested CSS.
 */
export function parseCss(css) {
  const clean = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const out = [];
  const walk = (text, at) => {
    let i = 0;
    while (i < text.length) {
      const brace = text.indexOf('{', i);
      if (brace < 0) break;
      const sel = text.slice(i, brace).trim().replace(/\s+/g, ' ');
      let depth = 1, j = brace + 1;
      while (j < text.length && depth > 0) {
        if (text[j] === '{') depth++;
        else if (text[j] === '}') depth--;
        j++;
      }
      const body = text.slice(brace + 1, j - 1);
      if (/^@(media|supports)/.test(sel)) walk(body, at ? `${at} and ${sel}` : sel);
      else if (sel) {
        const decls = body.split(';').map((d) => d.trim()).filter(Boolean).map((d) => {
          const k = d.indexOf(':');
          return k < 0 ? null : [d.slice(0, k).trim(), d.slice(k + 1).trim().replace(/\s+/g, ' ')];
        }).filter(Boolean);
        out.push({ at, sel, decls });
      }
      i = j;
    }
  };
  walk(clean, '');
  return out;
}

const norm = (v) => String(v).toLowerCase()
  .replace(/\s*,\s*/g, ',')
  .replace(/(^|[\s,(])\.(\d)/g, '$10.$2')
  .replace(/\s+/g, ' ')
  .trim();

/** Later blocks win, property by property, exactly as the cascade does here. */
export function effective(rules) {
  const m = new Map();
  for (const r of rules) {
    const key = `${r.at}||${r.sel}`;
    if (!m.has(key)) m.set(key, new Map());
    for (const [k, v] of r.decls) m.get(key).set(k, norm(v));
  }
  return m;
}

/** Everything that applies to one page, in document order. */
export function pageRules(sourceFile) {
  const html = rd(sourceFile);
  const rules = [];
  // <link rel=stylesheet> and <style> interleave, so walk the head in order
  // rather than doing all links then all styles -- the order is the cascade.
  const token = /<link\b[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>|<style[^>]*>([\s\S]*?)<\/style>/g;
  const missing = [];
  for (const m of html.matchAll(token)) {
    if (m[1] !== undefined) {
      if (!m[1].startsWith('/')) continue; // off-site; not ours to fingerprint
      const f = m[1].split('?')[0].replace(/^\//, '');
      if (!has(f)) { missing.push(m[1]); continue; }
      rules.push(...parseCss(rd(f)));
    } else {
      rules.push(...parseCss(m[2]));
    }
  }
  return { rules, missing };
}

const model = JSON.parse(rd('data/pages.json'));
const fingerprint = { _readme: [
  'Generated by scripts/css-fingerprint.mjs. One entry per page: a hash of every',
  '(media query, selector) that applies to it and the declarations that survive the',
  'cascade, plus the count, so a diff shows whether rules moved or only changed.',
  '',
  'Its job is to detect CSS that changed under markup that did not -- the class of',
  'accident a shared stylesheet makes possible. Regenerate it in any commit that',
  'legitimately changes styling, and read the diff before you do.',
], generatedBy: 'scripts/css-fingerprint.mjs', pages: {} };

const problems = [];
for (const p of model.pages) {
  if (!has(p.sourceFile)) continue;
  const { rules, missing } = pageRules(p.sourceFile);
  if (missing.length) problems.push(`${p.route}: references a stylesheet that is not present: ${missing.join(', ')}`);
  const eff = effective(rules);
  const flat = [...eff]
    .map(([key, decls]) => `${key}{${[...decls].sort().map(([k, v]) => `${k}:${v}`).join(';')}}`)
    .sort()
    .join('\n');
  fingerprint.pages[p.route] = {
    selectors: eff.size,
    declarations: [...eff.values()].reduce((a, d) => a + d.size, 0),
    hash: crypto.createHash('sha256').update(flat).digest('hex').slice(0, 16),
  };
}

if (!CHECK) {
  fs.writeFileSync(path.join(ROOT, OUT), JSON.stringify(fingerprint, null, 2) + '\n');
  console.log(`${OUT}  ${Object.keys(fingerprint.pages).length} pages`);
  for (const p of problems) console.log('  WARNING  ' + p);
  process.exit(0);
}

// ---- --check ---------------------------------------------------------------
if (!has(OUT)) {
  console.error(`CANNOT CHECK: ${OUT} does not exist. Run without --check to create it.`);
  process.exit(2);
}
const before = JSON.parse(rd(OUT)).pages ?? {};
const after = fingerprint.pages;

const changed = [];
for (const route of new Set([...Object.keys(before), ...Object.keys(after)])) {
  const b = before[route], a = after[route];
  if (!b) { changed.push([route, 'NEW page, no committed fingerprint', null, null]); continue; }
  if (!a) { changed.push([route, 'page is gone from the model', null, null]); continue; }
  if (b.hash !== a.hash) {
    changed.push([route, 'effective CSS differs',
      `${b.selectors} selectors / ${b.declarations} declarations`,
      `${a.selectors} selectors / ${a.declarations} declarations`]);
  }
}

for (const p of problems) console.log('  WARNING  ' + p);
if (!changed.length) {
  console.log(`css-fingerprint: all ${Object.keys(after).length} pages match the committed fingerprint.`);
  process.exit(0);
}

// Which of these pages had their own HTML touched? A page whose markup you
// edited changing its CSS is ordinary. A page you did not open changing its CSS
// is the thing a shared stylesheet made possible, and it is worth naming
// separately rather than burying in a list of twenty-two routes.
//
// THE COMPARISON POINT DEPENDS ON WHETHER THE TREE IS DIRTY, and getting that
// wrong inverts the whole signal.
//
// The first version asked `git diff --name-only HEAD` and nothing else. That is
// right locally, before committing, which is where it was written and tested.
// In CI the checkout is clean, so it returns NOTHING, every differing page falls
// into the "untouched markup" bucket, and the alarm category fires on every
// intentional CSS change — in the one environment that gates the deploy. The
// loudest line in the build becomes the line that is always there, which is
// precisely how a check stops being read. This one exists to be read.
//
// So: dirty tree, compare against HEAD. Clean tree, compare the commit against
// its parent, which is the change actually under inspection. SS-201 reaches for
// git the same way and for the same reason.
let touched = null;
let basis = null;
try {
  const { execFileSync } = await import('node:child_process');
  const git = (args) => execFileSync('git', args, { cwd: ROOT }).toString();
  const dirty = git(['status', '--porcelain']).trim().length > 0;
  if (dirty) {
    touched = new Set(git(['diff', '--name-only', 'HEAD']).split('\n').map((s) => s.trim()).filter(Boolean));
    basis = 'the working tree against HEAD';
  } else {
    // A first commit has no parent; there is nothing to compare and saying so
    // beats reporting every page as an unexplained change.
    const parent = git(['rev-list', '--max-count=1', '--skip=1', 'HEAD']).trim();
    if (parent) {
      touched = new Set(git(['diff', '--name-only', `${parent}..HEAD`]).split('\n').map((s) => s.trim()).filter(Boolean));
      basis = `HEAD against its parent ${parent.slice(0, 7)}`;
    }
  }
} catch { /* no git, or not a repository -- fall back to the plain listing */ }

const bySource = new Map(model.pages.map((p) => [p.route, p.sourceFile]));
const untouched = touched ? changed.filter(([r]) => !touched.has(bySource.get(r))) : [];
const edited = touched ? changed.filter(([r]) => touched.has(bySource.get(r))) : changed;

console.log(`css-fingerprint: ${changed.length} page(s) differ from the committed fingerprint.`);
if (basis) console.log(`  (markup compared by ${basis})`);
else console.log('  (git unavailable, so no page can be classified by whether its markup moved)');

if (untouched.length) {
  console.log('');
  console.log(`  ${untouched.length} PAGE(S) CHANGED WITHOUT THEIR MARKUP BEING TOUCHED.`);
  console.log('  This is the accident a shared stylesheet makes possible: a rule moved');
  console.log('  under pages nobody opened. Confirm each one is intended.');
  for (const [route, why, b, a] of untouched) {
    console.log(`    ${route}`);
    console.log(`        ${why}${b ? `   ${b}  ->  ${a}` : ''}`);
  }
}
if (edited.length) {
  console.log('');
  console.log(`  ${edited.length} page(s) whose own HTML also changed in this working tree:`);
  for (const [route, , b, a] of edited) console.log(`    ${route}${b ? `   ${b}  ->  ${a}` : ''}`);
}

console.log('');
console.log('If every one of those is intended, regenerate:  node scripts/css-fingerprint.mjs');
console.log('Read the page list before you do. The count is the blast radius.');
process.exit(1);
