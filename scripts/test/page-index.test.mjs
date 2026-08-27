/**
 * scripts/build-page-index.mjs is the single extractor every validation rule
 * reads through. Its own header says so: "One extractor, one model, one set of
 * blind spots." Until 2026-08-26 it was also the only component in that chain
 * with no test, which is how a truncating meta() regex survived: the 50-odd
 * rules built on the model are tested, the thing that BUILDS the model was not.
 *
 *   node scripts/test/page-index.test.mjs
 *   node scripts/test/page-index.test.mjs --defects
 *
 * --defects restores the exact regex that shipped and asserts this suite goes
 * red on it. That is the only evidence a green run here is worth anything, and
 * it is the same rule scripts/test/harness.mjs applies to the function tests.
 *
 * WHY THE OLD REGEX IS RE-DERIVED FROM SOURCE RATHER THAN PASTED. The defect
 * is applied by substituting the CURRENT function body out of a copy of the
 * real file, so this suite cannot drift away from what build-page-index.mjs
 * actually does. If the anchor stops matching, the suite REFUSES TO RUN instead
 * of quietly testing a snapshot of something that no longer exists.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SRC = path.join(REPO, 'scripts', 'build-page-index.mjs');
const DEFECTS = process.argv.includes('--defects');

// The regex exactly as it stood at 0d9df25, before the delimiter backreference.
const SHIPPED_BODY = [
  'export function meta(html, attr, value) {',
  "  const v = value.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');",
  '  const a = new RegExp(`<meta[^>]*\\\\b${attr}=["\']${v}["\'][^>]*\\\\bcontent=["\']([^"\']*)["\']`, \'i\');',
  '  const b = new RegExp(`<meta[^>]*\\\\bcontent=["\']([^"\']*)["\'][^>]*\\\\b${attr}=["\']${v}["\']`, \'i\');',
  '  return (html.match(a) || html.match(b) || [])[1] ?? null;',
  '}',
].join('\n');

/**
 * build-page-index.mjs writes data/pages.json as a side effect of being run, so
 * it cannot simply be imported: doing that mid-suite would regenerate a
 * committed artifact from whatever tree the test happens to sit on, and
 * cross-coverage.test.mjs already asserts that suite leaves pages.json
 * byte-identical. Everything from the JSON-LD helper onward is therefore cut
 * off and only the pure header -- constants and meta() -- is imported.
 */
async function loadMeta({ withDefect }) {
  // Normalised on read. git's autocrlf hands this file back with CRLF on
  // Windows, and the scan below compares a whole line to '}' -- which silently
  // never matches when the line is '}\r'. That is the same shape as the defect
  // this suite exists for: a check that reports nothing because its input was
  // not quite what it assumed, and reports it as success.
  let src = fs.readFileSync(SRC, 'utf8').split(/\r?\n/).join('\n');

  if (withDefect) {
    const lines = src.split('\n');
    const i = lines.findIndex((l) => l.startsWith('export function meta(html, attr, value)'));
    if (i < 0) {
      console.error('REFUSING TO RUN: no `export function meta(html, attr, value)` in build-page-index.mjs.');
      console.error('The extractor changed shape. Re-read it and update this suite rather than deleting the check.');
      process.exit(2);
    }
    let end = i;
    while (end < lines.length && lines[end] !== '}') end++;
    if (end >= lines.length) {
      console.error('REFUSING TO RUN: could not find the end of meta().');
      process.exit(2);
    }
    lines.splice(i, end - i + 1, SHIPPED_BODY);
    src = lines.join('\n');
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siegestack-pageindex-'));
  const scripts = path.join(dir, 'scripts');
  fs.mkdirSync(scripts);
  // Everything above this marker is pure: imports, ROOT/ORIGIN constants,
  // decode(), meta(). Everything below reads the filesystem and writes the
  // artifacts. Cutting here is what makes the import side-effect-free.
  const cut = src.indexOf('/** Every @type in a JSON-LD graph');
  if (cut < 0) {
    console.error('REFUSING TO RUN: the marker that ends the header section of build-page-index.mjs is gone.');
    console.error('Looked for: /** Every @type in a JSON-LD graph');
    process.exit(2);
  }
  const file = path.join(scripts, 'meta-only.mjs');
  fs.writeFileSync(file, src.slice(0, cut));
  const mod = await import(pathToFileURL(file).href);
  if (typeof mod.meta !== 'function') {
    console.error('REFUSING TO RUN: build-page-index.mjs no longer exports meta().');
    process.exit(2);
  }
  return mod.meta;
}

let pass = 0;
const failures = [];
function eq(label, actual, expected) {
  if (actual === expected) { pass++; console.log('  PASS  ' + label); return; }
  failures.push(label);
  console.log('  FAIL  ' + label);
  console.log('          expected: ' + JSON.stringify(expected));
  console.log('          actual  : ' + JSON.stringify(actual));
}

const meta = await loadMeta({ withDefect: DEFECTS });

console.log('\npage-index: meta() attribute parsing' + (DEFECTS ? '  [DEFECTS INJECTED]' : ''));

// The two real tags this was found on. Both live on the site today.
const APOS = '<meta property="og:description" content="Stop treating Claude like a chatbot. Here\'s the Claude AI workflow that ships real work.">';
eq("an apostrophe inside a double-quoted attribute is content, not a delimiter",
  meta(APOS, 'property', 'og:description'),
  "Stop treating Claude like a chatbot. Here's the Claude AI workflow that ships real work.");

const APOS2 = '<meta property="og:description" content="What changes when the schema is the vendor\'s.">';
eq("a trailing possessive does not truncate the value",
  meta(APOS2, 'property', 'og:description'),
  "What changes when the schema is the vendor's.");

// The mirror case. Nothing on the site uses it today, which is exactly why it
// needs a test rather than an inspection.
const DQ = `<meta name="twitter:description" content='He said "no" twice.'>`;
eq('a double quote inside a single-quoted attribute is content',
  meta(DQ, 'name', 'twitter:description'),
  'He said "no" twice.');

// The reason two regexes existed in the first place.
const REVERSED = '<meta content="reversed order" name="description">';
eq('content= before name= still resolves', meta(REVERSED, 'name', 'description'), 'reversed order');

// The failure the rewrite had to avoid: a lazy [\s\S] group that can cross `>`
// and capture from one tag into the next.
const TWO_TAGS = [
  '<meta property="og:description" content="first tag\'s value">',
  '<meta content="second tag" name="description">',
].join('\n');
eq('a value never runs past its own tag into the next one',
  meta(TWO_TAGS, 'name', 'description'), 'second tag');
eq('...and the tag before it is unaffected',
  meta(TWO_TAGS, 'property', 'og:description'), "first tag's value");

// Ordinary cases, so a rewrite that breaks the common path is caught too.
eq('a plain value', meta('<meta name="robots" content="index, follow">', 'name', 'robots'), 'index, follow');
eq('an absent tag is null', meta('<meta name="robots" content="x">', 'name', 'description'), null);
eq('a tag with no content attribute is null',
  meta('<meta name="description">', 'name', 'description'), null);

// The attribute VALUE is matched with its own delimiter too.
eq("a single-quoted attribute name matches",
  meta(`<meta name='description' content="ok">`, 'name', 'description'), 'ok');

// Regex metacharacters in the attribute value must stay literal.
eq('a dotted attribute value is not treated as a pattern',
  meta('<meta property="og:image:width" content="1200">', 'property', 'og:image:width'), '1200');

console.log('');
if (DEFECTS) {
  if (failures.length === 0) {
    console.log('DEFECTS RUN PASSED, WHICH MEANS THIS SUITE PROVES NOTHING.');
    console.log('The shipped regex was restored and every assertion still passed, so');
    console.log('none of them actually exercise the delimiter handling. Fix the suite.');
    process.exit(1);
  }
  console.log(`defects run: ${failures.length} assertion(s) failed as required, ${pass} passed.`);
  console.log('The suite is sensitive to the bug it was written for.');
  process.exit(0);
}

if (failures.length) {
  console.log(`${failures.length} failure(s), ${pass} passed.`);
  process.exit(1);
}
console.log(`page-index: ${pass} assertions passed.`);
