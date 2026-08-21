/**
 * SS-003 — proving the input guard fires.
 *
 * A single assertion pass protecting seven blind spots is itself a single point
 * of silent failure, which is the exact shape the sweep was chasing. Without
 * these tests it is the nineteenth rule that can go quiet, and it would be the
 * one holding up all the others.
 *
 * So: for every input the guard asserts on, deliberately vacuate that input and
 * assert the guard errors. If the guard stops firing, this goes red.
 *
 * No files are touched. checkInputs() is a pure function and gets handed broken
 * inputs directly -- which is the whole reason it was built as one.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkInputs, INPUT_MANIFEST, CORPUS_MANIFEST, MODEL_POPULATION, MODEL_COLLECTIONS,
} from '../lib/input-guard.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
let failures = 0;

const check = (name, cond, detail) => {
  if (cond) console.log(`  PASS  ${name}`);
  else { console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); failures++; }
};

console.log('\ninput-guard (SS-003)');

// --- A healthy fixture, which every probe below mutates one field of ---------
const healthyModel = () => ({
  allowHtml: ['/'],
  llmsTxtRoutes: ['/'],
  totals: { phantomSitemapEntries: [] },
  pages: [{
    route: '/', sourceFile: 'index.html', class: 'indexable',
    textContent: 'real extracted text', jsonLdGraphs: [{ '@type': 'WebSite' }], internalLinksOut: ['/about'],
  }],
});
const healthyInputs = () => new Map(
  INPUT_MANIFEST.map((s) => [s.file, { present: true, parsed: { [s.key]: [{ placeholder: true }] } }]),
);
const healthyCorpora = () => new Map(CORPUS_MANIFEST.map((s) => [s.file, { present: true, bytes: 1024 }]));

const run = ({ inputs = healthyInputs(), corpora = healthyCorpora(), model = healthyModel() } = {}) =>
  checkInputs({ inputs, corpora, model });

const errorsFor = (out, file) => out.filter((f) => f.severity === 'error' && f.route === file);

// --- Baseline: healthy inputs produce nothing --------------------------------
check('healthy inputs produce no findings', run().length === 0,
  `got ${JSON.stringify(run().map((f) => f.route))}`);

// --- Class 1: shape, per manifest entry --------------------------------------
for (const spec of INPUT_MANIFEST) {
  // B1: the key renamed. This is the SS-602 case verbatim.
  const renamed = healthyInputs();
  renamed.set(spec.file, { present: true, parsed: { RENAMED: [{ placeholder: true }] } });
  const out = run({ inputs: renamed });
  const errs = errorsFor(out, spec.file);
  check(`${spec.file}: renamed key errors`, errs.length > 0);
  check(`${spec.file}: the message names the expected key`,
    errs.some((e) => String(e.observed).includes(spec.key) || e.message.includes(spec.key)),
    'the message must say what shape was expected');

  // Not an array.
  const wrongType = healthyInputs();
  wrongType.set(spec.file, { present: true, parsed: { [spec.key]: { not: 'an array' } } });
  check(`${spec.file}: non-array value errors`, errorsFor(run({ inputs: wrongType }), spec.file).length > 0);

  // Does not parse.
  const broken = healthyInputs();
  broken.set(spec.file, { present: true, parseError: 'Unexpected token }' });
  check(`${spec.file}: unparseable file errors`, errorsFor(run({ inputs: broken }), spec.file).length > 0);

  // Missing file — an error unless the file is declared optional.
  const missing = healthyInputs();
  missing.set(spec.file, { present: false });
  const missingErrs = errorsFor(run({ inputs: missing }), spec.file);
  check(`${spec.file}: missing file ${spec.optional ? 'is tolerated (declared optional)' : 'errors'}`,
    spec.optional ? missingErrs.length === 0 : missingErrs.length > 0);

  // Class 2: empty. Error or warning depending on the declaration, but never silent.
  const empty = healthyInputs();
  empty.set(spec.file, { present: true, parsed: { [spec.key]: [] } });
  const emptyOut = run({ inputs: empty }).filter((f) => f.route === spec.file);
  check(`${spec.file}: empty collection is reported (${spec.allowEmpty ? 'warning' : 'error'})`,
    emptyOut.length > 0 && emptyOut[0].severity === (spec.allowEmpty ? 'warning' : 'error'),
    `got ${JSON.stringify(emptyOut.map((f) => f.severity))}`);
}

// --- Class 3: corpus accounting (B3) -----------------------------------------
for (const spec of CORPUS_MANIFEST) {
  const gone = healthyCorpora();
  gone.set(spec.file, { present: false, bytes: 0 });
  check(`${spec.file}: a missing corpus errors`, errorsFor(run({ corpora: gone }), spec.file).length > 0);

  const blank = healthyCorpora();
  blank.set(spec.file, { present: true, bytes: 0 });
  check(`${spec.file}: an empty corpus errors`, errorsFor(run({ corpora: blank }), spec.file).length > 0);
}

// --- Class 4: model population ------------------------------------------------
for (const spec of MODEL_POPULATION) {
  const m = healthyModel();
  for (const p of m.pages) p[spec.field] = Array.isArray(p[spec.field]) ? [] : '';
  const errs = errorsFor(run({ model: m }), 'data/pages.json');
  check(`model.${spec.field}: empty on every page errors`, errs.length > 0);
  check(`model.${spec.field}: the message names the rules it silences`,
    errs.some((e) => e.message.includes(spec.consumers.split(',')[0].trim())));
}
{
  const m = healthyModel();
  m.pages = [];
  check('model with zero pages errors', errorsFor(run({ model: m }), 'data/pages.json').length > 0);
}
{
  const m = healthyModel();
  for (const p of m.pages) p.class = 'served-noindex';
  check('model with zero indexable pages errors',
    errorsFor(run({ model: m }), 'data/pages.json').some((e) => e.message.includes('indexable')));
}
for (const spec of MODEL_COLLECTIONS) {
  const m = healthyModel();
  let node = m;
  for (const k of spec.path.slice(0, -1)) node = node[k];
  delete node[spec.path.at(-1)];
  check(`model.${spec.path.join('.')}: absent collection errors`,
    errorsFor(run({ model: m }), 'data/pages.json').length > 0);
}

// --- Manifest coverage --------------------------------------------------------
//
// The difference between a guard and a guard that happens to cover today's
// inputs. It reads validate-pages.mjs and compares the files it actually opens
// against the manifest.
//
// THE FLOOR IS THE POINT. This cross-check is itself in the class it exists to
// catch: if a refactor renames readInput(), the scan finds zero read sites,
// compares zero against the manifest, finds no gap and passes -- trivially
// green, guarding nothing. So it fails when it finds FEWER read sites than the
// manifest declares, not only when it finds ones the manifest lacks. Removing
// an input legitimately means removing its manifest entry in the same commit,
// and the floor moves with it deliberately.
{
  const src = fs.readFileSync(path.join(ROOT, 'scripts', 'validate-pages.mjs'), 'utf8');
  const readSites = [...src.matchAll(/readInput\(\s*(?:DENYLIST_LOCAL|'([^']+)')\s*\)/g)]
    .map((m) => m[1] ?? '.denylist.local.json');
  const listSites = [...src.matchAll(/listOf\(\s*(?:DENYLIST_LOCAL|'([^']+)')\s*,/g)]
    .map((m) => m[1] ?? '.denylist.local.json');
  const opened = new Set([...readSites, ...listSites].filter((f) => f !== undefined));

  check(`manifest coverage: at least ${INPUT_MANIFEST.length} read sites found (floor)`,
    opened.size >= INPUT_MANIFEST.length,
    `found ${opened.size} distinct files opened; the manifest declares ${INPUT_MANIFEST.length}. ` +
    'If the read helper was renamed this scan is blind and would otherwise pass trivially.');

  const declared = new Set(INPUT_MANIFEST.map((s) => s.file));
  const unguarded = [...opened].filter((f) => !declared.has(f));
  check('manifest coverage: every file the validator opens is in the manifest',
    unguarded.length === 0, `unguarded: ${JSON.stringify(unguarded)}`);

  const unread = [...declared].filter((f) => !opened.has(f));
  check('manifest coverage: every manifest entry is actually read by the validator',
    unread.length === 0, `declared but never read: ${JSON.stringify(unread)}`);
}

process.exit(failures ? 1 : 0);
