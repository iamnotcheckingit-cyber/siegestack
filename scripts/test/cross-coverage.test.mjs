/**
 * Cross-coverage: two rules that protect OTHER rules' blind spots.
 *
 * The 2026-08-21 blind-spot sweep (docs/validator-blind-spots.md) found that
 * two rules were doing load-bearing work nobody had asked them to do:
 *
 *   SS-604 catches an extractor regression that silences SS-606 and SS-607.
 *          Emptying the correction fields on every page makes both ageing rules
 *          go quiet; SS-604 notices, because HEAD~1 still carries the markers.
 *
 *   SS-102 catches a mass declassification that silences SS-301, SS-302,
 *          SS-305, SS-306, SS-504 and SS-601. Reclassify every page out of
 *          `indexable` and six rules vacuously pass; SS-102 errors, because the
 *          sitemap side of its parity check has emptied while llms.txt has not.
 *
 * Both were accidents of how the rules happened to be written. This file turns
 * them into guarantees: a future refactor that breaks either coupling fails
 * here instead of quietly widening the blind spot it was covering.
 *
 * The validator is driven as a subprocess against a MUTATED COPY of the page
 * model, then the model is restored byte-for-byte. Nothing else in the tree is
 * touched.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MODEL = path.join(ROOT, 'data', 'pages.json');
const VALIDATOR = path.join(ROOT, 'scripts', 'validate-pages.mjs');

let failures = 0;

/**
 * Snapshot taken before anything runs. The restore assertion at the foot
 * compares against THIS, not against `git status` -- the model legitimately
 * carries an uncommitted commit-stamp line most of the time, and asking git
 * would make the suite fail for a reason that has nothing to do with it.
 * The question is whether this file put the bytes back, not whether the tree
 * was clean when it started.
 */
const MODEL_AT_START = fs.readFileSync(MODEL);

const runValidator = () => {
  try {
    return execFileSync('node', [VALIDATOR], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    return (e.stdout ?? '') + (e.stderr ?? '');
  }
};

/** Mutate the model, run the validator, restore. Always restores, even on throw. */
const withMutatedModel = (mutate) => {
  const original = fs.readFileSync(MODEL);
  try {
    const m = JSON.parse(original.toString('utf8'));
    mutate(m);
    fs.writeFileSync(MODEL, JSON.stringify(m, null, 2));
    return runValidator();
  } finally {
    fs.writeFileSync(MODEL, original);
  }
};

const fired = (out, id) => out.split('\n').some((l) => l.trim().startsWith(`${id}  `));

const check = (name, condition, detail) => {
  if (condition) console.log(`  PASS  ${name}`);
  else { console.error(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); failures++; }
};

console.log('\ncross-coverage');

// ---------------------------------------------------------------------------
// SS-604 covers SS-606 and SS-607
// ---------------------------------------------------------------------------
{
  const out = withMutatedModel((m) => {
    for (const p of m.pages) { p.corrections = []; p.correctionDates = {}; p.disclosures = []; }
  });
  check(
    'SS-604 fires when the correction fields are emptied, covering SS-606 and SS-607',
    fired(out, 'SS-604'),
    'the ageing rules can now go silent with nothing noticing',
  );
  check(
    'SS-606 and SS-607 are indeed silent in that state (the blind spot is real)',
    !fired(out, 'SS-606') && !fired(out, 'SS-607'),
    'one of them started reporting — good, but update this file and the sweep doc',
  );
}

// ---------------------------------------------------------------------------
// SS-102 covers the SS-3xx / SS-5xx / SS-6xx indexable rules
// ---------------------------------------------------------------------------
{
  const out = withMutatedModel((m) => {
    for (const p of m.pages) if (p.class === 'indexable') p.class = 'served-noindex';
  });
  check(
    'SS-102 fires when every page is declassified, covering the indexable-scoped rules',
    fired(out, 'SS-102'),
    'six rules can now vacuously pass with nothing noticing',
  );
  check(
    'SS-601 is indeed silent in that state (the blind spot is real)',
    !fired(out, 'SS-601'),
    'SS-601 started reporting — good, but update this file and the sweep doc',
  );
}

// ---------------------------------------------------------------------------
// The model is restored
// ---------------------------------------------------------------------------
{
  const restored = fs.readFileSync(MODEL).equals(MODEL_AT_START);
  check('data/pages.json is left byte-identical to how this suite found it', restored,
    'the suite mutated the model and did not put it back');
}

process.exit(failures ? 1 : 0);
