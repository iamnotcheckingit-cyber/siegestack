/**
 * SS-003 — the inputs must be usable before any finding means anything.
 *
 * WHY THIS EXISTS
 * ---------------
 * The 2026-08-21 blind-spot sweep (docs/validator-blind-spots.md) found the
 * same defect in seventeen places: a rule that produces no output when its
 * input is missing, empty or the wrong shape, which is byte-identical to a rule
 * that produced no output because the site is fine.
 *
 * The worst instance was SS-602. That rule keeps employer, client and
 * individual names off a public site and out of public CI logs, and its own
 * skip text claims the right discipline -- "REPORTED AS SKIPPED, not passed" --
 * but only for a MISSING file. A `.denylist.local.json` that is PRESENT with
 * the `terms` key renamed produced an empty list, zero iterations, and no line
 * at all. The summary was identical to a clean run.
 *
 * Rather than patching seven rules, the honesty lives here, once, and the next
 * rule someone adds inherits it.
 *
 * IT IS A PURE FUNCTION AND THAT IS DELIBERATE. All IO happens in the caller.
 * A guard that read files itself could only be tested by mutating real ones,
 * and a suite that mutates real files is a suite that eventually leaves debris
 * in the repository it is meant to protect.
 *
 * WHAT IT CANNOT DO -- read this before trusting a green result
 * ------------------------------------------------------------
 * The population class catches TOTAL regressions, not partial ones. If the
 * extractor stops producing `textContent` for every page, this fires. If it
 * breaks for half the pages, this does NOT fire and nothing else will either.
 *
 * That is a deliberate trade, not an oversight. A per-page assertion would
 * false-positive constantly -- plenty of pages legitimately carry no JSON-LD
 * and no outbound links -- and a rule that cries wolf gets ignored, which is
 * the mechanism that produced every finding in the sweep. Detecting partial
 * regressions needs a stored baseline count to compare against, which is a
 * different and much heavier mechanism. It is recorded as a known gap in
 * docs/validator-blind-spots.md and is not scheduled.
 *
 * So: a green SS-003 means the inputs are present, well-shaped and not wholly
 * empty. It is NOT evidence that the extractor is healthy for every page.
 */

/**
 * Every file the validator reads. `key` is the property expected to hold an
 * array; `allowEmpty` says whether a correctly-shaped but empty collection is
 * a legitimate state or a defect.
 *
 * `consumers` is not decoration. When this fires at 2am the first question is
 * "what stopped being checked", and the answer has to be in the message.
 */
export const INPUT_MANIFEST = [
  {
    file: 'data/pages.json', key: 'pages', allowEmpty: false, optional: false,
    consumers: 'every rule -- the model is the validator\'s only view of the site',
  },
  {
    file: 'data/validation-suppressions.json', key: 'suppressions', allowEmpty: true, optional: false,
    consumers: 'SS-001, and the suppression path of every other rule',
  },
  {
    file: 'data/freshness-exclusions.json', key: 'exclusions', allowEmpty: true, optional: false,
    consumers: 'SS-201',
  },
  {
    file: 'data/og-overrides.json', key: 'overrides', allowEmpty: true, optional: false,
    consumers: 'SS-306',
  },
  {
    file: 'data/non-html-routes.json', key: 'routes', allowEmpty: true, optional: false,
    consumers: 'SS-401',
  },
  {
    file: 'data/jsonld-exempt.json', key: 'routes', allowEmpty: true, optional: false,
    consumers: 'SS-504',
  },
  {
    file: 'data/claims-registry.json', key: 'claims', allowEmpty: true, optional: false,
    consumers: 'SS-601',
  },
  {
    file: 'data/stated-correction-counts.json', key: 'routes', allowEmpty: true, optional: false,
    consumers: 'SS-605',
  },
  {
    // Gitignored and legitimately absent on a fresh clone -- SS-602 reports
    // SKIPPED in that case and always has. What it did NOT survive was the file
    // being present and unreadable, so an empty term list is an error here even
    // though every other collection is allowed to be empty. B1, B2.
    file: '.denylist.local.json', key: 'terms', allowEmpty: false, optional: true,
    consumers: 'SS-602 -- the identifier denylist, the rule that keeps client and employer names off a public site',
  },
];

/**
 * Files SS-602 scans as corpora. B3: `has(f) ? rd(f) : ''` scanned an empty
 * string and called it scanned, so a missing llms-full.txt silently dropped
 * 216 KB -- the largest published surface on the site -- out of the sweep, and
 * findings went from two to one with nothing saying why.
 */
export const CORPUS_MANIFEST = [
  { file: 'llms.txt', consumers: 'SS-602' },
  { file: 'llms-full.txt', consumers: 'SS-602 -- the largest published surface on the site' },
  { file: 'sitemap.xml', consumers: 'SS-602, and SS-101/SS-102/SS-201 by way of the model' },
];

/**
 * Model fields that must be populated on at least one page. Empty on SOME pages
 * is normal and silent; empty on EVERY page is an extractor regression wearing
 * a clean run's clothes. B5, B6, B8.
 */
export const MODEL_POPULATION = [
  { field: 'textContent', consumers: 'SS-601, SS-602, SS-603', empty: (v) => !String(v ?? '').trim() },
  { field: 'jsonLdGraphs', consumers: 'SS-501, SS-502, SS-503 -- including the rating-markup ban', empty: (v) => !Array.isArray(v) || v.length === 0 },
  { field: 'internalLinksOut', consumers: 'SS-401, SS-402', empty: (v) => !Array.isArray(v) || v.length === 0 },
];

/** Top-level model collections that must exist and be non-empty. B9, B10. */
export const MODEL_COLLECTIONS = [
  { path: ['allowHtml'], consumers: 'SS-101, SS-105' },
  { path: ['llmsTxtRoutes'], consumers: 'SS-102' },
  { path: ['totals', 'phantomSitemapEntries'], consumers: 'SS-101', allowEmpty: true },
];

const finding = (severity, route, message, observed) => ({ severity, id: 'SS-003', route, message, observed });

/**
 * @param {object} args
 * @param {Map<string,{present:boolean,parsed?:any,parseError?:string}>} args.inputs  keyed by manifest file path
 * @param {Map<string,{present:boolean,bytes:number}>} args.corpora                   keyed by corpus file path
 * @param {any} args.model                                                            the parsed page model
 * @returns {Array<{severity:string,id:string,route:string,message:string,observed:string}>}
 */
export function checkInputs({ inputs, corpora, model }) {
  const out = [];

  // --- Class 1 and 2: shape, then vacuity -----------------------------------
  for (const spec of INPUT_MANIFEST) {
    const got = inputs.get(spec.file);

    if (!got || !got.present) {
      if (!spec.optional) {
        out.push(finding('error', spec.file,
          `Input file is missing. Consumed by ${spec.consumers}.`,
          `expected ${spec.key}:array`));
      }
      continue; // an optional absent file is a declared state, not a defect
    }

    if (got.parseError) {
      out.push(finding('error', spec.file,
        `Input file does not parse, so ${spec.consumers} would run against nothing.`,
        `parse error: ${String(got.parseError).slice(0, 120)}`));
      continue;
    }

    const value = got.parsed?.[spec.key];
    if (value === undefined) {
      const keys = Object.keys(got.parsed ?? {}).filter((k) => k !== '_readme');
      out.push(finding('error', spec.file,
        `Input is unusable: expected key "${spec.key}" holding an array; it is absent. ${spec.consumers} consumes this and would have reported nothing -- not a skip, not a pass, no line at all.`,
        `keys=${JSON.stringify(keys)} expected=${spec.key}:array`));
      continue;
    }
    if (!Array.isArray(value)) {
      out.push(finding('error', spec.file,
        `Input is unusable: key "${spec.key}" is not an array. Consumed by ${spec.consumers}.`,
        `typeof ${spec.key}=${Array.isArray(value) ? 'array' : typeof value}`));
      continue;
    }
    if (value.length === 0) {
      out.push(finding(spec.allowEmpty ? 'warning' : 'error', spec.file,
        spec.allowEmpty
          ? `Input parsed correctly and is empty. Legitimate, but reported so an empty input never looks like a clean run. Consumed by ${spec.consumers}.`
          : `Input parsed correctly and is EMPTY, which this input is never allowed to be. ${spec.consumers} is running against zero entries and cannot report anything.`,
        `${spec.key}: 0 entries`));
    }
  }

  // --- Class 3: corpus accounting (B3) --------------------------------------
  for (const spec of CORPUS_MANIFEST) {
    const got = corpora.get(spec.file);
    if (!got || !got.present) {
      out.push(finding('error', spec.file,
        `Corpus file is missing, so it is not being scanned. Consumed by ${spec.consumers}. The scan does not fail when this happens -- it reads an empty string and reports success.`,
        'not present'));
      continue;
    }
    if (got.bytes === 0) {
      out.push(finding('error', spec.file,
        `Corpus file is present but empty, so scanning it proves nothing. Consumed by ${spec.consumers}.`,
        '0 bytes'));
    }
  }

  // --- Class 4: model population -------------------------------------------
  const pages = Array.isArray(model?.pages) ? model.pages : [];
  if (pages.length === 0) {
    out.push(finding('error', 'data/pages.json',
      'The page model contains no pages, so every rule below it passes vacuously.', '0 pages'));
  } else {
    for (const spec of MODEL_POPULATION) {
      const populated = pages.filter((p) => !spec.empty(p[spec.field])).length;
      if (populated === 0) {
        out.push(finding('error', 'data/pages.json',
          `No page in the model has a populated "${spec.field}". Empty on some pages is normal; empty on every page is an extractor regression, and it silences ${spec.consumers} without any of them saying so.`,
          `0 of ${pages.length} pages populated`));
      }
    }

    const indexable = pages.filter((p) => p.class === 'indexable').length;
    if (indexable === 0) {
      out.push(finding('error', 'data/pages.json',
        'No page is classified indexable, so every indexable-scoped rule (SS-301, SS-302, SS-305, SS-306, SS-504, SS-601) passes vacuously.',
        `0 of ${pages.length} pages indexable`));
    }
  }

  for (const spec of MODEL_COLLECTIONS) {
    let node = model;
    for (const k of spec.path) node = node?.[k];
    const label = spec.path.join('.');
    if (node === undefined) {
      out.push(finding('error', 'data/pages.json',
        `Model collection "${label}" is absent. ${spec.consumers} reads it through "?? []", so it cannot tell an empty result from a missing field.`,
        `${label}=undefined`));
    } else if (!Array.isArray(node)) {
      out.push(finding('error', 'data/pages.json',
        `Model collection "${label}" is not an array. Consumed by ${spec.consumers}.`, `typeof=${typeof node}`));
    } else if (node.length === 0 && !spec.allowEmpty) {
      out.push(finding('error', 'data/pages.json',
        `Model collection "${label}" is empty. Consumed by ${spec.consumers}.`, `${label}: 0 entries`));
    }
  }

  return out;
}
