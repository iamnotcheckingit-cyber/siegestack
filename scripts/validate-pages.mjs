/**
 * validate-pages — the invariants that keep siegestack.com honest.
 *
 *   npm run validate:pages
 *
 * Errors exit non-zero. Warnings print and exit zero. Every rule has a stable
 * ID so one can be suppressed for one route without disabling the file.
 *
 * IT DOES NOT PARSE HTML. Everything it checks comes out of data/pages.json,
 * built by scripts/build-page-index.mjs. Two scripts parsing the same HTML with
 * two slightly different regexes is a bug generator: the validator would pass on
 * text the generator never saw, or fail on text that is not really there. One
 * extractor, one model, one set of blind spots.
 *
 * IT NEVER WRITES. Not to sitemap.xml, not to lastmod, not to anything. See
 * SS-203 -- a validator that repairs the value it is checking is not a
 * validator, it is a laundering step that guarantees a green build.
 *
 * Node builtins only, plus `git log` for SS-201.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rd = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const rdJson = (p) => JSON.parse(rd(p));
const has = (p) => fs.existsSync(path.join(ROOT, p));

// ---------------------------------------------------------------------------
// SS-203 guard, first thing, before anything is loaded.
// ---------------------------------------------------------------------------
if (process.argv.some((a) => /^--(fix|write|write-lastmod|repair)$/.test(a))) {
  console.error(
    'SS-203  This validator has no write mode and will not grow one.\n' +
    '        A failing SS-201 means a human decides whether the page changed.\n' +
    '        Auto-stamping lastmod on build makes every page permanently "fresh"\n' +
    '        and deletes the only signal the rule exists to carry.'
  );
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------
const MODEL = rdJson('data/pages.json');
const PAGES = MODEL.pages;
const SUPPRESSIONS = rdJson('data/validation-suppressions.json').suppressions ?? [];
const FRESH_EXCL = rdJson('data/freshness-exclusions.json').exclusions ?? [];
const OG_OVERRIDES = rdJson('data/og-overrides.json').overrides ?? [];
const NON_HTML = rdJson('data/non-html-routes.json').routes ?? [];
const JSONLD_EXEMPT = rdJson('data/jsonld-exempt.json').routes ?? [];
const CLAIMS = rdJson('data/claims-registry.json').claims ?? [];

const DENYLIST_LOCAL = '.denylist.local.json';
const DENYLIST = has(DENYLIST_LOCAL) ? (rdJson(DENYLIST_LOCAL).terms ?? []) : null;

const INDEXABLE = PAGES.filter((p) => p.class === 'indexable');
const byRoute = new Map(PAGES.map((p) => [p.route, p]));
const nonHtmlRoutes = new Set(NON_HTML.map((r) => r.route));

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
const findings = [];
const skipped = [];
const suppressed = [];

const isSuppressed = (id, route) =>
  SUPPRESSIONS.some((s) => s.ruleId === id && s.route === route && String(s.reason ?? '').trim());

function report(severity, id, route, message, observed) {
  if (isSuppressed(id, route)) { suppressed.push({ id, route, message }); return; }
  findings.push({ severity, id, route, message, observed });
}
const error = (id, route, message, observed) => report('error', id, route, message, observed);
const warn = (id, route, message, observed) => report('warning', id, route, message, observed);
const skip = (id, why) => skipped.push({ id, why });

/**
 * One route could not be checked by one rule, while every other route still
 * was. It is a warning AND a counted route-skip, deliberately both: the warning
 * puts the route and the reason in the body where they can be read, and the
 * count puts it in the summary line where it cannot be missed.
 *
 * A skipped route that produces no output is indistinguishable from a passing
 * one. That is the whole reason this exists.
 */
const routeSkips = [];
const routeSkip = (id, route, why, observed) => {
  routeSkips.push({ id, route });
  warn(id, route, why, observed);
};

// ---------------------------------------------------------------------------
// SS-001 — the suppression file validates itself
// ---------------------------------------------------------------------------
for (const [i, s] of SUPPRESSIONS.entries()) {
  const where = `data/validation-suppressions.json[${i}]`;
  if (!String(s.reason ?? '').trim()) {
    findings.push({ severity: 'error', id: 'SS-001', route: where,
      message: 'Suppression has no reason. An unexplained suppression is indistinguishable from a bug someone got tired of.',
      observed: JSON.stringify(s) });
  }
  if (!s.ruleId || !s.route) {
    findings.push({ severity: 'error', id: 'SS-001', route: where,
      message: 'Suppression needs both ruleId and route.', observed: JSON.stringify(s) });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(s.addedOn ?? ''))) {
    findings.push({ severity: 'error', id: 'SS-001', route: where,
      message: 'Suppression needs addedOn as YYYY-MM-DD, so an old one can be found and re-argued.',
      observed: String(s.addedOn) });
  }
}

// ---------------------------------------------------------------------------
// SS-002 — the model must describe HEAD, not a snapshot of some earlier tree
// ---------------------------------------------------------------------------
{
  let headSha = null;
  try { headSha = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT }).toString().trim(); }
  catch { skip('SS-002', 'git unavailable; cannot confirm data/pages.json describes HEAD'); }

  if (headSha) {
    if (MODEL.generatedFrom?.commit !== headSha) {
      findings.push({ severity: 'error', id: 'SS-002', route: 'data/pages.json',
        message: 'Page model is stale. It was generated from a different commit, so every rule below would be validating a tree that is not this one. Run: node scripts/build-page-index.mjs',
        observed: `generatedFrom.commit=${MODEL.generatedFrom?.commit} HEAD=${headSha}` });
    }
    let dirty = [];
    try {
      dirty = execFileSync('git', ['status', '--porcelain', '--', '*.html'], { cwd: ROOT })
        .toString().trim().split('\n').filter(Boolean);
    } catch { /* handled above */ }
    if (dirty.length) {
      findings.push({ severity: 'error', id: 'SS-002', route: 'data/pages.json',
        message: 'HTML files are modified relative to HEAD, so the page model does not describe the tree being validated.',
        observed: dirty.join(' | ').slice(0, 300) });
    }
  }
}

// ===========================================================================
// SS-1xx — Route parity
// ===========================================================================

// SS-101 — filesystem HTML routes ≡ ALLOW_HTML ≡ sitemap ∪ noindex ∪ error ∪ verification
{
  const fsRoutes = new Set(PAGES.map((p) => p.route));
  const allowHtml = new Set(MODEL.allowHtml ?? []);
  const expected = new Set(
    PAGES.filter((p) => ['indexable', 'served-noindex', 'error-page', 'verification'].includes(p.class))
      .map((p) => p.route)
  );

  for (const r of fsRoutes) {
    if (!allowHtml.has(r)) {
      error('SS-101', r, 'HTML route exists in the repository but is absent from ALLOW_HTML in publish-gate.ts, so it is not served.', r);
    }
  }
  for (const r of allowHtml) {
    if (!fsRoutes.has(r)) {
      error('SS-101', r, 'ALLOW_HTML names a route with no HTML file behind it. Either the page was deleted and the allow entry left, or the entry is a typo.', r);
    }
  }
  for (const r of expected) {
    if (!fsRoutes.has(r)) error('SS-101', r, 'Classified route has no source file.', r);
  }
  for (const r of MODEL.totals?.phantomSitemapEntries ?? []) {
    error('SS-101', r, 'Sitemap lists a route with no HTML file behind it.', r);
  }
}

// SS-102 — sitemap ≡ llms.txt
{
  const sitemapRoutes = new Set(INDEXABLE.map((p) => p.route));
  const llms = new Set(MODEL.llmsTxtRoutes ?? []);
  // llms.txt legitimately references non-page URLs; they are not sitemap drift.
  const llmsIgnorable = new Set([...nonHtmlRoutes, '/llms.txt', '/llms-full.txt', '/robots.txt', '/sitemap.xml']);

  for (const r of sitemapRoutes) {
    if (!llms.has(r)) {
      error('SS-102', r, 'In sitemap.xml but not linked from llms.txt. llms.txt is hand-maintained and has gone stale before -- twelve pages were missing for a day.', r);
    }
  }
  for (const r of llms) {
    if (!sitemapRoutes.has(r) && !llmsIgnorable.has(r)) {
      error('SS-102', r, 'Linked from llms.txt but absent from sitemap.xml. Either it should be published, or llms.txt is pointing crawlers at something unlisted.', r);
    }
  }
}

// SS-103 — no sitemap route disallowed by robots.txt
for (const p of INDEXABLE) {
  if (p.robotsTxtDisallowed) {
    error('SS-103', p.route, 'Route is in sitemap.xml and disallowed by robots.txt. The two files are giving crawlers opposite instructions.', `robots.txt Disallow matches ${p.route}`);
  }
}

// SS-104 — inSitemap && noindex
for (const p of PAGES) {
  if (p.inSitemap && p.noindex) {
    error('SS-104', p.route, 'Route is in sitemap.xml and carries noindex. The sitemap asks for indexing and the page refuses; one of them is stale.', p.robotsDirective);
  }
}

// SS-105 — standing guard on the .html deny-by-default fix
{
  const allowHtml = new Set(MODEL.allowHtml ?? []);
  for (const p of PAGES) {
    if (!allowHtml.has(p.route)) {
      error('SS-105', p.route, `${p.sourceFile} is in the publish directory but not in ALLOW_HTML. Before 2026-08-20 it would have been served anyway, because .html was allowed by extension.`, p.sourceFile);
    }
  }
}

// ===========================================================================
// SS-2xx — Freshness
// ===========================================================================
{
  const excluded = new Set(FRESH_EXCL.map((e) => String(e.sha).slice(0, 7)));
  for (const e of FRESH_EXCL) {
    if (!String(e.reason ?? '').trim()) {
      findings.push({ severity: 'error', id: 'SS-201', route: 'data/freshness-exclusions.json',
        message: 'Freshness exclusion has no reason.', observed: JSON.stringify(e) });
    }
  }

  /**
   * Three outcomes that used to be two, and the conflation is what made this
   * rule stop protecting the site without saying so:
   *
   *   git-unavailable  execFileSync threw. Git really is broken or absent.
   *   no-history       git ran fine and returned nothing. The file is new and
   *                    has never been committed. `git log -- newfile` exits 0
   *                    with empty output, so the old code destructured '' into
   *                    an undefined date and returned the SAME sentinel as a
   *                    thrown git -- which tripped `gitOk = false; break`.
   *   all-excluded     every commit touching the file is in
   *                    freshness-exclusions.json, so there is no content date
   *                    to compare against.
   *
   * The old `null` for all-excluded was silently swallowed by `if (actual &&
   * ...)`: a route in that state was never checked and never said so.
   */
  const contentDate = (file) => {
    let log;
    try { log = execFileSync('git', ['log', '--format=%h %cs', '--', file], { cwd: ROOT }).toString().trim(); }
    catch { return { state: 'git-unavailable' }; }
    if (!log) return { state: 'no-history' };
    for (const line of log.split('\n')) {
      const [sha, date] = line.split(' ');
      if (!excluded.has(sha.slice(0, 7))) return { state: 'ok', date };
    }
    return { state: 'all-excluded' };
  };

  const scoped = PAGES.filter((p) => p.inSitemap && !['verification', 'error-page'].includes(p.class));
  const today = new Date().toISOString().slice(0, 10);

  // SS-202 runs in its OWN loop and needs no git at all. It used to live inside
  // the SS-201 loop, so the `break` on a git problem disabled the future-date
  // check for every remaining route too -- a second rule silently switched off
  // by an unrelated failure, which nothing anywhere reported.
  for (const p of scoped) {
    if (p.sitemapLastmod && p.sitemapLastmod > today) {
      error('SS-202', p.route, 'sitemap lastmod is in the future.', `lastmod=${p.sitemapLastmod} today=${today}`);
    }
  }

  let gitOk = true;
  for (const p of scoped) {
    const r = contentDate(p.sourceFile);

    // Only a broken git stops the whole rule. Everything else is per-route.
    if (r.state === 'git-unavailable') { gitOk = false; break; }

    if (r.state === 'no-history') {
      routeSkip('SS-201', p.route,
        'Freshness not checked: the source file has no commit history yet, so there is no content date to compare against. Expected exactly once, on the commit that introduces the page. If this route is still skipping on a later run, the file is not being committed and the route has been unchecked since.',
        p.sourceFile);
      continue;
    }
    if (r.state === 'all-excluded') {
      routeSkip('SS-201', p.route,
        'Freshness not checked: every commit touching the source file is listed in data/freshness-exclusions.json, so the rule has nothing left to date the page by. Either the page genuinely has not changed since it was written, or an exclusion is too broad.',
        p.sourceFile);
      continue;
    }

    if (p.sitemapLastmod !== r.date) {
      error('SS-201', p.route,
        'sitemap lastmod disagrees with the newest content commit touching the source file.',
        `lastmod=${p.sitemapLastmod} newest-content-commit=${r.date} (${p.sourceFile})`);
    }
  }
  if (!gitOk) skip('SS-201', 'git itself is unavailable (shallow clone or no git). This is the ONLY condition that disables the whole rule; a single undatable file no longer does. CI checks it.');
}

// ===========================================================================
// SS-3xx — Metadata
// ===========================================================================
const BRAND_SUFFIX = /\| SiegeStack$/;

{
  const seenTitles = new Map();
  const seenDescs = new Map();

  for (const p of INDEXABLE) {
    // SS-301
    if (!p.title) error('SS-301', p.route, 'No <title>.', null);
    else {
      if (p.titleLength > 60) error('SS-301', p.route, `Title is ${p.titleLength} chars; over 60 it is truncated in results.`, p.title);
      if (!BRAND_SUFFIX.test(p.title)) error('SS-301', p.route, 'Title does not end in the brand suffix "| SiegeStack".', p.title);
      const prev = seenTitles.get(p.title);
      if (prev) error('SS-301', p.route, `Title is not unique; also used by ${prev}.`, p.title);
      else seenTitles.set(p.title, p.route);
    }

    // SS-302
    if (!p.metaDescription) error('SS-302', p.route, 'No meta description.', null);
    else {
      if (p.descriptionLength < 120 || p.descriptionLength > 160) {
        error('SS-302', p.route, `Meta description is ${p.descriptionLength} chars; outside 120-160.`, p.metaDescription);
      }
      if (/(?:\.\.\.|…)$/.test(p.metaDescription) || /[,;-]$/.test(p.metaDescription.trim())) {
        error('SS-302', p.route, 'Meta description looks truncated mid-thought.', p.metaDescription.slice(-60));
      }
      const prev = seenDescs.get(p.metaDescription);
      if (prev) error('SS-302', p.route, `Meta description is not unique; also used by ${prev}.`, p.metaDescription.slice(0, 60));
      else seenDescs.set(p.metaDescription, p.route);
    }

    // SS-305
    if (!p.canonical) error('SS-305', p.route, 'No canonical link.', null);
    else {
      if (!/^https:\/\//.test(p.canonical)) error('SS-305', p.route, 'Canonical is not an absolute https URL.', p.canonical);
      if (p.canonicalSelfReferencing === false) error('SS-305', p.route, 'Canonical does not point at this route.', p.canonical);
    }
  }

  // SS-303 / SS-304 — indexable errors, everything else warns
  for (const p of PAGES) {
    const sev = p.class === 'indexable' ? error : warn;
    if (p.h1Count !== 1) sev('SS-303', p.route, `Page has ${p.h1Count} <h1> elements; it must have exactly one.`, p.h1.join(' | ') || '(none)');
    for (const s of p.headingSkips) sev('SS-304', p.route, 'Heading level skips a rank.', s);
  }

  // SS-306 — og divergence must be declared
  const declared = new Set(OG_OVERRIDES.map((o) => `${o.route}|${o.field}`));
  for (const o of OG_OVERRIDES) {
    if (!String(o.reason ?? '').trim()) {
      findings.push({ severity: 'error', id: 'SS-306', route: 'data/og-overrides.json',
        message: 'og override has no reason.', observed: JSON.stringify({ route: o.route, field: o.field }) });
    }
  }
  for (const p of INDEXABLE) {
    if (p.ogTitle !== p.title && !declared.has(`${p.route}|og:title`)) {
      error('SS-306', p.route, 'og:title differs from <title> and the divergence is not declared in data/og-overrides.json.', `title=${p.title} og=${p.ogTitle}`);
    }
    if (p.ogDescription !== p.metaDescription && !declared.has(`${p.route}|og:description`)) {
      error('SS-306', p.route, 'og:description differs from the meta description and the divergence is not declared.', `og=${String(p.ogDescription).slice(0, 70)}`);
    }
  }
}

// ===========================================================================
// SS-4xx — Link integrity
// ===========================================================================
for (const p of PAGES) {
  // SS-401
  for (const target of p.internalLinksOut) {
    if (!byRoute.has(target) && !nonHtmlRoutes.has(target)) {
      error('SS-401', p.route, 'Internal link resolves to nothing.', target);
    }
  }
  // SS-402
  if (p.class === 'indexable') {
    for (const target of p.internalLinksOut) {
      const t = byRoute.get(target);
      if (t?.noindex) error('SS-402', p.route, 'Indexable page links to a noindex page, passing crawlers to a dead end.', target);
    }
  }
  // SS-404
  for (const hop of p.internalLinksNeedingHop) {
    warn('SS-404', p.route, `Internal link needs a redirect hop; link straight to ${hop.resolvesTo}.`, hop.hrefAsWritten);
  }
}
// SS-403
for (const p of INDEXABLE) {
  if (p.inboundInternalLinks === 0) {
    warn('SS-403', p.route, 'Orphan: in the sitemap with zero inbound internal links.', '0 inbound');
  }
}

// ===========================================================================
// SS-5xx — Structured data
// ===========================================================================
const TYPE_ALLOWLIST = new Set([
  'Organization', 'ProfessionalService', 'Person', 'WebSite', 'WebPage',
  'CollectionPage', 'ContactPage', 'AboutPage', 'Article', 'TechArticle',
  'BlogPosting', 'BreadcrumbList', 'ListItem', 'ItemList', 'FAQPage',
  'Question', 'Answer', 'Service', 'OfferCatalog', 'Offer', 'Thing',
  'SoftwareApplication', 'WebApplication', 'ImageObject',
  'PresentationDigitalDocument', 'HowTo', 'HowToStep', 'PostalAddress',
  'ContactPoint', 'CreativeWork',
]);
const RATING_KEYS = /"(?:aggregateRating|reviewRating|ratingValue|ratingCount|reviewCount)"|"@type"\s*:\s*"(?:Review|AggregateRating|Rating)"/;

/**
 * SS-502 identity index: entity -> field -> value -> routes asserting it.
 *
 * Comparison is on the INTERSECTION of fields, not on the whole node. Most
 * Organization nodes on this site are nested publisher/author references that
 * legitimately carry only a name; demanding a byte-identical node would report
 * twenty findings that are all "a stub is shorter than the full record" and none
 * that are a contradiction. A field present in two places with two different
 * values is a contradiction. A field present in one place is a reference.
 */
const identityIndex = new Map();
const IDENTITY_FIELDS = ['url', 'email', 'logo', 'sameAs', 'jobTitle', 'description', 'telephone'];

for (const p of PAGES) {
  for (const err of p.jsonLdParseErrors) {
    error('SS-501', p.route, 'JSON-LD block does not parse, so no consumer reads any of it.', err);
  }
  for (const t of p.jsonLd) {
    if (!TYPE_ALLOWLIST.has(t)) {
      error('SS-501', p.route, 'JSON-LD @type is not in the allowlist. Add it deliberately or remove it.', t);
    }
  }
  const raw = JSON.stringify(p.jsonLdGraphs ?? []);
  if (RATING_KEYS.test(raw)) {
    error('SS-503', p.route, 'Rating or review markup found. There is no legitimate source for it on this site.', raw.match(RATING_KEYS)?.[0]);
  }

  // SS-502 — index every identity assertion; conflicts are resolved after the loop
  const walk = (n) => {
    if (Array.isArray(n)) return n.forEach(walk);
    if (!n || typeof n !== 'object') return;
    const types = [].concat(n['@type'] ?? []);
    for (const t of ['Organization', 'Person', 'ProfessionalService']) {
      if (!types.includes(t) || !n.name) continue;
      const entity = `${t} "${n.name}"`;
      if (!identityIndex.has(entity)) identityIndex.set(entity, new Map());
      const fields = identityIndex.get(entity);
      for (const f of IDENTITY_FIELDS) {
        if (n[f] === undefined) continue;
        const value = JSON.stringify(n[f]);
        if (!fields.has(f)) fields.set(f, new Map());
        const values = fields.get(f);
        if (!values.has(value)) values.set(value, new Set());
        values.get(value).add(p.route);
      }
    }
    Object.values(n).forEach(walk);
  };
  walk(p.jsonLdGraphs ?? []);
}

for (const [entity, fields] of identityIndex) {
  for (const [field, values] of fields) {
    if (values.size < 2) continue;
    const variants = [...values].map(([v, routes]) => `${v} on ${[...routes].join(', ')}`);
    // Reported once per conflicting field, against the first route that asserts
    // it, rather than once per page -- the defect is one disagreement, not N.
    const firstRoute = [...[...values][0][1]][0];
    error('SS-502', firstRoute,
      `${entity} asserts ${values.size} different values for "${field}" across the site. Consumers keep whichever they crawled last.`,
      variants.join('   |   '));
  }
}

// SS-504
{
  const exempt = new Set(JSONLD_EXEMPT.map((r) => r.route));
  for (const p of INDEXABLE) {
    if (p.jsonLd.length === 0 && !exempt.has(p.route)) {
      warn('SS-504', p.route, 'Indexable route carries no JSON-LD and is not listed in data/jsonld-exempt.json.', '0 blocks');
    }
  }
}

// ===========================================================================
// SS-6xx — Content policy
// ===========================================================================
const CLAIM_RE = /(~?\d+(?:\.\d+)?\s*%|\b\d+(?:\.\d+)?x\b|\bfaster\b|\breduced\b|\bimproved\b|\bcut\b)/gi;

{
  const registered = new Map();
  for (const c of CLAIMS) registered.set(`${c.route}|${c.claim}`, c);

  /**
   * B6. A page whose extracted text is empty has NOT lost its claims -- it has
   * not been read. The two are indistinguishable to everything downstream, and
   * conflating them made this rule give destructive advice: emptying one page's
   * textContent turned six "registered but has no measurement basis" warnings
   * into six "Registry entry no longer matches anything on the page; delete
   * it." Following that instruction deletes six legitimate registry rows, and
   * the finding total did not move, so the summary line looked unchanged.
   *
   * Silence fails to protect. Confident wrong advice does harm. This rule is
   * the one that guards the site's central editorial promise, so it does not
   * get to guess which of the two it is looking at.
   */
  const unreadable = (p) => !String(p.textContent ?? '').trim();
  for (const p of INDEXABLE) {
    if (unreadable(p)) {
      routeSkip('SS-601', p.route,
        'Claims not checked: the page has no extracted text at all. That is an extraction failure, not a page with no claims -- do NOT read this as the claims having been removed, and do not delete registry entries for this route on the strength of it.',
        p.sourceFile);
    }
  }

  for (const p of INDEXABLE) {
    if (unreadable(p)) continue;
    const counts = new Map();
    for (const m of p.textContent.matchAll(CLAIM_RE)) {
      counts.set(m[0], (counts.get(m[0]) ?? 0) + 1);
    }
    for (const [claim, n] of counts) {
      const entry = registered.get(`${p.route}|${claim}`);
      if (!entry) {
        error('SS-601', p.route, 'Numeric or comparative performance claim with no entry in data/claims-registry.json.', `"${claim}" ×${n}`);
      } else if (n > (entry.occurrences ?? 0)) {
        error('SS-601', p.route, `Claim appears ${n} times but only ${entry.occurrences} are registered. A new instance was added.`, `"${claim}"`);
      } else if (entry.disposition === 'not-a-claim') {
        // The registry's readme has always named this as one of the three valid
        // outcomes, and until now nothing implemented it -- so marking an entry
        // not-a-claim changed nothing and the warning stayed. That made the
        // documented way of resolving a row a promise the tool did not keep,
        // which is the same defect class as a stale derived value. A reason is
        // required: an unexplained disposition is indistinguishable from someone
        // silencing a warning they got tired of, exactly as with SS-001.
        if (!String(entry.reason ?? '').trim()) {
          error('SS-601', p.route, 'Claim is marked disposition:"not-a-claim" with no reason. An unexplained disposition is indistinguishable from a silenced warning.', `"${claim}"`);
        }
      } else if (String(entry.measurementBasis).startsWith('TODO')) {
        warn('SS-601', p.route, 'Claim is registered but has no measurement basis yet.', `"${claim}" ×${n}`);
      }
    }
  }
  // Registry entries whose claim has left the page.
  for (const c of CLAIMS) {
    const p = byRoute.get(c.route);
    if (!p) { warn('SS-601', c.route, 'Claims registry names a route that does not exist.', c.claim); continue; }
    // The route-skip above already said this page could not be read. Saying
    // "delete it" here as well is the harm.
    if (unreadable(p)) continue;
    if (!new RegExp(CLAIM_RE.source, 'gi').test(p.textContent) || !p.textContent.includes(c.claim.replace(/^~/, '~'))) {
      const still = [...p.textContent.matchAll(CLAIM_RE)].some((m) => m[0] === c.claim);
      if (!still) warn('SS-601', c.route, 'Registry entry no longer matches anything on the page; delete it.', c.claim);
    }
  }
}

// SS-602 — identifier denylist
if (!DENYLIST) {
  skip('SS-602', `${DENYLIST_LOCAL} not present. Copy data/denylist.example.json to it and fill in the terms. This rule is REPORTED AS SKIPPED, not passed -- a policy check that silently passes when its input is missing is worse than no check.`);
} else {
  const corpora = [
    ...PAGES.map((p) => ({ where: p.route, text: p.textContent })),
    ...PAGES.map((p) => ({ where: `${p.route} (JSON-LD)`, text: JSON.stringify(p.jsonLdGraphs ?? []) })),
    { where: 'llms.txt', text: rd('llms.txt') },
    { where: 'llms-full.txt', text: has('llms-full.txt') ? rd('llms-full.txt') : '' },
    { where: 'sitemap.xml', text: rd('sitemap.xml') },
  ];
  for (const { term, substring } of DENYLIST) {
    if (!term) continue;
    const esc = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(substring ? esc : `\\b${esc}\\b`, 'i');
    for (const c of corpora) {
      if (re.test(c.text)) {
        // The term itself is NOT printed. This output can land in a public CI log.
        error('SS-602', c.where, 'Denylisted identifier found in published output. The term is not printed here on purpose -- CI logs are public. Search locally.', `denylist entry #${DENYLIST.findIndex((d) => d.term === term) + 1}`);
      }
    }
  }
}

// SS-603 — marketing filler
const FILLER = [
  'best-in-class', 'world-class', 'synergy', 'synergies', 'cutting-edge',
  'state-of-the-art', 'seamless integration', 'game-changer', 'game-changing',
  'leverage our', 'industry-leading', 'best of breed', 'turnkey solution',
  'robust and scalable', 'mission-critical solution', 'thought leader',
  'move the needle', 'low-hanging fruit', 'paradigm shift', 'holistic approach',
];
for (const p of INDEXABLE) {
  for (const phrase of FILLER) {
    if (new RegExp(`\\b${phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(p.textContent)) {
      warn('SS-603', p.route, 'Marketing filler phrase.', phrase);
    }
  }
}

// ===========================================================================
// SS-7xx — Hygiene
// ===========================================================================
{
  let imgCount = 0;
  for (const p of INDEXABLE) {
    for (const img of p.images) {
      imgCount++;
      if (!img.altPresent) warn('SS-701', p.route, '<img> has no alt attribute.', img.src);
      else if (img.altEmpty) warn('SS-701', p.route, '<img> has an empty alt. Correct for decoration; wrong if it carries meaning.', img.src);
      else {
        const near = `${img.adjacentTextBefore} ${img.adjacentTextAfter}`.toLowerCase();
        if (img.alt.length > 8 && near.includes(img.alt.toLowerCase())) {
          warn('SS-701', p.route, 'alt text duplicates adjacent visible text verbatim; a screen reader hears it twice.', img.alt);
        }
      }
    }
  }
  if (imgCount === 0) {
    skip('SS-701', 'No <img> elements on any indexable page. Every graphic on this site is inline SVG or CSS, and the only two <img> tags live inside a <script> template literal on /label-tool. The rule passes vacuously -- it is not evidence of good alt text.');
  }
}

// ===========================================================================
// SS-6xx (continued) — the corrections practice
//
// The site's editorial posture is that a published claim which turns out to be
// wrong is corrected in public rather than quietly edited. Until 89458a4 that
// rested entirely on remembering, and nothing in this file referenced it.
//
// None of these rules can detect a correction that SHOULD have been written and
// was not -- that needs a judgement about whether a fact changed. They check the
// three things that are decidable from the tree.
// ===========================================================================
{
  // SS-604 (error) -- corrections are append-only.
  //
  // The page states the principle itself: "deleting a correction along with its
  // subject is how a record stops being a record." A correction that can quietly
  // disappear is not a record, it is a note. Compares the slugs present at HEAD
  // against the slugs present in the previous commit of the same file.
  //
  // IT CHECKS THE COMMIT, NOT THE WORKING TREE. Deleting a marker in an
  // uncommitted edit does NOT trip this rule: the model describes the working
  // tree while the comparison is against HEAD~1, so the pair is off by one.
  // That is not a hole -- SS-002 already errors on any dirty HTML tree, so the
  // validator never gets here with uncommitted markup, and CI validates a real
  // commit. It is written down because proving this rule by breaking the
  // working tree produces a silent pass and looks exactly like a rule that does
  // not work. Prove it on a throwaway branch with a real commit instead.
  const prevOf = (file) => {
    try {
      return execFileSync('git', ['show', `HEAD~1:${file.replace(/\\/g, '/')}`], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 }).toString();
    } catch { return null; } // new file, or no parent commit -- nothing to compare
  };
  let compared = 0;
  for (const p of PAGES) {
    const before = prevOf(p.sourceFile);
    if (before === null) continue;
    compared++;
    const had = new Set([...before.matchAll(/data-correction="([a-z0-9-]+)"/g)].map((m) => m[1]));
    for (const slug of had) {
      if (!p.corrections.includes(slug)) {
        error('SS-604', p.route, 'A published correction was removed. Corrections are append-only -- collapse or move one, but do not delete it.', slug);
      }
    }
    // Same guarantee for standing disclosures, and a stronger one: a disclosure
    // is what makes invented or illustrative content honest. Losing one silently
    // re-creates the defect it was written to close.
    const hadDisc = new Set([...before.matchAll(/data-disclosure="([a-z0-9-]+)"/g)].map((m) => m[1]));
    for (const slug of hadDisc) {
      if (!p.disclosures.includes(slug)) {
        error('SS-604', p.route, 'A standing disclosure was removed. It is what makes the content it labels honest; removing it re-opens the defect.', slug);
      }
    }
  }
  if (compared === 0) skip('SS-604', 'No parent commit to compare against, so nothing could be checked. Reported as SKIPPED rather than passed.');

  // SS-605 (error) -- a stated correction count must match the markers.
  //
  // /working-with-claude-blog's intro enumerates its corrections in prose. That
  // sentence is a derived value and it went stale the first time a correction was
  // added: it said four when there were five, and grepping for the new heading
  // would have reported everything fine. Self-declaring via
  // data-correction-count, so the rule needs no list of which pages state one.
  //
  // Counted on DISTINCT SLUGS, not elements. One correction may be surfaced in
  // more than one place -- cross-session-memory has a section and an FAQ answer
  // on the same page -- and a reader counts the corrections, not the mentions.
  for (const p of PAGES) {
    if (p.statedCorrectionCount == null) continue;
    if (p.statedCorrectionCount !== p.corrections.length) {
      error('SS-605', p.route, 'The page states a correction count that disagrees with the corrections actually marked on it.',
        `stated=${p.statedCorrectionCount} distinct=${p.corrections.length} (${p.correctionElementCount} elements) ${JSON.stringify(p.corrections)}`);
    }
  }

  // SS-606 (WARNING, deliberately) -- a registered claim vanished from a route.
  //
  // If a claim tracked in claims-registry.json disappears from a page, that is
  // usually a retraction and should carry a correction. Warning rather than
  // error, for two reasons that are both real on this site:
  //
  //   1. A claim can vanish because the whole section went. The article keeps
  //      the litigation correction "even though the section it belonged to has
  //      been removed" -- as an error this rule would demand a marker on a page
  //      with nothing left to correct.
  //   2. The house convention is to QUOTE the retracted figure inside the
  //      retraction, which keeps the token on the page and means a correctly
  //      written correction never trips this at all. It fires on the silent
  //      deletions, which is the right polarity, but it is a weak signal and
  //      an error would train people to route around it.
  //
  // It caught one of the three corrections shipped on 2026-08-21. That is the
  // honest measure of its reach.
  // SS-607 (warning) -- a correction is past its inline window.
  //
  // Policy: a correction is a dated note about something that CHANGED, and its
  // subject is gone from the page. It stays where the claim was for 90 days --
  // long enough that someone meeting the old wording in a cached result or a
  // shared link lands on the correction beside it -- and then collapses to a
  // dated one-line link into /corrections, with the full text moving there word
  // for word. Collapsing moves text. It never shortens or deletes it.
  //
  // A STANDING DISCLOSURE IS NOT A CORRECTION AND IS NOT CHECKED HERE. Nothing
  // about it was corrected; the thing it labels is still on the page and the
  // marker is what makes it honest. It carries data-disclosure, this rule reads
  // data-correction, and the two are separate fields in the model precisely so
  // that no ageing rule can reach a disclosure. If this rule could, the 90-day
  // sweep would eventually strip "Example -- not live data" off a panel of
  // fabricated numbers and recreate that defect on a timer, unattended.
  //
  // IT WARNS, IT DOES NOT COLLAPSE. Same argument as SS-203: a validator that
  // performs the edit it is checking is a laundering step. Collapsing is a
  // judgement about wording and a human makes it; this rule only says when one
  // is due. Mark the collapsed notice data-collapsed="true" once it links to
  // /corrections#slug.
  const INLINE_WINDOW_DAYS = 90;
  {
    const todayMs = Date.parse(new Date().toISOString().slice(0, 10));
    for (const p of PAGES) {
      for (const [slug, date] of Object.entries(p.correctionDates ?? {})) {
        if (p.collapsedCorrections?.includes(slug)) continue;
        const age = Math.floor((todayMs - Date.parse(date)) / 86400000);
        if (age > INLINE_WINDOW_DAYS) {
          warn('SS-607', p.route, `Correction has been inline for ${age} days, past the ${INLINE_WINDOW_DAYS}-day window. Collapse it to a dated one-line link into /corrections#${slug} and move the full text there.`, `${slug} corrected ${date}`);
        }
      }
    }
  }

  for (const p of PAGES) {
    const registered = CLAIMS.filter((c) => c.route === p.route);
    for (const c of registered) {
      if (!p.textContent.includes(c.claim) && p.corrections.length === 0) {
        warn('SS-606', p.route, 'A claim in claims-registry.json is no longer on the page and the page carries no correction. If it was retracted, say so; if the entry is dead, delete it.', c.claim);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
const errors = findings.filter((f) => f.severity === 'error');
const warnings = findings.filter((f) => f.severity === 'warning');

const order = (f) => f.id;
const grouped = (list) => {
  const g = new Map();
  for (const f of list.sort((a, b) => order(a).localeCompare(order(b)))) {
    if (!g.has(f.id)) g.set(f.id, []);
    g.get(f.id).push(f);
  }
  return g;
};

const print = (label, list) => {
  if (!list.length) return;
  console.log(`\n${label} (${list.length})`);
  for (const [id, items] of grouped(list)) {
    console.log(`\n  ${id}  ${items.length} ${items.length === 1 ? 'finding' : 'findings'}`);
    for (const f of items) {
      console.log(`    ${f.route}`);
      console.log(`      ${f.message}`);
      if (f.observed != null && f.observed !== '') console.log(`      observed: ${String(f.observed).slice(0, 220)}`);
    }
  }
};

console.log(`validate-pages  ${PAGES.length} routes (${INDEXABLE.length} indexable)  @ ${MODEL.generatedFrom?.commit}`);
print('ERRORS', errors);
print('WARNINGS', warnings);

if (skipped.length) {
  console.log(`\nSKIPPED (${skipped.length})`);
  for (const s of skipped) console.log(`  ${s.id}  ${s.why}`);
}
if (suppressed.length) {
  console.log(`\nSUPPRESSED (${suppressed.length})`);
  for (const s of suppressed) console.log(`  ${s.id}  ${s.route}`);
}

if (routeSkips.length) {
  const rules = [...new Set(routeSkips.map((r) => r.id))].sort().join(', ');
  console.log(`\nROUTE SKIPS (${routeSkips.length})  ${rules} — one route each, listed above as warnings with the reason.`);
  for (const r of routeSkips) console.log(`  ${r.id}  ${r.route}`);
}
console.log(`\n${errors.length} error(s), ${warnings.length} warning(s), ${routeSkips.length} route-skip(s), ${skipped.length} skipped, ${suppressed.length} suppressed`);
process.exit(errors.length ? 1 : 0);
