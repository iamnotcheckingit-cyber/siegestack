/**
 * Builds data/pages.json and reports/page-inventory.csv from the repository.
 *
 *   node scripts/build-page-index.mjs
 *
 * WHY THIS IS GENERATED
 * ---------------------
 * It is the input to scripts/validate-pages.mjs. A hand-maintained inventory
 * would rot exactly the way llms.txt's route count did -- correct on the day it
 * was written, silently wrong the next time a page landed. Nothing here is
 * authored; every field is read out of a file that already exists.
 *
 * NO NEW DEPENDENCIES. Node builtins only, plus one `git log` per source file.
 *
 * THREE PARSING TRAPS THIS FILE EXISTS TO AVOID
 * ---------------------------------------------
 * 1. HTML COMMENTS. working-with-claude.html:19 carries a comment listing the
 *    ten places its slide count lives, and that comment contains the literal
 *    text "<title>". A naive /<title>(.*?)<\/title>/ reads 370 characters out
 *    of that file. Comments are stripped before ANY extraction.
 * 2. <style> AND <script>. Every page on this site carries its own inline
 *    stylesheet -- there is no external CSS. A numeric-claim scan that does not
 *    strip <style> finds forty-plus "50%" hits that are flex-basis values. Text,
 *    headings and links are all read from the comment- AND block-stripped copy.
 *    JSON-LD is extracted BEFORE that strip, because it lives inside <script>.
 * 3. THE ALLOW-LIST IS NOT IN netlify.toml. Deny-by-default is
 *    netlify/edge-functions/publish-gate.ts. The `inNetlifyAllow` field keeps
 *    the name the spec asked for, but it is computed by replaying that file's
 *    isAllowed() logic -- see allowFromPublishGate() below. netlify.toml is read
 *    only for pretty-URL rewrites and X-Robots-Tag headers.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ORIGIN = 'https://siegestack.com';

const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(ROOT, p));

// ---------------------------------------------------------------------------
// HTML text extraction
// ---------------------------------------------------------------------------

const stripComments = (h) => h.replace(/<!--[\s\S]*?-->/g, ' ');
const stripBlocks = (h) =>
  h.replace(/<script\b[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[\s\S]*?<\/style>/gi, ' ');

const ENTITIES = {
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'",
  '&apos;': "'", '&mdash;': '—', '&ndash;': '–', '&nbsp;': ' ',
  '&rarr;': '→', '&middot;': '·', '&hellip;': '…',
  '&rsquo;': '’', '&lsquo;': '‘', '&ldquo;': '“', '&rdquo;': '”',
};
const decode = (s) =>
  String(s ?? '')
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&[a-z]+;/gi, (e) => (e in ENTITIES ? ENTITIES[e] : e))
    .replace(/\s+/g, ' ')
    .trim();

/**
 * <meta> lookup that tolerates attribute order (content= before name=).
 *
 * THE CONTENT GROUP MUST CLOSE ON THE QUOTE THAT OPENED IT. It used to be
 * `content=["']([^"']*)["']` -- a character class excluding BOTH quote
 * characters regardless of which one had opened the attribute -- so
 * content="Here's the workflow" was read as `Here`, silently, with no error
 * anywhere. Measured at HEAD on 2026-08-26: two og:descriptions were truncated
 * in data/pages.json, /working-with-claude-blog at "Here" and /prophet-21 at
 * "the vendor".
 *
 * SCOPE OF THAT, stated exactly, because it is smaller than it first looked:
 * llms-full.txt does not emit og:description and reports/page-inventory.csv
 * carries descriptionLength (the meta description) rather than the og value, so
 * NOTHING PUBLISHED WAS WRONG. The damage was confined to the model.
 *
 * IT WAS INVISIBLE BECAUSE BOTH ROUTES ALREADY DECLARED AN OG DIVERGENCE in
 * data/og-overrides.json. SS-306 asks only whether og differs from the page
 * value; a truncated value differs; so a declared divergence sat on top of a
 * parsing bug and made it indistinguishable from intent.
 *
 * THE VARIANT THAT HAS NOT FIRED YET IS THE WORSE ONE. meta() also feeds
 * `description` and `robots`. No description on this site contains an
 * apostrophe today. The day one does, SS-302 measures the length of a string
 * the page does not serve and reports a correct description as too short --
 * and the repair for that reads as padding a description, not as fixing a
 * parser.
 *
 * The rewrite matches one <meta> tag at a time and backreferences the
 * delimiter, so the content group cannot run past its own closing quote or
 * across a tag boundary. Exported for scripts/test/page-index.test.mjs: this
 * was the only component the entire validation suite depends on that had no
 * test of its own.
 */
export function meta(html, attr, value) {
  const v = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const named = new RegExp(`\\b${attr}=(["'])${v}\\1`, 'i');
  for (const [tag] of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (!named.test(tag)) continue;
    const c = tag.match(/\bcontent=(["'])([\s\S]*?)\1/i);
    if (c) return c[2];
  }
  return null;
}

/**
 * The visible "Last updated" date a page shows a READER, if it shows one.
 *
 * Distinct from sitemapLastmod, which is what the page tells a CRAWLER, and
 * from gitLastCommitDate, which is what the repository knows. Nothing compared
 * the first against the other two until SS-204, so /privacy-policy could and
 * did display "Last updated: January 22, 2026" on a file whose newest content
 * commit was seven months later.
 *
 * REQUIRES THE LABEL, not just a date. /corrections is full of lines like
 * "26 August 2026 &middot; Citation terms" and every one of them is the date of
 * a correction, not of the page. Matching a bare date there would invent a
 * freshness claim the page never made and then report it as wrong.
 *
 * Returns { text, iso } or null. `iso` is null when the words are present but
 * the date does not parse -- which is itself worth seeing, because a date a
 * machine cannot read is one a rule cannot check.
 */
const MONTHS = {
  january: '01', february: '02', march: '03', april: '04', may: '05', june: '06',
  july: '07', august: '08', september: '09', october: '10', november: '11', december: '12',
};

function visibleUpdated(html) {
  // Comments, script and style are already gone from `clean`; this is called
  // with that copy. Tags are dropped so the label and the date can be adjacent
  // across markup, which they are on /working-with-claude-blog.
  const text = html.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/\s+/g, ' ');
  const m = /\b(Last updated|Last reviewed|Updated)\b[:\s]*([A-Z][a-z]+ \d{1,2},? \d{4}|\d{1,2} [A-Z][a-z]+ \d{4}|\d{4}-\d{2}-\d{2})/.exec(text);
  if (!m) return null;

  const raw = m[2].trim();
  let iso = null;
  let d;
  if ((d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw))) iso = raw;
  else if ((d = /^([A-Za-z]+) (\d{1,2}),? (\d{4})$/.exec(raw))) {
    const mm = MONTHS[d[1].toLowerCase()];
    if (mm) iso = `${d[3]}-${mm}-${String(d[2]).padStart(2, '0')}`;
  } else if ((d = /^(\d{1,2}) ([A-Za-z]+) (\d{4})$/.exec(raw))) {
    const mm = MONTHS[d[2].toLowerCase()];
    if (mm) iso = `${d[3]}-${mm}-${String(d[1]).padStart(2, '0')}`;
  }
  return { text: `${m[1]}: ${raw}`, iso };
}

/** Every @type in a JSON-LD graph, however deeply nested. */
function collectTypes(node, out = []) {
  if (Array.isArray(node)) { node.forEach((n) => collectTypes(n, out)); return out; }
  if (node && typeof node === 'object') {
    if (node['@type']) [].concat(node['@type']).forEach((t) => out.push(t));
    Object.values(node).forEach((v) => collectTypes(v, out));
  }
  return out;
}

// ---------------------------------------------------------------------------
// netlify.toml -- pretty-URL rewrites and X-Robots-Tag only
// ---------------------------------------------------------------------------

const TOML = read('netlify.toml');

/** `from = "/x"` -> `to = "/x.html"` with status 200. Maps sourceFile -> route. */
const prettyRoutes = new Map();
for (const m of TOML.matchAll(
  /\[\[redirects\]\][^[]*?from\s*=\s*"([^"]+)"[^[]*?to\s*=\s*"([^"]+)"[^[]*?status\s*=\s*(\d+)/g
)) {
  const [, from, to, status] = m;
  if (status === '200' && to.endsWith('.html') && !from.endsWith('.html')) {
    prettyRoutes.set(to.replace(/^\//, ''), from);
  }
}

/** X-Robots-Tag by exact `for` path, from netlify.toml and _headers alike. */
const headerRobots = new Map();
for (const m of TOML.matchAll(/\[\[headers\]\]\s*for\s*=\s*"([^"]+)"([\s\S]*?)(?=\n\[\[|\n\[functions|$)/g)) {
  const tag = (m[2].match(/X-Robots-Tag\s*=\s*"([^"]*)"/) || [])[1];
  if (tag) headerRobots.set(m[1], tag);
}
if (exists('_headers')) {
  let current = null;
  for (const line of read('_headers').split(/\r?\n/)) {
    if (/^\s*#/.test(line) || !line.trim()) continue;
    if (/^\//.test(line)) { current = line.trim(); continue; }
    const t = line.match(/^\s*X-Robots-Tag:\s*(.+)$/i);
    if (t && current && !headerRobots.has(current)) headerRobots.set(current, t[1].trim());
  }
}
const headerRobotsFor = (route) =>
  headerRobots.get(route) ??
  [...headerRobots].find(([p]) => p.endsWith('/*') && route.startsWith(p.slice(0, -1)))?.[1] ??
  null;

// ---------------------------------------------------------------------------
// publish-gate.ts -- the real allow-list. Its logic is replayed, not guessed.
// ---------------------------------------------------------------------------

const GATE = read('netlify/edge-functions/publish-gate.ts');
const gateBlock = (name) => (GATE.match(new RegExp(`${name}\\s*=[^[]*\\[([\\s\\S]*?)\\]`)) || [])[1] ?? '';
const gateList = (name) => [...gateBlock(name).matchAll(/"([^"]+)"/g)].map((m) => m[1]);

/**
 * ALLOW_HTML is exported separately from the isAllowed() replay on purpose.
 * SS-101 compares the repository against THIS SET, not against the decision
 * function -- replaying isAllowed() is what kept the .html hole invisible for as
 * long as it existed, because it answered "allowed" for anything ending .html
 * without ever consulting a list. A parity rule that asks the decision instead
 * of the list cannot, even in principle, detect drift in the list.
 */
const ALLOW_HTML = new Set(gateList('ALLOW_HTML'));
const ALLOW_REDIRECT_SOURCE = new Set(gateList('ALLOW_REDIRECT_SOURCE'));
const ALLOW_EXACT = new Set(gateList('ALLOW_EXACT'));
const ALLOW_PREFIX = gateList('ALLOW_PREFIX');
const DENY_PREFIX = gateList('DENY_PREFIX');
const ALLOW_EXT = /\.(?:svg|png|jpe?g|webp|avif|gif|ico|woff2?)$/i;

if (ALLOW_HTML.size === 0) {
  console.error('FATAL: ALLOW_HTML could not be read out of publish-gate.ts. The file changed shape; fix this parser rather than shipping an index that thinks nothing is allowed.');
  process.exit(1);
}

/** Mirrors isAllowed() in publish-gate.ts. Kept only for the `inNetlifyAllow` field. */
function allowFromPublishGate(route) {
  const lower = route.toLowerCase();
  const bare = route.replace(/\/$/, '');
  if (DENY_PREFIX.some((p) => lower.startsWith(p))) return false;
  if (lower.endsWith('.html')) {
    return ALLOW_HTML.has(route) || ALLOW_REDIRECT_SOURCE.has(route) ||
      ALLOW_HTML.has(route.slice(0, -'.html'.length));
  }
  return (
    ALLOW_HTML.has(route) || ALLOW_HTML.has(bare) ||
    ALLOW_EXACT.has(route) || ALLOW_EXACT.has(bare) ||
    ALLOW_REDIRECT_SOURCE.has(route) ||
    ALLOW_PREFIX.some((p) => route.startsWith(p)) ||
    ALLOW_EXT.test(route)
  );
}

// ---------------------------------------------------------------------------
// sitemap.xml / llms.txt / robots.txt
// ---------------------------------------------------------------------------

const sitemap = new Map();
for (const m of read('sitemap.xml').matchAll(/<url>([\s\S]*?)<\/url>/g)) {
  const b = m[1];
  const loc = (b.match(/<loc>\s*([^<]*?)\s*<\/loc>/) || [])[1];
  if (!loc) continue;
  const route = loc.replace(ORIGIN, '') || '/';
  sitemap.set(route, {
    lastmod: (b.match(/<lastmod>\s*([^<]*?)\s*<\/lastmod>/) || [])[1] ?? null,
    priority: (b.match(/<priority>\s*([^<]*?)\s*<\/priority>/) || [])[1] ?? null,
    changefreq: (b.match(/<changefreq>\s*([^<]*?)\s*<\/changefreq>/) || [])[1] ?? null,
  });
}

const LLMS = read('llms.txt');
// The trailing-punctuation strip is load-bearing: llms.txt is prose, so URLs end
// sentences. Without it the set contains "/audit." and "/contact." and the
// parity rule reports drift that is really a full stop.
const llmsRoutes = new Set(
  [...LLMS.matchAll(/https:\/\/siegestack\.com(\/[A-Za-z0-9._/-]*)?/g)]
    .map((m) => (m[1] || '/').replace(/[.,;:)\]]+$/, ''))
    .map((r) => r || '/')
);

/** robots.txt Disallow paths for User-agent: * only. */
const robotsDisallow = [];
{
  let wildcard = false;
  for (const line of read('robots.txt').split(/\r?\n/)) {
    const ua = line.match(/^\s*User-agent:\s*(.+)$/i);
    if (ua) { wildcard = ua[1].trim() === '*'; continue; }
    const d = line.match(/^\s*Disallow:\s*(\S*)/i);
    if (d && wildcard && d[1]) robotsDisallow.push(d[1]);
  }
}

// ---------------------------------------------------------------------------
// Route universe
// ---------------------------------------------------------------------------

const htmlFiles = execFileSync('git', ['ls-files', '*.html'], { cwd: ROOT })
  .toString().trim().split('\n').filter(Boolean).sort();

const routeOf = (file) => {
  if (file === 'index.html') return '/';
  if (prettyRoutes.has(file)) return prettyRoutes.get(file);
  return '/' + file; // no pretty-URL rewrite: served at its own .html path
};

/** Why a file is in the inventory. Lets the validator scope rules correctly. */
function classify(file, route, noindex) {
  if (file === '404.html') return 'error-page';
  if (/^google[a-z0-9]+\.html$/.test(file)) return 'verification';
  if (sitemap.has(route)) return 'indexable';
  if (noindex) return 'served-noindex';
  return 'served-unlisted';
}

const gitDate = (file) => {
  try {
    return execFileSync('git', ['log', '-1', '--format=%cs', '--', file], { cwd: ROOT })
      .toString().trim() || null;
  } catch { return null; }
};

// ---------------------------------------------------------------------------
// Per-file extraction
// ---------------------------------------------------------------------------

const pages = [];

for (const file of htmlFiles) {
  const raw = read(file);
  const route = routeOf(file);

  // JSON-LD first: it lives inside <script>, which the next step removes.
  const jsonLd = [];
  const jsonLdErrors = [];
  const jsonLdGraphs = [];
  for (const m of stripComments(raw).matchAll(
    /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi
  )) {
    try {
      const parsed = JSON.parse(m[1]);
      jsonLdGraphs.push(parsed);
      jsonLd.push(...collectTypes(parsed));
    } catch (e) { jsonLdErrors.push(String(e.message).slice(0, 120)); }
  }

  const clean = stripBlocks(stripComments(raw));

  const title = decode((clean.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] ?? '') || null;
  const description = decode(meta(clean, 'name', 'description') ?? '') || null;
  const ogTitle = decode(meta(clean, 'property', 'og:title') ?? '') || null;
  const ogDescription = decode(meta(clean, 'property', 'og:description') ?? '') || null;
  const canonical = (clean.match(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']/i) ||
    clean.match(/<link[^>]*href=["']([^"']+)["'][^>]*rel=["']canonical["']/i) || [])[1] ?? null;

  // Headings
  const headings = [];
  for (const m of clean.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi)) {
    const text = decode(m[2].replace(/<[^>]+>/g, ' '));
    headings.push({ level: Number(m[1]), text: text.length > 120 ? text.slice(0, 117) + '…' : text });
  }
  const h1 = headings.filter((h) => h.level === 1).map((h) => h.text);
  const headingSkips = [];
  for (let i = 1; i < headings.length; i++) {
    if (headings[i].level > headings[i - 1].level + 1) {
      headingSkips.push(`h${headings[i - 1].level}→h${headings[i].level} @ "${headings[i].text.slice(0, 48)}"`);
    }
  }

  // Links
  const internal = new Set();
  const external = new Set();
  const needingHop = [];
  for (const m of clean.matchAll(/<a\b[^>]*href=["']([^"']+)["']/gi)) {
    let href = m[1].trim();
    if (/^(mailto:|tel:|javascript:|#)/i.test(href)) continue;
    if (href.startsWith(ORIGIN)) href = href.slice(ORIGIN.length) || '/';
    if (/^https?:\/\//i.test(href)) { external.add(href.split('#')[0]); continue; }
    if (!href.startsWith('/')) continue; // relative links: none on this site
    href = href.split('#')[0].split('?')[0];
    if (!href) continue;
    if (/\.(png|jpe?g|svg|ico|webp|gif|json|js|txt|xml|zip|bat|md)$/i.test(href)) continue;
    const asWritten = href;
    if (href !== '/' && href.endsWith('/')) href = href.slice(0, -1);
    if (href.endsWith('.html')) {
      const pretty = prettyRoutes.get(href.replace(/^\//, ''));
      if (pretty) href = pretty; // /about.html 301s to /about; count the destination
    }
    // SS-404 needs the hop recorded, not silently absorbed. Resolving it here
    // and reporting it there is the point: the link graph stays honest about
    // where a reader ends up, and the validator can still say the markup makes
    // them travel to get there.
    if (href !== asWritten) needingHop.push({ hrefAsWritten: asWritten, resolvesTo: href });
    internal.add(href);
  }

  // Images. `adjacentText` is the nearest preceding or following text node, so
  // SS-701 can tell an informative alt from one that just repeats the caption.
  const images = [];
  for (const m of clean.matchAll(/<img\b[^>]*>/gi)) {
    const tag = m[0];
    const alt = (tag.match(/\balt=["']([^"']*)["']/i) || [])[1];
    const before = decode(clean.slice(Math.max(0, m.index - 220), m.index).replace(/<[^>]+>/g, ' '));
    const after = decode(clean.slice(m.index + tag.length, m.index + tag.length + 220).replace(/<[^>]+>/g, ' '));
    images.push({
      src: (tag.match(/\bsrc=["']([^"']*)["']/i) || [])[1] ?? null,
      alt: alt === undefined ? null : decode(alt),
      altPresent: alt !== undefined,
      altEmpty: alt !== undefined && decode(alt) === '',
      adjacentTextBefore: before.slice(-160),
      adjacentTextAfter: after.slice(0, 160),
    });
  }

  // Robots
  const metaRobots = decode(meta(clean, 'name', 'robots') ?? '') || null;
  const visibleUpdatedValue = visibleUpdated(clean);
  const xRobots = headerRobotsFor(route);
  const robotsDirective = [metaRobots, xRobots].filter(Boolean).join(' + ') || null;
  const noindex = /noindex/i.test(robotsDirective ?? '');

  // The rendered text, comment- and block-stripped. SS-601 (numeric claims),
  // SS-602 (identifier denylist) and SS-603 (filler phrases) all scan THIS,
  // never the HTML -- which is what keeps the validator from growing a second,
  // subtly different parser. Without the <style> strip a claim scan finds forty
  // flex-basis "50%" values on this site alone.
  const textContent = decode(clean.replace(/<[^>]+>/g, ' '));
  const wordCount = textContent.split(/\s+/).filter(Boolean).length;
  const sm = sitemap.get(route) ?? null;

  // Corrections and standing disclosures. Read from attributes, never from the
  // word "correction" in the prose: that word appears as a QR error-correction
  // level on /label-tool and as a data-rights bullet on /privacy-policy, and it
  // is absent from the retraction of the "roughly 20% of the time" figure,
  // which never uses it. Right text, wrong instrument.
  //
  // Keyed on the slug, not the element. One correction can appear in more than
  // one place -- the cross-session-memory retraction has its own section and an
  // FAQ answer on the same page -- and a reader counting corrections counts the
  // thing corrected, not how many times it is mentioned.
  const corrections = [];
  for (const m of clean.matchAll(/data-correction="([a-z0-9-]+)"[^>]*?data-corrected="(\d{4}-\d{2}-\d{2})"/g)) {
    corrections.push({ slug: m[1], corrected: m[2] });
  }
  const correctionSlugs = [...new Set(corrections.map((c) => c.slug))].sort();
  // Earliest date wins per slug: the correction was made once, even if a later
  // commit added a second mention of it.
  const correctionDates = Object.fromEntries(
    correctionSlugs.map((s) => [s, corrections.filter((c) => c.slug === s).map((c) => c.corrected).sort()[0]]),
  );
  // A standing disclosure is NOT an ageing correction. Nothing was corrected:
  // the thing being disclosed is still on the page and the marker is what makes
  // it honest. Kept in a separate field so no rule can ever treat one as the
  // other and collapse it on a timer.
  const disclosures = [...new Set([...clean.matchAll(/data-disclosure="([a-z0-9-]+)"/g)].map((m) => m[1]))].sort();
  // Already collapsed to a one-line link into /corrections. SS-607 stops
  // nagging about these; the full text now lives on the record page.
  const collapsedCorrections = [...new Set(
    [...clean.matchAll(/data-correction="([a-z0-9-]+)"[^>]*?data-collapsed="true"/g)].map((m) => m[1]),
  )].sort();
  const statedCount = /data-correction-count="(\d+)"/.exec(clean);

  pages.push({
    route,
    sourceFile: file,
    class: classify(file, route, noindex),
    title,
    titleLength: title ? title.length : 0,
    metaDescription: description,
    descriptionLength: description ? description.length : 0,
    ogTitle,
    ogDescription,
    canonical,
    canonicalSelfReferencing: canonical ? canonical === ORIGIN + (route === '/' ? '/' : route) : null,
    h1,
    h1Count: h1.length,
    h1Flag: h1.length !== 1,
    headingOutline: headings,
    headingSkips,
    jsonLd: [...new Set(jsonLd)].sort(),
    jsonLdGraphs,
    jsonLdParseErrors: jsonLdErrors,
    internalLinksOut: [...internal].sort(),
    internalLinksNeedingHop: needingHop,
    externalLinksOut: [...external].sort(),
    inboundInternalLinks: 0, // filled below
    images,
    corrections: correctionSlugs,
    correctionElementCount: corrections.length,
    correctionDates,
    disclosures,
    collapsedCorrections,
    statedCorrectionCount: statedCount ? Number(statedCount[1]) : null,
    textContent,
    wordCount,
    inSitemap: sitemap.has(route),
    visibleUpdated: visibleUpdatedValue,
    sitemapLastmod: sm?.lastmod ?? null,
    sitemapPriority: sm?.priority ?? null,
    sitemapChangefreq: sm?.changefreq ?? null,
    gitLastCommitDate: gitDate(file),
    lastmodMatchesGit: sm?.lastmod ? sm.lastmod === gitDate(file) : null,
    inNetlifyAllow: allowFromPublishGate(route),
    inAllowHtml: ALLOW_HTML.has(route),
    hasPrettyUrlRewrite: prettyRoutes.has(file),
    inLlmsTxt: llmsRoutes.has(route),
    robotsDirective,
    noindex,
    robotsTxtDisallowed: robotsDisallow.some((d) => route.startsWith(d)),
  });
}

// Derived: inbound internal links, counted over the whole universe.
const byRoute = new Map(pages.map((p) => [p.route, p]));
for (const p of pages) {
  for (const target of p.internalLinksOut) {
    const t = byRoute.get(target);
    if (t) t.inboundInternalLinks++;
  }
}

// Link targets nothing in the universe resolves to.
const unresolved = new Map();
for (const p of pages) {
  for (const target of p.internalLinksOut) {
    if (!byRoute.has(target)) {
      if (!unresolved.has(target)) unresolved.set(target, []);
      unresolved.get(target).push(p.route);
    }
  }
}

// Sitemap entries with no source file behind them.
const phantomSitemap = [...sitemap.keys()].filter((r) => !byRoute.has(r));

// ---------------------------------------------------------------------------
// Emit
// ---------------------------------------------------------------------------

fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true });
fs.mkdirSync(path.join(ROOT, 'reports'), { recursive: true });

const out = {
  generatedBy: 'scripts/build-page-index.mjs',
  generatedFrom: {
    commit: execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT }).toString().trim(),
    allowListSource: 'netlify/edge-functions/publish-gate.ts',
  },
  allowHtml: [...ALLOW_HTML].sort(),
  llmsTxtRoutes: [...llmsRoutes].sort(),
  robotsTxtDisallow: robotsDisallow,
  totals: {
    routes: pages.length,
    indexable: pages.filter((p) => p.class === 'indexable').length,
    sitemapEntries: sitemap.size,
    phantomSitemapEntries: phantomSitemap,
    unresolvedInternalLinkTargets: Object.fromEntries(unresolved),
  },
  pages,
};

fs.writeFileSync(path.join(ROOT, 'data/pages.json'), JSON.stringify(out, null, 2) + '\n');

const COLS = [
  'route', 'sourceFile', 'class', 'title', 'titleLength', 'descriptionLength',
  'canonicalSelfReferencing', 'h1Count', 'headingSkips', 'jsonLd', 'internalOut',
  'inboundInternalLinks', 'externalOut', 'wordCount', 'inSitemap', 'sitemapLastmod',
  'sitemapPriority', 'sitemapChangefreq', 'gitLastCommitDate', 'lastmodMatchesGit',
  'inNetlifyAllow', 'inLlmsTxt', 'robotsDirective', 'noindex',
];
const csvCell = (v) => {
  const s = Array.isArray(v) ? v.join('; ') : v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
const rows = pages.map((p) =>
  COLS.map((c) => {
    switch (c) {
      case 'internalOut': return csvCell(p.internalLinksOut.length);
      case 'externalOut': return csvCell(p.externalLinksOut.length);
      case 'headingSkips': return csvCell(p.headingSkips.length);
      case 'jsonLd': return csvCell(p.jsonLd);
      default: return csvCell(p[c]);
    }
  }).join(',')
);
fs.writeFileSync(
  path.join(ROOT, 'reports/page-inventory.csv'),
  [COLS.join(','), ...rows].join('\n') + '\n'
);

console.log(`data/pages.json          ${pages.length} routes`);
console.log(`reports/page-inventory.csv`);
