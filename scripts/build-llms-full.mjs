/**
 * Builds /llms-full.txt from the published pages.
 *
 *   node scripts/build-llms-full.mjs
 *
 * WHY THIS IS GENERATED AND NOT WRITTEN
 * ------------------------------------
 * llms.txt is hand-maintained and went stale: the 2026-08-10 revision updated
 * the slide count in "all ten places", every one of which was inside
 * working-with-claude.html, and llms.txt -- an eleventh place, in a separate
 * file -- kept saying 33 for five days. A full-text file maintained by hand
 * would rot the same way, only bigger and less visibly. Re-run this after any
 * content change and the problem cannot arise.
 *
 * WHAT IS DELIBERATELY EXCLUDED
 * -----------------------------
 * Only pages that are actually indexable. /jesse, /nicole and /secret are
 * private or noindex, and /consultant-expertise is a noindex intake form.
 * Publishing them here would hand a crawler exactly what the noindex header
 * exists to withhold. PAGES below is an allowlist for that reason -- a glob
 * would silently pick up the next private page someone adds.
 *
 * The deck carries a visually hidden <article> that mirrors its slides for
 * crawlers. Taking both would duplicate the entire deck, so the mirror is
 * dropped and the slides are kept, being the fuller of the two.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Ordered as a reader should meet them, not alphabetically.
const PAGES = [
  ['index.html', '/', 'SiegeStack — custom integrations, dashboards and apps'],
  ['case-studies.html', '/case-studies', 'Case studies'],
  ['erp-report-slow-month-to-date.html', '/erp-report-slow-month-to-date', 'Why your ERP report is fast on Today and times out on month-to-date'],
  ['sql-server-erp-performance.html', '/sql-server-erp-performance', 'SQL Server performance for ERP reporting'],
  ['prophet-21.html', '/prophet-21', 'Epicor Prophet 21 and Kinetic reporting and integration'],
  ['operations-modernization.html', '/operations-modernization', 'Operations modernization'],
  ['etl-showcase.html', '/etl-showcase', 'CRM and ERP integration showcase'],
  ['working-with-claude-blog.html', '/working-with-claude-blog', 'How to use Claude AI effectively'],
  ['working-with-claude.html', '/working-with-claude', 'Working with Claude — the slide deck'],
  ['insights.html', '/insights', 'Insights'],
  ['services/erp-integration.html', '/services/erp-integration', 'Service: ERP integration'],
  ['services/etl-data-pipelines.html', '/services/etl-data-pipelines', 'Service: ETL and data pipelines'],
  ['services/bi-dashboards.html', '/services/bi-dashboards', 'Service: BI dashboards'],
  ['services/automated-reporting.html', '/services/automated-reporting', 'Service: automated reporting'],
  ['services/performance-tuning.html', '/services/performance-tuning', 'Service: performance tuning'],
  ['services/security-access-audit.html', '/services/security-access-audit', 'Service: security and access audit'],
  ['industries/distribution.html', '/industries/distribution', 'For distributors'],
  ['case-studies/kpi-console.html', '/case-studies/kpi-console', 'Case study: KPI console'],
  ['case-studies/month-to-date-timeout.html', '/case-studies/month-to-date-timeout', 'Case study: month-to-date timeout'],
  ['case-studies/label-service.html', '/case-studies/label-service', 'Case study: label service'],
  ['about.html', '/about', 'About SiegeStack'],
  ['contact.html', '/contact', 'Contact'],
  ['privacy-policy.html', '/privacy-policy', 'Privacy policy'],
];

const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…',
  mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”',
  middot: '·', times: '×', rarr: '→', larr: '←', check: '✓', copy: '©',
  deg: '°', frac12: '½', eacute: 'é', uuml: 'ü',
};

function decode(s) {
  return s
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z][a-z0-9]*);/gi, (m, name) => ENTITIES[name] ?? ENTITIES[name.toLowerCase()] ?? m);
}

function extract(html, file) {
  let s = html;

  // Order matters: comments first, or a commented-out <script> confuses the
  // script strip below.
  s = s.replace(/<!--[\s\S]*?-->/g, '');
  s = s.replace(/<script[\s\S]*?<\/script>/gi, '');
  s = s.replace(/<style[\s\S]*?<\/style>/gi, '');
  s = s.replace(/<head[\s\S]*?<\/head>/gi, '');

  // Chrome that repeats on every page and carries no information.
  s = s.replace(/<nav[\s\S]*?<\/nav>/gi, '');
  s = s.replace(/<footer[\s\S]*?<\/footer>/gi, '');

  // The deck's hidden crawler mirror -- see the header comment.
  if (file === 'working-with-claude.html') {
    s = s.replace(/<article style="position:absolute;left:-99999px[\s\S]*?<\/article>/gi, '');
  }

  // Structure worth keeping, innermost first.
  s = s.replace(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_, __, t) => `**${t.trim()}**`);
  s = s.replace(/<(em|i)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_, __, t) => `*${t.trim()}*`);
  s = s.replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, (_, t) => `\`${t.trim()}\``);
  s = s.replace(/<a\b[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, (_, href, t) => {
    const text = t.replace(/<[^>]+>/g, '').trim();
    if (!text) return '';
    if (href.startsWith('#') || !href) return text;
    const abs = href.startsWith('/') ? `https://siegestack.com${href}` : href;
    return `[${text}](${abs})`;
  });

  s = s.replace(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi, (_, t) => `\n\n## ${t.replace(/<[^>]+>/g, '').trim()}\n`);
  s = s.replace(/<h2\b[^>]*>([\s\S]*?)<\/h2>/gi, (_, t) => `\n\n### ${t.replace(/<[^>]+>/g, '').trim()}\n`);
  s = s.replace(/<h3\b[^>]*>([\s\S]*?)<\/h3>/gi, (_, t) => `\n\n#### ${t.replace(/<[^>]+>/g, '').trim()}\n`);
  s = s.replace(/<h4\b[^>]*>([\s\S]*?)<\/h4>/gi, (_, t) => `\n\n##### ${t.replace(/<[^>]+>/g, '').trim()}\n`);

  s = s.replace(/<li\b[^>]*>([\s\S]*?)<\/li>/gi, (_, t) => `\n- ${t.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()}`);
  s = s.replace(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi, (_, t) => ` | ${t.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()}`);
  s = s.replace(/<\/tr>/gi, ' |\n');
  s = s.replace(/<\/(p|div|section|article|ul|ol|table|blockquote)>/gi, '\n\n');
  s = s.replace(/<br\s*\/?>/gi, '\n');

  s = s.replace(/<[^>]+>/g, '');
  s = decode(s);

  // Whitespace last, so the tag stripping above cannot leave ragged runs.
  s = s.replace(/[ \t]+/g, ' ');
  s = s.replace(/ *\n */g, '\n');
  s = s.replace(/\n{3,}/g, '\n\n');
  return s.trim();
}

const stamp = process.argv[2] || new Date().toISOString().slice(0, 10);

const header = `# SiegeStack — full text

Every indexable page on siegestack.com, in full, concatenated so it can be read
without crawling. Generated from the pages themselves by
scripts/build-llms-full.mjs; do not edit by hand, the next build overwrites it.

The short guide, and the terms under which this material should be cited, are at
https://siegestack.com/llms.txt — READ THAT FIRST. In particular: every figure
here comes from a single named engagement and is not a benchmark, no client or
employer is named anywhere or can be inferred, and where no baseline was
measured no percentage is published.

Private and noindex pages are deliberately absent.

Generated ${stamp}.

---
`;

const parts = [header];
let pages = 0;

for (const [file, url, title] of PAGES) {
  const full = path.join(ROOT, file);
  if (!fs.existsSync(full)) { console.error(`  MISSING: ${file}`); process.exitCode = 1; continue; }
  const body = extract(fs.readFileSync(full, 'utf8'), file);
  parts.push(`\n\n# ${title}\nhttps://siegestack.com${url}\n\n${body}\n\n---\n`);
  pages++;
  console.log(`  ${url.padEnd(34)} ${String(body.length).padStart(7)} chars`);
}

const out = parts.join('');
fs.writeFileSync(path.join(ROOT, 'llms-full.txt'), out);
console.log(`\n  ${pages} pages, ${out.length} chars (${(out.length / 1024).toFixed(0)} KB) -> llms-full.txt`);

// A private page reaching this file is the one failure that matters.
const FORBIDDEN = ['/jesse', '/nicole', '/secret', 'consultant-expertise', 'DADS_PIN', 'JESSES_PIN', 'NICOLES_PIN'];
const leaked = FORBIDDEN.filter((t) => out.includes(t));
if (leaked.length) {
  console.error(`\n  FATAL: private material reached llms-full.txt: ${leaked.join(', ')}`);
  process.exit(1);
}
console.log('  private-page check: clean');
