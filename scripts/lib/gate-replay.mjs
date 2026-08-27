/**
 * Replays netlify/edge-functions/publish-gate.ts against a path, from that
 * file's own source.
 *
 * WHY REPLAY RATHER THAN RE-IMPLEMENT. The gate is deny-by-default and its
 * allow-lists change. A second copy of the rules in the validator would drift,
 * and drift here means the validator says a file is servable while production
 * 404s it — the exact failure this module exists to catch, one level up.
 * scripts/build-page-index.mjs already replays isAllowed() for `inNetlifyAllow`;
 * this is the same idea extracted so a rule can use it too.
 *
 * IT REFUSES RATHER THAN GUESSING. If a construct it needs is missing from the
 * gate, `parseGate` returns { ok: false, why }. A replay that silently loses one
 * of the allow-lists would answer "denied" for things that are served, or
 * "allowed" for things that are not, and either way it would be confident.
 *
 * TWO REAL MISSES MOTIVATED THIS, one commit apart, and they were the same bug
 * wearing different extensions:
 *
 *   .css  Phase 5 added /assets/site.<hash>.css. ALLOW_EXT is media-only, so
 *         all three stylesheets would have 404'd and every page would have
 *         rendered unstyled. Caught before shipping.
 *   .txt  Phase 6 added assets/fonts/OFL.txt as an Open Font License
 *         obligation. .txt is denied by default. The licence existed in the
 *         repository and was unreachable on the web. NOT caught before
 *         shipping, because the rule written after the first miss only looked
 *         at <link rel="stylesheet">.
 *
 * So this answers for ANY path, and SS-106 asks it about every same-origin URL
 * a page or a stylesheet references.
 */
import fs from 'node:fs';
import path from 'node:path';

export const GATE_FILE = 'netlify/edge-functions/publish-gate.ts';

const setLiteral = (src, name) => {
  const m = src.match(new RegExp(`const ${name} = new Set\\(\\[([\\s\\S]*?)\\n\\]\\)`));
  if (!m) return null;
  return new Set([...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]));
};

const arrayLiteral = (src, name) => {
  const m = src.match(new RegExp(`const ${name} = \\[([\\s\\S]*?)\\n\\]`));
  if (!m) return null;
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
};

const regexLiteral = (src, name) => {
  const m = src.match(new RegExp(`const ${name} = (/[^;]*/[a-z]*);`));
  if (!m) return null;
  const body = m[1].slice(1, m[1].lastIndexOf('/'));
  const flags = m[1].slice(m[1].lastIndexOf('/') + 1);
  try { return new RegExp(body, flags); } catch { return null; }
};

export function parseGate(root = '.') {
  const file = path.join(root, GATE_FILE);
  if (!fs.existsSync(file)) return { ok: false, why: `${GATE_FILE} is not present.` };
  const src = fs.readFileSync(file, 'utf8');

  const parts = {
    ALLOW_HTML: setLiteral(src, 'ALLOW_HTML'),
    ALLOW_EXACT: setLiteral(src, 'ALLOW_EXACT'),
    ALLOW_REDIRECT_SOURCE: setLiteral(src, 'ALLOW_REDIRECT_SOURCE'),
    ALLOW_PREFIX: arrayLiteral(src, 'ALLOW_PREFIX'),
    DENY_PREFIX: arrayLiteral(src, 'DENY_PREFIX'),
    ALLOW_EXT: regexLiteral(src, 'ALLOW_EXT'),
    ALLOW_ASSET_CSS: regexLiteral(src, 'ALLOW_ASSET_CSS'),
  };
  const missing = Object.entries(parts).filter(([, v]) => v == null).map(([k]) => k);
  // ALLOW_REDIRECT_SOURCE is optional only in the sense that it may be spelled
  // differently; everything else is load-bearing and its absence means the
  // replay is not describing the deployed gate.
  const required = missing.filter((k) => k !== 'ALLOW_REDIRECT_SOURCE');
  if (required.length) {
    return { ok: false, why: `Could not read ${required.join(', ')} out of ${GATE_FILE}. The replay would be answering from an incomplete copy of the rules.` };
  }
  if (!parts.ALLOW_REDIRECT_SOURCE) parts.ALLOW_REDIRECT_SOURCE = new Set();

  const isAllowed = (rawPath) => {
    let p = rawPath;
    try { p = decodeURIComponent(rawPath); } catch { /* judge the raw form */ }
    const lower = p.toLowerCase();
    const bare = p.replace(/\/$/, '');

    if (parts.DENY_PREFIX.some((d) => lower.startsWith(d))) return false;
    if (lower.endsWith('.html')) {
      return parts.ALLOW_HTML.has(p)
        || parts.ALLOW_REDIRECT_SOURCE.has(p)
        || parts.ALLOW_HTML.has(p.slice(0, -'.html'.length));
    }
    return parts.ALLOW_HTML.has(p)
      || parts.ALLOW_HTML.has(bare)
      || parts.ALLOW_EXACT.has(p)
      || parts.ALLOW_EXACT.has(bare)
      || parts.ALLOW_REDIRECT_SOURCE.has(p)
      || parts.ALLOW_PREFIX.some((x) => p.startsWith(x))
      || parts.ALLOW_EXT.test(p)
      || parts.ALLOW_ASSET_CSS.test(p);
  };

  return { ok: true, isAllowed, parts };
}
