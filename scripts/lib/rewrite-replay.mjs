/**
 * Replays netlify.toml's 200-rewrite table, from that file's own source.
 *
 * WHY THIS EXISTS, and it is a correction rather than a feature.
 *
 * SS-106 replayed publish-gate.ts and then asked, separately, whether the file
 * existed on disk. A path served by a 200-rewrite passes the first question and
 * fails the second: /favicon.ico is allowed by the gate, has never existed as a
 * file, and has ALWAYS returned 200 — netlify.toml rewrites it. The rule
 * reported a 404 on 23 pages that were not 404ing, and the remedy applied on
 * the strength of that report happened to be correct for an entirely different
 * reason. A wrong diagnosis with a right fix is still a wrong diagnosis, and it
 * is precisely what /delivery-config-audit is about — except there the config
 * was never read, and here it was read and misread.
 *
 * There are six of these: /favicon.ico, four apple-touch-icon paths, and /audit
 * (which rewrites into /docs/, a directory the gate denies — the edge judges the
 * REQUESTED path, before the rewrite engine, so the deny never applies).
 *
 * THE POINT IS TO REPLAY, NOT TO RE-IMPLEMENT. That is what made the gate check
 * trustworthy and it is the only thing that keeps this honest: a second copy of
 * the rewrite table drifts, and drift here produces exactly the false positive
 * that got 23 pages edited.
 *
 * SCOPE. status = 200 rewrites only. A 301 is a different question — the browser
 * sees the redirect and asks again — and conflating them would let a broken
 * target hide behind a redirect chain.
 */
import fs from 'node:fs';
import path from 'node:path';

export const TOML_FILE = 'netlify.toml';

export function parseRewrites(root = '.') {
  const file = path.join(root, TOML_FILE);
  if (!fs.existsSync(file)) return { ok: false, why: `${TOML_FILE} is not present.` };
  const toml = fs.readFileSync(file, 'utf8');

  const map = new Map();
  for (const m of toml.matchAll(
    /\[\[redirects\]\][^[]*?from\s*=\s*"([^"]+)"[^[]*?to\s*=\s*"([^"]+)"[^[]*?status\s*=\s*(\d+)/g,
  )) {
    const [, from, to, status] = m;
    if (status !== '200') continue;
    if (from.includes('*') || from.includes(':')) continue; // splats and placeholders are not resolvable here
    map.set(from, to);
  }

  if (!map.size) {
    return { ok: false, why: `Found no status = 200 rewrites in ${TOML_FILE}. The table moved or the parse is wrong, and treating that as "no rewrites" would report every rewritten path as missing.` };
  }

  /**
   * The path a request for `p` actually serves. One hop: this site has no
   * rewrite whose target is itself a rewrite source, and following chains
   * blindly would loop.
   */
  const resolve = (p) => map.get(p) ?? p;

  return { ok: true, resolve, map };
}
