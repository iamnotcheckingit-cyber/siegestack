/**
 * publish-gate — deny-by-default for the published surface.
 *
 * WHY THIS EXISTS
 * ---------------
 * `publish = "."` makes the repository root the web root, so every committed
 * file is served unless something says otherwise. That is how MAIL.md and
 * DNS-SNAPSHOT.md — operational documentation, authoritative and current —
 * came to be downloadable from the domain. Nobody decided it; the publish
 * directory did.
 *
 * The first fix was a list of names. A name list only blocks what someone
 * thought of, and the next file dropped in the root re-opens the question
 * silently. The second attempt tried to express classes with redirect globs
 * (`/*.md`, `/package*.json`) — Netlify ignores those, because a splat may only
 * END a path segment, so both rules deployed, neither ever ran, and MAIL.md
 * kept returning 200 while the config looked correct.
 *
 * This inverts it. Nothing is served unless it is on a list here.
 *
 * WHY AN EDGE FUNCTION RATHER THAN A CATCH-ALL REDIRECT
 * ----------------------------------------------------
 * A forced `/* -> /404.html` catch-all is the only way redirects can express
 * deny-by-default, and it matches every asset too — favicons, the service
 * workers, the manifests, robots.txt, the sitemap. Allowing those back requires
 * a self-referential 200 rewrite per file, which is unpredictable, and a broad
 * rule matching ahead of a specific one is precisely what 404'd the best page on
 * this site in d0aa04a. A gate that can enumerate is safer than a rule that has
 * to be tricked into exceptions.
 *
 * THE ASYMMETRY IS DELIBERATE
 * ---------------------------
 * Media extensions are allowed anywhere; documents and code are not. Adding an
 * image should not require editing this file, because an image nobody
 * allowlisted 404s in a way that is easy to miss and harmless to permit. Adding
 * a .md, .mjs, .json or .txt SHOULD require editing this file, because that is
 * the class that leaked. The failure modes are not symmetric, so the rules are
 * not either.
 *
 * IT FAILS OPEN. If anything in here throws, the request passes through. A gate
 * on `/*` that fails closed is a sitewide outage triggered by its own bug, and
 * the thing it protects against is embarrassment rather than compromise — the
 * repository is public on GitHub either way. Serving a document by accident is
 * strictly better than serving nothing at all.
 */

// Extensionless routes and root files that must resolve. Pretty URLs, not the
// .html files behind them: the edge runs on the path as requested, before the
// rewrite engine turns /prophet-21 into /prophet-21.html.
const ALLOW_EXACT = new Set([
  "/",
  // Pages in the sitemap
  "/about", "/contact", "/case-studies", "/insights", "/prophet-21",
  "/operations-modernization", "/etl-showcase", "/erp-report-slow-month-to-date",
  "/sql-server-erp-performance", "/working-with-claude", "/working-with-claude-blog",
  "/delivery-config-audit", "/privacy-policy",
  // Reachable on purpose, deliberately not in the sitemap
  "/audit",                    // the audit report, linked from /delivery-config-audit
  "/consultant-expertise",     // noindex intake form
  "/jesse", "/nicole",         // PIN-gated private threads
  "/secret",                   // browser-side encrypted messages
  "/epicor-p21-kinetic-reporting",   // 301 to /prophet-21; must reach the redirect
  // Crawl and citation layer
  "/robots.txt", "/sitemap.xml", "/llms.txt", "/llms-full.txt",
  // Named scripts and manifests. Everything else with these extensions is denied.
  "/consultant-form.js", "/jesse-sw.js", "/nicole-sw.js",
  "/jesse-manifest.json", "/nicole-manifest.json",
]);

// Directory prefixes. The three page directories, plus the function surfaces,
// which must never be gated here — they carry their own auth and validation.
const ALLOW_PREFIX = [
  "/services/",
  "/case-studies/",
  "/industries/",
  "/api/",
  "/.netlify/",
];

// Media only. Adding an image must not require editing this file.
const ALLOW_EXT = /\.(?:html|svg|png|jpe?g|webp|avif|gif|ico|woff2?)$/i;

// Denied even though they match an allowed pattern above. `.html` is broadly
// allowed so that direct .html hits reach their 301 and the Search Console
// verification file resolves — these are the paths that must not ride along.
const DENY_PREFIX = ["/docs/", "/scripts/", "/netlify/", "/private-files"];

/**
 * Pure decision. Kept separate from execution so that "fail open" means what it
 * says: only THIS can fail open, by returning true. An earlier version wrapped
 * context.next() in the same try block, so when the downstream chain threw, the
 * catch called context.next() again — the exact call that had just failed — and
 * the second throw escaped anyway. Fail-open that only works when nothing is
 * wrong is not fail-open. Caught by scripts/test/publish-gate.test.mjs before
 * this ever deployed.
 */
function isAllowed(rawPath: string): boolean {
  let path = rawPath;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    // Malformed percent-encoding. Judge the raw form rather than giving up.
  }
  const lower = path.toLowerCase();

  if (DENY_PREFIX.some((p) => lower.startsWith(p))) return false;

  return (
    ALLOW_EXACT.has(path) ||
    ALLOW_EXACT.has(path.replace(/\/$/, "")) ||
    ALLOW_PREFIX.some((p) => path.startsWith(p)) ||
    ALLOW_EXT.test(path)
  );
}

export default async (request: Request, context: any) => {
  let allowed = true;
  let path = "";
  try {
    path = new URL(request.url).pathname;
    allowed = isAllowed(path);
  } catch (err) {
    // Fail open, loudly. A gate that 404s the site because of its own bug is a
    // worse outcome than the leak it prevents.
    console.error(JSON.stringify({
      event: "PUBLISH_GATE_ERROR",
      detail: String((err as Error)?.message || err).slice(0, 200),
    }));
    allowed = true;
  }

  if (!allowed) {
    console.log(JSON.stringify({ event: "PUBLISH_GATE_DENIED", path }));
    return notFound();
  }

  // Deliberately OUTSIDE the try. If the downstream chain fails that is not
  // this gate's failure to absorb, and retrying it here would just throw again.
  return context.next();
};

function notFound(_context?: unknown) {
  // A plain response rather than a rewrite to /404.html. Rewriting would mean
  // relying on edge-API behaviour this file cannot test before deploying, and
  // the whole point of the gate is to be predictable; a denied path returning a
  // bare 404 is indistinguishable from any other missing path, which is all
  // that is required of it.
  return new Response("Not Found\n", {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
      "x-content-type-options": "nosniff",
    },
  });
}

// Excluded rather than allowlisted: the function endpoints carry their own auth
// and validation, and there is no reason to spend edge CPU on every call to
// them. /api/* is rewritten to /.netlify/functions/* downstream, so it still
// passes through ALLOW_PREFIX above.
export const config = {
  path: "/*",
  excludedPath: ["/.netlify/*"],
};
