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
 * this site in 19ea665. A gate that can enumerate is safer than a rule that has
 * to be tricked into exceptions.
 *
 * THE ASYMMETRY IS DELIBERATE
 * ---------------------------
 * Media extensions are allowed anywhere; documents, code and PAGES are not.
 * Adding an image should not require editing this file, because an image nobody
 * allowlisted 404s in a way that is easy to miss and harmless to permit. Adding
 * a .md, .mjs, .json, .txt or .html SHOULD require editing this file, because
 * those are the classes that leak. The failure modes are not symmetric, so the
 * rules are not either.
 *
 * `.html` was on the wrong side of that line until 2026-08-20. It was allowed by
 * extension, so every stray, orphaned or draft page in the publish directory was
 * public, and the allow-list below — the thing anyone would read to check —
 * played no part in the decision. ALLOW_HTML is now the only authority for it.
 *
 * IT FAILS OPEN. If anything in here throws, the request passes through. A gate
 * on `/*` that fails closed is a sitewide outage triggered by its own bug, and
 * the thing it protects against is embarrassment rather than compromise — the
 * repository is public on GitHub either way. Serving a document by accident is
 * strictly better than serving nothing at all.
 */

// EVERY PAGE THIS SITE SERVES, as its canonical route. This list is the SOLE
// authority for HTML — there is no longer an extension fallback behind it, so a
// page absent from here is not served, full stop.
//
// It used to be shorter, and `.html` was allowed by extension instead. That
// meant deny-by-default denied nothing for the one file type that gets served
// as a page: any stray, orphaned, draft or forgotten .html in the publish
// directory was public, and no amount of reading this file would show it,
// because the allow-list was not what decided. Replaying isAllowed() could not
// surface the drift either — it answered "yes" for anything ending in .html.
//
// Kept in the same order as sitemap.xml so the two can be read side by side.
// scripts/validate-pages.mjs (SS-101, SS-105) asserts this set equals the set
// of .html files in the repository. Adding a page means adding it here.
const ALLOW_HTML = new Set([
  // The 27 routes in sitemap.xml
  "/",
  "/operations-modernization", "/etl-showcase", "/working-with-claude-blog",
  "/working-with-claude", "/case-studies", "/erp-report-slow-month-to-date",
  "/prophet-21", "/prophet-21-upgrade-reporting", "/delivery-config-audit",
  "/sql-server-erp-performance", "/insights", "/about", "/contact",
  "/services/erp-integration", "/services/etl-data-pipelines",
  "/services/bi-dashboards", "/services/automated-reporting",
  "/services/performance-tuning", "/services/security-access-audit",
  "/case-studies/kpi-console", "/case-studies/month-to-date-timeout",
  "/case-studies/label-service", "/industries/distribution",
  "/label-tool", "/privacy-policy", "/corrections",
  // Served on purpose, deliberately absent from the sitemap
  "/consultant-expertise",     // noindex intake form
  "/jesse", "/nicole",         // PIN-gated private threads
  "/secret",                   // browser-side encrypted messages
  // Served at their own .html path, having no pretty-URL rewrite
  "/404.html",
  "/googleeaab9608ff5e7c66.html",   // Search Console; a 404 here unverifies the domain
]);

// Paths that exist only to REACH a redirect, and serve nothing themselves.
// Denying these would not hide a page, it would delete a 301: the edge runs on
// the path as requested, before the rewrite engine, so a denied /about.html
// never reaches the rule that would have sent it to /about. The equity-carrying
// P21 redirects are the ones that matter here — see the note in netlify.toml
// about 19ea665, where a rule matching ahead of another 404'd the best page on
// the site. Every `<route>.html` source is derived from ALLOW_HTML below rather
// than listed, so the two cannot drift; only the odd ones out live here.
const ALLOW_REDIRECT_SOURCE = new Set([
  "/epicor-p21-kinetic-reporting",        // 301 to /prophet-21
  "/epicor-p21-kinetic-reporting.html",   // 301 to /prophet-21
  "/index.html",                          // pretty_urls sends it to /
]);

// Non-HTML files that must resolve. Everything else with these extensions is
// denied, which is the point: adding a .js, .json or .txt is a decision.
const ALLOW_EXACT = new Set([
  "/audit",                    // the audit report, linked from /delivery-config-audit
  // Crawl and citation layer
  "/robots.txt", "/sitemap.xml", "/llms.txt", "/llms-full.txt",
  // Named scripts and manifests
  "/consultant-form.js", "/jesse-sw.js", "/nicole-sw.js",
  "/label-tool-xlsx.js",       // SheetJS, fetched on demand by /label-tool
  "/jesse-manifest.json", "/nicole-manifest.json",
  // IndexNow key file. Bing fetches this exact path to verify submissions;
  // .txt is denied by default, so without this line the key 404s and every
  // IndexNow submission comes back 403 "key not found".
  "/0374ea43379b487e8fa886bf520fbdcc.txt",
  // The Open Font License text and the notice naming each family. Shipping
  // these is what OFL-1.1 requires in return for self-hosting the fonts, and
  // an obligation discharged into a directory nobody can reach is not
  // discharged. They were DENIED for one commit -- .txt is denied by default,
  // ALLOW_EXT is media-only, and ALLOW_ASSET_CSS has no slash in its character
  // class so nothing under /assets/fonts/ matched it either.
  //
  // Listed individually rather than by prefix because the filenames are stable
  // (no content hash: a licence does not change) and because this file says
  // adding a .txt is a decision. Two decisions, visible in a diff.
  "/assets/fonts/OFL.txt",
  "/assets/fonts/NOTICE.txt",
]);

// The function surfaces, which must never be gated here — they carry their own
// auth and validation. The three page directories used to be listed too; they
// are gone because ALLOW_HTML now names those pages individually, and a bare
// "/services/" prefix would have allowed /services/notes.md straight past the
// document rules.
const ALLOW_PREFIX = [
  "/api/",
  "/.netlify/",
];

// Stylesheets, and ONLY from /assets/.
//
// They carry a content hash in the filename — see the header of
// assets/site.*.css and the /*.css note in netlify.toml — so listing each one
// here would mean editing this file on every CSS change, and forgetting would
// 404 the stylesheet and render the entire site unstyled. Scoping to one
// directory keeps "adding a .css is a decision" true, because the DIRECTORY is
// the decision: a stray .css anywhere else is still denied, and anything under
// /assets/ that is not a stylesheet is still denied.
//
// No slashes in the character class, so /assets/sub/x.css does not match and
// neither does a traversal that decodes to one.
const ALLOW_ASSET_CSS = /^\/assets\/[a-z0-9._-]+\.css$/i;

// Media only. Adding an image must not require editing this file; adding a page
// must. `html` is deliberately NOT in this list — that was the hole.
const ALLOW_EXT = /\.(?:svg|png|jpe?g|webp|avif|gif|ico|woff2?)$/i;

// Denied even where something above would otherwise allow them. /data/ and
// /reports/ are new: the build now generates data/pages.json and
// reports/page-inventory.csv into the publish directory, and neither is site
// content. They are already denied by having no rule that allows them; this is
// belt and braces, and it documents the intent.
const DENY_PREFIX = [
  "/docs/", "/scripts/", "/netlify/", "/private-files", "/data/", "/reports/",
];

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
  const bare = path.replace(/\/$/, "");

  if (DENY_PREFIX.some((p) => lower.startsWith(p))) return false;

  // HTML is decided by ALLOW_HTML and nothing else. This branch RETURNS, so a
  // .html path can never fall through to the prefix or extension rules below —
  // which is the whole of the fix. Do not add an `||` to the end of it.
  if (lower.endsWith(".html")) {
    return (
      ALLOW_HTML.has(path) ||
      ALLOW_REDIRECT_SOURCE.has(path) ||
      // /about.html exists only to 301 to /about, so it is allowed exactly when
      // /about is. Derived, not listed, so adding a page cannot forget it.
      ALLOW_HTML.has(path.slice(0, -".html".length))
    );
  }

  return (
    ALLOW_HTML.has(path) ||
    ALLOW_HTML.has(bare) ||
    ALLOW_EXACT.has(path) ||
    ALLOW_EXACT.has(bare) ||
    ALLOW_REDIRECT_SOURCE.has(path) ||
    ALLOW_PREFIX.some((p) => path.startsWith(p)) ||
    ALLOW_EXT.test(path) ||
    ALLOW_ASSET_CSS.test(path)
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
