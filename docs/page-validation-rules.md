# Page validation rules

`npm run validate:pages` — rebuilds `data/pages.json` from HEAD, then checks every rule below.
Errors exit non-zero and fail both CI and the Netlify deploy. Warnings print and exit zero.

The validator never parses HTML and never writes. It reads `data/pages.json`, produced by
`scripts/build-page-index.mjs`. One extractor, one model, one set of blind spots — two
scripts parsing the same HTML with two slightly different regexes is a bug generator.

**Scope classes** (assigned in `build-page-index.mjs`):

| Class | Count | What it is |
|---|---|---|
| `indexable` | 26 | In `sitemap.xml` |
| `served-noindex` | 4 | `/consultant-expertise`, `/jesse`, `/nicole`, `/secret` |
| `error-page` | 1 | `/404.html` |
| `verification` | 1 | `/googleeaab9608ff5e7c66.html` |

**Suppression.** `data/validation-suppressions.json` turns one rule off for one route.
`reason` is required and validated by SS-001. There is no way to disable a rule globally
short of deleting it, which at least shows up in a diff.

---

## SS-0xx — the validator's own inputs

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-001** | error | suppression file | A suppression with no `reason`, no `ruleId`/`route`, or no `addedOn` date | An unexplained suppression is indistinguishable from a bug someone got tired of. The date is so an old one can be found and re-argued. |
| **SS-002** | error | `data/pages.json` | The page model was generated from a different commit, or HTML files are dirty relative to HEAD | Every rule below reads the model. Validating a stale snapshot produces a green run that describes a tree nobody is shipping. |

## SS-1xx — route parity

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-101** | error | all 32 | Drift in **both** directions between filesystem HTML routes, `ALLOW_HTML` in `publish-gate.ts`, and `sitemap ∪ served-noindex ∪ error-page ∪ verification` | **Phase 1 finding #7.** `inNetlifyAllow` was `true` for all 32 routes — including `/404.html` and the Google verification file — because `.html` was allowed by extension. Every page looked allow-listed whether or not it was on the list. This rule compares against `ALLOW_HTML` **as a set**, never against `isAllowed()`: replaying the decision function answered "allowed" for anything ending `.html` without consulting the list, so it could not detect list drift even in principle. |
| **SS-102** | error | indexable | A sitemap route missing from `llms.txt`, or an `llms.txt` route absent from the sitemap | `llms.txt` is hand-maintained and has gone stale twice: its route count was wrong on two occasions four days apart, and twelve pages added on 2026-08-15 were absent from it for a day. `/audit`, `/llms.txt`, `/llms-full.txt`, `/robots.txt` and `/sitemap.xml` are exempted as legitimate non-page references. |
| **SS-103** | error | indexable | A sitemap route that `robots.txt` disallows | The two files giving crawlers opposite instructions. |
| **SS-104** | error | all 32 | `inSitemap && noindex` | **Phase 1 finding #2.** `/privacy-policy` was in the sitemap and served `noindex, follow` at the same time, with 26 inbound internal links — every footer on the site. The sitemap asked for indexing and the page refused, and nothing anywhere compared the two. Fixed in `fa0a9b0`; this rule is what stops it recurring. |
| **SS-105** | error | all 32 | An `.html` file in the publish directory absent from `ALLOW_HTML` | Standing guard on `0df77b5`. Before that commit a stray, orphaned or draft `.html` left in the publish directory was public, and no amount of reading the config would show it. |

## SS-2xx — freshness

Scope excludes `verification` (the Google file's 2026-01-20 date is correct and permanent)
and `error-page`.

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-201** | error | indexable | `sitemapLastmod` ≠ the date of the newest commit touching `sourceFile`, **excluding** SHAs in `data/freshness-exclusions.json` | **Phase 1 finding: 24 of 26 routes drifted.** Raw git dates are unusable on their own — commit `b1f31e9` added a `<main>` landmark to all 32 files in one pass and reset every date to 2026-08-20, so a rule keyed to git alone reports 26 content changes that did not happen, which trains you to ignore it. The exclusion list is what makes the signal real. A SHA belongs there only if it changed no published copy at all. |
| **SS-202** | error | indexable | `lastmod` in the future | A date nobody can have measured. |
| **SS-203** | error (exit 2) | the validator itself | `--fix`, `--write`, `--write-lastmod`, `--repair` | Not a check on the site; a check on this file. Auto-stamping `lastmod` on build makes every page permanently "fresh" and deletes the only signal SS-201 carries. The validator refuses to grow a write mode. |

## SS-3xx — metadata

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-301** | error | indexable | Missing, duplicate, >60 char, or non-brand-suffixed `<title>` | Titles over 60 chars truncate in results; duplicates make two pages compete for the same query. Brand suffix is `\| SiegeStack`. |
| **SS-302** | error | indexable | Missing, duplicate, outside 120–160 chars, or truncated mid-thought | A description cut off mid-word reads as neglect in the one place a stranger judges the page. |
| **SS-303** | error on indexable, warning elsewhere | all 32 | `h1` count ≠ 1 | Warning off the indexable surface because `/jesse`, `/nicole` and the verification file have no business having one. |
| **SS-304** | error on indexable, warning elsewhere | all 32 | Heading level skipping a rank (h1→h4) | A screen-reader outline with a missing level is a broken table of contents. |
| **SS-305** | error | indexable | Canonical missing, relative, http, or pointing elsewhere | Cross-canonicals are possible but must be argued for; none exist today. |
| **SS-306** | error | indexable | `og:title` / `og:description` differing from the page's own, without a declaration in `data/og-overrides.json` | Deliberate social copy and silent drift look identical in a diff. Declaring the divergence is what tells them apart. Seeded 2026-08-20 with the 9 title and 11 description divergences that already existed, all marked `TODO(pappy)`. |

## SS-4xx — link integrity

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-401** | error | all 32 | An internal link resolving to nothing | Non-HTML publishable targets are declared in `data/non-html-routes.json` — `/audit` rewrites to a `.md` and is not a broken link. |
| **SS-402** | error | indexable | An indexable page linking to a `noindex` page | Passes crawlers to a dead end. Currently passes because the four `served-noindex` routes are linked from nowhere, which is also how `/jesse` and `/nicole` stay private. |
| **SS-403** | warning | indexable | In the sitemap with zero inbound internal links | Orphan pages. Warning, not error — a new page is legitimately orphaned for one commit. |
| **SS-404** | warning | all 32 | An internal link written as `/about.html` that needs a 301 hop | The link graph resolves the hop so counts stay honest; this rule reports it so the markup can be fixed. |

## SS-5xx — structured data

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-501** | error | all 32 | JSON-LD that does not parse, or an `@type` outside the allowlist | One malformed block means no consumer reads any of the page's structured data. |
| **SS-502** | error | all 32 | The same `Organization` / `Person` / `ProfessionalService` asserting different values for the same identity field | Compared on the **intersection** of fields, not whole nodes: most Organization nodes here are nested `publisher` references carrying only a name, and demanding a byte-identical node reports twenty findings that all say "a stub is shorter than the full record". A field present twice with two values is a contradiction; a field present once is a reference. |
| **SS-503** | error | all 32 | `aggregateRating`, `Review`, `Rating`, `ratingValue`, `reviewCount` | There is no legitimate source for rating markup on this site. Currently zero occurrences; the rule exists so that stays true. |
| **SS-504** | warning | indexable | No JSON-LD, and not listed in `data/jsonld-exempt.json` | Legal pages are exempt — there is no schema.org type that says anything true about a privacy policy, and inventing one is worse than the absence. |

## SS-6xx — content policy

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-601** | error unregistered / error on new instances / warning on `TODO` basis | indexable | `\d+%`, `\d+x`, "faster", "reduced", "improved", "cut" without an entry in `data/claims-registry.json` | The site's editorial rule is that no percentage or performance claim is published without a measured baseline. `occurrences` is load-bearing: the rule errors when a page carries **more** instances of a token than are registered, so adding a second unmeasured "27%" beside a registered one is caught. It is not matched on surrounding text, because a typo fix next to a claim should not turn the build red. Scanning `textContent` rather than HTML is what keeps it usable — an unstripped `<style>` block yields forty flex-basis `50%` false hits on this site alone. |
| **SS-602** | error, or **SKIPPED** | all output | Employer, client, facility, person or contract identifiers anywhere in page text, JSON-LD, `llms.txt`, `llms-full.txt` or `sitemap.xml` | Terms load from `.denylist.local.json`, which is gitignored. The terms are never committed and are never printed in output: this repository is public and CI logs are public, so a committed denylist would publish exactly the strings it exists to keep off the site — the same failure as a `robots.txt` `Disallow` advertising a private URL, which `netlify.toml` already refuses to do for `/jesse`. **Reports SKIPPED when the file is absent, never PASSED**: a policy check that silently passes when its input is missing is worse than no check. |
| **SS-603** | warning | indexable | "best-in-class", "world-class", "synergy", "cutting-edge", "seamless integration", "game-changing", "industry-leading", "turnkey solution", "paradigm shift", and eleven more | Stock marketing phrasing. Warning — it is a house-style matter, not a correctness one. |

## SS-7xx — hygiene

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-701** | warning, currently **SKIPPED** | indexable | `<img>` with no `alt`, empty `alt`, or `alt` duplicating adjacent visible text verbatim | No indexable page has an `<img>`: every graphic on this site is inline SVG or CSS, and the only two `<img>` tags live inside a `<script>` template literal on `/label-tool`. The rule reports SKIPPED rather than passing, because a vacuous pass is not evidence of good alt text. |

---

## Wiring

| Where | Command | Effect |
|---|---|---|
| CI | `.github/workflows/validate.yml` → `npm run validate:pages` | Required check. `fetch-depth: 0` — a shallow clone has no history for SS-201 to walk, and the rule would report SKIPPED while the check went green. |
| CI | same workflow | Also fails if the committed `data/pages.json`, `reports/page-inventory.csv` or `llms-full.txt` differ from what HEAD generates. |
| Netlify | `netlify.toml` → `command = "npm run netlify:build"` | `build:llms` → `validate:pages` → `test`. A non-zero exit fails the **deploy**, not just the merge. This site had no build command before 2026-08-20. |
