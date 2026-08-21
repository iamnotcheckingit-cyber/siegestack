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
| **SS-201** | error, or a **route-skip** | indexable | `sitemapLastmod` ≠ the date of the newest commit touching `sourceFile`, **excluding** SHAs in `data/freshness-exclusions.json` | **Phase 1 finding: 24 of 26 routes drifted.** Raw git dates are unusable on their own — commit `b1f31e9` added a `<main>` landmark to all 32 files in one pass and reset every date to 2026-08-20, so a rule keyed to git alone reports 26 content changes that did not happen, which trains you to ignore it. The exclusion list is what makes the signal real. A SHA belongs there only if it changed no published copy at all. |
| **SS-202** | error | indexable | `lastmod` in the future | A date nobody can have measured. |
| **SS-203** | error (exit 2) | the validator itself | `--fix`, `--write`, `--write-lastmod`, `--repair` | Not a check on the site; a check on this file. Auto-stamping `lastmod` on build makes every page permanently "fresh" and deletes the only signal SS-201 carries. The validator refuses to grow a write mode. |

### Route-skips, and why SS-201 grew them

A rule can be unable to check **one** route without being unable to check any. That state is a
**route-skip**: a warning naming the route and the reason, *plus* a count in the summary line.
A skipped route that produces no output is indistinguishable from a passing one.

```
0 error(s), 29 warning(s), 0 route-skip(s), 2 skipped, 0 suppressed
```

SS-201 has three non-checking states, and until 2026-08-21 two of them were invisible:

| State | Old behaviour | Now |
|---|---|---|
| `git-unavailable` — git threw | Skipped the whole rule | Unchanged. This is the **only** condition that disables the rule for every route. |
| `no-history` — the file has never been committed | **Returned the same sentinel as a broken git**, tripping `gitOk = false; break`. One new page disabled freshness for all 26 routes, mid-change, when the check matters most. `git log -- newfile` exits 0 with empty output, so `''.split(' ')` yielded an undefined date. | Route-skip. Expected exactly once, on the commit that introduces the page; the warning says so, and a route still skipping later means the file is not being committed. |
| `all-excluded` — every commit touching the file is in the exclusions list | Returned `null`, which `if (actual && …)` silently swallowed. The route was never checked and never said so. | Route-skip naming the route and pointing at the exclusions file. |

**A second rule was collaterally disabled.** SS-202 (future `lastmod`) lived inside the SS-201
loop, so the `break` on a git problem switched off the future-date check for every remaining
route too. It now runs in its own loop and needs no git at all.

**Proven, not assumed.** A staged-but-uncommitted page route-skipped itself while a
deliberately broken `lastmod` on `/about` still errored — under the old code `/about` would
have been silently unchecked. Excluding the four commits touching one page put **nine** routes
into `all-excluded`, all nine now reported; previously all nine passed silently.

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

## SS-6xx (continued) — the corrections practice

The site corrects published claims in public rather than editing them quietly. Until
2026-08-21 that rested entirely on remembering, and no rule referenced it. **None of these
can detect a correction that *should* have been written and was not** — that needs a
judgement about whether a fact changed. They check what is decidable from the tree.

Markers are read from attributes, never from the word "correction" in the prose: that word
is a QR error-correction level on `/label-tool` and a data-rights bullet on
`/privacy-policy`, and it is **absent from the retraction of the "roughly 20% of the time"
figure**, which never uses it.

| ID | Severity | Scope | Catches | Why it exists |
|---|---|---|---|---|
| **SS-604** | error | all 32 | A `data-correction` or `data-disclosure` slug present in the file's previous commit and missing now | The page states the principle itself: "deleting a correction along with its subject is how a record stops being a record." The disclosure half matters more — losing the "Example — not live data" marker re-opens the exact defect W7 closed. **Checks the commit, not the working tree**: SS-002 already blocks dirty trees, and proving this rule by breaking the working tree yields a silent pass that looks like a broken rule. |
| **SS-605** | error | any page declaring `data-correction-count` | A stated count that disagrees with the distinct slugs marked | `/working-with-claude-blog` enumerates its corrections in prose. That sentence went stale the moment a fifth was added — it said four — and grepping for the new heading would have said everything was fine. Same class as the slide count in eleven places. Counts **distinct slugs, not elements**: one correction can be surfaced twice on a page (`cross-session-memory` has a section and an FAQ answer), and a reader counts corrections, not mentions. |
| **SS-606** | warning | all 32 | A `claims-registry.json` claim no longer present on its route, on a page with no correction marker | Warning on purpose. A claim can vanish because the whole section went — the article keeps the litigation correction "even though the section it belonged to has been removed" — and the house convention of **quoting the retracted figure inside the retraction** keeps the token on the page, so a correctly written correction never trips it. It fires on silent deletions, which is the right polarity, but it caught **one of the three** corrections shipped 2026-08-21. That is its honest reach. |

**Corrections vs standing disclosures are different things and carry different markup.**
A correction is dated and describes something that *changed*. A standing disclosure
(`data-disclosure`) describes something still on the page — the invented figures on
`/etl-showcase` and the marker that makes them honest. Nothing was corrected there. They
are separate fields in the model so that no ageing or collapse rule can ever treat a
disclosure as an old correction and strip it.

| **SS-607** | warning | all 32 | A correction inline for more than 90 days that is not marked `data-collapsed="true"` | The lifecycle policy: a correction stays where the claim was for 90 days — long enough that someone meeting the old wording in a cached result or a shared link lands on the correction beside it — then collapses to a dated one-line link into `/corrections`, with the full text moving there word for word. **It warns; it does not collapse.** Same argument as SS-203 — a validator that performs the edit it is checking is a laundering step, and collapsing is a judgement about wording. **It cannot reach a standing disclosure**: disclosures carry no date and live in a separate field, so no ageing rule can select one. If it could, the sweep would eventually strip "Example — not live data" off a panel of fabricated numbers and recreate that defect on a timer, unattended. |

**Every one of these was proven to fail before being trusted.** SS-605 and SS-606 by editing
the working copy; SS-604 (both halves) by committing the deletion on a throwaway branch;
SS-607 by backdating a marker past the window, then confirming `data-collapsed="true"`
silences it and that the disclosure on the same page is unreachable by age.

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
