# Audit reconciliation — siegestack.com

Phase 0. Read-only. Repo state: `main` @ `5c00995` (2026-08-20). No writes outside this file.

Scope note: verdicts are against the **source tree only**. Runtime behaviour (headers actually
emitted, edge-function decisions, redirect resolution) is Phase 4 and is marked
`UNVERIFIABLE-FROM-REPO` where it matters.

---

## 1. Claims ledger

| # | Assertion | Verdict | Evidence |
|---|---|---|---|
| 1 | `/llms.txt` and `/llms-full.txt` exist and are current | **CONFIRMED** | `llms.txt:1` (214 lines), `llms-full.txt:1` (5,159 lines). `llms.txt:123` "Last updated 2026-08-20"; `llms-full.txt:15` "Generated 2026-08-20". Route count self-enforced at `llms.txt:126-131` via `scripts/build-llms-full.mjs`. See caveat C1. |
| 2 | Homepage `<title>` is "Custom Integrations, Dashboards & Apps \| SiegeStack" | **CONFIRMED** | `index.html:19` — exact string match, 51 chars. |
| 3 | Sitemap has ~25–30 URLs with valid `lastmod`, `priority`, `changefreq` | **PARTIAL** | `sitemap.xml`: 26 `<loc>`, 26 `<lastmod>`, **13** `<priority>`, **13** `<changefreq>`. Count is in range and `lastmod` is universal; the other two are on half the entries only (`sitemap.xml:76-132` carry `lastmod` alone). |
| 4 | A `/prophet-21` page exists and is deeply specific | **CONFIRMED** | `prophet-21.html` — 1,984 words, 1 h1, JSON-LD present. `sitemap.xml:46`, `publish-gate.ts:53`, `llms.txt:74-82`. Depth boundary stated in-page and re-stated at `llms.txt:80-82` (P21 deep, Kinetic transferable only). |
| 5 | A `/sql-server-erp-performance` page exists | **CONFIRMED** | `sql-server-erp-performance.html` — 1,535 words. `sitemap.xml:64`, `publish-gate.ts:55`, `llms.txt:92`. |
| 6 | A `/working-with-claude` page exists | **CONFIRMED** | `working-with-claude.html` — 4,545 words (`sitemap.xml:28`), plus `working-with-claude-blog.html` — 8,730 words (`sitemap.xml:22`). Both routed at `netlify.toml:118-139`. |
| 7 | Case-study pages exist and are anonymized per policy | **CONFIRMED** | Hub `case-studies.html` + `case-studies/kpi-console.html` (780w), `case-studies/month-to-date-timeout.html` (602w), `case-studies/label-service.html` (481w). Policy stated in-page at `case-studies.html:307` (industry, size, location, item numbers, dollar figures "removed rather than disguised") and `case-studies.html:310` (why no percentages). Denylist scan for employer/client identifiers is Phase 2 — see G7. |
| 8 | A browser-based barcode label tool is published | **CONFIRMED** | `label-tool.html` — 2,187 words, self-contained. `sitemap.xml:124`, `netlify.toml:316-325`, `publish-gate.ts:57`, `llms.txt:51-61`. |
| 9 | Six service concepts are "trapped on the homepage" with no dedicated pages | **REFUTED as stated** | The number is inverted. `index.html:740-820` carries **seventeen** service cards. **Six** have dedicated pages (`services/*.html`, all six in sitemap). **Eleven** deliberately have none — the reason is recorded at `llms.txt:87-89`: "the only written material behind them sits inside a Claude-workflow article, and routing a buyer there would be worse than not linking." The audit named the count of pages that *exist* as the count that is *missing*. |
| 10 | Salesforce / Shopify / NetSuite / HubSpot are named as platforms worked with | **CONFIRMED**, framing disputed | Salesforce: `etl-showcase.html`, `index.html`, `services/erp-integration.html`. HubSpot: same three. Shopify: `etl-showcase.html`, `index.html`. NetSuite: `index.html` only. All four are named — but `llms.txt:28-30` scopes them as *integration targets*, explicitly "not partners, resellers, certifications or endorsements." NetSuite is the thinnest (one page, no supporting material). |
| 11 | No structured data / JSON-LD is present | **REFUTED** | `application/ld+json` in **25 of 32** HTML files. 25 distinct `@type` values in use, incl. `Organization` (27), `Service` (26), `BreadcrumbList` (24), `FAQPage` (6), `Article` (5), `Person` (9), `SoftwareApplication`, `WebApplication`, `ProfessionalService`. Also: **zero** occurrences of `aggregateRating`, `review`, or `ratingValue` sitewide — the Phase 2 hard-error rule already passes. |
| 12 | No geographic (Houston) signal exists anywhere on the site | **PARTIAL** | "Houston" appears in **0** files. But geo signal is not absent: `areaServed` is set on 12 pages — `"United States"` (`services/*:41`, `prophet-21.html:52`, `industries/distribution.html:41`, `operations-modernization.html:49`, `sql-server-erp-performance.html:52`) and `"Worldwide"` (`index.html:79`, `etl-showcase.html:73`). `about.html:368`, `contact.html:431`, `index.html:1058` all state **"Remote"**. City-level absence is a posture, not a gap. See policy flag P2. |
| 13 | Internal linking is sparse / non-clustered | **REFUTED (sparse) / PARTIAL (non-clustered)** | Measured over all 26 sitemap routes: **zero orphans**, minimum 13 outbound internal links per page, minimum 2 inbound. Not sparse. The *shape* claim survives: inbound counts are bimodal — 22–28 for nav/footer-linked pages, 2–7 for everything else — which is a near-uniform mesh from global chrome, not a hub-and-spoke hierarchy. Weakest inbound: `/working-with-claude` (2), `/prophet-21-upgrade-reporting` (3), `/delivery-config-audit` (3). |

### Inbound/outbound link measurements (basis for #13)

| Route | out→sitemap | inbound |
|---|---|---|
| `/` | 20 | 28 |
| `/operations-modernization` | 19 | 27 |
| `/case-studies` | 23 | 26 |
| `/etl-showcase` | 18 | 26 |
| `/prophet-21` | 20 | 26 |
| `/privacy-policy` | 18 | 26 |
| `/about` | 19 | 25 |
| `/contact` | 18 | 25 |
| `/insights` | 24 | 25 |
| `/sql-server-erp-performance` | 19 | 25 |
| `/label-tool` | 13 | 24 |
| `/services/erp-integration` | 13 | 24 |
| `/industries/distribution` | 16 | 23 |
| `/services/etl-data-pipelines` | 19 | 23 |
| `/services/performance-tuning` | 19 | 23 |
| `/services/automated-reporting` | 18 | 22 |
| `/services/bi-dashboards` | 19 | 22 |
| `/services/security-access-audit` | 19 | 22 |
| `/erp-report-slow-month-to-date` | 19 | 10 |
| `/case-studies/label-service` | 21 | 7 |
| `/working-with-claude-blog` | 19 | 7 |
| `/case-studies/kpi-console` | 21 | 6 |
| `/case-studies/month-to-date-timeout` | 22 | 6 |
| `/delivery-config-audit` | 19 | 3 |
| `/prophet-21-upgrade-reporting` | 20 | 3 |
| `/working-with-claude` | 6 | 2 |

Only three internal link targets sit outside the sitemap, all three intentionally:
`/audit`, `/consultant-expertise`, `/secret`.

---

## 2. DISPUTED — where the audits contradict each other

| Point | Audit A says | Audit B says | Repo supports |
|---|---|---|---|
| `/llms.txt` currency | present and current *(unattributed)* | absent or stale *(unattributed)* | **A.** Both files exist, both dated 2026-08-20, and `llms.txt` has a machine-enforced route count. |
| Structured data | Grok, Copilot: none present | — *(uncontested by the others, but contradicted by the tree)* | **Neither.** 25 files carry JSON-LD. Both audits are wrong; this is the strongest evidence they were written from search snippets rather than the repo. |
| Service-page coverage | ChatGPT-class: six concepts stranded, no pages | Grok implicitly treats service pages as existing (it found `/prophet-21`, `/sql-server-erp-performance`) | **Grok.** Six service pages exist; eleven concepts are pageless *by written decision*. |
| Platform naming | ChatGPT-class: Salesforce/Shopify/NetSuite/HubSpot should be named | Site policy (`llms.txt:28-30`) already names them, as integration targets only | **The repo.** The recommendation is already implemented, and re-implementing it as claimed experience would breach the framing the site sets. |
| Internal linking | Gemini, ChatGPT-class: sparse | — | **Neither.** Zero orphans, 13–24 outbound per page. The measurable defect is *undifferentiated*, not sparse. |
| Geographic signal | ChatGPT-class: no geo signal at all | — | **Partial.** `areaServed` is set on 12 pages; only city-level is absent, and "Remote" is stated three times. |
| Where deny-by-default lives | *(brief describes `netlify.toml`)* | — | **Neither.** The gate is `netlify/edge-functions/publish-gate.ts`; `netlify.toml:592-600` says so explicitly. `netlify.toml` keeps only two defence-in-depth 404 rules. This matters for Phase 2's parity check — see G2. |

---

## 3. Policy-violation flags — dead on arrival

Recommendations that would breach a stated rule if implemented. Not to be actioned.

| # | Recommendation | Rule it breaches |
|---|---|---|
| P1 | Add performance/outcome percentages to case studies or service pages to make them "results-driven" | "No percentage or performance claim without a measured baseline." `case-studies.html:310` publishes the reasoning; `llms.txt:24-27` binds citers to it. The four homepage figures (`index.html:714-730`) each deep-link to their source anchor — that discipline is the ceiling, not a floor to build on. |
| P2 | Build Houston / Texas / local-SEO landing pages | The site states "Remote" in three footers (`about.html:368`, `contact.html:431`, `index.html:1058`) and sets `areaServed` to United States/Worldwide. A city page would assert a service area the site declines to claim, and geo-page farms are the spam pattern the editorial policy exists to avoid. |
| P3 | Present Salesforce / Shopify / NetSuite / HubSpot as platforms with delivered client work | `llms.txt:28-30`: named vendors "are not partners, resellers, certifications or endorsements." NetSuite is currently a single mention on `index.html` with nothing behind it — deepening it would require substance you have to supply, not copy. |
| P4 | Unblock AhrefsBot / SemrushBot / MJ12bot / DotBot / BLEXBot so audit tools can crawl | `robots.txt:13-14` records the tradeoff as a deliberate accept: "any report they produce about it will look thin. That is this file, not the site." Three of the four audits are downstream of exactly this and describe it as a site defect. |
| P5 | Add `aggregateRating` / `Review` schema for rich-result stars | No legitimate source exists. Currently zero occurrences sitewide; Phase 2 already specs this as a hard error. |
| P6 | Name the employer or a client to make case studies credible | `case-studies.html:307`; `llms.txt:22-24`. Non-negotiable. |
| P7 | Add `Disallow` lines for `/jesse`, `/nicole`, `/secret` to robots.txt | `netlify.toml:485-488` explains why not: robots.txt is public, so a `Disallow` **advertises** the private URL. `X-Robots-Tag` is already the stronger control. |
| P8 | Write ~11 new service pages so every homepage concept has one | Not a policy breach, but it contradicts a written decision (`llms.txt:87-89`). Any of these would be a Phase 3 `noindex` scaffold at best — you supply the substance or the page does not ship. |

---

## 4. Findings outside the assertion list

Discovered while gathering evidence. Each changes what Phase 2 has to do.

| # | Finding | Evidence | Why it matters |
|---|---|---|---|
| G1 | **HSTS is not set anywhere in the repo.** Zero occurrences of `Strict-Transport-Security` in `netlify.toml`, `_headers`, or either edge function. | grep across `*.toml`, `_headers`, `*.ts`, `*.mjs` — no hits | Your posture list names HSTS as existing. It is most likely coming from Netlify's own Force-HTTPS behaviour, not from this repo, which means it is not under version control and cannot be validated from source. `UNVERIFIABLE-FROM-REPO`; Phase 4 must confirm it live, and Phase 2 cannot assert it. |
| G2 | **Deny-by-default is not in `netlify.toml`, and is not keyed to the sitemap.** | `netlify.toml:592-600`; `publish-gate.ts:50-92` | Phase 2's four-way parity check must read `publish-gate.ts` (`ALLOW_EXACT`, `ALLOW_PREFIX`, `ALLOW_EXT`, `DENY_PREFIX`), not `netlify.toml`. And the allow-list intentionally exceeds the sitemap by five routes (`/audit`, `/consultant-expertise`, `/jesse`, `/nicole`, `/secret`) plus a 301 source (`/epicor-p21-kinetic-reporting`) — so "allow-list ≡ sitemap" would be red by design. The parity rule needs an explicit intentional-extras allowlist. |
| G3 | **`/privacy-policy` is in the sitemap and carries `noindex`.** | `sitemap.xml:130` vs `privacy-policy.html:19` (`<meta name="robots" content="noindex, follow">`) | A real, live contradiction — the only one of its kind. Also makes it a target of the Phase 2 rule "zero links to `noindex` pages from indexable pages": it currently has **26 inbound internal links**, i.e. every page in the footer. Needs your decision, not a mechanical fix. |
| G4 | **No CI exists.** No `.github/` directory at all. | `ls -a .github` → absent | Phase 2 says "wire `validate:pages` into CI as a required check." There is nothing to wire into; the workflow would have to be created from scratch. Flagging so you decide whether that is in scope. |
| G5 | **Netlify runs no build command.** `netlify.toml` has `publish = "."` and no `command`. | `netlify.toml:1-2`; grep for `command` → no hit | Two consequences. (a) `scripts/build-llms-full.mjs` never runs on deploy — `llms-full.txt` currency depends entirely on remembering to run it by hand, which is the exact failure mode its own header documents (`build-llms-full.mjs:6-13`). (b) Phase 2's "wire into the Netlify build command so a failing invariant blocks deploy" means *introducing* a build step to a site that has never had one. On a `publish = "."` site that is a real deploy risk and should be a deliberate decision. |
| G6 | **The freshness rule as specified will fail on all 26 routes.** | `git log b1f31e9` (2026-08-20, "Give every page a main landmark…") touched every page | `sitemapLastmod == git last-commit date of sourceFile` is currently red everywhere, because one sitewide cosmetic accessibility commit reset the git date on all 26 files while none of the content changed. The rule is right about the bug class but the signal is noisy: a sitewide whitespace/landmark/footer commit is indistinguishable from a rewrite. Phase 2 needs a decision from you — see checklist item 3. |
| G7 | **The denylist source file does not exist yet.** | `.gitignore` has no denylist entry; no local file present | Phase 2 specs "seed the list from a gitignored local file." You have to supply it — it cannot be inferred, and guessing at employer/client identifiers is exactly the thing the policy forbids. |
| G8 | **`/etl-showcase` publishes an unlabelled mock dashboard marked "Live".** | `etl-showcase.html:1768-1790` — "Integration Health Dashboard", pulsing `live-dot`, `99.97%` uptime, `142ms`, `2.3%` retry rate, `+0.02% vs last week` | Nothing on the page says these are illustrative — grep for "illustrative / sample / example data / mock / simulated" returns nothing. Under your own rule ("no percentage or performance claim without a measured baseline") this is an in-repo violation, not an audit recommendation, and the Phase 2 claims-registry rule will flag it. Your call whether it gets a caption or a registry entry. |
| G9 | Three meta descriptions exceed 160 chars; one is under 130. | `delivery-config-audit` 225, `label-tool` 211, `prophet-21-upgrade-reporting` 207; `insights` 122 | Pre-loading the Phase 2 error list. |
| G10 | Five titles exceed 60 chars. | `case-studies/kpi-console` 80, `delivery-config-audit` 69, `case-studies/month-to-date-timeout` 67, `case-studies/label-service` 67, `label-tool` 63, `prophet-21-upgrade-reporting` 61 | Same. |
| G11 | Four sitemap routes do not end in the brand suffix. | `/operations-modernization`, `/case-studies`, `/insights`, `/about` | The Phase 2 rule "ends in the brand suffix pattern" would flag four existing titles. `/about` ends "\| Scott Allen Willis" — arguably correct and needing an exemption, not a rewrite. |
| G12 | `og:description` differs from `meta description` on 9 of 26 routes; `og:title` differs from `<title>` on 8. | measured across all sitemap routes | Phase 2 spec calls for consistency. Some of these are likely deliberate (social copy ≠ SERP copy). Needs a severity decision: error or warning. |
| G13 | **Parser trap: `<title>` appears inside HTML comments.** | `working-with-claude.html:19` — a comment listing the ten places the slide count lives | A naive `<title>` regex reads 370 chars from that file. Any Phase 1/2 extractor must strip comments, `<script>` and `<style>` *before* parsing — the same applies to the numeric-claim scan, which otherwise drowns in CSS `50%` values (I measured 40+ false hits from stylesheet content alone). |

### Caveat C1 — what "current" means for `llms.txt`

`llms.txt` is hand-maintained. Its route **count** is machine-enforced (`llms.txt:126-131`,
`build-llms-full.mjs`), and that check exists because the count was wrong twice in four days.
But the enforcement only fires when someone runs the generator, and G5 says nothing runs it
automatically. So: currently accurate, structurally unprotected.

---

## Phase 0 ends here. Awaiting go-ahead.

Before Phase 1 I need decisions on **G2** (parity baseline), **G3** (`/privacy-policy`),
**G4/G5** (does CI + a Netlify build command exist to be created?), **G6** (freshness signal),
and **G7** (denylist file). Phase 1 can proceed without them; Phase 2 cannot.
