# Validator blind spots — inventory

**Read-only sweep, 2026-08-21. No rule was changed.** Findings are recorded here so they can
be audited against the code that produced them; fixing in the same pass would destroy that.

## Why this exists

Three defects surfaced on 2026-08-21 that were the same defect: a rule that looked healthy
while checking nothing.

- SS-607's 90-day sweep would eventually have stripped a standing disclosure off a panel of
  invented figures, on a timer.
- The `llms-full.txt` staleness check had never once run against a correct file.
- SS-201 disabled itself for all 26 routes when any one file had no commit history — and
  inside that, two more: the `all-excluded` state was swallowed by `if (actual && …)`, and
  SS-202 was collaterally switched off by an unrelated rule's `break`.

That is a property of how these rules are written, not three coincidences.

## Method

Reading the code and asking "what disables this" is what missed `all-excluded` and the SS-202
shutdown in the first place. So every finding below except the two marked **INFERRED** was
produced by **constructing the failure state and observing the output**.

`data/pages.json` is the validator's only input, so most states were constructed by mutating
the model directly, running `node scripts/validate-pages.mjs`, and diffing the output against
a baseline. File-level states (`.denylist.local.json`, `llms-full.txt`) were constructed on
disk. Every probe restored its input byte-for-byte; the tree was confirmed clean afterwards.

Baseline for every probe: `0 error(s), 29 warning(s), 0 route-skip(s), 2 skipped, 0 suppressed`.

**Three outcomes**, in the language of the SS-201 post-mortem:

- **reported** — the rule said it could not check, naming what and why. SS-701 is the model.
- **misreported** — it said something, and the something was wrong or actively misleading.
- **silent** — no output at all. Indistinguishable from a pass.

---

## Findings

| # | Rule(s) | Constructed condition | What the output said | Blast radius | Self-heals | Severity |
|---|---|---|---|---|---|---|
| **B1** | SS-602 | `.denylist.local.json` **present but the `terms` key renamed** | **Silent.** Not reported as skipped, not reported as passed — SS-602 produced no line at all, and the summary was byte-identical to a clean run. | The whole rule, every corpus | **No** | **Critical** |
| **B2** | SS-602 | `.denylist.local.json` present with `"terms": []` | **Silent.** Same as B1. | The whole rule | **No** | **Critical** |
| **B3** | SS-602 | `llms-full.txt` absent, denylist term present in it | **Misreported.** Findings dropped 2 → 1. The `llms-full.txt` corpus vanished from the scan and nothing said so; the remaining finding made the run look healthy. | One corpus — the largest published surface (216 KB) | No | **High** |
| **B4** | SS-602 | A denylist entry with `"term": ""` | **Silent.** `if (!term) continue` skips it without comment, unlike SS-001/SS-306 which error on a missing `reason`. | One term | No | Medium |
| **B5** | SS-501, SS-502, SS-503 | `jsonLd` and `jsonLdGraphs` emptied on every page (extractor regression) | **Silent** for all three. Only SS-504 noticed, warning on 25 routes — and only because they are indexable and unexempt. **SS-503, the rating-markup ban, is completely blind.** | Three rules sitewide | No | **High** |
| **B6** | SS-601 | `textContent` emptied on one page | **Misreported, destructively.** Six "registered but has no measurement basis" warnings became six **"Registry entry no longer matches anything on the page; delete it."** Following that advice deletes six legitimate registry rows. The total stayed at 24 findings, so the summary line was unchanged. | One page, but the advice is destructive | No | **High** |
| **B7** | SS-605 | `data-correction-count` removed from the page that declares one | **Silent.** `if (p.statedCorrectionCount == null) continue` — deleting the attribute deletes the check. The rule I wrote today has the same shape as the one I was fixing. | One page | No | **High** |
| **B8** | SS-401, SS-402, SS-404 | `internalLinksOut` emptied on every page | **Silent** for all three. | Three rules sitewide | No | Medium |
| **B9** | SS-101 | `totals.phantomSitemapEntries` key renamed | **Silent.** `?? []` cannot distinguish "no phantom entries" from "the field is gone". | One check within SS-101 | No | Medium |
| **B10** | SS-301, SS-302, SS-305, SS-306, SS-504, SS-601 | Every page reclassified out of `indexable` (`INDEXABLE` becomes empty) | **Partly reported.** Six rules went silent, SS-601 visibly dropping 24 → 0. **SS-102 caught it** with 27 errors, and the header prints `(0 indexable)`. So it is loud — but by accident, via a neighbouring rule, not because any rule asserts the population is non-empty. | Six rules sitewide | No | Medium |
| **B11** | SS-606, SS-607 | `corrections` / `correctionDates` / `disclosures` emptied on every page | **Silent** for both — but **SS-604 caught it** with 10 errors, because HEAD~1 still had the markers. Genuine cross-coverage: the append-only rule protects the two ageing rules from an extractor regression. | Two rules, covered | Yes, while history exists | Low |
| **B12** | SS-503 | Rating markup present only inside a block that fails to parse | **Silent** for SS-503; SS-501 errors on the parse failure. You learn a block is broken, never that it contains rating markup. The ban is not absolute. | One page | No | Medium |
| **B13** | SS-604 | A page whose `sourceFile` cannot be read at `HEAD~1` | **Silent.** `prevOf` returns `null` and the loop `continue`s. `if (compared === 0)` only catches the case where *every* file fails. | One route | Yes, next commit | Low |
| **B14** | SS-001 | `data/validation-suppressions.json` present with the `suppressions` key renamed | **Silent.** No suppressions are validated and none are applied. Fails safe — nothing gets silenced — but the file is unreadable to the rule and it does not say so. | The rule | No | Low |
| **B15** | SS-303, SS-304 | A page with a real `h1` defect reclassified to `served-noindex` | **Reported, downgraded.** The finding appeared as a warning instead of an error. Visible, not silent — recording it because misclassification silently changes severity. | One route's severity | No | Low |
| **B16** *(INFERRED)* | SS-002 | `git status --porcelain` throws while `git rev-parse` succeeds | `catch { /* handled above */ }` leaves `dirty = []`, so the dirty-tree half passes silently. Not constructed — it needs git working for one subcommand and failing for another. | One half of SS-002 | n/a | Low |
| **B17** *(INFERRED)* | SS-604 | `git show HEAD~1:<file>` unavailable on a repo with a single commit | Every `prevOf` returns `null`, `compared === 0`, and the rule **does** report SKIPPED. Behaves correctly by inspection; not constructed because it needs a fresh repo. | The rule | n/a | None |

---

## What the pattern actually is

Four distinct shapes, not one:

1. **`?? []` on a container that is then iterated.** An empty container means zero iterations
   means zero findings, and zero findings is the same output as success. B1, B2, B9, B14. This
   is the dominant shape and it is why B1 is critical: it turns a renamed key into a silent
   policy bypass.
2. **A conditional `continue` keyed on the presence of the thing being checked.** B7 is the
   purest form — the check is gated on the attribute it exists to verify, so deleting the
   attribute deletes the check.
3. **A field read from the model that the model might not populate.** B5, B6, B8, B11. The
   validator deliberately does not parse HTML, which is right, but it also never asserts that
   the extractor gave it anything.
4. **A ternary that substitutes empty for missing.** B3 — `has(f) ? rd(f) : ''` scans an empty
   string and calls it scanned.

**Only one rule on the site handles this honestly today: SS-701**, which reports SKIPPED with
its reasoning rather than passing when there are no images to check. SS-602 *claims* the same
discipline in its own skip text — "REPORTED AS SKIPPED, not passed" — but only for a **missing**
file. A present, malformed one sails straight through, which is B1.

---

## Prioritized, non-self-healing first

**Nothing here is fixed. This is a proposal.**

1. **B1 + B2 + B4 — SS-602 validates its own input.** Highest priority by some distance. This
   is the rule that keeps employer, client and individual names off a public site and out of
   public CI logs, and a renamed key silently disables it while the build stays green. It should
   fail loudly on a file it cannot read, on a zero-length term list, and on an entry with no
   term — the same argument SS-001 already makes about suppressions with no reason.
2. **B3 — SS-602 corpus accounting.** Report which corpora were actually scanned, and treat a
   missing `llms-full.txt` as a skip rather than an empty string.
3. **B5 — structured-data rules assert they were given structured data.** If `jsonLdGraphs` is
   empty across every page, that is an extractor regression, not a clean site. SS-503 in
   particular should never be able to pass by seeing nothing.
4. **B7 — SS-605 should not be gated on the attribute it checks.** Either the page declares a
   count or the rule reports that it cannot check that page.
5. **B6 — SS-601's "delete it" advice needs a guard.** Do not tell someone to delete registry
   rows when the page's text is empty; that is an extractor failure wearing a content failure's
   message.
6. **B9, B8, B12 — narrower `?? []` and empty-collection cases.** Same shape, smaller blast
   radius.
7. **B10 — assert the population.** A run where `INDEXABLE` is empty should say so as a finding,
   not rely on SS-102 happening to notice and on a human reading the header.
8. **B13, B14, B15, B16** — low. Self-healing, fail-safe, or merely a severity change.

**A general option worth considering instead of eight separate fixes:** a single end-of-run
assertion pass that checks the *inputs* were non-vacuous — model non-empty, each declared data
file parsed to a non-empty collection of the expected shape, every corpus accounted for — and
reports anything vacuous as a skip. That would close B1, B2, B5, B8, B9, B10 and B14 at once,
and would put the honesty in one place rather than in twenty.

## Coverage note

The sweep covered every rule from SS-001 to SS-701. Two findings are marked **INFERRED** and
were not constructed; both are low severity and the reason is stated on each. Everything else
in the table was produced by running the validator against a state built on purpose, and the
"what the output said" column is what it actually printed.
