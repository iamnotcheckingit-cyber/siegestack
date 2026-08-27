# Claims basis worksheet

**Purpose.** `data/claims-registry.json` holds 24 entries — 25 when this file was written; the `/etl-showcase`
"+0.8% vs last week" delta was removed by W7 and its entry deleted. Every remaining one reads
`measurementBasis: "TODO(pappy)"` and `dateMeasured: "TODO(pappy)"`, which means the site's
central editorial rule — *no percentage or performance claim without a measured baseline* — is
declared but not evidenced anywhere in the repo. This file exists so they can be settled in
one sitting.

**Nothing here is filled in for you, and nothing is guessed.** The "what would satisfy it"
column says what evidence the entry needs, not what the answer is.

**Three valid outcomes per row**, per the registry's own readme:

1. Fill `measurementBasis` and `dateMeasured` — the claim is real and you can say how it was measured.
2. Remove the claim from the page — you cannot reconstruct the basis.
3. Mark `disposition: "not-a-claim"` — the token is prose, not an assertion. The registry
   readme already names the `/case-studies` "82% faster" as this case: that page is *arguing
   against* opening with a figure, not making one.

**How to use it.** Work down the table. For each row either write the basis into
`data/claims-registry.json`, delete the claim from the page, or add the `disposition` key.
Then run `npm run validate:pages`.

**Rows 5–8 are settled — W7 shipped 2026-08-21.** The panel is now marked as an example beside the figures, the pulsing "Live" indicator and the week-on-week deltas are gone, and row 6 no longer exists on the page. Rows 5, 7 and 8 are the three surviving invented numbers; they need no basis because the panel no longer claims they are measurements. The original caveat read:

**Caveat on rows 5–8.** The four `/etl-showcase` figures belong to the mock "Integration Health
Dashboard" and are the subject of W7. If that display is changed or removed, those rows go with
it and never need a basis. Do not spend time on them before W7 is settled.

---

## Fill these three first

Seven of the percentage rows are not seven measurements. They are **three**, each published in
several places. Settle the measurement once and every row that inherits it is answered.

### M1 — the database view audit

Rows **9, 11, 16, 18, 20** (first occurrence only) and **N1**, and **22** — the deck's
~27% sits on the "Auditing 300+ Database Views" slide, so it is this measurement.
**Row 23 is NOT M1**: answered 2026-08-27, it is M2. Row 20 is split across both — see M2.
Published as: "300+ views audited · ~27% aggregate gain · 70 change sets · 99%+ match rate."
Source section: `/working-with-claude-blog#perf-gain`.

Needs, in one paragraph: what was measured (elapsed time, logical reads, CPU — which?), how the
baseline was captured and with what tool, what population the ~27% is aggregated over, what
counts as an audited view and how 300+ was counted, what "match" means in the 99%+ and against
what comparison key, and the date.

### M2 — the macro-replacement reconciliation

**Identified 2026-08-27. This was filed as "the migration reconciliation", as though it were a
separate engagement. It is not.** It is the nine-spreadsheet-macros replacement, and it is
published in two places that describe the same measurement:

| Where | Wording |
|---|---|
| `/working-with-claude-blog#macros` | "Reconciliation runs at 99%+. The remaining percent is genuinely ambiguous and is surfaced for a human" |
| `/working-with-claude` deck, "9 Macros → 1 Automation" | "Tested against legacy output until we hit 99%+ match. The team validated daily before we cut over." |

Rows **23** and the *second* occurrence of row **20**. Row **24** ("cut over") is the same
slide and remains a `not-a-claim` candidate, unruled.

The word "migration" came from the deck's own cut-over language, and reading it as a distinct
engagement is what made Q1 look like a contradiction: two accounts of one number. There were
always two numbers.

Needs: what legacy output the new script was reconciled against, the comparison key and
tolerance, what makes the residual percent "ambiguous", and the date. **No longer blocked** —
the provenance is settled, the measurement detail is not.

### M3 — the security grade

Row **N2**.
Published as: "B → A+ security grade, one site" (`/`) and the numeric scores 75 → 125
(`/working-with-claude-blog#security-grade`).

Needs: the scoring tool by name, and the dates of the before and after scans. Lower value than
M1 and M2 — W6 removed this figure from the homepage row on 2026-08-21, so it now survives
only in the article, where it is labelled Personal.

---

## Q1 — OPEN QUESTION, blocks W5 and both 99%+ rows

**Which engagement did the 99%+ figure come from?** The site currently gives it two
incompatible provenances:

| Where | How it is framed | Row |
|---|---|---|
| `/working-with-claude-blog#perf-gain` | A **view-audit match rate** — rewritten views checked against their originals | 16, 20 |
| `/working-with-claude` (deck) | A **migration reconciliation** — new output tested against legacy output until 99%+ match | 23 |
| `/` (stat row) | Labelled "automation match rate", anchored to `#macros`, which contains no match rate at all | 11 |

These are three different descriptions of one number, and at most one is right. **W5 is held
because of this**: re-pointing the homepage anchor would pick one provenance arbitrarily and
publish it as settled.

Answer this before touching M1's 99%+ component, row 23, or the homepage stat row. If the two
are genuinely separate measurements that happen to share a figure, say so — then M1 and M2 stay
separate and each needs its own basis.

### ANSWERED 2026-08-27 — the view audit

**The operator's answer: the 99%+ on the homepage came from the database view audit.** That is
the recollection this question needed and the hypothesis below did not have, so the hypothesis
is refuted and W5 is unblocked. Row 11 is done: the homepage anchor now points at `#perf-gain`
and the label reads "match rate", carried on the page as a correction
(`homepage-match-rate-provenance`).

**Two things found while applying it, both of which change what the question was about.**

*One.* The reason given below and in row 11 for calling the anchor wrong — that `#macros`
"contains no match rate at all" — **is false.** `#macros` ends with "Reconciliation runs at
99%+." That sentence was there the whole time. Every argument in this section that leans on the
absence of a match rate in `#macros` was leaning on something that is not so, including the
third bullet of the hypothesis.

*Two.* It follows that **the article publishes two separate 99%+ figures**, on two different
engagements: a view-audit match rate at `#perf-gain` and a reconciliation rate at `#macros`.
The homepage was quoting the first and linking to the second. This is not one figure with two
stories, which is the shape this section assumed throughout — so the framing "at most one is
right" in the table above was wrong too: both were right, about different work.

**Row 23 — ANSWERED 2026-08-27, same day.** The deck slide ("Tested against legacy output
until we hit 99%+ match") is `#macros`'s reconciliation restated: same measurement, second
place. The page confirms the answer rather than merely permitting it — the slide is titled
"9 Macros → 1 Automation". So the slide is accurate as written and nothing on it changed;
what changed is M2's identity, which had been filed as a separate "migration reconciliation"
purely because of the slide's cut-over wording.

**Row 20 is answered too, and still cannot be recorded properly.** Its two occurrences are M1
and M2 respectively. The registry is keyed on (claim, route), so one row cannot carry two
bases; the single `measurementBasis` names both instead. Recorded as a schema limit in the row.

**What that leaves.** Every 99%+ on the site now has a known provenance. **None has a
measurement.** M1 and M2 both still need method, comparison key and date — see their sections.
`dateMeasured` is `TODO(pappy)` on every row. **SS-601 now checks it** (2026-08-27), so the
three provenance-only rows warn again and the count went back 13 → 16. That is the honest
number: it counts rows nobody has measured, not rows nobody has traced.

### Superseded hypothesis — kept because it was wrong in an instructive way

**The 99%+ belongs to the script-replacement engagement, not the view audit.** This is a
reading of the page text, not a recollection, and nobody has confirmed it. It is written down
so it can be checked, not so it can be assumed.

The reasoning, all of it internal evidence:

- The `#macros` section describes the replacement script as "querying the database directly,
  **and reconciling records**." A reconciliation is what produces a match rate.
- The deck slide reads "Tested against **legacy output** until we hit 99%+ match" — legacy
  output being what the replaced macros produced. It sits beside the migration and cut-over
  language, not beside anything about database views.
- In the `#perf-gain` summary line — "300+ views audited · ~27% aggregate gain · 70 change
  sets · 99%+ match rate" — three of the four items measure the same object and the fourth
  does not. It reads like a figure appended to a list it does not belong to.

**What it would mean if it holds.** (Refuted 2026-08-27 — the operator's recollection says the
view audit. Kept as written, because the reasoning failed on a checkable fact rather than on
judgement: its third bullet and the reading below both depend on `#macros` having no match
rate, and `#macros` has one.) The homepage tile is correct exactly as it stands —
right anchor (`#macros`) and right label ("automation match rate"), because replacing manual
macros with a scheduled script *is* the automation. The defect shrinks to **one item on the
`#perf-gain` summary line that belongs to a different engagement**. That inverts W5: the fix
lands on the article, not on the homepage.

**What keeps it unconfirmed.** A view-rewrite audit produces a natural match rate of its own —
a rewritten view returning the same rows as the original — so 99%+ is plausible in both
places, which is presumably how it drifted. The text can say which reading is more coherent.
It cannot say which one happened.

If it holds, **M1 and M2 are two measurements, not one figure with two stories**, and each
needs its own basis.

---

## The registered claims

| # | Claim | × | Route | Where it appears | Source anchor | What would satisfy the basis |
|---|---|---|---|---|---|---|
| 1 | `40%` | 1 | `/case-studies` | "Consulting case studies tend to open with a figure — 82% faster, 40% fewer errors." | — | Nothing. This is the page arguing against invented figures. Strong candidate for `not-a-claim`. |
| 2 | `82%` | 1 | `/case-studies` | Same sentence as row 1 | — | Same as row 1. The registry readme already names this one. |
| 3 | `faster` | 1 | `/case-studies` | Same sentence as row 1 | — | Same as row 1 — the token is inside the quoted example, not an assertion. |
| 4 | `faster` | 1 | `/case-studies/label-service` | "For a floor printer this matters — it prints faster, positions predictably…" | — | Either a print-time comparison (native label commands vs rendered image, same printer, same label, N runs) with a date, or `not-a-claim` if this is qualitative. |
| 5 | `0.02%` | 1 | `/etl-showcase` | Now only inside the correction note, which quotes the removed "+0.02% vs last week" | — | Nothing needed. It survives as a quotation inside a published correction — the same shape as row 17. |
| 6 | `0.8%` | — | `/etl-showcase` | **GONE.** Was "Retry Rate 2.3% +0.8% vs last week"; the deltas were removed by W7 and the registry entry deleted with them. | — | Nothing needed. Kept as a row so the numbering does not shift under you. |
| 7 | `2.3%` | 1 | `/etl-showcase` | Example dashboard, "**Retry Rate 2.3%**"; panel now marked "Example — not live data" | — | Nothing needed. The panel no longer presents this as a measurement. |
| 8 | `99.97%` | 1 | `/etl-showcase` | Example dashboard, "**API Uptime 99.97%**"; panel now marked "Example — not live data" | — | Nothing needed. Same as row 7. |
| 9 | `~27%` | 1 | `/` | Stat row, "~27% performance gain" | `/working-with-claude-blog#perf-gain` | What was measured (elapsed time? logical reads? CPU?), across how many views, against what baseline capture, with what tool, on what date. The article says "aggregate gain" — say aggregated over what population. |
| 10 | `100%` | 1 | `/` | FAQ, "Do we own the code you write?" → "100%. Everything we build is yours." | — | Not a measurement — it is an ownership answer. Candidate for `not-a-claim`. |
| 11 | `99%` | 1 | `/` | Stat row, "99%+ match rate" | `#perf-gain` | **DONE 2026-08-27.** Q1 answered: the view audit. Anchor re-pointed from `#macros`, label was "automation match rate". Correction `homepage-match-rate-provenance`. Basis recorded; `dateMeasured` still open. The old source-anchor note in this row — "`#macros`, which contains no match rate" — was FALSE; see Q1. |
| 12 | `100%` | 1 | `/label-tool` | Print settings, "set it to 100% or 'Actual size'" | — | A print-dialog instruction, not a claim. Candidate for `not-a-claim`. |
| 13 | `cut` | 1 | `/label-tool` | "The version this was cut down from does the other half…" | — | "cut down from" is prose. Candidate for `not-a-claim`. |
| 14 | `faster` | 1 | `/operations-modernization` | "People who have followed the work adopt the result faster than people handed a finished workbook on go-live day." | — | Either an adoption measure (what was counted, over what period, for which two groups) or `not-a-claim` if this is an observation rather than a measurement. Worth a deliberate decision — it reads as a claim. |
| 15 | `100%` | 1 | `/privacy-policy` | "no method of transmission over the Internet is 100% secure" | — | Standard privacy boilerplate. Candidate for `not-a-claim`. |
| 16 | `~27%` | 1 | `/working-with-claude-blog` | Summary line: "300+ views audited · ~27% aggregate gain · 70 change sets · 99%+ match rate" | `#perf-gain` | Same evidence as row 9 — this is the source instance the homepage links to. Fill this one first; row 9 inherits it. |
| 17 | `20%` | 1 | `/working-with-claude-blog` | "An earlier version of this article put a number on that — 'roughly 20% of the time.' I have removed it, because I never measured it…" | `#corrections` | Nothing. This is the published correction *recording* an unmeasured figure. `not-a-claim` — and if the text is ever removed, the correction goes with it. |
| 18 | `27%` | 2 | `/working-with-claude-blog` | Section heading "A 27% Performance Gain Across Hundreds of Database Views", plus one body instance | `#perf-gain` | Same as row 16. Note `×2` — SS-601 errors if a third instance appears. |
| 19 | `95%` | 1 | `/working-with-claude-blog` | "Test against reality (this is where 95% of AI users fail)" | — | **This one needs a real decision.** It is a rhetorical figure about a population nobody has surveyed — the same class as the "confidently wrong ~20%" statistic already removed as a correction. Either a citation or removal; `not-a-claim` would be generous. |
| 20 | `99%` | 2 | `/working-with-claude-blog` | Summary line (row 16) at `#perf-gain`, plus the body sentence "Reconciliation runs at 99%+" at `#macros` | `#perf-gain` **and** `#macros` | **TWO MEASUREMENTS IN ONE ROW.** Occurrence 1 is M1, occurrence 2 is M2 — established 2026-08-27. Both provenances are known; the registry is keyed on (claim, route) and cannot hold two bases for one row, so the single `measurementBasis` names both. That is a schema limit, not an answer: neither measurement has its detail or date yet. |
| 21 | `faster` | 4 | `/working-with-claude-blog` | Four prose instances, e.g. "the faster the next kind converges" | — | Prose throughout. Candidate for `not-a-claim`. Note `×4` — a fifth instance turns the build red. |
| 22 | `~27%` | 1 | `/working-with-claude` | Deck slide: "~27% performance improvement measured after deployment" | — (the deck has no section anchors) | Same evidence as row 16. The slide says "measured after deployment", which asserts a measurement more strongly than the article does — so this wording needs the basis or needs softening. |
| 23 | `99%` | 1 | `/working-with-claude` | Deck slide: "Tested against legacy output until we hit 99%+ match." | — | **ANSWERED 2026-08-27 — M2**, the macro-replacement reconciliation restated from `#macros`. Not a third measurement and not the view audit. The slide is accurate as written; nothing on the page changed. Basis recorded, `dateMeasured` open. |
| 24 | `cut` | 1 | `/working-with-claude` | "The team validated daily before we cut over." | — | "cut over" is prose. Candidate for `not-a-claim`. |
| 25 | `faster` | 1 | `/working-with-claude` | "a clean prompt in a fresh session is faster and better than an elaborate system" | — | Prose. Candidate for `not-a-claim`. |

---

## NOT REGISTERED — two published figures SS-601 cannot see

Both sit in the homepage stat row beside claims that *are* registered. Neither is caught by any
rule today, so neither would turn the build red no matter what it said.

| # | Claim | Route | Where it appears | Source anchor | Why SS-601 misses it | What would satisfy the basis |
|---|---|---|---|---|---|---|
| N1 | `300+` | `/` and `/working-with-claude-blog` | Stat row, "300+ views audited"; and the article summary line | `/working-with-claude-blog#perf-gain` | **NOT REGISTERED.** SS-601 tokenises digit-percent, digit-x, and the words faster/reduced/improved/cut. A bare count with a `+` matches none of them. | The population definition: what counts as an audited view, how the 300 was counted, and on what date. This is the denominator for rows 9, 11, 16 and 20 — without it none of those percentages have a scope. |
| N2 | `B → A+` | `/working-with-claude-blog` only, as of 2026-08-21 | The article section. **Removed from the homepage stat row by W6** — it came from a personal project and stood unlabelled beside professional results | `/working-with-claude-blog#security-grade` | **NOT REGISTERED.** A letter grade contains no digit-percent, digit-x, or tracked verb. | The scoring tool and both report dates. The article states the numeric scores (75 → 125), so the tool is identifiable — name it, and record when each scan ran. Lower priority now that it is confined to the article, where it is labelled *Personal*. |

### If you want these two enforced

SS-601's token set would need a bare-count pattern and a grade pattern. That is a change to
`scripts/validate-pages.mjs`, not to this file, and it would light up unrelated numbers across
the site — worth doing deliberately, not as a side effect of this worksheet.

---

## What this worksheet does not answer

- **Whether any measurement basis exists in writing at all.** That is the open question. If the
  answer for a given row is "no record survives", outcome 2 or 3 applies — reconstructing a
  number from memory is exactly what the site's rule exists to prevent.
- **Rows 9, 11, 16, 18, 20, 22 and 23 are probably three underlying measurements, not seven.**
  The view audit (27% and 99%+ across 300+ views), a migration reconciliation (row 23), and the
  security grade. Settle each measurement once and the rows that share it inherit the answer.
