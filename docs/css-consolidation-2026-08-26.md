# CSS consolidation, 2026-08-26 — the diff log

Acceptance evidence for Phase 5. Every rule that was not identical across the
variants is listed here, with where it ended up and why.

## What replaced what

Twenty-two pages carried their own inline <style> block. They now load:

| file | rules | loaded by |
|---|---|---|
| `/assets/site.c5bd116dbc.css` | 25 + 6 | all 22 |
| `/assets/doc.41dcc80e68.css` | doc template | 15 pages |
| `/assets/article.c305c30cd1.css` | article template | 7 pages |

The filenames carry a content hash. netlify.toml serves /*.css with
max-age=31536000, immutable, and its comment had been waiting since the rule
was written for whoever added the first stylesheet. A hash obeys that by
construction rather than by memory.

## The finding that changed the shape of the work

**This site has two page templates, not one drifted stylesheet.** The split is
15 pages against 7, and it is the SAME 15 and 7 for every selector that
disagrees. That is not what drift looks like.

| | doc (15 pages) | article (7 pages) |
|---|---|---|
| `h2` | 1.3rem, rule underneath | 1.6rem, no rule |
| `p` | `color: var(--light-slate)` | inherits |
| `ul` | coloured, `padding-left: 1.5rem` | `margin: 0 0 1rem 1.25rem` |
| `a` | `text-decoration: none` | underlined |
| `.hero h1` | fixed 2.5rem | `clamp(2rem, 5vw, 3rem)` |
| `html` | — | `scroll-behavior: smooth` |

Merging them into one sheet would have restyled 21 pages. They are two files.

## --blue-bright: one definition, and it was never a bug

The doc pages omit the token from `:root` and write
`var(--blue-bright, #57cbff)` at its single consumer. The article pages define
it and write `var(--blue-bright)`. **Identical rendered colour, two spellings.**

It is now defined once in the shared `:root` and the fallback is gone. That
had to happen BEFORE the families were compared — doing it after leaves
`var(--blue-bright)` referenced with nothing defining it, which is what the
first attempt shipped into the working tree.

## Rules that stayed page-local

| selector | pages | why |
|---|---|---|
| `.cform` | 1 | the contact form, one page |
| `.cform label` | 1 | the contact form, one page |
| `.cform input, .cform textarea` | 1 | the contact form, one page |
| `.cform textarea` | 1 | the contact form, one page |
| `.cform input:focus, .cform textarea:focus` | 1 | the contact form, one page |
| `.cform .req` | 1 | the contact form, one page |
| `.cform button` | 1 | the contact form, one page |
| `.cform-status` | 1 | the contact form, one page |
| `.cform-status.ok` | 1 | the contact form, one page |
| `.cform-status.err` | 1 | the contact form, one page |
| `.hp` | 1 | the contact form, one page |
| `.sched` | 1 | the contact form, one page |
| `.calendly-inline-widget` | 2 | two pages, different values |
| `.om-track h2` | 1 | differs between the two pages that use it |
| `.om-track h3` | 6 | differs between the two pages that use it |
| `.p21-schedule` | 1 | the P21 scheduling block, one page |
| `.p21-schedule h2` | 1 | the P21 scheduling block, one page |
| `.p21-schedule > p` | 1 | the P21 scheduling block, one page |
| `code` | 1 | element selector, one page |

## The two bugs the verification caught

The acceptance test compares, for every page, the effective declaration of
every property before and after. It failed twice before it passed.

**1. Hoisting a class rule onto pages that have the markup.** The first pass
assumed a class-rooted selector was inert wherever it was not defined. It is
not: `@media (max-width: 768px) .hero h1` and `.content` existed only on the
doc pages, and the article pages have that markup and deliberately had no
768px rule for it. Hoisting changed their mobile rendering. All seven failed.
The hoist now requires the class to be genuinely absent from the HTML of every
page that does not define the rule.

**2. Reading only the largest <style> block.** /contact keeps its 1280px nav
rule in a SECOND block. Reading only the biggest one made /contact look like
the single page in scope lacking that rule — and one non-holder that HAS the
markup was enough to stop `.nav-links` and `.mobile-menu-btn` hoisting for the
other twenty. The emitter and the verifier now read the same thing.

## The one that would have taken the site down

publish-gate.ts is deny-by-default and `ALLOW_EXT` covers
svg/png/jpg/webp/avif/gif/ico/woff2 — **not .css**. All three stylesheets would
have 404`d and every page would have rendered unstyled, from a commit whose
diff reads as a tidy-up. Nothing in the suite would have said a word.

`ALLOW_ASSET_CSS` now allows .css under /assets/ and nowhere else, and
**SS-106** replays that pattern from the gate`s own source against every
`<link rel="stylesheet">`, checking both that the file exists and that the gate
would serve it. Either alone is a false negative.

## Verification result

All 22 pages: every selector and every declaration accounted for. 66 additions
were class selectors whose markup the page cannot match, reported separately
rather than counted as equivalent.

The one intended difference is `--blue-bright` in `:root`, described above.
