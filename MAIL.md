# Mail setup for siegestack.com

Two separate jobs, easy to conflate, and conflating them breaks the working one.

| | Inbound (receiving) | Outbound (sending) |
|---|---|---|
| Who | ImprovMX | ImprovMX SMTP (same vendor) |
| Used by | the `mailto:` links across the site | the `/contact` and `/api/expertise` form notifications |
| Status | **working** | **working** — delivery confirmed 2026-08-16 |

ImprovMX forwards mail *to* you. Forwarding alone does not send mail *for* you
— but the paid tier adds SMTP, which does, and that is now the recommended
route because it needs no second vendor and no new DNS.

## Where this stands

Outbound was wired on 2026-08-15 over the course of one long evening. What is
established, and what is not:

- **The SMTP variables are set in Netlify, scoped to Functions, and the site has
  been rebuilt since.** `SMTP_PASS` was corrected once during that evening; a
  rebuild is what carries a changed value into `process.env` inside a function.
- **The zone was rebuilt** to clear a duplicate `MX` set and a group of records
  pointing at a `send.siegestack.com` that does not exist. `DNS-SNAPSHOT.md`
  holds the before-state and the rules that rebuild followed.
- **The send budget was raised from 6s to 8s** because real ImprovMX handshakes
  were intermittently exceeding six seconds and losing notifications that would
  otherwise have gone out.
- **The SMTP send itself works.** Re-tested live on 2026-08-16: two of three
  submissions returned `notified:true`, so authentication, the envelope and the
  loop guard are all past and the credentials are good.
- **It is unreliable, and that is a latency problem rather than a mail
  problem.** The third of those three exceeded the 8s budget. See the budget
  discussion under Option A — the number cannot go higher, so either the misses
  are accepted or the notification moves off the request path.
- **Delivery is confirmed.** The 2026-08-16 test notifications arrived in the
  destination mailbox. Acceptance by the provider and delivery to a human are
  different claims and both now have evidence behind them, so the chain is good
  end to end: SPF, DKIM, the envelope, the forwarder and the mailbox.
  `notified:true` in a response can from here be read as "it got there",
  which was not a safe reading before.

## What is provisioned today

Verified against two independent resolvers on 2026-08-15 and re-verified after
the zone rebuild on 2026-08-16:

| Record | Value |
|---|---|
| `MX` | `10 mx1.improvmx.com`, `20 mx2.improvmx.com` |
| `TXT` (SPF) | `v=spf1 include:spf.improvmx.com ~all` |
| `CNAME` | `dkimprovmx1._domainkey` → `dkimprovmx1.improvmx.com` |
| `CNAME` | `dkimprovmx2._domainkey` → `dkimprovmx2.improvmx.com` |
| `TXT` | `_dmarc` → `v=DMARC1; p=none;` |

One `MX` pair only, and `send.siegestack.com` is `NXDOMAIN` — both of which are
the point, per rules 2 and 3 in `DNS-SNAPSHOT.md`. Check both whenever mail
behaviour goes strange again: the original failure was two `MX` sets coexisting,
which reads as intermittent rather than broken.

`info@siegestack.com` and `scott@siegestack.com` both deliver.

## The collision to avoid (applies to Option C only)

Skip this section if you use ImprovMX SMTP or Resend without a domain. It
matters only when verifying a THIRD-PARTY sender on this domain.

**Verify any outbound provider on a subdomain, not the root.**

Providers like Resend want their own `MX` record for bounce handling. Putting
that on the root domain replaces or competes with `mx1/mx2.improvmx.com` and
**silently breaks inbound forwarding** — mail to `info@` starts disappearing,
and nothing announces it.

Use `send.siegestack.com`. The root keeps ImprovMX; the subdomain gets the
sender. DKIM selectors do not collide either way (`resend._domainkey` vs
`dkimprovmx1/2._domainkey`), so DKIM is not the risk here — the MX is.

## Wiring outbound

### Option A — ImprovMX SMTP (start here if you have the paid tier)

This is the best route when it is available, and an earlier version of this file
talked you out of it for a weak reason. ImprovMX already handles this domain's
mail and its SPF and DKIM already cover the domain, so the notification can come
**from `info@siegestack.com`** legitimately. No second vendor, no second
account, and **no new DNS**, which means no way to disturb the MX records that
make the forwarding work.

Set six variables in Netlify, **scoped to Functions**, then redeploy.

**Do not paste the real values into this file or any other file in the repo.**
Netlify's secrets scanner fails the build when an env var's value appears in
repo content, and it does not care whether the value is actually sensitive —
writing the SMTP hostname into this document broke every build until it was
taken out again.

Values come from the ImprovMX console:

```
SMTP_HOST    = <the SMTP host shown in the ImprovMX console>
SMTP_PORT    = 587
SMTP_USER    = <the full alias, as shown in the console>
SMTP_PASS    = the SMTP password from the ImprovMX console
CONTACT_FROM = SiegeStack <that same alias>
CONTACT_TO   = <the mailbox that alias forwards to — NOT on siegestack.com>
```

**`CONTACT_TO` is required and has no default.** An earlier version of this file
said it was optional and fell back to `info@siegestack.com`. That default is
what produced the `550`, so the function no longer has one: with a provider
configured and `CONTACT_TO` unset it declines to send and reports
`reason: no_to` rather than quietly constructing a destination that cannot work.

The reason the obvious default is wrong: ImprovMX is a forwarder. Mail sent to
the alias is relayed onward, so asking it to send *from* the alias *to* an
address it forwards asks it to feed its own forwarder, and it rejects that.

**The guard is the whole domain, not just the one address.** Setting
`CONTACT_TO` to `scott@siegestack.com` while sending from `info@siegestack.com`
is the same loop and is refused the same way — the function compares the domain
of each and reports `reason: to_equals_from` (the code name is narrower than the
check). `CONTACT_TO` has to be a mailbox somewhere else entirely, which is the
address the alias forwards to anyway.

That guard applies to the SMTP path only. Under Option B or C the destination
never passes back through ImprovMX, so a `siegestack.com` address is fine there.

Port 465 also works and is selected automatically as implicit TLS; 587 upgrades
via STARTTLS.

SMTP takes precedence over Resend when both are configured.

**The timeout matters more than the credentials here.** Netlify kills a
synchronous function at 10s and nothing in this repo raises that. SMTP is a
multi-round-trip handshake and can sit there. If the send outlives the function,
the request dies *after* the submission was stored, and the page tells the
sender it failed when it did not — the worst outcome available, because it
invites them to give up on a message you are holding.

So the notification gets a hard **8-second** budget, enforced both by
nodemailer's own connection/greeting/socket timeouts and by an outer race, and
the transport is closed in a `finally`. A timeout set at or above the platform
ceiling can never fire; that is exactly how this went wrong on the other site.

The mechanism was tested at the original 6s setting by making the transport hang
for 60 seconds: it gave up at 6.6s, the request returned 200, and the submission
was stored — so the outer race costs about 0.6s beyond the budget it enforces,
and 8s lands near 8.6s worst case, inside the 10s ceiling.

**It is 8s rather than 6s because 6s was measurably too tight.** ImprovMX
intermittently takes longer than six seconds to complete a handshake on a cold
connection, and the tighter budget was dropping notifications that would have
been delivered. A timeout here costs a missed page, never a lost submission,
because the durable write has already happened by the time any of this runs.

**8s is still too tight, and raising it again is not the fix.** Three live
submissions on 2026-08-16 took 2.5s, 7.4s and 8.6s — the last one exceeded the
budget and reported `smtp_unknown`. ImprovMX's handshake latency is simply that
variable. But 8.6s against a 10s platform ceiling leaves under 1.4s, and going
over the ceiling is the catastrophic case this whole file exists to avoid: the
request dies *after* the submission was stored and the page tells the sender it
failed. **Do not raise `NOTIFY_BUDGET_MS` past 8s.**

The real options are to accept a missed page on roughly a third of submissions —
which loses nothing, only immediacy — or to move the notification off the
request path entirely, into a background function or a queue, where a slow
handshake costs nobody anything. That is unbuilt.

### Option B — Resend with no DNS at all

Resend lets you send from its own `onboarding@resend.dev` address **to the email
you signed up with**, without verifying any domain. For a notification that only
ever goes to you, that is the entire requirement.

1. Create a Resend account using the address you want notifications at.
2. Copy an API key.
3. Set three variables in Netlify, **scoped to Functions**, and redeploy:

   ```
   RESEND_API_KEY = re_...
   CONTACT_FROM   = SiegeStack <onboarding@resend.dev>
   CONTACT_TO     = the address you signed up with
   ```

That is it. **No DNS records, so no possibility of disturbing the ImprovMX MX
records** and no chance of breaking the forwarding that already works.

The limits: it can only deliver to your own account address, and the From line
says `resend.dev`. Neither matters for a message from your own server to you.
Worth confirming the current free-tier terms in the dashboard rather than
trusting this file — providers change these.

### Option C — Resend with a verified domain

Only needed if you are on Resend AND notifications must come from siegestack.com
rather than resend.dev. Not needed at all if you use Option A.

1. **Verify `send.siegestack.com` in Resend.** It will give you three records to
   add — copy the values from its dashboard, they are account and region
   specific:

   - `MX` on `send` → `feedback-smtp.<region>.amazonses.com`, priority 10
   - `TXT` on `send` → `v=spf1 include:amazonses.com ~all`
   - `TXT` on `resend._domainkey.send` → the public key it shows you

   Add these to the **subdomain**. Do not touch the root records in the table
   above.

2. **Set three Netlify environment variables, scoped to Functions** (not just
   Builds — the build seeing a value tells you nothing about `process.env`
   inside a function, and that trap has cost an evening before):

   ```
   RESEND_API_KEY = re_...
   CONTACT_FROM   = SiegeStack <hello@send.siegestack.com>
   CONTACT_TO     = info@siegestack.com
   ```

   `CONTACT_FROM` has **no default on purpose**. The obvious one —
   `info@siegestack.com` — is on the root domain, which the provider will not
   have verified, so it would 403 on every send. Rather than fail that way, the
   function refuses to attempt the send and logs
   `CONTACT_NOTIFY_MISCONFIGURED` naming the fix.

   `CONTACT_TO` is **required and has no default either**, for the reason given
   under Option A. `info@siegestack.com` is the right value *here* though: it is
   an inbound address, ImprovMX forwards it, it needs no verification, and the
   same-domain loop guard does not apply on this path because the mail leaves
   through Resend rather than back through the forwarder.

3. **Redeploy.** Changing variable scope does not retroactively fix a deploy
   that was already built.

## Two functions use these variables, not one

`netlify/functions/contact-api.mjs` (`/api/contact`) and
`netlify/functions/submit-expertise.mjs` (`/api/expertise`, the consultant
matrix on `/consultant-expertise`) share the same six variables and the same
notification code. Nothing extra needs setting for the second one — but it also
means a wrong value breaks both at once, and a fix to the notification block in
one file has to be applied to the other. Both files carry that notice at the
top.

The log events are prefixed differently, so they can be told apart:
`CONTACT_*` versus `EXPERTISE_*`.

`npm test` exercises the shared notification logic through the expertise
function without deploying anything — every `reason` branch, the loop guard, the
redaction, and a hanging transport giving up at the budget. `npm run
test:defects` proves the suite still fails on deliberately broken code, which is
the only thing that makes a pass worth anything. Run both before changing either
function.

## Diagnosing it from outside

The endpoint returns a coarse `reason` alongside `notified`, so a
misconfiguration is one `curl` away rather than a dashboard session:

| `reason` | Meaning |
|---|---|
| *(absent, `notified:true`)* | Sent. |
| `no_provider` | Neither `SMTP_HOST` nor `RESEND_API_KEY` is visible to the function. Usually a Builds-only variable scope, or no rebuild since setting them. |
| `no_to` | A provider is configured but `CONTACT_TO` is not. It has no default — see Option A. |
| `no_from` | A provider is configured but `CONTACT_FROM` is not. |
| `to_equals_from` | `CONTACT_TO` is on the same *domain* as `CONTACT_FROM`. SMTP path only. See above. |
| `smtp_eauth_535` | Credentials rejected. Wrong SMTP password. |
| `smtp_esocket*` / `smtp_econnection*` | The port never opened. Wrong host or port. |
| `smtp_etimedout*` | Opened, then sat there. Nodemailer's own socket timeout fired. |
| `smtp_unknown` with `smtpSaid: "smtp exceeded 8000ms"` | The **outer race** gave up at the 8s budget. This is the common timeout in practice, not `smtp_etimedout` — the race rejects with a plain `Error` carrying no `code`, so the reason falls through to `unknown`. Nothing is wrong with the credentials. |
| `smtp_emessage_550` | The provider refused the envelope — most often the loop above. |
| `http_<status>` | Resend path only. Resend answered with that status. |
| `resend_failed` | Resend path only. The request threw or outran the budget. |

The codes are checked in that order, so `no_to` masks `no_from` when both are
unset — fix them together rather than one per deploy.

SMTP failures also return **`smtpSaid`**: up to 160 characters of the mail
server's own response, with anything that looks like an address stripped out.
It is the only thing that distinguishes one `550` from another, and it is worth
reading before theorising.

```
curl -s -X POST https://siegestack.com/api/contact \
  -H "content-type: application/json" \
  -d '{"email":"you@example.com","message":"test"}'
```

It stores a real submission each time, so delete the test entries afterwards.

## What happens with outbound unwired

Nothing is lost. The form writes to the `siegestack-contact` blob store first
and only then attempts a notification, so submissions are captured whether or
not mail works — that ordering is the whole point, and it is the claim the
homepage makes under "Forms That Don't Lose Submissions".

The cost of leaving it unwired is not data. It is **latency**: nobody is paged,
so a submission sits until someone goes looking. The function logs
`CONTACT_RECEIVED` with the stored key on every submission, so Netlify's
function logs are the interim inbox.

## Worth doing later

`_dmarc` is `p=none`, which is monitor-only: it publishes a policy and asks
receivers to do nothing about failures. **It was `p=quarantine` before the
2026-08-15 zone rebuild and was deliberately relaxed** — quarantine tells
receivers to hold anything failing alignment, which is the wrong instruction
while DKIM is being re-established (`DNS-SNAPSHOT.md`, rule 4). So this is a
knowing, temporary setting, not an oversight.

**The first condition is now met: delivery was confirmed 2026-08-16.** What is
left is the "for a while" part. The zone was rebuilt on 2026-08-15, so DKIM has
one day of history behind it, and `p=quarantine` instructs receivers to hold
anything failing alignment — including mail from a sender nobody remembered was
there. Give it a week of ordinary traffic first, then set:

```
_dmarc  TXT  v=DMARC1; p=quarantine
```

Netlify DNS cannot edit a record in place — it has to be deleted and recreated,
which is a moment where the zone has no DMARC record at all. That is harmless
for a minute and is not worth avoiding, but do it deliberately rather than
discovering it halfway through.

Consider adding `rua=mailto:` first and reading a week of aggregate reports.
That turns "I think everything is aligned" into a list of every sender using
this domain, which is the actual question `p=quarantine` is betting on.
