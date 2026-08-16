# Mail setup for siegestack.com

Two separate jobs, easy to conflate, and conflating them breaks the working one.

| | Inbound (receiving) | Outbound (sending) |
|---|---|---|
| Who | ImprovMX | not configured yet |
| Used by | the `mailto:` links across the site | the `/contact` form notification |
| Status | **working** | **not wired** |

ImprovMX forwards mail *to* you. It does not send mail *for* you. Wiring the
contact form's notification is a separate provider and a separate set of DNS
records.

## What is provisioned today

Verified against two independent resolvers on 2026-08-15:

| Record | Value |
|---|---|
| `MX` | `10 mx1.improvmx.com`, `20 mx2.improvmx.com` |
| `TXT` (SPF) | `v=spf1 include:spf.improvmx.com ~all` |
| `CNAME` | `dkimprovmx1._domainkey` → `dkimprovmx1.improvmx.com` |
| `CNAME` | `dkimprovmx2._domainkey` → `dkimprovmx2.improvmx.com` |
| `TXT` | `_dmarc` → `v=DMARC1; p=none` |

`info@siegestack.com` and `scott@siegestack.com` both deliver.

## The collision to avoid

**Verify any outbound provider on a subdomain, not the root.**

Providers like Resend want their own `MX` record for bounce handling. Putting
that on the root domain replaces or competes with `mx1/mx2.improvmx.com` and
**silently breaks inbound forwarding** — mail to `info@` starts disappearing,
and nothing announces it.

Use `send.siegestack.com`. The root keeps ImprovMX; the subdomain gets the
sender. DKIM selectors do not collide either way (`resend._domainkey` vs
`dkimprovmx1/2._domainkey`), so DKIM is not the risk here — the MX is.

## Wiring outbound — the short way first

**ImprovMX being set up does not contribute to this.** It is inbound. Outbound
is a separate provider. (ImprovMX's paid tier does include SMTP sending, which
would avoid a second vendor entirely — but a Netlify Function cannot speak raw
SMTP without adding a library, so it is not the cheap option here.)

### Option A — no DNS at all (start here)

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

### Option B — your own domain on the From line

Only needed if notifications must come *from* siegestack.com, or go to someone
other than you.

1. **Verify `send.siegestack.com` in Resend.** It will give you three records to
   add — copy the values from its dashboard, they are account and region
   specific:

   - `MX` on `send` → `feedback-smtp.<region>.amazonses.com`, priority 10
   - `TXT` on `send` → `v=spf1 include:amazonses.com ~all`
   - `TXT` on `resend._domainkey.send` → the public key it shows you

   Add these to the **subdomain**. Do not touch the root records in the table
   above.

2. **Set two Netlify environment variables, scoped to Functions** (not just
   Builds — the build seeing a value tells you nothing about `process.env`
   inside a function, and that trap has cost an evening before):

   ```
   RESEND_API_KEY = re_...
   CONTACT_FROM   = SiegeStack <hello@send.siegestack.com>
   ```

   `CONTACT_FROM` has **no default on purpose**. The obvious one —
   `info@siegestack.com` — is on the root domain, which the provider will not
   have verified, so it would 403 on every send. Rather than fail that way, the
   function refuses to attempt the send and logs
   `CONTACT_NOTIFY_MISCONFIGURED` naming the fix.

   `CONTACT_TO` is optional and defaults to `info@siegestack.com`. That one is
   inbound, ImprovMX forwards it, and it needs no verification.

3. **Redeploy.** Changing variable scope does not retroactively fix a deploy
   that was already built.

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
receivers to do nothing about failures. That is the correct setting while you
are still adding senders. Once outbound is verified and stable, tighten it to
`p=quarantine` — until then the domain is not actually protected from spoofing.
