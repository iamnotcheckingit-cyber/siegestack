# Mail setup for siegestack.com

Two separate jobs, easy to conflate, and conflating them breaks the working one.

| | Inbound (receiving) | Outbound (sending) |
|---|---|---|
| Who | ImprovMX | ImprovMX SMTP (same vendor) |
| Used by | the `mailto:` links across the site | the `/contact` form notification |
| Status | **working** | **code ready, env vars not set** |

ImprovMX forwards mail *to* you. Forwarding alone does not send mail *for* you
— but the paid tier adds SMTP, which does, and that is now the recommended
route because it needs no second vendor and no new DNS.

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

Set five variables in Netlify, **scoped to Functions**, then redeploy.

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
```

`CONTACT_TO` is optional and defaults to `info@siegestack.com`. Port 465 also
works and is selected automatically as implicit TLS; 587 upgrades via STARTTLS.

SMTP takes precedence over Resend when both are configured.

**The timeout matters more than the credentials here.** Netlify kills a
synchronous function at 10s and nothing in this repo raises that. SMTP is a
multi-round-trip handshake and can sit there. If the send outlives the function,
the request dies *after* the submission was stored, and the page tells the
sender it failed when it did not — the worst outcome available, because it
invites them to give up on a message you are holding.

So the notification gets a hard 6-second budget, enforced both by nodemailer's
own connection/greeting/socket timeouts and by an outer race, and the transport
is closed in a `finally`. A timeout set at or above the platform ceiling can
never fire; that is exactly how this went wrong on the other site. Tested by
making the transport hang for 60 seconds: it gave up at 6.6s, the request
returned 200, and the submission was stored.

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
