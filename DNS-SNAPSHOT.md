# DNS snapshot — siegestack.com

Captured 2026-08-15 21:20 from public resolvers, immediately before the zone was
rebuilt. Keep this as the restore point. DNS is public information, so nothing
here is sensitive.

## What was live at capture time

| Name | Type | Value | Status |
|---|---|---|---|
| `siegestack.com` | `A` | `18.208.88.157`, `98.84.224.111` | ✅ **the website — must survive** |
| `www.siegestack.com` | `A` | `18.208.88.157`, `98.84.224.111` | ✅ **the website — must survive** |
| `siegestack.com` | `NS` | `dns1–dns4.p04.nsone.net` | ✅ Netlify DNS (NS1) |
| `siegestack.com` | `MX` | `10 mx1.improvmx.com`, `20 mx2.improvmx.com` | ✅ correct |
| `siegestack.com` | `TXT` | `v=spf1 include:spf.improvmx.com ~all` | ✅ correct |
| `_dmarc.siegestack.com` | `TXT` | `v=DMARC1; p=quarantine` | ⚠️ see below |
| `dkimprovmx1._domainkey` | `CNAME` | `dkimprovmx1._domainkey.send.siegestack.com` | ❌ **broken** |
| `dkimprovmx2._domainkey` | `CNAME` | `dkimprovmx2._domainkey.send.siegestack.com` | ❌ **broken** |

A second, conflicting `MX` set also existed at capture time —
`10 mx1.send.siegestack.com` / `20 mx2.send.siegestack.com` — returned
intermittently by different NS1 servers. That duplicate is what made delivery a
coin flip and made the ImprovMX panel show green while sending still failed.

`send.siegestack.com` is `NXDOMAIN`. Every record pointing at it was dead.

## What it should be

| Name | Type | Value |
|---|---|---|
| `siegestack.com` | `A` | `18.208.88.157`, `98.84.224.111` |
| `www` | `A` | `18.208.88.157`, `98.84.224.111` |
| `@` | `MX` 10 | `mx1.improvmx.com` |
| `@` | `MX` 20 | `mx2.improvmx.com` |
| `@` | `TXT` | `v=spf1 include:spf.improvmx.com ~all` |
| `dkimprovmx1._domainkey` | `CNAME` | `dkimprovmx1.improvmx.com` |
| `dkimprovmx2._domainkey` | `CNAME` | `dkimprovmx2.improvmx.com` |
| `_dmarc` | `TXT` | `v=DMARC1; p=none` while re-establishing |

Verified against `safesapcrtx.org`, which uses the same provider and works.

## Rules for the rebuild

1. **The `A` records are the website.** If the zone is deleted rather than
   edited, they must go back or the site goes down. They are not mail records
   and nothing about the mail problem required touching them.
2. **Nothing may reference `send.siegestack.com`.** That subdomain does not
   exist. It came from the Resend "verify a subdomain" route, which was never
   used and is not needed with ImprovMX SMTP.
3. **One MX pair only.** The original failure was not a wrong value, it was two
   value sets coexisting, so adding a correct record without deleting the wrong
   one reproduces the bug exactly.
4. **DMARC back to `p=none` until sending is confirmed.** It is currently
   `p=quarantine`, which instructs receivers to quarantine anything failing
   alignment — unhelpful while DKIM is being re-established. Tighten it again
   afterwards.
5. Allow up to an hour for the 3600s TTL, and verify against a public resolver
   rather than the provider's own panel. The panel showed green throughout the
   outage because it happened to get the good half of a flapping answer.
