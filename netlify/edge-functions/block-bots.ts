import type { Context } from "https://edge.netlify.com";

// Blocked subnets (prefix match)
const BLOCKED_SUBNETS = [
  "103.",    // 103.0.0.0/8
  "47.",     // 47.0.0.0/8
  "43.",     // 43.0.0.0/8
  "49.51.",  // Known bot range
  "101.32.", // Known bot range
];

// Whitelist - always allow (Google, Bing crawlers)
const ALLOWED_PREFIXES = [
  "66.249.", "66.102.", "64.233.", "72.14.", "74.125.",
  "209.85.", "216.239.", "108.177.", "142.250.", "172.217.", "216.58.",
  "40.77.", "157.55.", "207.46.", "13.66.", "52.167.",
];

// Allowed countries
const ALLOWED_COUNTRIES = [
  "US", "CA", "GB", "IE", "DE", "FR", "NL", "BE", "AT",
  "CH", "IT", "ES", "PT", "SE", "NO", "DK", "FI", "PL", "CZ",
  "AU", "NZ", "JP", "SG", "KR"
];

export default async (request: Request, context: Context) => {
  const clientIP = context.ip || "";
  const country = context.geo?.country?.code || "";

  // 1. Whitelist check - let crawlers through
  for (const prefix of ALLOWED_PREFIXES) {
    if (clientIP.startsWith(prefix)) {
      return context.next();
    }
  }

  // 2. Block bad subnets
  for (const subnet of BLOCKED_SUBNETS) {
    if (clientIP.startsWith(subnet)) {
      return new Response("Access Denied", { status: 403 });
    }
  }

  // 3. Geo block - only allow specific countries
  if (country && !ALLOWED_COUNTRIES.includes(country)) {
    return new Response("Access Denied", { status: 403 });
  }

  return context.next();
};
