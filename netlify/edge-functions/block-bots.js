// WHITELIST - Always allow these (checked first)
const ALLOWED_PREFIXES = [
  // Google crawlers
  "66.249.", "66.102.", "64.233.", "72.14.", "74.125.",
  "209.85.", "216.239.", "108.177.", "142.250.", "172.217.", "216.58.",
  // Bing crawlers
  "40.77.", "157.55.", "207.46.", "13.66.", "52.167.",
  // AWS/monitoring
  "34.252.", "23.23.", "34.227.", "34.228."
];

// Blocked individual IPs
const BLOCKED_IPS = [
  "27.102.129.111",
  "103.42.183.153",
  "47.238.156.95",
  "43.155.188.157",
  "101.32.209.4",
  "49.51.183.84"
];

// Blocked subnets (checked with startsWith)
const BLOCKED_SUBNETS = [
  "103.",   // 103.0.0.0/8
  "47.",    // 47.0.0.0/8
  "43.",    // 43.0.0.0/8
  "49.51.", // Known bot range
  "101.32." // Known bot range
];

// Allowed countries only
const ALLOWED_COUNTRIES = [
  "US", "CA", "GB", "IE", "DE", "FR", "NL", "BE", "AT",
  "CH", "IT", "ES", "PT", "SE", "NO", "DK", "FI", "PL", "CZ",
  "AU", "NZ", "JP", "SG", "KR"
];

export default async (request, context) => {
  const clientIP = context.ip || "";
  const country = context.geo?.country?.code || "";

  // 1. WHITELIST - Always allow Google, Bing, etc.
  for (const prefix of ALLOWED_PREFIXES) {
    if (clientIP.startsWith(prefix)) {
      return context.next();
    }
  }

  // 2. Block specific IPs (exact match)
  if (BLOCKED_IPS.includes(clientIP)) {
    return new Response("Access Denied", { status: 403 });
  }

  // 3. Block subnets (prefix match)
  for (const subnet of BLOCKED_SUBNETS) {
    if (clientIP.startsWith(subnet)) {
      return new Response("Access Denied", { status: 403 });
    }
  }

  // 4. Geographic blocking - block if country known and not allowed
  if (country && !ALLOWED_COUNTRIES.includes(country)) {
    return new Response("Service not available in your region", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
