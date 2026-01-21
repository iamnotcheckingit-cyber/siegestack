// WHITELIST - Always allow these (checked first)
const ALLOWED_PREFIXES = [
  // Google crawlers
  "66.249.",    // Googlebot
  "66.102.",    // Google
  "64.233.",    // Google
  "72.14.",     // Google
  "74.125.",    // Google
  "209.85.",    // Google
  "216.239.",   // Google
  "108.177.",   // Google
  "142.250.",   // Google
  "172.217.",   // Google
  "216.58.",    // Google
  // Bing crawlers
  "40.77.",     // Bingbot
  "157.55.",    // Bingbot
  "207.46.",    // Bingbot
  "13.66.",     // Bing
  "52.167.",    // Bing
  // Problem user - allow while investigating
  "2600:100d:a0ed:733b:",
  // AWS/monitoring (legitimate services)
  "34.252.",
  "23.23.",
  "34.227.",
  "34.228."
];

// Blocked individual IPs
const BLOCKED_IPS = [
  "27.102.129.111"
];

// Blocked IP prefixes (subnets)
const BLOCKED_SUBNETS = [
  "103.",  // 103.0.0.0/8
  "47.",   // 47.0.0.0/8
  "43.",   // 43.0.0.0/8 (Tencent cloud bots)
  "49.51." // Known bot range
];

// Allowed countries (block everything else)
const ALLOWED_COUNTRIES = [
  "US", "CA", "GB", "IE",           // North America + UK/Ireland
  "DE", "FR", "NL", "BE", "AT",     // Western Europe
  "CH", "IT", "ES", "PT", "SE",     // More Europe
  "NO", "DK", "FI", "PL", "CZ",     // Northern/Central Europe
  "AU", "NZ",                        // Australia/NZ
  "JP", "SG", "KR"                   // Trusted Asia-Pacific
];

export default async (request, context) => {
  const clientIP = context.ip || "";
  const country = context.geo?.country?.code || "";

  // WHITELIST CHECK FIRST - Always allow Google, Bing, etc.
  for (const prefix of ALLOWED_PREFIXES) {
    if (clientIP.startsWith(prefix)) {
      return context.next();
    }
  }

  // Block specific IPs
  if (BLOCKED_IPS.includes(clientIP)) {
    return new Response("Access Denied", { status: 403 });
  }

  // Block subnets
  for (const subnet of BLOCKED_SUBNETS) {
    if (clientIP.startsWith(subnet)) {
      return new Response("Access Denied", { status: 403 });
    }
  }

  // Geographic blocking (skip if no country detected)
  if (country && !ALLOWED_COUNTRIES.includes(country)) {
    return new Response("Service not available in your region", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
