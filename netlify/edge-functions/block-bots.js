// Blocked individual IPs
const BLOCKED_IPS = [
  "27.102.129.111",
  "43.130.3.120",
  "43.153.76.247",
  "49.51.36.179"
];

// Blocked IP prefixes (subnets)
const BLOCKED_SUBNETS = [
  "103.",  // 103.0.0.0/8
  "47.",   // 47.0.0.0/8
  "43.",   // 43.0.0.0/8 (Tencent cloud - heavy bot traffic)
  "49.51" // Known bot range
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

  // Geographic blocking (skip if no country detected - might be legitimate)
  if (country && !ALLOWED_COUNTRIES.includes(country)) {
    return new Response("Service not available in your region", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
