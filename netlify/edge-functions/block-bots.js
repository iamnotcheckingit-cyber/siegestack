// RATE LIMITING - 60 requests per minute per IP
const RATE_LIMIT = 60;
const RATE_WINDOW = 60000; // 1 minute in ms
const requestCounts = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const record = requestCounts.get(ip);

  if (!record || now - record.timestamp > RATE_WINDOW) {
    requestCounts.set(ip, { count: 1, timestamp: now });
    return true;
  }

  record.count++;
  if (record.count > RATE_LIMIT) {
    return false;
  }
  return true;
}

// Clean old entries periodically (prevent memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of requestCounts) {
    if (now - record.timestamp > RATE_WINDOW) {
      requestCounts.delete(ip);
    }
  }
}, 60000);

// WHITELIST - Always allow these (checked first)
const ALLOWED_PREFIXES = [
  // Google crawlers
  "66.249.", "66.102.", "64.233.", "72.14.", "74.125.",
  "209.85.", "216.239.", "108.177.", "142.250.", "172.217.", "216.58.",
  // Bing crawlers
  "40.77.", "157.55.", "207.46.", "13.66.", "52.167.",
  // Problem user - investigating
  "2600:100d:a0ed:733b:",
  // AWS/monitoring
  "34.252.", "23.23.", "34.227.", "34.228."
];

// Blocked individual IPs
const BLOCKED_IPS = ["27.102.129.111"];

// Blocked subnets
const BLOCKED_SUBNETS = [
  "103.",  // 103.0.0.0/8
  "47.",   // 47.0.0.0/8
  "43.",   // 43.0.0.0/8
  "49.51." // Known bot range
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

  // WHITELIST - Always allow Google, Bing, etc.
  for (const prefix of ALLOWED_PREFIXES) {
    if (clientIP.startsWith(prefix)) {
      return context.next();
    }
  }

  // RATE LIMIT CHECK
  if (!checkRateLimit(clientIP)) {
    return new Response("Rate limit exceeded. Try again later.", {
      status: 429,
      headers: { "Retry-After": "60" }
    });
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

  // Geographic blocking
  if (country && !ALLOWED_COUNTRIES.includes(country)) {
    return new Response("Service not available in your region", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
