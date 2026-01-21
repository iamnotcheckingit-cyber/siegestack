const BLOCKED_IPS = [
  "27.102.129.111"
];

export default async (request, context) => {
  const clientIP = context.ip;

  if (BLOCKED_IPS.includes(clientIP)) {
    return new Response("Access Denied", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
