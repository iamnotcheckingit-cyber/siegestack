const BLOCKED_IPS = [
  "27.102.129.111",
  "43.130.3.120",
  "43.153.76.247",
  "49.51.36.179"
];

export default async (request, context) => {
  const clientIP = context.ip;

  if (BLOCKED_IPS.includes(clientIP)) {
    return new Response("Access Denied", { status: 403 });
  }

  return context.next();
};

export const config = { path: "/*" };
