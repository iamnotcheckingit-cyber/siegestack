/**
 * The private thread at /jesse. Two people, one channel, nothing ever deleted.
 *
 * WHAT THIS IS
 * ------------
 * A PIN-gated message thread between two people. It is not linked from
 * anywhere, not in the sitemap, and served noindex. Anyone who finds the URL by
 * accident gets a PIN prompt and nothing else -- no title, no names, no hint
 * about what is behind it.
 *
 * THREE DESIGN RULES, in the order they matter
 * --------------------------------------------
 * 1. NOTHING IS EVER LOST. Every message is its own blob under a
 *    timestamp-sorted key, written once and never read-modify-written. There is
 *    no index object to corrupt, no array to clobber, and no concurrent-write
 *    path that can drop a message. Deleting is not implemented, on purpose.
 *
 * 2. STORAGE HOLDS CIPHERTEXT. Message bodies are AES-256-GCM encrypted before
 *    they are written. Anyone reaching the storage layer sees random bytes and
 *    a timestamp. This is encryption AT REST, not end-to-end: this function
 *    holds the key and decrypts in order to answer a request. The honest threat
 *    model is "the blob store leaks", not "the server is hostile".
 *
 * 3. AUTHENTICATION IS SERVER-SIDE. This repository is PUBLIC. Every line here
 *    is readable by anyone, which is fine and expected -- the PINs live only in
 *    Netlify environment variables and are never committed. Nothing in the
 *    browser decides who gets in.
 *
 * CONFIGURATION
 * -------------
 *   DADS_PIN               required. Anything else is a locked door.
 *   JESSES_PIN             required.
 *   JESSE_SESSION_SECRET   optional. Signs session cookies. If unset, it is
 *                          derived from the two PINs -- which means changing a
 *                          PIN signs everyone out, and that is the correct
 *                          behaviour anyway.
 *   JESSE_MSG_KEY          optional. 32 bytes, hex or base64, for message
 *                          encryption. If unset it is derived from the two
 *                          PINs.
 *
 *                          *** READ THIS BEFORE CHANGING A PIN ***
 *                          With JESSE_MSG_KEY unset, the encryption key depends
 *                          on the PINs, so changing a PIN makes every existing
 *                          message permanently unreadable. Set JESSE_MSG_KEY
 *                          explicitly -- to the value printed by
 *                          `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
 *                          -- BEFORE you ever rotate a PIN, and rule 1 holds.
 *                          Undecryptable messages are surfaced, never dropped.
 */

import { getStore } from '@netlify/blobs';
import webpush from 'web-push';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const config = {
  path: [
    '/api/jesse/session',
    '/api/jesse/login',
    '/api/jesse/logout',
    '/api/jesse/messages',
    '/api/jesse/send',
    '/api/jesse/export',
    '/api/jesse/files',
    '/api/jesse/file',
    '/api/jesse/upload',
    '/api/jesse/push-key',
    '/api/jesse/subscribe',
    '/api/jesse/gif',
    '/api/jesse/gif-send',
  ],
};

const PEOPLE = {
  dad: { id: 'dad', name: 'Dad', pinVar: 'DADS_PIN' },
  jesse: { id: 'jesse', name: 'Jesse', pinVar: 'JESSES_PIN' },
};

const SESSION_DAYS = 30;
const MAX_MESSAGE_CHARS = 4000;
const PAGE_SIZE = 200;

// ---------------------------------------------------------------- key material

/**
 * Derived keys are namespaced by purpose so the session key and the message key
 * can never be the same bytes even though both fall back to the same PINs.
 */
function derive(purpose) {
  return crypto
    .createHash('sha256')
    .update(`siegestack/jesse/${purpose}|${process.env.DADS_PIN || ''}|${process.env.JESSES_PIN || ''}`)
    .digest();
}

function sessionKey() {
  const explicit = process.env.JESSE_SESSION_SECRET;
  return explicit ? crypto.createHash('sha256').update(explicit).digest() : derive('session');
}

function messageKey() {
  const raw = (process.env.JESSE_MSG_KEY || '').trim();
  if (!raw) return derive('messages');
  // Accept hex or base64 for whatever the key generator produced, but only at
  // exactly 32 bytes. A short key that silently got padded would be a weaker
  // cipher that still looked like it worked.
  const buf = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  if (buf.length !== 32) {
    console.error('JESSE_MSG_KEY is set but is not 32 bytes; falling back to the derived key');
    return derive('messages');
  }
  return buf;
}

// -------------------------------------------------------------------- crypto

function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', messageKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

/**
 * Same cipher, raw bytes, for uploaded files. Kept separate from encrypt()
 * because base64-ing a multi-megabyte file through a JSON envelope would inflate
 * it by a third for no reason -- the blob body holds ciphertext directly and the
 * iv/tag ride along in blob metadata.
 */
function encryptBytes(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', messageKey(), iv);
  const data = Buffer.concat([cipher.update(buf), cipher.final()]);
  return { data, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

function decryptBytes(data, iv, tag) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey(), Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(data)), decipher.final()]);
  } catch {
    return null;
  }
}

/**
 * Returns null rather than throwing on a bad key or tampered ciphertext. The
 * caller renders that as a visible placeholder in the thread: a message that
 * cannot be read must still be seen to exist. Silently skipping it would be a
 * message quietly disappearing, which rule 1 forbids.
 */
function decrypt(enc) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey(), Buffer.from(enc.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(enc.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(enc.ct, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------- sessions

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function equalBytes(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function issueToken(who) {
  const payload = b64u(JSON.stringify({ who, exp: Date.now() + SESSION_DAYS * 86400000 }));
  const sig = b64u(crypto.createHmac('sha256', sessionKey()).update(payload).digest());
  return `v1.${payload}.${sig}`;
}

function readToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  const expected = b64u(crypto.createHmac('sha256', sessionKey()).update(parts[1]).digest());
  if (!equalBytes(parts[2], expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!data.exp || data.exp < Date.now()) return null;
    return PEOPLE[data.who] || null;
  } catch {
    return null;
  }
}

function cookieValue(req, name) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > -1 && part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

const COOKIE = 'jesse_session';

function setCookie(token) {
  // SameSite=Lax rather than Strict: Strict withholds the cookie on a
  // click-through from a messaging app, so the page would demand the PIN again
  // every time one of us tapped the link we had just sent the other.
  return token
    ? `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
    : `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// -------------------------------------------------------------- brute force

const guardStore = () => getStore({ name: 'jesse-guard', consistency: 'strong' });

/**
 * Per-IP lockout. Six digits is a million combinations; four attempts per
 * lockout window with exponential backoff puts a full sweep well beyond any
 * practical attack, without ever locking out the two people who belong here for
 * more than a minute after a fat-fingered entry.
 *
 * The counter is keyed by a hash of the IP so the guard store never holds an
 * address in the clear.
 */
function guardKey(ip) {
  return `fail/${crypto.createHash('sha256').update(`jesse|${ip}`).digest('hex').slice(0, 32)}`;
}

async function lockoutRemaining(ip) {
  try {
    const rec = await guardStore().get(guardKey(ip), { type: 'json' });
    if (rec?.until && rec.until > Date.now()) return Math.ceil((rec.until - Date.now()) / 1000);
  } catch { /* the guard must never be the reason the door won't open */ }
  return 0;
}

async function recordFailure(ip) {
  try {
    const store = guardStore();
    const key = guardKey(ip);
    const rec = (await store.get(key, { type: 'json' })) || { n: 0 };
    const n = rec.n + 1;
    // Free swings for the first three, then 60s doubling to an hour.
    const wait = n <= 3 ? 0 : Math.min(60 * 2 ** (n - 4), 3600);
    await store.setJSON(key, { n, until: Date.now() + wait * 1000 });
    return wait;
  } catch {
    return 0;
  }
}

async function clearFailures(ip) {
  try {
    await guardStore().delete(guardKey(ip));
  } catch { /* nothing to do */ }
}

// --------------------------------------------------------------------- thread

const threadStore = () => getStore({ name: 'jesse-thread', consistency: 'strong' });

/**
 * Strictly increasing millisecond stamps.
 *
 * Date.now() alone is not enough. Two messages sent inside the same millisecond
 * get the same zero-padded prefix, and then the random suffix -- not the order
 * they were sent in -- decides how they sort. That is not theoretical: sending
 * three messages in quick succession reordered them in about one test run in
 * six. A thread that shuffles the order of what you said is a broken thread.
 *
 * Bumping past the last stamp guarantees order for anything this container
 * handles in sequence. Two containers writing in the very same millisecond can
 * still tie, but those messages are genuinely concurrent and any order is
 * honest; the random suffix is what keeps them from overwriting each other.
 */
let lastStamp = 0;
function nextStamp() {
  lastStamp = Math.max(Date.now(), lastStamp + 1);
  return lastStamp;
}

/**
 * Keys sort lexicographically into chronological order because the timestamp is
 * zero-padded to a fixed width. That is what lets an incremental poll filter on
 * the key alone without fetching a single blob body, and what lets the newest
 * page be taken off the end of a sorted key list.
 */
function newMessageKey(ts) {
  return `msg/${String(ts).padStart(16, '0')}-${crypto.randomBytes(4).toString('hex')}`;
}

async function loadMessages({ after = null, limit = PAGE_SIZE } = {}) {
  const store = threadStore();
  const { blobs } = await store.list({ prefix: 'msg/' });
  let keys = blobs.map((b) => b.key).sort();

  const total = keys.length;
  if (after) keys = keys.filter((k) => k > after);

  // Take the newest `limit` keys, then hand them back newest-first.
  const truncated = keys.length > limit;
  if (truncated) keys = keys.slice(-limit);

  const messages = await Promise.all(
    keys.map(async (key) => {
      const rec = await store.get(key, { type: 'json' });
      if (!rec) return null;
      // A message can be an attachment with no words, so an absent body is not
      // a failure to decrypt -- only an encrypted body that will not open is.
      const text = rec.enc ? decrypt(rec.enc) : '';
      return {
        key,
        ts: rec.ts,
        who: rec.who,
        name: PEOPLE[rec.who]?.name || rec.who,
        text: text === null ? null : text,
        // An explicit flag beats making the client infer meaning from a null.
        unreadable: text === null,
        att: rec.att || null,
      };
    })
  );

  return {
    messages: messages.filter(Boolean).reverse(), // newest first
    total,
    truncated,
    latestKey: keys.length ? keys[keys.length - 1] : after,
  };
}

// ----------------------------------------------------------------- the rail

/**
 * Files live in private-files/ and are NOT reachable over the web: netlify.toml
 * 404s that path, and netlify.toml's [functions] included_files is what puts
 * them inside this function's bundle. They come out only through here, only
 * with a valid session. Same door as the messages, on purpose -- a script sent
 * to a kid over a private channel should not be sitting on a guessable URL.
 *
 * The bundler does not guarantee where included_files land relative to the
 * compiled function, so the directory is resolved by trying the plausible roots
 * rather than assuming one. Whichever hits is cached for the container's life.
 */
const FILE_DIR_CANDIDATES = [
  () => path.resolve(process.cwd(), 'private-files'),
  () => path.resolve(process.cwd(), '../private-files'),
  () => new URL('../../private-files/', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
];

let cachedDir;
function fileDir() {
  if (cachedDir !== undefined) return cachedDir;
  for (const candidate of FILE_DIR_CANDIDATES) {
    try {
      const dir = candidate();
      if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
        cachedDir = dir;
        return dir;
      }
    } catch { /* try the next one */ }
  }
  console.error(JSON.stringify({ event: 'JESSE_FILE_DIR_MISSING', cwd: process.cwd() }));
  cachedDir = null;
  return null;
}

function manifest() {
  const dir = fileDir();
  if (!dir) return {};
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')).files || {};
  } catch {
    // A malformed manifest must not hide the files themselves.
    return {};
  }
}

/**
 * Filenames are validated against a strict allowlist AND checked for membership
 * in the real directory listing. Either alone would probably do; both together
 * mean no string a caller invents can escape the folder.
 */
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Files reach the rail two ways, and the difference matters.
 *
 *   SHIPPED  committed to private-files/ in the repo. Convenient, but this
 *            repository is PUBLIC -- a file here is on GitHub for anyone to
 *            download even though the 404 rule keeps it off siegestack.com.
 *            Only for things that are fine in the open, like the RAM script.
 *
 *   UPLOADED sent through the page, AES-256-GCM encrypted, stored in Netlify
 *            Blobs. Never enters git, never appears on GitHub, and comes back
 *            out only through this function with a valid session. This is the
 *            one to use for anything real.
 *
 * Both are listed together with an `origin` so the page can say which is which,
 * because a private channel that quietly publishes a file would be worse than
 * no private channel at all.
 */
const filesStore = () => getStore({ name: 'jesse-files', consistency: 'strong' });

function shippedFiles() {
  const dir = fileDir();
  if (!dir) return [];
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return [];
  }

  const meta = manifest();
  const order = Object.keys(meta);

  return entries
    .filter((name) => name !== 'manifest.json' && SAFE_NAME.test(name))
    .map((name) => {
      let size = 0;
      let mtime = 0;
      try {
        const st = fs.statSync(path.join(dir, name));
        if (!st.isFile()) return null;
        size = st.size;
        mtime = st.mtimeMs;
      } catch {
        return null;
      }
      const m = meta[name] || {};
      return {
        name, display: name, size, mtime, origin: 'shipped',
        label: m.label || name, note: m.note || '', password: m.password || '', from: '',
        image: Boolean(imageTypeFor(name)),
      };
    })
    .filter(Boolean)
    .sort((a, b) => {
      // Listed files keep the manifest's order; unlisted ones follow, newest first.
      const ai = order.indexOf(a.name);
      const bi = order.indexOf(b.name);
      if (ai > -1 && bi > -1) return ai - bi;
      if (ai > -1) return -1;
      if (bi > -1) return 1;
      return b.mtime - a.mtime;
    });
}

/**
 * Stored name for an upload.
 *
 * Uploads are keyed by a generated unique name rather than the file's own,
 * because phones hand out the same handful of names forever -- two photos both
 * called IMG_0001.jpg would otherwise be one photo, and the first would be gone.
 * Rule 1 does not allow that. The original name is kept in metadata and is what
 * gets displayed and downloaded.
 */
function storedName(original, ts) {
  const ext = path.extname(original).toLowerCase().replace(/[^a-z0-9.]/g, '');
  const stem = path.basename(original, path.extname(original)).replace(/[^A-Za-z0-9._-]/g, '').slice(0, 40) || 'file';
  return `${String(ts).padStart(16, '0')}-${crypto.randomBytes(3).toString('hex')}-${stem}${ext}`;
}

async function uploadedFiles() {
  try {
    const { blobs } = await filesStore().list({ prefix: 'file/' });
    const found = await Promise.all(
      blobs.map(async (b) => {
        const meta = await filesStore().getMetadata(b.key);
        const m = meta?.metadata || {};
        const stored = b.key.slice('file/'.length);
        const display = m.name || stored;
        return {
          name: stored,             // what /api/jesse/file wants
          display,                  // what a human should read
          size: Number(m.size) || 0,
          mtime: Number(m.ts) || 0,
          origin: 'uploaded',
          label: display,
          note: m.note || '',
          password: '',
          from: PEOPLE[m.who]?.name || '',
          image: Boolean(imageTypeFor(display)),
        };
      })
    );
    return found.filter(Boolean).sort((a, b) => b.mtime - a.mtime);
  } catch (err) {
    console.error(JSON.stringify({ event: 'JESSE_UPLOAD_LIST_FAILED', detail: String(err?.message || err).slice(0, 200) }));
    return [];
  }
}

async function listFiles() {
  // Uploads first: they are the ones someone sent on purpose, just now.
  const up = await uploadedFiles();
  const shipped = shippedFiles();
  const taken = new Set(up.map((f) => f.name));
  return [...up, ...shipped.filter((f) => !taken.has(f.name))].map(({ mtime, ...rest }) => rest);
}

/**
 * Ceiling on one upload. The platform caps a function's request body around
 * 6 MB, so this sits below that with room to spare rather than letting a photo
 * fail somewhere less legible than here.
 *
 * Phone photos routinely exceed it, which is why the page downscales images
 * before sending. That is a convenience, not the limit itself -- this check is
 * the limit, because the page cannot be trusted to have run.
 */
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

const CONTENT_TYPES = {
  '.zip': 'application/zip',
  '.bat': 'application/octet-stream',
  '.ps1': 'text/plain; charset=utf-8',
  '.cmd': 'application/octet-stream',
  '.exe': 'application/octet-stream',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8',
  '.json': 'application/json',
  '.pdf': 'application/pdf',
};

/**
 * Types that may be served INLINE, so an <img> can render them in the thread.
 *
 * This is an allowlist and it is short on purpose. Everything not named here is
 * served as application/octet-stream with Content-Disposition: attachment --
 * the browser downloads it and never interprets it. Serving a user-supplied
 * file with a user-supplied content type is how an upload becomes a stored XSS,
 * so the type is derived from the extension here, never from what the uploader
 * claimed.
 *
 * SVG is deliberately absent. It is an image everywhere else in the world, but
 * it is also a document that can carry script, and it would run on this origin
 * -- the one origin where a session cookie for this thread exists. An .svg
 * still uploads and still downloads; it just will not render inline.
 */
const INLINE_IMAGE_TYPES = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.heic': 'image/heic',
  '.heif': 'image/heif',
  '.bmp': 'image/bmp',
};

const imageTypeFor = (name) => INLINE_IMAGE_TYPES[path.extname(name).toLowerCase()] || null;

// ------------------------------------------------------------------ presence

/**
 * "Is the other one there right now?"
 *
 * Every authenticated request stamps the caller's clock. Nothing polls just to
 * announce itself -- the thread already polls every few seconds, so presence
 * rides along on traffic that was happening anyway.
 *
 * ONLINE_WINDOW is deliberately longer than the poll interval. At exactly one
 * interval, a single slow request makes someone flicker offline while they are
 * sitting right there reading; three intervals is quiet.
 */
const ONLINE_WINDOW = 25000;
const presenceStore = () => getStore({ name: 'jesse-presence', consistency: 'strong' });

async function touchPresence(who) {
  try {
    await presenceStore().setJSON(`seen/${who}`, { ts: Date.now() });
  } catch { /* presence is a nicety; never fail a request over it */ }
}

async function presenceOf(who) {
  try {
    const rec = await presenceStore().get(`seen/${who}`, { type: 'json' });
    if (!rec?.ts) return { online: false, lastSeen: null };
    return { online: Date.now() - rec.ts < ONLINE_WINDOW, lastSeen: rec.ts };
  } catch {
    return { online: false, lastSeen: null };
  }
}

const otherPerson = (who) => (who === 'dad' ? 'jesse' : 'dad');

// ---------------------------------------------------------------- web push

/**
 * VAPID keys live in Blobs, generated on first use, NOT in environment
 * variables.
 *
 * That is a deliberate departure from how the PINs are handled, and the reason
 * is scar tissue: an evening was lost to environment variables that existed on
 * the wrong Netlify project with the wrong scope. These keys are not a shared
 * secret anyone needs to type, so there is no reason to make a human carry them
 * between a dashboard and a runtime. Generated once, persisted, done.
 *
 * The private key never leaves the server. The public key is handed to the
 * browser, which is exactly what it is for.
 */
const keyStore = () => getStore({ name: 'jesse-keys', consistency: 'strong' });

let vapidCache = null;
async function vapid() {
  if (vapidCache) return vapidCache;
  const store = keyStore();
  let keys = await store.get('vapid', { type: 'json' });
  if (!keys?.publicKey || !keys?.privateKey) {
    keys = webpush.generateVAPIDKeys();
    await store.setJSON('vapid', keys);
    console.log(JSON.stringify({ event: 'JESSE_VAPID_GENERATED' }));
  }
  webpush.setVapidDetails('mailto:noreply@siegestack.com', keys.publicKey, keys.privateKey);
  vapidCache = keys;
  return keys;
}

const pushStore = () => getStore({ name: 'jesse-push', consistency: 'strong' });

/** One key per device, derived from its endpoint, so re-subscribing replaces. */
const subKey = (who, endpoint) =>
  `sub/${who}/${crypto.createHash('sha256').update(endpoint).digest('hex').slice(0, 32)}`;

/**
 * Notify the other person's devices.
 *
 * The payload carries WHO, never WHAT.
 *
 * It used to pass the message sliced to 120 characters, which for almost every
 * real message is the entire thing -- rendered on a lock screen, in whatever
 * room the phone happens to be lying in. That is a materially different privacy
 * setting from a thread behind a PIN, and the comment here claimed the message
 * was never sent while the code sent it. The code is now what the comment said.
 *
 * A dead subscription (410/404) is deleted rather than retried -- that is the
 * browser telling us the device is gone, and keeping it would mean failing on
 * every send forever.
 */
async function notifyOther(sender, preview) {
  try {
    const { publicKey } = await vapid();
    const target = otherPerson(sender);
    const { blobs } = await pushStore().list({ prefix: `sub/${target}/` });
    if (!blobs.length) return;

    // `preview` is a fixed description chosen by the caller ("sent a message",
    // "sent a photo"), never message content. Sliced anyway as a belt-and-braces
    // guard against a future caller passing something longer.
    const payload = JSON.stringify({
      title: `${PEOPLE[sender]?.name || sender} sent a message`,
      body: String(preview || '').slice(0, 60),
      url: '/jesse',
    });

    await Promise.all(blobs.map(async ({ key }) => {
      const sub = await pushStore().get(key, { type: 'json' });
      if (!sub) return;

      // A subscription is welded to the VAPID key it was created with, and one
      // made against a different key can never be delivered to -- the push
      // service answers 403 forever. Drop it so the browser builds a fresh one
      // on its next visit, instead of failing silently on every send until
      // someone thinks to read the logs.
      //
      // `sub.key` is absent on anything stored before this existed. Unknown is
      // not the same as wrong, so those are still attempted.
      if (sub.key && sub.key !== publicKey) {
        await pushStore().delete(key);
        console.log(JSON.stringify({ event: 'JESSE_PUSH_STALE_KEY' }));
        return;
      }

      try {
        await webpush.sendNotification(sub, payload);
      } catch (err) {
        if (err?.statusCode === 404 || err?.statusCode === 410) {
          await pushStore().delete(key);
        } else {
          console.error(JSON.stringify({ event: 'JESSE_PUSH_FAILED', status: err?.statusCode || 0 }));
        }
      }
    }));
  } catch (err) {
    // A failed notification must never fail the message that triggered it.
    console.error(JSON.stringify({ event: 'JESSE_PUSH_ERROR', detail: String(err?.message || err).slice(0, 200) }));
  }
}

// --------------------------------------------------------------------- gifs

/**
 * GIF search proxied through here so the API key stays server-side, and so the
 * browser never talks to GIPHY directly with our session cookie in flight.
 *
 * When a GIF is chosen its BYTES are fetched here and stored encrypted like any
 * other attachment. Nothing in the thread hotlinks to GIPHY -- if it did, GIPHY
 * would learn every time either of you opened the conversation. The search
 * words still reach them; the reading does not.
 */
const GIF_ENDPOINT = 'https://api.giphy.com/v1/gifs/search';
const MAX_GIF_BYTES = 5 * 1024 * 1024;

/**
 * Content rating for GIF search: 'g', the strictest GIPHY offers.
 *
 * This channel is a father and his teenage son. The rating a general-purpose
 * chat app would pick is the wrong default here, and the cost of being too
 * strict is that a rude GIF does not show up -- which is not a cost worth
 * weighing against the alternative. Raise it only on an explicit request from
 * the site owner.
 *
 * Note this filters what SEARCH returns. It is not a guarantee about every
 * image that can reach the thread: either person can still upload any file
 * from their own device, and that is theirs to manage, not something a rating
 * parameter can police.
 */
const GIF_RATING = 'g';

/**
 * Accept either name.
 *
 * The canonical one is GIPHY_API_KEY, but this project has now lost real time
 * twice to a variable that existed under a slightly different name than the
 * code read -- JESSES_KEY for JESSES_PIN, then GIPHY_KEY for this. Reading both
 * costs one line and removes a whole category of "it is set and it does not
 * work". Anything plausible that a person would actually type is honoured.
 */
function giphyKey() {
  return process.env.GIPHY_API_KEY || process.env.GIPHY_KEY || process.env.GIPHY || '';
}

async function searchGifs(q) {
  const key = giphyKey();
  if (!key) return { ok: false, error: 'no_key' };
  const url = `${GIF_ENDPOINT}?api_key=${encodeURIComponent(key)}&q=${encodeURIComponent(q)}&limit=24&rating=${GIF_RATING}&bundle=messaging_non_clips`;
  const res = await fetch(url);
  if (!res.ok) return { ok: false, error: 'search_failed' };
  const data = await res.json();
  return {
    ok: true,
    gifs: (data.data || []).map((g) => ({
      id: g.id,
      title: g.title || 'GIF',
      preview: g.images?.fixed_width_small?.url || g.images?.preview_gif?.url || '',
      full: g.images?.downsized?.url || g.images?.original?.url || '',
    })).filter((g) => g.preview && g.full),
  };
}

// -------------------------------------------------------------------- replies

function json(body, { status = 200, cookie = null } = {}) {
  const headers = {
    'Content-Type': 'application/json',
    // Never let a proxy, a browser back button, or a CDN hold a copy of this.
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'Referrer-Policy': 'no-referrer',
  };
  if (cookie) headers['Set-Cookie'] = cookie;
  return new Response(JSON.stringify(body), { status, headers });
}

// -------------------------------------------------------------------- handler

export default async (req, context) => {
  const action = new URL(req.url).pathname.split('/').filter(Boolean).pop();
  const ip = context.ip || req.headers.get('x-nf-client-connection-ip') || 'unknown';

  const configured = Boolean(process.env.DADS_PIN && process.env.JESSES_PIN);

  /**
   * The `configured` gate applies to session verification too, not just login.
   *
   * Without it, a deploy missing the PIN env vars still verifies cookies -- and
   * with both PINs absent, sessionKey() falls back to
   * sha256("siegestack/jesse/session||"), a constant anyone can compute from
   * this public repository. That is a forgeable session for anonymous callers.
   *
   * login already refuses to run in that state, for exactly this reason. This
   * line is the other half of that guard, and it was missing.
   */
  const me = configured ? readToken(cookieValue(req, COOKIE)) : null;

  try {
    if (action === 'session') {
      // `configured` is deliberately public: the page needs to distinguish
      // "wrong PIN" from "this was never set up", and the second is not a
      // secret. It reveals nothing an attacker can use -- a locked door that
      // says it is locked is still locked.
      return json({ ok: true, configured, who: me?.id || null, name: me?.name || null });
    }

    if (action === 'login') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });

      // Refuse to authenticate at all rather than compare against an empty
      // string, which would make a blank PIN the master key.
      if (!configured) return json({ ok: false, error: 'not_configured' }, { status: 503 });

      const held = await lockoutRemaining(ip);
      if (held) return json({ ok: false, error: 'locked', retryAfter: held }, { status: 429 });

      const { pin } = await req.json().catch(() => ({}));
      const candidate = String(pin || '').trim();

      // Both comparisons always run: returning early on the first match would
      // leak which PIN was closer through response timing.
      let matched = null;
      for (const person of Object.values(PEOPLE)) {
        const actual = process.env[person.pinVar] || '';
        const same =
          candidate.length > 0 &&
          equalBytes(
            crypto.createHash('sha256').update(candidate).digest(),
            crypto.createHash('sha256').update(actual).digest()
          );
        if (same) matched = person;
      }

      if (!matched) {
        const wait = await recordFailure(ip);
        return json({ ok: false, error: 'bad_pin', retryAfter: wait }, { status: 401 });
      }

      await clearFailures(ip);
      return json({ ok: true, who: matched.id, name: matched.name }, { cookie: setCookie(issueToken(matched.id)) });
    }

    if (action === 'logout') {
      return json({ ok: true }, { cookie: setCookie(null) });
    }

    // Everything past this point requires a valid session.
    if (!me) return json({ ok: false, error: 'unauthorized' }, { status: 401 });

    // Being here at all is proof of life. Recorded before the work, so a slow
    // response cannot make someone look absent while they are plainly present.
    await touchPresence(me.id);

    if (action === 'messages') {
      const after = new URL(req.url).searchParams.get('after');
      // Both people, always, in a fixed order -- the bar across the top shows
      // the pair, so "who is here" reads the same for whoever is looking.
      const [thread, dad, jesse] = await Promise.all([
        loadMessages({ after }),
        presenceOf('dad'),
        presenceOf('jesse'),
      ]);
      return json({
        ok: true,
        who: me.id,
        presence: [
          { id: 'dad', name: PEOPLE.dad.name, ...dad },
          { id: 'jesse', name: PEOPLE.jesse.name, ...jesse },
        ],
        ...thread,
      });
    }

    if (action === 'push-key') {
      const { publicKey } = await vapid();
      return json({ ok: true, publicKey });
    }

    if (action === 'subscribe') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });
      const body = await req.json().catch(() => null);

      // The page and the service worker both post { subscription, publicKey }.
      // A bare PushSubscription is what older builds sent and is still taken --
      // just without the key that lets notifyOther() recognise a stale one, so
      // it is stored as null rather than assumed to be the current key.
      const sub = body?.subscription?.endpoint ? body.subscription : body;
      if (!sub?.endpoint) return json({ ok: false, error: 'bad_subscription' }, { status: 400 });

      await pushStore().setJSON(subKey(me.id, sub.endpoint), {
        endpoint: sub.endpoint,
        keys: sub.keys,
        expirationTime: sub.expirationTime ?? null,
        key: typeof body?.publicKey === 'string' ? body.publicKey : null,
      });
      return json({ ok: true });
    }

    if (action === 'gif') {
      const q = (new URL(req.url).searchParams.get('q') || '').trim().slice(0, 100);
      if (!q) return json({ ok: true, gifs: [] });
      return json(await searchGifs(q));
    }

    if (action === 'gif-send') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });
      if (!giphyKey()) return json({ ok: false, error: 'no_key' }, { status: 503 });

      const { url, title } = (await req.json().catch(() => ({}))) || {};
      // Only GIPHY's own CDN. Without this the endpoint would happily fetch any
      // URL a caller named, which is a server-side request forgery with our
      // network position behind it.
      if (!/^https:\/\/[a-z0-9.-]*\.giphy\.com\//i.test(String(url || ''))) {
        return json({ ok: false, error: 'bad_url' }, { status: 400 });
      }

      const res = await fetch(url);
      if (!res.ok) return json({ ok: false, error: 'fetch_failed' }, { status: 502 });
      const raw = Buffer.from(await res.arrayBuffer());
      if (!raw.length || raw.length > MAX_GIF_BYTES) return json({ ok: false, error: 'too_big' }, { status: 413 });

      const display = (String(title || 'gif').replace(/[^A-Za-z0-9 _-]/g, '').trim().slice(0, 40) || 'gif') + '.gif';
      const ts = nextStamp();
      const stored = storedName(display.replace(/ /g, '-'), ts);
      const { data, iv, tag } = encryptBytes(raw);
      await filesStore().set(`file/${stored}`, data, {
        metadata: { name: display, note: '', size: raw.length, ts, who: me.id, iv, tag },
      });

      const att = { file: stored, name: display, size: raw.length, image: true };
      const key = newMessageKey(ts);
      await threadStore().setJSON(key, { ts, who: me.id, enc: encrypt(''), att });
      await notifyOther(me.id, 'sent a GIF');

      return json({ ok: true, message: { key, ts, who: me.id, name: me.name, text: '', unreadable: false, att } });
    }

    if (action === 'send') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });

      const { text } = await req.json().catch(() => ({}));
      const body = String(text || '').trim();
      if (!body) return json({ ok: false, error: 'empty' }, { status: 400 });
      if (body.length > MAX_MESSAGE_CHARS) return json({ ok: false, error: 'too_long' }, { status: 400 });

      const ts = nextStamp();
      const key = newMessageKey(ts);
      await threadStore().setJSON(key, { ts, who: me.id, enc: encrypt(body) });

      // Awaited, not fire-and-forget: this container may be frozen the instant
      // the response is written, and a detached promise would die unsent.
      await notifyOther(me.id, 'sent a message');

      // Echo the stored message back so the sender's thread updates from the
      // server's version of events rather than an optimistic local guess.
      return json({
        ok: true,
        message: { key, ts, who: me.id, name: me.name, text: body, unreadable: false },
      });
    }

    if (action === 'files') {
      return json({ ok: true, files: await listFiles(), maxUpload: MAX_UPLOAD_BYTES });
    }

    if (action === 'upload') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });

      const params = new URL(req.url).searchParams;
      const name = (params.get('name') || '').trim();
      const note = (params.get('note') || '').slice(0, 300);

      // The allowlist is the whole defence for the stored key, so it is strict
      // rather than clever: no slashes, no dots leading, nothing to traverse.
      if (!SAFE_NAME.test(name) || name.length > 120) {
        return json({ ok: false, error: 'bad_name' }, { status: 400 });
      }

      const raw = Buffer.from(await req.arrayBuffer());
      if (!raw.length) return json({ ok: false, error: 'empty' }, { status: 400 });
      if (raw.length > MAX_UPLOAD_BYTES) return json({ ok: false, error: 'too_big' }, { status: 413 });

      const ts = nextStamp();
      const stored = storedName(name, ts);
      const { data, iv, tag } = encryptBytes(raw);
      await filesStore().set(`file/${stored}`, data, {
        metadata: { name, note, size: raw.length, ts, who: me.id, iv, tag },
      });

      // Anything sent through the page becomes part of the conversation, not
      // just a row in a sidebar. A photo you have to go hunting for in a file
      // list is not "sending someone a photo".
      const att = { file: stored, name, size: raw.length, image: Boolean(imageTypeFor(name)) };
      const caption = (params.get('text') || '').trim().slice(0, MAX_MESSAGE_CHARS);
      const key = newMessageKey(ts);
      await threadStore().setJSON(key, { ts, who: me.id, enc: encrypt(caption), att });

      await notifyOther(me.id, att.image ? 'sent a photo' : 'sent a file');

      return json({
        ok: true,
        files: await listFiles(),
        message: { key, ts, who: me.id, name: me.name, text: caption, unreadable: false, att },
      });
    }

    if (action === 'file') {
      const params = new URL(req.url).searchParams;
      const name = params.get('name') || '';
      if (!SAFE_NAME.test(name)) return json({ ok: false, error: 'not_found' }, { status: 404 });

      /**
       * The displayed filename is what a human should see when they save it;
       * `name` is the stored key, which for an upload has a timestamp glued to
       * the front. Quotes and control characters are stripped because this
       * value goes into a response header.
       */
      const headersFor = (display) => {
        const safeDisplay = String(display || name).replace(/[^\w. \-()]/g, '_').slice(0, 100);
        const image = imageTypeFor(display || name);
        return {
          // Inline only for the short image allowlist. Everything else is
          // octet-stream + attachment, so the browser never interprets it.
          'Content-Type': image || CONTENT_TYPES[path.extname(name).toLowerCase()] || 'application/octet-stream',
          'Content-Disposition': `${image ? 'inline' : 'attachment'}; filename="${safeDisplay}"`,
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'no-store, private',
          'X-Robots-Tag': 'noindex, nofollow, noarchive',
        };
      };

      // An upload shadows a shipped file of the same name, matching the rail.
      const blob = await filesStore().getWithMetadata(`file/${name}`, { type: 'arrayBuffer' });
      if (blob) {
        const plain = decryptBytes(blob.data, blob.metadata?.iv, blob.metadata?.tag);
        if (!plain) return json({ ok: false, error: 'undecryptable' }, { status: 500 });
        return new Response(plain, { headers: headersFor(blob.metadata?.name) });
      }

      const dir = fileDir();
      if (dir && shippedFiles().some((f) => f.name === name)) {
        return new Response(fs.readFileSync(path.join(dir, name)), { headers: headersFor(name) });
      }
      return json({ ok: false, error: 'not_found' }, { status: 404 });
    }

    if (action === 'export') {
      // The whole thread, in the clear, oldest first. This is the backup hatch:
      // rule 1 is only true if there is a way to get everything out.
      const store = threadStore();
      const { blobs } = await store.list({ prefix: 'msg/' });
      const keys = blobs.map((b) => b.key).sort();
      const all = await Promise.all(
        keys.map(async (key) => {
          const rec = await store.get(key, { type: 'json' });
          if (!rec) return null;
          const text = rec.enc ? decrypt(rec.enc) : null;
          return { key, ts: rec.ts, at: new Date(rec.ts).toISOString(), who: rec.who, text, unreadable: text === null };
        })
      );
      return new Response(JSON.stringify({ exportedAt: new Date().toISOString(), count: all.length, messages: all.filter(Boolean) }, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="jesse-thread-${new Date().toISOString().slice(0, 10)}.json"`,
          'Cache-Control': 'no-store',
          'X-Robots-Tag': 'noindex, nofollow, noarchive',
        },
      });
    }

    return json({ ok: false, error: 'not_found' }, { status: 404 });
  } catch (err) {
    console.error(JSON.stringify({ event: 'JESSE_API_ERROR', action, detail: String(err?.message || err).slice(0, 300) }));
    return json({ ok: false, error: 'server' }, { status: 500 });
  }
};
