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
 *
 *   TURN_URLS              optional, but video calls between two phones on
 *   TURN_SECRET            mobile data will not connect without it. Both sides
 *                          are usually behind carrier-grade NAT, and STUN
 *                          cannot punch through that -- the media has to be
 *                          relayed. See iceServers() for the three supported
 *                          configurations; TURN_URLS + TURN_SECRET is the one
 *                          to prefer, because what reaches the browser then
 *                          expires within the hour.
 *                          Alternatives: TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN,
 *                          or TURN_URLS + TURN_USERNAME + TURN_PASSWORD.
 *                          Unset means STUN only, which is where this started.
 *
 *                          Scope these to Functions in Netlify, not just
 *                          Builds. A build that sees the value says nothing
 *                          about whether process.env here does.
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
    '/api/jesse/react',
    '/api/jesse/export',
    '/api/jesse/files',
    '/api/jesse/file',
    '/api/jesse/upload',
    '/api/jesse/push-key',
    '/api/jesse/subscribe',
    '/api/jesse/gif',
    '/api/jesse/gif-send',
    '/api/jesse/call',
    '/api/jesse/turn',
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

// ------------------------------------------------------------------ reactions

/**
 * Tap-to-react, without breaking rule 1.
 *
 * A reaction is not stored as a mutable field on the message -- that would mean
 * read-modify-writing a message blob, which is the one thing the whole storage
 * design refuses to do. Each tap is its own append-only record instead, and the
 * CURRENT state is whatever each person's newest record says. Changing your mind
 * appends; taking it back appends a `none`. Nothing is ever overwritten and
 * nothing is ever deleted, so the history of who reacted with what and when
 * survives in full even though the thread only renders the latest.
 *
 * EVERYTHING NEEDED TO READ THEM IS IN THE KEY.
 *
 *   rx/<message id>/<timestamp>-<who>-<code>
 *
 * That is the point of the layout, not a cosmetic choice. Reactions have to be
 * returned on every poll -- someone can react to a message from last week, which
 * an incremental `after=` cursor would never surface -- so this runs constantly.
 * With the facts in the key, a single list() answers it and not one blob body is
 * fetched. The body is written anyway, so a future reader that does not trust
 * this key format can still recover the same answer from the records.
 *
 * The set is fixed and small. An arbitrary emoji from a caller would be a
 * caller-supplied string rendered next to a message, and a short allowlist is a
 * cheaper defence than trusting the renderer to stay safe forever.
 */
const REACTIONS = {
  heart: '❤️',
  up: '👍',
  haha: '😂',
  wow: '😮',
  fire: '🔥',
  sad: '😢',
};

/** Not a reaction: the record that says "I took mine back". */
const CLEAR_CODE = 'none';

/** The shape newMessageKey() produces, after the `msg/` prefix. */
const MSG_ID_RE = /^\d{16}-[0-9a-f]{8}$/;

/**
 * A caller hands us a full message key. Only the id half may go into a blob
 * key, and only after it is proved to be exactly what newMessageKey() writes --
 * a caller-supplied string that reaches a key path is how one thread's storage
 * would end up writable from a request meant for something else.
 */
function messageId(key) {
  const raw = String(key || '');
  const id = raw.startsWith('msg/') ? raw.slice(4) : raw;
  return MSG_ID_RE.test(id) ? id : null;
}

const RX_KEY_RE = /^(\d{16})-([a-z]+)-([a-z]+)$/;

/**
 * Returns { '<message key>': { code: ['who', ...] } } for the whole thread.
 *
 * Latest-record-wins per (message, person). Ties cannot happen for one person
 * because nextStamp() is strictly increasing.
 */
async function loadReactions() {
  const { blobs } = await threadStore().list({ prefix: 'rx/' });

  const latest = new Map(); // `${id}|${who}` -> { ts, code, id, who }
  for (const b of blobs) {
    const parts = b.key.split('/');
    if (parts.length !== 3) continue;
    const id = parts[1];
    if (!MSG_ID_RE.test(id)) continue;
    const m = RX_KEY_RE.exec(parts[2]);
    if (!m) continue;
    const [, ts, who, code] = m;
    // Anything unrecognised is ignored rather than rendered. A code retired in
    // a later version must not come back as an empty pill.
    if (!PEOPLE[who]) continue;
    if (code !== CLEAR_CODE && !REACTIONS[code]) continue;
    const slot = `${id}|${who}`;
    const prev = latest.get(slot);
    // Fixed-width zero-padded stamps, so a string compare is a time compare.
    if (!prev || prev.ts < ts) latest.set(slot, { ts, code, id, who });
  }

  const out = {};
  for (const { id, who, code } of latest.values()) {
    if (code === CLEAR_CODE) continue;
    const key = `msg/${id}`;
    if (!out[key]) out[key] = {};
    if (!out[key][code]) out[key][code] = [];
    out[key][code].push(who);
  }
  return out;
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
        audio: Boolean(audioTypeFor(name)),
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
          audio: Boolean(audioTypeFor(display)),
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

/**
 * The same idea for sound, so a voice message can be played where it was sent
 * instead of downloading as a file you have to go and find.
 *
 * Media containers, all of them, and none of them scriptable -- which is the
 * whole test this list has to pass, for the same reason SVG is missing from the
 * image list above.
 *
 * `.mp4` is deliberately absent even though the recorder on iOS produces
 * `audio/mp4`: the extension is ambiguous between sound and video, and a real
 * video served as `audio/mp4` would be a file that plays with no picture and no
 * explanation. Recordings are written as `.m4a`, which means only one thing.
 */
const INLINE_AUDIO_TYPES = {
  '.webm': 'audio/webm',
  '.m4a': 'audio/mp4',
  '.mp3': 'audio/mpeg',
  '.ogg': 'audio/ogg',
  '.oga': 'audio/ogg',
  '.wav': 'audio/wav',
  '.aac': 'audio/aac',
};

const audioTypeFor = (name) => INLINE_AUDIO_TYPES[path.extname(name).toLowerCase()] || null;

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

// ------------------------------------------------------------ call signalling

/**
 * WebRTC signalling. Deliberately NOT the thread store: these are ephemeral
 * routing details, not messages, and they must never survive into the
 * transcript or the export.
 *
 * Netlify Functions cannot hold a socket open, so there is nowhere to put a
 * persistent signalling channel -- the page polls this instead, fast while a
 * call is being set up and not at all otherwise.
 *
 * Signals are read-once: the poll deletes what it hands back. An ICE candidate
 * replayed after the fact is not merely useless, it re-adds a dead transport
 * to a live connection. Anything left unread is swept after CALL_TTL_MS,
 * because the common way for a signal to go unread is the callee never picking
 * up, and a stale offer must not ring a phone ten minutes later.
 */
const callStore = () => getStore({ name: 'jesse-call', consistency: 'strong' });

const CALL_TTL_MS = 90_000;

/**
 * Addressed to the RECIPIENT, not the sender, so a poll is a prefix list with
 * no filtering. Zero-padded for the same reason message keys are: lexical order
 * has to equal chronological order, and nextStamp() rather than Date.now()
 * because ICE candidates arrive in bursts inside a single millisecond and
 * bare timestamps collide -- the same defect that once reordered messages.
 */
const signalKey = (to) =>
  `sig/${to}/${String(nextStamp()).padStart(16, '0')}-${crypto.randomBytes(4).toString('hex')}`;

// ------------------------------------------------------------------ TURN/STUN

/**
 * ICE servers, minted here rather than written into the page.
 *
 * STUN alone only works when at least one side is not behind a symmetric NAT.
 * Two phones on mobile data usually are, and then the media has to be relayed
 * by a TURN server. TURN costs money, so its credentials are worth stealing --
 * and this repository is PUBLIC, so they exist only as Netlify environment
 * variables and only ever reach the browser as a short-lived derivative.
 *
 * Three ways to configure it, checked in this order. Set exactly one.
 *
 *   1. HMAC (coturn's "TURN REST API", and what most providers speak)
 *        TURN_URLS    comma-separated, e.g. turn:host:3478,turns:host:5349
 *        TURN_SECRET  the shared secret. NEVER sent to the browser.
 *      The username is an expiry timestamp and the password is derived from it,
 *      so what the page receives stops working within the hour. This is the one
 *      to prefer: a leaked credential is worthless tomorrow.
 *
 *   2. Twilio Network Traversal Service
 *        TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
 *      Twilio mints the ephemeral credentials; we just relay them. Costs one
 *      outbound request per call setup, which is why it is not first.
 *
 *   3. Static credentials (some providers issue only these)
 *        TURN_URLS, TURN_USERNAME, TURN_PASSWORD
 *      Long-lived, so the browser holds a credential that keeps working. Use
 *      only if the provider offers nothing better.
 *
 * With none of them set this returns STUN only, which is exactly the behaviour
 * before TURN existed -- the feature degrades to where it started rather than
 * breaking.
 *
 * NOTE: the Netlify variable scope must include Functions. "Builds" is the
 * default and the build seeing a value tells you nothing about whether
 * process.env here does.
 */
const STUN_URLS = ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'];

const TURN_TTL_SECONDS = 3600;

function turnUrls() {
  return String(process.env.TURN_URLS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function iceServers() {
  const servers = [{ urls: STUN_URLS }];
  const urls = turnUrls();

  // 1. HMAC / coturn REST.
  if (urls.length && process.env.TURN_SECRET) {
    const expiry = Math.floor(Date.now() / 1000) + TURN_TTL_SECONDS;
    const username = `${expiry}:jesse`;
    const credential = crypto
      .createHmac('sha1', process.env.TURN_SECRET)
      .update(username)
      .digest('base64');
    servers.push({ urls, username, credential });
    return { servers, ttl: TURN_TTL_SECONDS, mode: 'hmac' };
  }

  // 2. Twilio NTS.
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    try {
      const sid = process.env.TWILIO_ACCOUNT_SID;
      const auth = Buffer.from(`${sid}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
      const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Tokens.json`, {
        method: 'POST',
        headers: { authorization: `Basic ${auth}` },
      });
      if (res.ok) {
        const body = await res.json();
        for (const s of body.ice_servers || []) {
          // Twilio returns one entry per URL, under `url` or `urls` depending
          // on how old the account is.
          const u = s.urls || s.url;
          if (!u) continue;
          servers.push(s.username ? { urls: u, username: s.username, credential: s.credential } : { urls: u });
        }
        return { servers, ttl: Number(body.ttl) || TURN_TTL_SECONDS, mode: 'twilio' };
      }
      console.error(JSON.stringify({ event: 'JESSE_TURN_TWILIO_HTTP', status: res.status }));
    } catch (err) {
      // A TURN failure must degrade to STUN, never fail the call outright.
      console.error(JSON.stringify({ event: 'JESSE_TURN_TWILIO_ERROR', detail: String(err?.message || err).slice(0, 200) }));
    }
    return { servers, ttl: 300, mode: 'stun-only' };
  }

  // 3. Static.
  if (urls.length && process.env.TURN_USERNAME && process.env.TURN_PASSWORD) {
    servers.push({ urls, username: process.env.TURN_USERNAME, credential: process.env.TURN_PASSWORD });
    return { servers, ttl: TURN_TTL_SECONDS, mode: 'static' };
  }

  return { servers, ttl: 3600, mode: 'stun-only' };
}

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
 *
 * The title is the sender's NAME ALONE and the body is what they did. It used
 * to read "Jesse sent a message" over a body of "sent a photo", which was
 * merely redundant -- until reactions arrived and it started announcing "sent a
 * message" for something that was not one. The action belongs in exactly one of
 * the two lines. localNotify() in the page says the same thing the same way, so
 * a notification looks identical whichever layer produced it.
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
      title: PEOPLE[sender]?.name || sender,
      body: String(preview || 'sent a message').slice(0, 60),
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
      // Reactions are NOT filtered by `after`. The cursor exists so a poll does
      // not re-send messages already on screen, but a reaction can land on a
      // message from last week -- one an incremental poll will never mention
      // again. So the whole map goes every time, and the page repaints from it.
      // It costs one list() and no blob reads; see loadReactions().
      const [thread, reactions, dad, jesse] = await Promise.all([
        loadMessages({ after }),
        loadReactions(),
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
        reactions,
        ...thread,
      });
    }

    if (action === 'push-key') {
      const { publicKey } = await vapid();
      return json({ ok: true, publicKey });
    }

    if (action === 'turn') {
      // Behind the session check like everything else: these are paid relay
      // credentials, and an open endpoint handing them out is someone else's
      // bandwidth bill.
      const { servers, ttl, mode } = await iceServers();
      return json({ ok: true, iceServers: servers, ttl, mode });
    }

    if (action === 'call') {
      const store = callStore();

      // GET -- drain everything addressed to me, oldest first, and sweep
      // anything stale belonging to either of us on the way past.
      if (req.method === 'GET') {
        const { blobs } = await store.list({ prefix: `sig/${me.id}/` });
        const keys = blobs.map((b) => b.key).sort();
        const cutoff = Date.now() - CALL_TTL_MS;

        const signals = [];
        await Promise.all(keys.map(async (key) => {
          const sig = await store.get(key, { type: 'json' });
          await store.delete(key);           // read-once, see callStore()
          if (!sig) return;
          if (typeof sig.at === 'number' && sig.at < cutoff) return;   // too old to act on
          signals.push(sig);
        }));

        signals.sort((a, b) => (a.at || 0) - (b.at || 0));
        return json({ ok: true, signals });
      }

      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });

      const body = await req.json().catch(() => null);
      const type = String(body?.type || '');
      if (!['offer', 'answer', 'ice', 'hangup', 'decline', 'busy'].includes(type)) {
        return json({ ok: false, error: 'bad_type' }, { status: 400 });
      }

      // The payload is opaque here -- SDP and ICE are only meaningful to the two
      // browsers. Capped so a malformed client cannot park unbounded data in a
      // store that has no user-facing way to clear it.
      const data = body?.data ?? null;
      if (data !== null && JSON.stringify(data).length > 64_000) {
        return json({ ok: false, error: 'too_large' }, { status: 413 });
      }

      const to = otherPerson(me.id);
      await store.setJSON(signalKey(to), { from: me.id, type, data, at: Date.now() });

      // Only an offer rings. Answers, candidates and hangups are traffic between
      // two people who are already looking at the call.
      if (type === 'offer') await notifyOther(me.id, 'is calling');

      return json({ ok: true });
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

    if (action === 'react') {
      if (req.method !== 'POST') return json({ ok: false, error: 'method' }, { status: 405 });

      const { key, code } = (await req.json().catch(() => ({}))) || {};
      const id = messageId(key);
      if (!id) return json({ ok: false, error: 'bad_message' }, { status: 400 });

      const chosen = String(code || '');
      if (chosen !== CLEAR_CODE && !REACTIONS[chosen]) {
        return json({ ok: false, error: 'bad_reaction' }, { status: 400 });
      }

      // Refuse to react to a message that is not there. Without this, a typo in
      // a key would quietly create reactions hanging off nothing, which would
      // then be listed and parsed on every poll forever with no way to see them
      // and no way to remove them.
      const target = await threadStore().get(`msg/${id}`, { type: 'json' });
      if (!target) return json({ ok: false, error: 'bad_message' }, { status: 404 });

      const ts = nextStamp();
      await threadStore().setJSON(
        `rx/${id}/${String(ts).padStart(16, '0')}-${me.id}-${chosen}`,
        { ts, who: me.id, code: chosen, msg: `msg/${id}` }
      );

      // Only for reacting to something the other person said, and never for
      // taking one back. A notification for "Dad removed a thumbs up" is noise
      // on a phone, and reacting to your own message is not news to anybody.
      if (chosen !== CLEAR_CODE && target.who !== me.id) {
        await notifyOther(me.id, `reacted ${REACTIONS[chosen]}`);
      }

      return json({ ok: true, reactions: await loadReactions() });
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
      //
      // `secs` is the recorder's own count of how long it recorded for, so the
      // player can show a length before anything has been downloaded. It is
      // cosmetic and it comes from the client, so it is clamped rather than
      // trusted -- nothing depends on it being right.
      const audio = Boolean(audioTypeFor(name));
      const secs = Math.min(3600, Math.max(0, Math.round(Number(params.get('secs')) || 0)));
      const att = {
        file: stored,
        name,
        size: raw.length,
        image: Boolean(imageTypeFor(name)),
        audio,
        secs: audio ? secs : 0,
      };
      const caption = (params.get('text') || '').trim().slice(0, MAX_MESSAGE_CHARS);
      const key = newMessageKey(ts);
      await threadStore().setJSON(key, { ts, who: me.id, enc: encrypt(caption), att });

      await notifyOther(me.id, att.audio ? 'sent a voice message' : att.image ? 'sent a photo' : 'sent a file');

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
        // Inline for the two short media allowlists -- pictures so they render
        // in the thread, sound so it plays there. Everything else is
        // octet-stream + attachment, so the browser never interprets it.
        const media = imageTypeFor(display || name) || audioTypeFor(display || name);
        return {
          'Content-Type': media || CONTENT_TYPES[path.extname(name).toLowerCase()] || 'application/octet-stream',
          'Content-Disposition': `${media ? 'inline' : 'attachment'}; filename="${safeDisplay}"`,
          'X-Content-Type-Options': 'nosniff',
          'Cache-Control': 'no-store, private',
          'X-Robots-Tag': 'noindex, nofollow, noarchive',
        };
      };

      /**
       * Byte ranges, for the sake of <audio>.
       *
       * Everything here is already in memory -- the file was decrypted whole to
       * answer the request at all -- so this is not a streaming optimisation and
       * it saves nothing. It is here because Safari asks for a range before it
       * will play a sound file, and answering 200-with-everything to a Range
       * request is the well-worn reason a voice message plays on a laptop and
       * silently refuses to on an iPhone. The iPhone is the device this is for.
       *
       * Advertising Accept-Ranges on every file is harmless and means a resumed
       * download of a large attachment works too.
       */
      const serve = (buf, headers) => {
        const base = { ...headers, 'Accept-Ranges': 'bytes' };
        const asked = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get('range') || '');
        if (!asked || !buf.length) {
          return new Response(buf, { headers: { ...base, 'Content-Length': String(buf.length) } });
        }

        let start;
        let end;
        if (asked[1] === '') {
          // A suffix range: "the last N bytes". N of 0 asks for nothing, which
          // is unsatisfiable rather than empty.
          const n = Number(asked[2] || 0);
          if (!n) return new Response(null, { status: 416, headers: { ...base, 'Content-Range': `bytes */${buf.length}` } });
          start = Math.max(0, buf.length - n);
          end = buf.length - 1;
        } else {
          start = Number(asked[1]);
          end = asked[2] === '' ? buf.length - 1 : Math.min(Number(asked[2]), buf.length - 1);
        }

        if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= buf.length) {
          return new Response(null, { status: 416, headers: { ...base, 'Content-Range': `bytes */${buf.length}` } });
        }

        const slice = buf.subarray(start, end + 1);
        return new Response(slice, {
          status: 206,
          headers: {
            ...base,
            'Content-Length': String(slice.length),
            'Content-Range': `bytes ${start}-${end}/${buf.length}`,
          },
        });
      };

      // An upload shadows a shipped file of the same name, matching the rail.
      const blob = await filesStore().getWithMetadata(`file/${name}`, { type: 'arrayBuffer' });
      if (blob) {
        const plain = decryptBytes(blob.data, blob.metadata?.iv, blob.metadata?.tag);
        if (!plain) return json({ ok: false, error: 'undecryptable' }, { status: 500 });
        return serve(plain, headersFor(blob.metadata?.name));
      }

      const dir = fileDir();
      if (dir && shippedFiles().some((f) => f.name === name)) {
        return serve(fs.readFileSync(path.join(dir, name)), headersFor(name));
      }
      return json({ ok: false, error: 'not_found' }, { status: 404 });
    }

    if (action === 'export') {
      // The whole thread, in the clear, oldest first. This is the backup hatch:
      // rule 1 is only true if there is a way to get everything out.
      const store = threadStore();
      const { blobs } = await store.list({ prefix: 'msg/' });
      const keys = blobs.map((b) => b.key).sort();
      // Reactions and attachments come out too. "Everything" that stops at the
      // words is not everything, and a backup you cannot rebuild the thread
      // from is not a backup.
      const reacted = await loadReactions();
      const all = await Promise.all(
        keys.map(async (key) => {
          const rec = await store.get(key, { type: 'json' });
          if (!rec) return null;
          const text = rec.enc ? decrypt(rec.enc) : null;
          return {
            key,
            ts: rec.ts,
            at: new Date(rec.ts).toISOString(),
            who: rec.who,
            text,
            unreadable: text === null,
            att: rec.att || null,
            reactions: reacted[key] || null,
          };
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
