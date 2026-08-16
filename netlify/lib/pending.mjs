/**
 * How the sweep knows what still needs a notification.
 *
 * The submission stores are APPEND-ONLY by design -- one blob per submission,
 * never read-modify-written. So "was this one notified?" cannot be a field on
 * the record. It is a separate marker blob instead, written only on success,
 * under its own prefix:
 *
 *   msg/0001786894456546-82aba12a          the submission        (never touched again)
 *   sent/msg/0001786894456546-82aba12a     the marker, if notified
 *   sweep/watermark                        see below
 *
 * A submission with no marker is pending. That is the whole protocol.
 *
 * IT FAILS TOWARDS A DUPLICATE, NEVER A SILENCE. If the send succeeds and the
 * marker write then fails, the sweep sends a second copy an hour later. A
 * duplicate notification is a mild annoyance; a missing one is the failure this
 * entire subsystem exists to prevent, so the ordering is deliberate.
 */

export const SENT_PREFIX = 'sent/';
export const WATERMARK_KEY = 'sweep/watermark';

/**
 * Records that a submission was notified. Never throws: it is called after the
 * notification already went out, and a failure here must not turn a delivered
 * message into a failed request.
 */
export async function markNotified(store, key, event = 'NOTIFY') {
  try {
    await store.setJSON(SENT_PREFIX + key, { at: new Date().toISOString() });
    return true;
  } catch (err) {
    // Worth a log line, because it is the one way a delivered notification can
    // still be sent twice.
    console.error(JSON.stringify({
      event: `${event}_MARK_FAILED`,
      key,
      detail: String(err?.message || err).slice(0, 200),
    }));
    return false;
  }
}

/**
 * The millisecond stamp embedded in a submission key by the writers, which pad
 * it to 16 digits so keys sort chronologically as strings.
 * `msg/0001786894456546-82aba12a` -> 1786894456546. Returns null if a key does
 * not carry one, and callers must treat null as "cannot judge its age".
 */
export function stampOf(key) {
  const m = /^[^/]+\/(\d{16})-/.exec(key);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) && n > 0 ? n : null;
}
