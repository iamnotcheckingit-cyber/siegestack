/**
 * In-memory stand-in for @netlify/blobs.
 *
 * Records every call so a test can assert on what was written and with which
 * options, and can be told to fail the next write on demand.
 */
export const __state = { stores: new Map(), failNext: false, calls: [] };

export function getStore(opts) {
  const name = typeof opts === 'string' ? opts : opts.name;
  if (!__state.stores.has(name)) __state.stores.set(name, new Map());
  const m = __state.stores.get(name);
  return {
    async setJSON(k, v) {
      __state.calls.push({ op: 'setJSON', store: name, key: k, opts });
      if (__state.failNext) { __state.failNext = false; throw new Error('stub: blob store unavailable'); }
      m.set(k, v);
    },
    async set(k, v) {
      __state.calls.push({ op: 'set', store: name, key: k, opts });
      if (__state.failNext) { __state.failNext = false; throw new Error('stub: blob store unavailable'); }
      m.set(k, v);
    },
    async get(k) { return m.get(k); },
    // The prefix filter is load-bearing for notify-sweep, which distinguishes
    // submissions from their "sent" markers and its watermark purely by prefix.
    // A stub that ignored it would make the sweep look correct while hiding a
    // bug that only shows up against the real store.
    async list({ prefix } = {}) {
      const keys = [...m.keys()].filter((k) => !prefix || k.startsWith(prefix));
      return { blobs: keys.map((key) => ({ key })) };
    },
    async delete(k) { m.delete(k); },
  };
}

export function reset() {
  __state.stores.clear();
  __state.calls.length = 0;
  __state.failNext = false;
}
