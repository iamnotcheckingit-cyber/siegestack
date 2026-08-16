/**
 * Stand-in for nodemailer.
 *
 * mode:
 *   'ok'    -- sendMail resolves and the message is recorded
 *   'hang'  -- sendMail never settles, so the caller's own budget has to fire
 *   'throw' -- sendMail rejects with __mail.err, or a default EAUTH 535 whose
 *              response text contains a real-looking address, so redaction can
 *              be asserted on rather than assumed
 */
export const __mail = { mode: 'ok', sent: [], created: [], closed: 0, err: null };

export function createTransport(cfg) {
  __mail.created.push(cfg);
  return {
    async sendMail(msg) {
      if (__mail.mode === 'hang') return new Promise(() => {});
      if (__mail.mode === 'throw') {
        throw (__mail.err || Object.assign(new Error('boom'), {
          code: 'EAUTH',
          responseCode: 535,
          response: '535 auth failed for scott@siegestack.com',
        }));
      }
      __mail.sent.push(msg);
      return { messageId: 'stub' };
    },
    close() { __mail.closed++; },
  };
}

export function reset() {
  __mail.sent.length = 0;
  __mail.created.length = 0;
  __mail.closed = 0;
  __mail.mode = 'ok';
  __mail.err = null;
}

export default { createTransport };
