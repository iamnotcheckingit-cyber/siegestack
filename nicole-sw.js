/**
 * Service worker for the private thread at /nicole.
 *
 * It exists for one reason: a push notification has to be received by something
 * that is still alive when the tab is not. This is that something.
 *
 * It deliberately does NOT cache anything. Caching a page whose whole point is
 * being behind a PIN would mean a stale, possibly readable copy sitting in
 * storage after sign-out. Every request goes to the network, every time.
 *
 * The payload it receives carries a name and a short preview only -- never the
 * message. A lock screen is a more public place than a thread behind a PIN, and
 * the server is what decides how little to send. See notifyOther() in
 * netlify/functions/nicole-api.mjs.
 *
 * SCOPE MATTERS HERE. The page registers this with { scope: '/nicole' }, not the
 * '/' it would default to. A registration is keyed by scope, and its push
 * subscription belongs to the registration -- so when this and /jesse-sw.js
 * both claimed '/', they shared one registration and one subscription, bound to
 * whichever thread's VAPID key got there first. The other thread's pushes were
 * then rejected outright and the ones that did arrive were handled by the wrong
 * worker. Two scopes, two registrations, two subscriptions. Keep it that way.
 *
 * Everything here is mirrored in jesse-sw.js by hand. The two files share no
 * code. Change one, change the other.
 */

var API = '/api/nicole/';
var TAG = 'nicole-thread';
var HOME = '/nicole';

self.addEventListener('install', function () {
  // Take over immediately rather than waiting for every old tab to close --
  // otherwise the first notification can be a page refresh away.
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(self.clients.claim());
});

/**
 * Icons are PNG, not the SVG this used to point at. Chrome on Android has no
 * SVG decoder in the notification path: it silently drops the image and falls
 * back to a generic bell. The badge is the bars alone in white on transparent,
 * because Android throws away a badge's colour and keeps only its alpha.
 */
function show(data) {
  return self.registration.showNotification(data.title || 'New message', {
    body: data.body || '',
    icon: '/private-icon-192.png',
    badge: '/private-badge-96.png',
    // One tag, so a burst of messages collapses into a single line rather
    // than stacking up a wall of them on a phone.
    tag: TAG,
    renotify: true,
    data: { url: data.url || HOME }
  });
}

self.addEventListener('push', function (event) {
  var data = { title: 'New message', body: '', url: HOME };
  try {
    if (event.data) data = Object.assign(data, event.data.json());
  } catch (e) {
    // A payload we cannot parse still deserves to become a notification --
    // silently dropping it would look identical to nothing having been sent.
  }

  event.waitUntil(show(data));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var target = (event.notification.data && event.notification.data.url) || HOME;

  // Focus the thread if it is already open somewhere rather than piling up
  // duplicate tabs every time a notification is tapped.
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].url.indexOf(HOME) !== -1 && 'focus' in list[i]) return list[i].focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});

function urlB64ToUint8(b64) {
  var pad = '='.repeat((4 - (b64.length % 4)) % 4);
  var raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  var out = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/**
 * Chrome and Firefox rotate a push subscription without asking, and fire this
 * when they do. Without a handler the old endpoint just stops working and
 * notifications die quietly -- the failure mode is indistinguishable from "no
 * one has messaged you", which is the worst possible way for this to break.
 *
 * The session cookie is HttpOnly and SameSite=Lax, and this is a same-origin
 * fetch, so it rides along. If the session has expired there is nothing useful
 * to do here: the page re-subscribes on next open, which is the backstop.
 */
self.addEventListener('pushsubscriptionchange', function (event) {
  event.waitUntil(
    fetch(API + 'push-key', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (k) {
        if (!k || !k.ok || !k.publicKey) throw new Error('no key');
        return self.registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlB64ToUint8(k.publicKey)
        }).then(function (sub) {
          return fetch(API + 'subscribe', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subscription: sub, publicKey: k.publicKey })
          });
        });
      })
      .catch(function () { /* the page re-subscribes on next open */ })
  );
});
