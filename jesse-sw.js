/**
 * Service worker for the private thread at /jesse.
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
 * netlify/functions/jesse-api.mjs.
 */

self.addEventListener('install', function () {
  // Take over immediately rather than waiting for every old tab to close --
  // otherwise the first notification can be a page refresh away.
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', function (event) {
  var data = { title: 'New message', body: '', url: '/jesse' };
  try {
    if (event.data) data = Object.assign(data, event.data.json());
  } catch (e) {
    // A payload we cannot parse still deserves to become a notification --
    // silently dropping it would look identical to nothing having been sent.
  }

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/favicon.svg',
      badge: '/favicon.svg',
      // One tag, so a burst of messages collapses into a single line rather
      // than stacking up a wall of them on a phone.
      tag: 'jesse-thread',
      renotify: true,
      data: { url: data.url || '/jesse' }
    })
  );
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var target = (event.notification.data && event.notification.data.url) || '/jesse';

  // Focus the thread if it is already open somewhere rather than piling up
  // duplicate tabs every time a notification is tapped.
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        if (list[i].url.indexOf('/jesse') !== -1 && 'focus' in list[i]) return list[i].focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});
