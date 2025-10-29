// /public/sw.js
self.addEventListener('install', (e) => { self.skipWaiting(); });
self.addEventListener('activate', (e) => { self.clients.claim(); });

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data.json(); } catch {}
  const title = data.title || 'New message';
  const body  = data.body || '';
  const tag   = (data.data && data.data.tag) || 'comms';
  const url   = (data.data && data.data.url) || '/';

  event.waitUntil(
    self.registration.showNotification(title, { body, tag })
  );

  self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    e.waitUntil(
      clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
        for (const c of list) {
          if ('focus' in c) { c.navigate(url); return c.focus(); }
        }
        return clients.openWindow(url);
      })
    );
  });
});
