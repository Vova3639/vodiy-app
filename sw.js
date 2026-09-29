const CACHE = 'vodiy-v41';
// Той самий публічний секрет застосунку (не таємниця — лише щоб чужі скрипти не
// спамили Worker), потрібен тут тільки для трекінгу кліків по адмінських пушах.
const PUSH_APP_SECRET = '-Ir0ChVhJ90OTvNo6wrdbiTzsJNxkCMR';
const PUSH_WORKER_URL = 'https://vodiy-push.vova3639.workers.dev';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './logo.svg',
  './icon-192.png',
  './icon-512.png',
  './icon-32.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;

  const isNav = e.request.mode === 'navigate' ||
    (e.request.headers.get('accept') || '').includes('text/html');
  const isVersionCheck = e.request.url.indexOf('version.json') !== -1;

  if (isNav || isVersionCheck) {
    // Network-first (and never served stale from cache) for the page itself and the
    // version check, so update detection and page updates always see the real latest.
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          if (!isVersionCheck) {
            const clone = res.clone();
            caches.open(CACHE).then((c) => c.put(e.request, clone));
          }
          return res;
        })
        .catch(() => isVersionCheck ? Promise.reject() : caches.match(e.request).then((r) => r || caches.match('./index.html')))
    );
    return;
  }

  // Cache-first for static assets (icons, manifest), with a network fallback that fills the cache.
  e.respondWith(
    caches.match(e.request).then((cached) => {
      if (cached) return cached;
      return fetch(e.request).then((res) => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return res;
      });
    })
  );
});

// Push-сповіщення (від vodiy-push worker на Cloudflare).
self.addEventListener('push', (e) => {
  let data = { title: 'Водій', body: '' };
  try { if (e.data) data = e.data.json(); } catch (err) {}
  const opts = {
    body: data.body || '',
    icon: './icon-192.png',
    badge: './icon-32.png',
    tag: data.tag || 'vodiy',
    // Явно вимикаємо "тихий" режим і додаємо вібрацію — на деяких Android-пристроях
    // канал сповіщень браузера інакше може йти без звуку/вібрації за замовчуванням.
    // Кастомний звук (як "пілінь" на iPhone) поставити з боку сайту технічно неможливо —
    // це системне обмеження Web Push на всіх платформах, не наше.
    silent: false,
    vibrate: [200, 80, 200],
    renotify: !!data.tag,
    data: { url: data.url || './', hid: data.hid || null }
  };
  e.waitUntil(self.registration.showNotification(data.title || 'Водій', opts));
});

// Клік по сповіщенню — фокусує вже відкриту вкладку (і переводить її на
// потрібний розділ, якщо адмінка вказала url), або відкриває нову.
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const rel = (e.notification.data && e.notification.data.url) || './';
  const hid = e.notification.data && e.notification.data.hid;
  const targetUrl = new URL(rel, self.registration.scope).href;
  const focusTask = self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) {
      if ('focus' in c) {
        if ('navigate' in c) { c.navigate(targetUrl).catch(() => {}); }
        return c.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
  });
  // Трекінг кліку для CTR в адмінці — не блокує й не зриває навігацію, якщо мережа підведе.
  const trackTask = hid
    ? fetch(PUSH_WORKER_URL + '/track/click', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-App-Secret': PUSH_APP_SECRET },
        body: JSON.stringify({ hid }),
      }).catch(() => {})
    : Promise.resolve();
  e.waitUntil(Promise.all([focusTask, trackTask]));
});
