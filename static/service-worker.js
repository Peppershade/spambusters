const CACHE_VERSION = 'v3';
const STATIC_CACHE = `spambusters-static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `spambusters-dynamic-${CACHE_VERSION}`;

const PRECACHE_ASSETS = [
    '/offline',
    '/static/css/app.css',
    '/static/manifest.json',
    '/static/icons/icon-192.png',
    '/static/icons/icon-512.png',
    '/static/js/app.js',
    '/static/js/dashboard.js',
    '/static/js/emails.js',
    '/static/js/landing.js',
    '/static/js/settings-security.js',
    '/static/js/settings-discord.js',
    '/static/js/settings-scanning.js',
    '/static/js/settings-email.js',
    '/static/js/settings-notifications.js',
    '/static/js/settings-reports.js'
];

// Install: pre-cache critical assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => cache.addAll(PRECACHE_ASSETS))
    );
    self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(
                keys
                    .filter(k => k.startsWith('spambusters-') && k !== STATIC_CACHE && k !== DYNAMIC_CACHE)
                    .map(k => caches.delete(k))
            )
        )
    );
    self.clients.claim();
});

// Fetch: strategy per request type
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);

    // Skip non-GET requests (POST forms, etc.)
    if (request.method !== 'GET') return;

    // Skip cross-origin requests (CDN has own caching)
    if (url.origin !== self.location.origin) return;

    // API calls: network-only (never cache user-specific data)
    if (url.pathname.startsWith('/api/')) return;

    // Page navigations: network-first, cache fallback, then offline page
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then(response => {
                    if (response.ok) {
                        const clone = response.clone();
                        caches.open(DYNAMIC_CACHE).then(cache => cache.put(request, clone));
                    }
                    return response;
                })
                .catch(() =>
                    caches.match(request).then(cached => cached || caches.match('/offline'))
                )
        );
        return;
    }

    // Static assets: cache-first, network fallback
    if (url.pathname.startsWith('/static/')) {
        event.respondWith(
            caches.match(request).then(cached => {
                if (cached) return cached;
                return fetch(request).then(response => {
                    if (response.ok) {
                        const clone = response.clone();
                        caches.open(STATIC_CACHE).then(cache => cache.put(request, clone));
                    }
                    return response;
                });
            })
        );
        return;
    }

    // Everything else: network-first, cache fallback
    event.respondWith(
        fetch(request)
            .then(response => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(DYNAMIC_CACHE).then(cache => cache.put(request, clone));
                }
                return response;
            })
            .catch(() => caches.match(request))
    );
});
