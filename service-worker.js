// Service worker for the Choir Setlist app.
//
// Precaches the app shell and every piano sample so the app runs
// offline once installed. Bump CACHE_VERSION whenever index.html or
// the sample set changes — old caches will be evicted on activate.

// Bump CACHE_VERSION whenever index.html, the sample set, or the
// icons change so old caches get evicted on activate.
const CACHE_VERSION = 'v3';
const CACHE_NAME = 'choir-setlist-' + CACHE_VERSION;

// Notes kept in sync with PIANO_NOTES in index.html.
const PIANO_NOTES = [
  'A2','A#2','B2','C2','C#2','D2','D#2','E2','F2','F#2','G2','G#2',
  'A3','A#3','B3','C3','C#3','D3','D#3','E3','F3','F#3','G3','G#3',
  'A4','A#4','B4','C4','C#4','D4','D#4','E4','F4','F#4','G4','G#4',
  'A5','A#5','B5','C5','C#5','D5','D#5','E5','F5','F#5','G5','G#5',
  'C6'
];

const APP_SHELL = [
  './',
  './index.html',
  './icons/icon-512.png'
];

const SOUND_URLS = PIANO_NOTES.map(
  note => './PianoSounds/' + encodeURIComponent(note) + '.mp3'
);

const PRECACHE_URLS = [...APP_SHELL, ...SOUND_URLS];

// Hosts whose responses we cache on first fetch (for Google Fonts).
const RUNTIME_CACHE_HOSTS = [
  'fonts.googleapis.com',
  'fonts.gstatic.com'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  event.respondWith((async () => {
    // Cache-first for everything we've precached or previously seen.
    const cached = await caches.match(req);
    if (cached) return cached;

    try {
      const resp = await fetch(req);
      // Only cache successful, basic/cors responses.
      if (resp && resp.ok) {
        const url = new URL(req.url);
        const sameOrigin = url.origin === self.location.origin;
        const isFontHost = RUNTIME_CACHE_HOSTS.includes(url.hostname);
        if (sameOrigin || isFontHost) {
          const respClone = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(req, respClone));
        }
      }
      return resp;
    } catch (err) {
      // Offline and not in cache: nothing we can do.
      throw err;
    }
  })());
});
