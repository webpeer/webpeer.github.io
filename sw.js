
// The cacheName should be updated every release:
const cacheName = "v18";
self.addEventListener("install", (e) => {
    console.log("[Service Worker] Install");
    e.waitUntil((async () => {
        const cache = await caches.open(cacheName);
        console.log("[Service Worker] Caching all: app shell and content");
        await cache.addAll([
            "/",
            "index.html",
            "index.css",
            "index.wasm",
            "index.js",
            "ios.png",
            "manifest.json",
        ]);
    })());
});

self.addEventListener("fetch", (e) => {
    e.respondWith((async () => {
        const r = await caches.match(e.request);
        console.log(`[Service Worker] Fetching resource: ${e.request.url}`);
        if (r) return r;
        const response = await fetch(e.request);
        const cache = await caches.open(cacheName);
        console.log(`[Service Worker] Caching new resource: ${e.request.url}`);
        cache.put(e.request, response.clone());
        return response;
    })());
});

self.addEventListener("activate", (e) => {
    e.waitUntil(
        caches.keys().then((keyList) => {
            return Promise.all(
                keyList.map((key) => {
                    if (key === cacheName) return;
                    return caches.delete(key);
                })
            );
        })
    );
});