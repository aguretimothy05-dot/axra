const CACHE_NAME = 'axra-v6-1';
const urlsToCache = ['/','/index.html','/manifest.json'];

self.addEventListener('install', event => {
	event.waitUntil(
		caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
	);
});

self.addEventListener('fetch', event => {
	event.respondWith(
		caches.match(event.request).then(response => {
			if (response) return response;
			return fetch(event.request).then(res => {
				if (!res || res.status !== 200 || res.type !== 'basic') return res;
				const resClone = res.clone();
				caches.open(CACHE_NAME).then(cache => cache.put(event.request, resClone));
				return res;
			});
		})
	);
});

self.addEventListener('activate', event => {
	event.waitUntil(
		caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
	);
});
