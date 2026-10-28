/* Service worker: makes the dashboard installable and usable offline on a
   phone. The app shell is cached on install (cache-first); the data files are
   network-first so a connected phone sees fresh data, but a phone with no
   signal falls back to the last successful sync. The "Updated N ago" line
   keeps that staleness honest. */
"use strict";

var CACHE = "appsec-feed-v3";
var SHELL = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-180.png"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(CACHE).then(function (c) { return c.addAll(SHELL); }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) { return k !== CACHE; })
        .map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (event) {
  var req = event.request;
  if (req.method !== "GET") return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // same-origin only

  var isData = url.pathname.endsWith("data.json") || url.pathname.endsWith("candidates.json") || url.pathname.endsWith("queue.json");

  if (isData) {
    // Network-first, fall back to cache (last good sync).
    event.respondWith(
      fetch(req).then(function (res) {
        var copy = res.clone();
        caches.open(CACHE).then(function (c) { c.put(req, copy); });
        return res;
      }).catch(function () { return caches.match(req); })
    );
  } else {
    // Stale-while-revalidate for the static shell: serve the cached copy
    // instantly (works offline), and refresh the cache in the background so a
    // new deploy is picked up on the next load without bumping sw.js.
    event.respondWith(
      caches.match(req).then(function (hit) {
        var network = fetch(req).then(function (res) {
          if (res && res.ok) {
            var copy = res.clone();
            caches.open(CACHE).then(function (c) { c.put(req, copy); });
          }
          return res;
        }).catch(function () { return hit; });
        return hit || network;
      })
    );
  }
});
