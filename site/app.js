/* Dashboard logic. Feed content is UNTRUSTED: every value from the JSON is
   inserted with textContent, never innerHTML, and links are rendered only when
   they use an http/https scheme. No third-party code, no CDN. */
"use strict";

(function () {
  var state = { items: [], candidates: [], activeTags: new Set(), query: "", view: "feed" };

  // ---- helpers ----------------------------------------------------------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }

  function safeHref(url) {
    // Only ever follow http/https. Anything else returns null (no link made).
    if (typeof url !== "string") return null;
    try {
      var u = new URL(url, window.location.href);
      return (u.protocol === "http:" || u.protocol === "https:") ? u.href : null;
    } catch (e) { return null; }
  }

  function link(url, text, cls) {
    var href = safeHref(url);
    var text2 = text == null ? url : text;
    if (!href) return el("span", cls, text2); // degrade to plain text, never a bad link
    var a = el("a", cls, text2);
    a.setAttribute("href", href);
    a.setAttribute("target", "_blank");
    a.setAttribute("rel", "noopener noreferrer");
    return a;
  }

  function fmtAge(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return "";
    var mins = Math.max(0, (Date.now() - t) / 60000);
    if (mins < 60) return Math.round(mins) + "m ago";
    if (mins < 1440) return Math.round(mins / 60) + "h ago";
    return Math.round(mins / 1440) + "d ago";
  }

  function scoreClass(s) { return s >= 70 ? "score hi" : s >= 45 ? "score mid" : "score"; }

  // ---- stats ------------------------------------------------------------
  function renderStats(stats) {
    var host = document.getElementById("stats");
    host.textContent = "";
    if (!stats) return;
    var cards = [
      { num: stats.kev_tracked, lbl: "KEV CVEs tracked", cls: "num" },
      { num: stats.kev_coverage_pct + "%", lbl: "KEV with Nuclei template", cls: "num accent" },
      { num: stats.open_gaps, lbl: "Open detection gaps", cls: "num kev" },
      { num: stats.total_items, lbl: "Feed items", cls: "num" }
    ];
    cards.forEach(function (c) {
      var box = el("div", "stat");
      var num = el("div", c.cls, c.num);
      box.appendChild(num);
      box.appendChild(el("div", "lbl", c.lbl));
      host.appendChild(box);
    });
  }

  // ---- feed -------------------------------------------------------------
  function allTags() {
    var set = {};
    state.items.forEach(function (it) { (it.tags || []).forEach(function (t) { set[t] = (set[t] || 0) + 1; }); });
    return Object.keys(set).sort(function (a, b) { return set[b] - set[a]; });
  }

  function renderChips() {
    var host = document.getElementById("chips");
    host.textContent = "";
    allTags().forEach(function (tag) {
      var chip = el("button", "chip", tag);
      chip.setAttribute("type", "button");
      chip.setAttribute("aria-pressed", state.activeTags.has(tag) ? "true" : "false");
      chip.addEventListener("click", function () {
        if (state.activeTags.has(tag)) state.activeTags.delete(tag); else state.activeTags.add(tag);
        renderChips();
        renderFeed();
      });
      host.appendChild(chip);
    });
  }

  function matches(it) {
    for (var t of state.activeTags) { if ((it.tags || []).indexOf(t) === -1) return false; }
    if (state.query) {
      var hay = (it.title + " " + it.summary + " " + (it.cves || []).join(" ")).toLowerCase();
      if (hay.indexOf(state.query) === -1) return false;
    }
    return true;
  }

  function feedCard(it) {
    var card = el("article", "card");

    var top = el("div", "card-top");
    var h = el("h3");
    h.appendChild(link(it.url, it.title));
    top.appendChild(h);
    top.appendChild(el("div", scoreClass(it.score), Math.round(it.score)));
    card.appendChild(top);

    var meta = el("div", "meta");
    meta.appendChild(el("span", null, it.source));
    if (it.published) meta.appendChild(el("span", null, fmtAge(it.published)));
    if (it.cves && it.cves.length) meta.appendChild(el("span", null, it.cves.join(", ")));
    card.appendChild(meta);

    if (it.summary) {
      var sum = it.summary.length > 220 ? it.summary.slice(0, 220) + "…" : it.summary;
      card.appendChild(el("p", "summary", sum));
    }

    var badges = el("div", "badges");
    if (it.kev) badges.appendChild(el("span", "badge kev", "KEV"));
    if (it.epss != null) badges.appendChild(el("span", "badge epss", "EPSS " + Math.round(it.epss * 100) + "%"));
    (it.tags || []).forEach(function (t) {
      badges.appendChild(el("span", t === "AI-sec" ? "badge ai" : "badge", t));
    });
    card.appendChild(badges);

    if (it.score_reasons && it.score_reasons.length) {
      var det = el("details", "reasons");
      det.appendChild(el("summary", null, "Why this scored " + Math.round(it.score)));
      var ul = el("ul");
      it.score_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul);
      card.appendChild(det);
    }
    return card;
  }

  function renderFeed() {
    var host = document.getElementById("feed");
    host.textContent = "";
    var shown = state.items.filter(matches);
    document.getElementById("feed-empty").hidden = shown.length !== 0;
    shown.forEach(function (it) { host.appendChild(feedCard(it)); });
  }

  // ---- detection queue --------------------------------------------------
  function kv(grid, k, v, vcls) {
    grid.appendChild(el("div", "k", k));
    grid.appendChild(el("div", vcls || null, v));
  }

  function queueCard(c) {
    var card = el("article", "card");

    var top = el("div", "card-top");
    top.appendChild(el("h3", null, c.cve_id + (c.product ? " · " + c.product : "")));
    top.appendChild(el("div", scoreClass(c.score), Math.round(c.score)));
    card.appendChild(top);

    var badges = el("div", "badges");
    if (c.kev) badges.appendChild(el("span", "badge kev", "KEV"));
    if (c.epss != null) badges.appendChild(el("span", "badge epss", "EPSS " + Math.round(c.epss * 100) + "%"));
    if (c.cvss_score != null) badges.appendChild(el("span", "badge", "CVSS " + c.cvss_score));
    if (c.detectability && c.detectability.has_poc) badges.appendChild(el("span", "badge ai", "PoC"));
    card.appendChild(badges);

    var grid = el("div", "cand-grid");
    kv(grid, "Vendor", c.vendor || "?");
    kv(grid, "Coverage", c.nuclei_template ? "template exists" : "GAP — no template",
       c.nuclei_template ? "cov-ok" : "cov-gap");
    var d = c.detectability || {};
    kv(grid, "Detectability", d.likely_http ? "HTTP" : (d.remote_network ? "remote (AV:N)" : "local"));
    kv(grid, "Template type", d.suggested_template_type || "?");
    card.appendChild(grid);

    if (c.candidate_reasons && c.candidate_reasons.length) {
      var det = el("details", "reasons");
      det.appendChild(el("summary", null, "Why it's a candidate"));
      var ul = el("ul");
      c.candidate_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul);
      card.appendChild(det);
    }

    var links = el("div", "links");
    links.appendChild(link(c.brief, "Detection brief"));
    links.appendChild(link("https://nvd.nist.gov/vuln/detail/" + c.cve_id, "NVD"));
    if (c.issue_number != null) {
      links.appendChild(el("span", null, "Issue #" + c.issue_number));
    }
    card.appendChild(links);
    return card;
  }

  function renderQueue() {
    var host = document.getElementById("queue");
    host.textContent = "";
    document.getElementById("queue-empty").hidden = state.candidates.length !== 0;
    state.candidates.forEach(function (c) { host.appendChild(queueCard(c)); });
  }

  // ---- tabs -------------------------------------------------------------
  function selectView(view) {
    state.view = view;
    var isFeed = view === "feed";
    document.getElementById("view-feed").hidden = !isFeed;
    document.getElementById("view-queue").hidden = isFeed;
    document.getElementById("tab-feed").setAttribute("aria-selected", isFeed ? "true" : "false");
    document.getElementById("tab-queue").setAttribute("aria-selected", isFeed ? "false" : "true");
  }

  // ---- load -------------------------------------------------------------
  function load() {
    Promise.all([
      fetch("data.json", { cache: "no-cache" }).then(function (r) { return r.json(); }),
      fetch("candidates.json", { cache: "no-cache" }).then(function (r) { return r.json(); })
    ]).then(function (res) {
      var data = res[0], cand = res[1];
      state.items = data.items || [];
      state.candidates = cand.candidates || [];
      renderStats(data.stats);
      var when = data.last_run || data.generated;
      document.getElementById("updated").textContent = when ? "Updated " + fmtAge(when) : "";
      renderChips();
      renderFeed();
      renderQueue();
    }).catch(function (e) {
      document.getElementById("updated").textContent = "Failed to load data";
      // eslint-disable-next-line no-console
      console.error(e);
    });
  }

  // ---- wire up ----------------------------------------------------------
  document.getElementById("tab-feed").addEventListener("click", function () { selectView("feed"); });
  document.getElementById("tab-queue").addEventListener("click", function () { selectView("queue"); });
  document.getElementById("search").addEventListener("input", function (e) {
    state.query = e.target.value.trim().toLowerCase();
    renderFeed();
  });

  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("sw.js").catch(function () { /* offline cache is best-effort */ });
    });
  }

  load();
})();
