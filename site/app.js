/* Dashboard logic. Feed content is UNTRUSTED: every value from the JSON is
   inserted with textContent, never innerHTML, and links are rendered only when
   they use an http/https scheme. No third-party code, no CDN. */
"use strict";

(function () {
  var SVG = "http://www.w3.org/2000/svg";
  var state = { items: [], candidates: [], stats: null, activeTags: new Set(), query: "", view: "feed" };

  // Per-source identity for the X-style avatar + handle.
  var SOURCES = {
    "PortSwigger Research": { i: "PS", c: "#e8651e", h: "portswigger", v: true },
    "Project Zero": { i: "P0", c: "#ea4335", h: "projectzero", v: true },
    "GitHub Security Lab": { i: "GH", c: "#8957e5", h: "ghsecuritylab", v: true },
    "tl;dr sec": { i: "TL", c: "#1a7f37", h: "tldrsec", v: false },
    "Risky Bulletin": { i: "RB", c: "#d7263d", h: "riskybiz", v: false },
    "Simon Willison": { i: "SW", c: "#0a7ea4", h: "simonw", v: false }
  };

  // ---- helpers ----------------------------------------------------------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }
  function svg(tag, attrs) {
    var n = document.createElementNS(SVG, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  function safeHref(url) {
    if (typeof url !== "string") return null;
    try {
      var u = new URL(url, window.location.href);
      return (u.protocol === "http:" || u.protocol === "https:") ? u.href : null;
    } catch (e) { return null; }
  }
  function link(url, text, cls) {
    var href = safeHref(url);
    if (!href) return el("span", cls, text == null ? url : text);
    var a = el("a", cls, text == null ? url : text);
    a.setAttribute("href", href);
    a.setAttribute("target", "_blank");
    a.setAttribute("rel", "noopener noreferrer");
    return a;
  }
  function fmtAge(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return "";
    var mins = Math.max(0, (Date.now() - t) / 60000);
    if (mins < 1) return "now";
    if (mins < 60) return Math.round(mins) + "m";
    if (mins < 1440) return Math.round(mins / 60) + "h";
    return Math.round(mins / 1440) + "d";
  }
  function scoreClass(s, base) { return base + (s >= 70 ? " hi" : s >= 45 ? " mid" : ""); }
  function hash(s) { var h = 0; for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return h; }
  function sourceMeta(name) {
    if (SOURCES[name]) return SOURCES[name];
    var words = String(name).split(/\s+/);
    var init = (words[0][0] || "?") + (words.length > 1 ? words[1][0] : "");
    return { i: init.toUpperCase(), c: "hsl(" + (Math.abs(hash(name)) % 360) + " 55% 45%)",
             h: String(name).toLowerCase().replace(/[^a-z0-9]+/g, ""), v: false };
  }
  var AI_TAGS = { "prompt injection": 1, "llm": 1, "rag": 1, "mcp": 1, "model context protocol": 1, "langchain": 1 };

  // ---- feed post --------------------------------------------------------
  function statItem(label, value, cls) {
    var s = el("span", "stat-item" + (cls ? " " + cls : ""));
    if (value != null) s.appendChild(el("span", "sv", value));
    s.appendChild(el("span", null, label));
    return s;
  }

  function feedPost(it) {
    var meta = sourceMeta(it.source);
    var post = el("article", "post");

    var av = el("div", "avatar", meta.i);
    av.style.background = "linear-gradient(135deg, " + meta.c + ", " + meta.c + "cc)";
    post.appendChild(av);

    var body = el("div", "post-body");

    var head = el("div", "post-head");
    head.appendChild(el("span", "p-source", it.source));
    if (meta.v) { var v = el("span", "verified", "✓"); v.setAttribute("title", "trusted research source"); head.appendChild(v); }
    head.appendChild(el("span", "p-handle", "@" + meta.h));
    head.appendChild(el("span", "p-dot", "·"));
    head.appendChild(el("span", "p-time", fmtAge(it.published)));
    head.appendChild(el("span", scoreClass(it.score, "p-score"), Math.round(it.score)));
    body.appendChild(head);

    var h = el("div", "p-title");
    h.appendChild(link(it.url, it.title));
    body.appendChild(h);

    if (it.summary) {
      var sum = it.summary.length > 230 ? it.summary.slice(0, 230).trim() + "…" : it.summary;
      body.appendChild(el("p", "p-text", sum));
    }

    if (it.cves && it.cves.length) {
      var cr = el("div", "cve-row");
      it.cves.slice(0, 6).forEach(function (c) { cr.appendChild(el("span", "cve-chip", c)); });
      body.appendChild(cr);
    }

    var stats = el("div", "p-stats");
    if (it.kev) stats.appendChild(statItem("KEV", null, "kev"));
    if (it.epss != null) stats.appendChild(statItem("EPSS", Math.round(it.epss * 100) + "%"));
    (it.tags || []).forEach(function (t) {
      if (t === "has-PoC") stats.appendChild(statItem("PoC", null, "poc"));
    });
    (it.tags || []).forEach(function (t) {
      if (t === "KEV" || t === "has-PoC" || t === "has-CVE") return;
      stats.appendChild(el("span", "tag-pill" + (t === "AI-sec" ? " ai" : ""), t));
    });
    if (stats.childNodes.length) body.appendChild(stats);

    if (it.score_reasons && it.score_reasons.length) {
      var det = el("details", "why");
      det.appendChild(el("summary", null, "Why it scored " + Math.round(it.score)));
      var ul = el("ul");
      it.score_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul);
      body.appendChild(det);
    }

    post.appendChild(body);
    return post;
  }

  // ---- queue post -------------------------------------------------------
  function queuePost(c) {
    var post = el("article", "post gap");

    var head = el("div", "gap-head");
    var idwrap = el("div");
    idwrap.appendChild(el("div", "gap-cve", c.cve_id));
    if (c.product || c.vendor) idwrap.appendChild(el("div", "gap-prod", (c.vendor ? c.vendor + " / " : "") + (c.product || "")));
    head.appendChild(idwrap);
    var gap = !c.nuclei_template;
    head.appendChild(el("span", "cov " + (gap ? "gap" : "ok"), gap ? "GAP" : "covered"));
    post.appendChild(head);

    var stats = el("div", "p-stats");
    stats.appendChild(el("span", scoreClass(c.score, "p-score"), Math.round(c.score)));
    if (c.kev) stats.appendChild(statItem("KEV", null, "kev"));
    if (c.epss != null) stats.appendChild(statItem("EPSS", Math.round(c.epss * 100) + "%"));
    if (c.cvss_score != null) stats.appendChild(statItem("CVSS", c.cvss_score));
    if (c.detectability && c.detectability.has_poc) stats.appendChild(statItem("PoC", null, "poc"));
    post.appendChild(stats);

    var d = c.detectability || {};
    var grid = el("div", "meta-grid");
    function row(k, v) { grid.appendChild(el("div", "k", k)); grid.appendChild(el("div", "v", v)); }
    row("Detectability", d.likely_http ? "HTTP" : (d.remote_network ? "remote (AV:N)" : "local"));
    row("Template type", d.suggested_template_type || "?");
    if (c.cwe && c.cwe.length) row("CWE", c.cwe.join(", "));
    post.appendChild(grid);

    if (c.candidate_reasons && c.candidate_reasons.length) {
      var det = el("details", "why");
      det.appendChild(el("summary", null, "Why it's a candidate"));
      var ul = el("ul");
      c.candidate_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul);
      post.appendChild(det);
    }

    var actions = el("div", "actions");
    actions.appendChild(link(c.brief, "Detection brief", "btn primary"));
    actions.appendChild(link("https://nvd.nist.gov/vuln/detail/" + c.cve_id, "NVD", "btn"));
    if (c.issue_number != null) actions.appendChild(el("span", "issue-ref", "Issue #" + c.issue_number));
    post.appendChild(actions);
    return post;
  }

  // ---- filters ----------------------------------------------------------
  function allTags() {
    var set = {};
    state.items.forEach(function (it) { (it.tags || []).forEach(function (t) { set[t] = (set[t] || 0) + 1; }); });
    return Object.keys(set).sort(function (a, b) { return set[b] - set[a]; }).map(function (t) { return [t, set[t]]; });
  }
  function renderChips() {
    var host = document.getElementById("chips");
    host.textContent = "";
    allTags().forEach(function (pair) {
      var tag = pair[0];
      var chip = el("button", "chip", tag);
      chip.setAttribute("type", "button");
      chip.setAttribute("aria-pressed", state.activeTags.has(tag) ? "true" : "false");
      chip.addEventListener("click", function () {
        if (state.activeTags.has(tag)) state.activeTags.delete(tag); else state.activeTags.add(tag);
        renderChips(); renderFeed();
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
  function renderFeed() {
    var host = document.getElementById("feed");
    host.textContent = "";
    var shown = state.items.filter(matches);
    document.getElementById("feed-empty").hidden = shown.length !== 0;
    shown.forEach(function (it) { host.appendChild(feedPost(it)); });
  }
  function renderQueue() {
    var host = document.getElementById("queue");
    host.textContent = "";
    document.getElementById("queue-empty").hidden = state.candidates.length !== 0;
    state.candidates.forEach(function (c) { host.appendChild(queuePost(c)); });
  }

  // ---- KPI strip (mobile/tablet) ---------------------------------------
  function renderKpis() {
    var s = state.stats; if (!s) return;
    var host = document.getElementById("kpi-strip");
    host.textContent = "";
    [
      ["n", s.kev_tracked, "KEV tracked"],
      ["n good", s.kev_coverage_pct + "%", "Nuclei coverage"],
      ["n kev", s.open_gaps, "Open gaps"],
      ["n", s.total_items, "Feed items"]
    ].forEach(function (k) {
      var box = el("div", "kpi");
      box.appendChild(el("div", k[0], k[1]));
      box.appendChild(el("div", "l", k[2]));
      host.appendChild(box);
    });
  }

  // ---- right rail -------------------------------------------------------
  function renderCoverage() {
    var s = state.stats; if (!s) return;
    var card = document.getElementById("rail-coverage");
    card.textContent = "";
    card.appendChild(el("h2", null, "KEV coverage"));

    var wrap = el("div", "gauge-wrap");
    var pct = s.kev_coverage_pct || 0;
    var size = 92, stroke = 11, r = (size - stroke) / 2, circ = 2 * Math.PI * r;
    var g = svg("svg", { class: "gauge", width: size, height: size, viewBox: "0 0 " + size + " " + size });
    var cx = size / 2;
    g.appendChild(svg("circle", { cx: cx, cy: cx, r: r, fill: "none", stroke: "#1e2636", "stroke-width": stroke }));
    var arc = svg("circle", {
      cx: cx, cy: cx, r: r, fill: "none", stroke: "#2fd4a7", "stroke-width": stroke,
      "stroke-linecap": "round", "stroke-dasharray": circ,
      "stroke-dashoffset": circ * (1 - pct / 100),
      transform: "rotate(-90 " + cx + " " + cx + ")"
    });
    g.appendChild(arc);
    wrap.appendChild(g);
    var txt = el("div", "gauge-txt");
    txt.appendChild(el("div", "big", pct + "%"));
    txt.appendChild(el("div", "sub", "of tracked KEV CVEs have a Nuclei template"));
    wrap.appendChild(txt);
    card.appendChild(wrap);

    var mini = el("div", "cov-mini");
    [["n", s.kev_tracked, "KEV tracked"], ["n kev", s.open_gaps, "Open gaps"]].forEach(function (m) {
      var b = el("div", "box");
      b.appendChild(el("div", m[0], m[1]));
      b.appendChild(el("div", "l", m[2]));
      mini.appendChild(b);
    });
    card.appendChild(mini);
  }

  function renderTopGaps() {
    var card = document.getElementById("rail-gaps");
    card.textContent = "";
    card.appendChild(el("h2", null, "Top detection gaps"));
    if (!state.candidates.length) { card.appendChild(el("p", "rail-foot", "No open gaps.")); return; }
    state.candidates.slice(0, 5).forEach(function (c, i) {
      var row = el("div", "gap-item");
      row.appendChild(el("div", "gap-rank", i + 1));
      var mid = el("div");
      mid.appendChild(el("div", "g-cve", c.cve_id));
      if (c.product) mid.appendChild(el("div", "g-prod", c.product));
      row.appendChild(mid);
      row.appendChild(el("div", "g-score", Math.round(c.score)));
      row.addEventListener("click", function () { selectView("queue"); });
      row.style.cursor = "pointer";
      card.appendChild(row);
    });
  }

  function renderTrending() {
    var card = document.getElementById("rail-trending");
    card.textContent = "";
    card.appendChild(el("h2", null, "Trending tags"));
    allTags().slice(0, 6).forEach(function (pair) {
      var row = el("div", "trend-item");
      var isAi = pair[0] === "AI-sec";
      row.appendChild(el("div", "t-tag" + (isAi ? " ai" : ""), "#" + pair[0]));
      row.appendChild(el("div", "t-n", pair[1] + " items"));
      row.addEventListener("click", function () {
        selectView("feed");
        state.activeTags = new Set([pair[0]]);
        renderChips(); renderFeed();
      });
      row.style.cursor = "pointer";
      card.appendChild(row);
    });
  }

  // ---- view switching ---------------------------------------------------
  function selectView(view) {
    state.view = view;
    var isFeed = view === "feed";
    document.getElementById("view-feed").hidden = !isFeed;
    document.getElementById("view-queue").hidden = isFeed;
    document.querySelectorAll("[data-view]").forEach(function (b) {
      var active = b.getAttribute("data-view") === view;
      if (b.classList.contains("seg-btn")) {
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", active ? "true" : "false");
      } else {
        b.setAttribute("aria-current", active ? "true" : "false");
      }
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // ---- load -------------------------------------------------------------
  function setGapBadges(n) {
    ["nav-gap-count", "tab-gap-count"].forEach(function (id) {
      var e = document.getElementById(id);
      if (!e) return;
      e.textContent = n;
      e.hidden = n === 0;
    });
  }

  function load() {
    Promise.all([
      fetch("data.json", { cache: "no-cache" }).then(function (r) { return r.json(); }),
      fetch("candidates.json", { cache: "no-cache" }).then(function (r) { return r.json(); })
    ]).then(function (res) {
      var data = res[0], cand = res[1];
      state.items = data.items || [];
      state.candidates = cand.candidates || [];
      state.stats = data.stats || null;

      var when = data.last_run || data.generated;
      var upd = when ? "Updated " + fmtAge(when) + " ago" : "";
      var un = document.getElementById("updated-nav"); if (un) un.textContent = upd;

      setGapBadges(state.candidates.length);
      renderKpis();
      renderChips();
      renderFeed();
      renderQueue();
      renderCoverage();
      renderTopGaps();
      renderTrending();
    }).catch(function (e) {
      var un = document.getElementById("updated-nav"); if (un) un.textContent = "Failed to load";
      // eslint-disable-next-line no-console
      console.error(e);
    });
  }

  // ---- wire up ----------------------------------------------------------
  document.querySelectorAll("[data-view]").forEach(function (b) {
    b.addEventListener("click", function () { selectView(b.getAttribute("data-view")); });
  });
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
