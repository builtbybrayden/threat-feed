/* Dashboard logic. Feed content is UNTRUSTED: every value from the JSON is
   inserted with textContent, never innerHTML, and links are rendered only when
   they use an http/https scheme. No third-party code, no CDN. */
"use strict";

(function () {
  var state = {
    items: [], threats: [], candidates: [], stats: null,
    view: "news",
    newsQuery: "", newsTags: new Set(),
    threatGapsOnly: false, threatEco: new Set()
  };

  // Source identity: avatar file slug, @handle, trusted-research flag.
  var SOURCES = {
    "PortSwigger Research": { slug: "portswigger", h: "portswigger", v: true },
    "Project Zero": { slug: "projectzero", h: "projectzero", v: true },
    "GitHub Security Lab": { slug: "ghsecuritylab", h: "ghsecuritylab", v: true },
    "tl;dr sec": { slug: "tldrsec", h: "tldrsec", v: false },
    "Risky Bulletin": { slug: "riskybiz", h: "riskybiz", v: false },
    "Simon Willison": { slug: "simonw", h: "simonw", v: false }
  };
  var AI_TAGS = { "prompt injection": 1, "llm": 1, "rag": 1, "mcp": 1, "model context protocol": 1, "langchain": 1 };

  // ---- helpers ----------------------------------------------------------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }
  function safeHref(url) {
    if (typeof url !== "string") return null;
    try { var u = new URL(url, window.location.href); return (u.protocol === "http:" || u.protocol === "https:") ? u.href : null; }
    catch (e) { return null; }
  }
  function link(url, text, cls) {
    var href = safeHref(url);
    if (!href) return el("span", cls, text == null ? url : text);
    var a = el("a", cls, text == null ? url : text);
    a.setAttribute("href", href); a.setAttribute("target", "_blank"); a.setAttribute("rel", "noopener noreferrer");
    return a;
  }
  function fmtAge(iso) {
    var t = Date.parse(iso); if (isNaN(t)) return "";
    var m = Math.max(0, (Date.now() - t) / 60000);
    if (m < 1) return "now"; if (m < 60) return Math.round(m) + "m";
    if (m < 1440) return Math.round(m / 60) + "h"; return Math.round(m / 1440) + "d";
  }
  function hash(s) { var h = 0; for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return h; }
  function sourceMeta(name) {
    if (SOURCES[name]) return SOURCES[name];
    var w = String(name).split(/\s+/);
    return { slug: null, i: ((w[0][0] || "?") + (w.length > 1 ? w[1][0] : "")).toUpperCase(),
             h: String(name).toLowerCase().replace(/[^a-z0-9]+/g, ""), v: false };
  }
  function scoreClass(s, base) { return base + (s >= 70 ? " hi" : s >= 45 ? " mid" : ""); }
  function initials(name) { var w = String(name).split(/\s+/); return ((w[0][0] || "?") + (w.length > 1 ? w[1][0] : "")).toUpperCase(); }

  function avatar(name) {
    var m = sourceMeta(name);
    var d = el("div", "avatar");
    if (m.slug) {
      var img = document.createElement("img");
      img.src = "avatars/" + m.slug + ".png"; img.alt = "";
      img.addEventListener("error", function () { d.textContent = initials(name); });
      d.appendChild(img);
    } else {
      d.textContent = m.i || initials(name);
    }
    return d;
  }

  function statItem(label, value, cls) {
    var s = el("span", "stat-item" + (cls ? " " + cls : ""));
    if (value != null) s.appendChild(el("span", "sv", value));
    s.appendChild(el("span", null, label));
    return s;
  }
  function pct(x) { return Math.round(x * 100) + "%"; }

  // ---- KPI header -------------------------------------------------------
  function renderKpis() {
    var s = state.stats; if (!s) return;
    var host = document.getElementById("kpis"); host.textContent = "";
    [
      ["n crit", s.actively_exploited_appsec, "Actively exploited"],
      ["n warn", s.newly_exploited, "Newly exploited · " + (s.newly_exploited_days || 30) + "d"],
      ["n poc", s.public_poc, "Public PoC"],
      ["n", s.open_gaps, "Detection gaps"]
    ].forEach(function (k) {
      var b = el("div", "kpi");
      b.appendChild(el("div", k[0], k[1]));
      b.appendChild(el("div", "l", k[2]));
      host.appendChild(b);
    });
  }

  // ---- NEWS -------------------------------------------------------------
  function newsTagCounts() {
    var set = {};
    state.items.forEach(function (it) { (it.tags || []).forEach(function (t) { set[t] = (set[t] || 0) + 1; }); });
    return Object.keys(set).sort(function (a, b) { return set[b] - set[a]; }).map(function (t) { return [t, set[t]]; });
  }
  function renderNewsChips() {
    var host = document.getElementById("news-chips"); host.textContent = "";
    newsTagCounts().slice(0, 12).forEach(function (p) {
      var c = el("button", "chip", p[0]); c.type = "button";
      c.setAttribute("aria-pressed", state.newsTags.has(p[0]) ? "true" : "false");
      c.addEventListener("click", function () {
        state.newsTags.has(p[0]) ? state.newsTags.delete(p[0]) : state.newsTags.add(p[0]);
        renderNewsChips(); renderNews();
      });
      host.appendChild(c);
    });
  }
  function newsMatch(it) {
    for (var t of state.newsTags) { if ((it.tags || []).indexOf(t) === -1) return false; }
    if (state.newsQuery) {
      var hay = (it.title + " " + it.summary + " " + (it.cves || []).join(" ")).toLowerCase();
      if (hay.indexOf(state.newsQuery) === -1) return false;
    }
    return true;
  }
  function newsPost(it) {
    var m = sourceMeta(it.source);
    var post = el("article", "post");
    post.appendChild(avatar(it.source));
    var body = el("div", "post-body");

    var head = el("div", "post-head");
    head.appendChild(el("span", "p-source", it.source));
    if (m.v) { var v = el("span", "verified", "✓"); v.title = "trusted research source"; head.appendChild(v); }
    head.appendChild(el("span", "p-handle", "@" + m.h));
    head.appendChild(el("span", "p-dot", "·"));
    head.appendChild(el("span", "p-time", fmtAge(it.published)));
    head.appendChild(el("span", scoreClass(it.score, "p-score"), Math.round(it.score)));
    body.appendChild(head);

    var h = el("div", "p-title"); h.appendChild(link(it.url, it.title)); body.appendChild(h);
    if (it.summary) { var s = it.summary.length > 220 ? it.summary.slice(0, 220).trim() + "…" : it.summary; body.appendChild(el("p", "p-text", s)); }
    if (it.cves && it.cves.length) {
      var cr = el("div", "cve-row");
      it.cves.slice(0, 6).forEach(function (c) { cr.appendChild(el("span", "cve-chip", c)); });
      body.appendChild(cr);
    }
    var stats = el("div", "p-stats");
    if (it.kev) stats.appendChild(statItem("KEV", null, "kev"));
    if (it.epss != null) stats.appendChild(statItem("EPSS", pct(it.epss)));
    if ((it.tags || []).indexOf("has-PoC") !== -1) stats.appendChild(statItem("PoC", null, "poc"));
    (it.tags || []).forEach(function (t) {
      if (["KEV", "has-PoC", "has-CVE", "research", "watchlist"].indexOf(t) !== -1) return;
      stats.appendChild(el("span", "tag-pill" + (t === "AI-sec" ? " ai" : ""), t));
    });
    if (stats.childNodes.length) body.appendChild(stats);
    if (it.score_reasons && it.score_reasons.length) {
      var det = el("details", "why");
      det.appendChild(el("summary", null, "Why it scored " + Math.round(it.score)));
      var ul = el("ul"); it.score_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul); body.appendChild(det);
    }
    post.appendChild(body);
    return post;
  }
  function renderNews() {
    var host = document.getElementById("news"); host.textContent = "";
    var shown = state.items.filter(newsMatch);
    document.getElementById("news-empty").hidden = shown.length !== 0;
    shown.forEach(function (it) { host.appendChild(newsPost(it)); });
  }

  // ---- THREATS ----------------------------------------------------------
  function threatEcosystems() {
    var set = {};
    state.threats.forEach(function (t) { (t.ecosystems || []).forEach(function (e) { set[e] = (set[e] || 0) + 1; }); });
    return Object.keys(set).sort(function (a, b) { return set[b] - set[a]; });
  }
  function renderThreatChips() {
    var host = document.getElementById("threat-chips"); host.textContent = "";
    var gaps = el("button", "chip", "Gaps only"); gaps.type = "button";
    gaps.setAttribute("aria-pressed", state.threatGapsOnly ? "true" : "false");
    gaps.addEventListener("click", function () { state.threatGapsOnly = !state.threatGapsOnly; renderThreatChips(); renderThreats(); });
    host.appendChild(gaps);
    threatEcosystems().forEach(function (e) {
      var c = el("button", "chip", e); c.type = "button";
      c.setAttribute("aria-pressed", state.threatEco.has(e) ? "true" : "false");
      c.addEventListener("click", function () {
        state.threatEco.has(e) ? state.threatEco.delete(e) : state.threatEco.add(e);
        renderThreatChips(); renderThreats();
      });
      host.appendChild(c);
    });
  }
  function threatMatch(t) {
    if (state.threatGapsOnly && t.coverage !== "gap") return false;
    for (var e of state.threatEco) { if ((t.ecosystems || []).indexOf(e) === -1) return false; }
    return true;
  }
  function threatCard(t) {
    var v = el("article", "vuln");
    var head = el("div", "vuln-head");
    var idw = el("div");
    idw.appendChild(el("div", "vuln-id", t.cve_id));
    var prod = (t.vendor ? t.vendor + " / " : "") + (t.product || "unknown product");
    idw.appendChild(el("div", "vuln-prod", prod));
    head.appendChild(idw);
    head.appendChild(el("span", "cov " + (t.coverage === "gap" ? "gap" : "covered"), t.coverage === "gap" ? "No template" : "Covered"));
    v.appendChild(head);

    var stats = el("div", "p-stats");
    stats.appendChild(el("span", scoreClass(t.score, "p-score"), Math.round(t.score)));
    if (t.kev) stats.appendChild(statItem(t.kev_added ? "KEV · " + String(t.kev_added).slice(0, 4) : "KEV", null, "kev"));
    if (t.epss != null) stats.appendChild(statItem("EPSS", pct(t.epss)));
    if (t.cvss_score != null) stats.appendChild(statItem("CVSS", t.cvss_score));
    if (t.has_poc) stats.appendChild(statItem("PoC", null, "poc"));
    (t.ecosystems || []).forEach(function (e) { stats.appendChild(el("span", "tag-pill eco", e)); });
    (t.vuln_classes || []).forEach(function (c) { stats.appendChild(el("span", "tag-pill", c)); });
    v.appendChild(stats);

    if (t.description) v.appendChild(el("p", "vuln-desc", t.description));

    if (t.sources && t.sources.length) {
      var sl = el("div", "src-links");
      t.sources.forEach(function (s) {
        var a = link(s.url, s.title);
        var wrap = el("div");
        wrap.appendChild(a);
        wrap.appendChild(el("span", "src-from", "  — " + s.source));
        sl.appendChild(wrap);
      });
      v.appendChild(sl);
    }

    var act = el("div", "actions");
    if (t.is_candidate && t.brief) act.appendChild(link(t.brief, "Detection brief", "btn primary"));
    act.appendChild(link("https://nvd.nist.gov/vuln/detail/" + t.cve_id, "NVD", "btn"));
    if (t.coverage === "gap" && t.is_candidate) act.appendChild(el("span", "issue-ref", "in detection queue"));
    v.appendChild(act);
    return v;
  }
  function renderThreats() {
    var host = document.getElementById("threats"); host.textContent = "";
    var shown = state.threats.filter(threatMatch);
    document.getElementById("threats-empty").hidden = shown.length !== 0;
    shown.forEach(function (t) { host.appendChild(threatCard(t)); });
  }

  // ---- DETECTION QUEUE --------------------------------------------------
  function queueCard(c) {
    var v = el("article", "vuln");
    var head = el("div", "vuln-head");
    var idw = el("div");
    idw.appendChild(el("div", "vuln-id", c.cve_id));
    idw.appendChild(el("div", "vuln-prod", (c.vendor ? c.vendor + " / " : "") + (c.product || "unknown product")));
    head.appendChild(idw);
    head.appendChild(el("span", "cov gap", "No template"));
    v.appendChild(head);

    var stats = el("div", "p-stats");
    stats.appendChild(el("span", scoreClass(c.score, "p-score"), Math.round(c.score)));
    if (c.kev) stats.appendChild(statItem("KEV", null, "kev"));
    if (c.epss != null) stats.appendChild(statItem("EPSS", pct(c.epss)));
    if (c.cvss_score != null) stats.appendChild(statItem("CVSS", c.cvss_score));
    if (c.detectability && c.detectability.has_poc) stats.appendChild(statItem("PoC", null, "poc"));
    (c.ecosystems || []).forEach(function (e) { stats.appendChild(el("span", "tag-pill eco", e)); });
    v.appendChild(stats);

    var d = c.detectability || {};
    var grid = el("div", "meta-grid");
    function row(k, val) { grid.appendChild(el("div", "k", k)); grid.appendChild(el("div", "v", val)); }
    row("Detectability", d.likely_http ? "HTTP" : (d.remote_network ? "remote (AV:N)" : "local"));
    row("Template type", d.suggested_template_type || "?");
    if (c.cwe && c.cwe.length) row("CWE", c.cwe.join(", "));
    v.appendChild(grid);

    if (c.candidate_reasons && c.candidate_reasons.length) {
      var det = el("details", "why");
      det.appendChild(el("summary", null, "Why it's a candidate"));
      var ul = el("ul"); c.candidate_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
      det.appendChild(ul); v.appendChild(det);
    }
    var act = el("div", "actions");
    act.appendChild(link(c.brief, "Detection brief", "btn primary"));
    act.appendChild(link("https://nvd.nist.gov/vuln/detail/" + c.cve_id, "NVD", "btn"));
    if (c.issue_number != null) act.appendChild(el("span", "issue-ref", "Issue #" + c.issue_number));
    v.appendChild(act);
    return v;
  }
  function renderQueue() {
    var host = document.getElementById("queue"); host.textContent = "";
    document.getElementById("queue-empty").hidden = state.candidates.length !== 0;
    state.candidates.forEach(function (c) { host.appendChild(queueCard(c)); });
  }

  // ---- RAIL -------------------------------------------------------------
  function renderRailGaps() {
    var card = document.getElementById("rail-gaps"); card.textContent = "";
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
      card.appendChild(row);
    });
  }
  function renderRailTrending() {
    var card = document.getElementById("rail-trending"); card.textContent = "";
    card.appendChild(el("h2", null, "Trending tags"));
    newsTagCounts().slice(0, 6).forEach(function (p) {
      var row = el("div", "trend-item");
      row.appendChild(el("div", "t-tag" + (p[0] === "AI-sec" ? " ai" : ""), "#" + p[0]));
      row.appendChild(el("div", "t-n", p[1]));
      row.addEventListener("click", function () { selectView("news"); state.newsTags = new Set([p[0]]); renderNewsChips(); renderNews(); });
      card.appendChild(row);
    });
  }

  // ---- view switching ---------------------------------------------------
  var VIEWS = ["news", "threats", "queue"];
  function selectView(view) {
    state.view = view;
    VIEWS.forEach(function (v) { document.getElementById("view-" + v).hidden = (v !== view); });
    document.querySelectorAll("[data-view]").forEach(function (b) {
      var active = b.getAttribute("data-view") === view;
      if (b.classList.contains("seg-btn")) { b.classList.toggle("is-active", active); b.setAttribute("aria-selected", active ? "true" : "false"); }
      else { b.setAttribute("aria-current", active ? "true" : "false"); }
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function setGapBadge(n) {
    var e = document.getElementById("nav-gap-count"); if (!e) return;
    e.textContent = n; e.hidden = n === 0;
  }

  // ---- load -------------------------------------------------------------
  function load() {
    Promise.all([
      fetch("data.json", { cache: "no-cache" }).then(function (r) { return r.json(); }),
      fetch("candidates.json", { cache: "no-cache" }).then(function (r) { return r.json(); })
    ]).then(function (res) {
      var data = res[0], cand = res[1];
      state.items = data.items || [];
      state.threats = data.threats || [];
      state.candidates = cand.candidates || [];
      state.stats = data.stats || null;
      var when = data.last_run || data.generated;
      var un = document.getElementById("updated-nav"); if (un) un.textContent = when ? "Updated " + fmtAge(when) + " ago" : "";
      setGapBadge(state.candidates.length);
      renderKpis();
      renderNewsChips(); renderNews();
      renderThreatChips(); renderThreats();
      renderQueue();
      renderRailGaps(); renderRailTrending();
    }).catch(function (e) {
      var un = document.getElementById("updated-nav"); if (un) un.textContent = "Failed to load";
      // eslint-disable-next-line no-console
      console.error(e);
    });
  }

  document.querySelectorAll("[data-view]").forEach(function (b) {
    b.addEventListener("click", function () { selectView(b.getAttribute("data-view")); });
  });
  document.getElementById("search").addEventListener("input", function (e) {
    state.newsQuery = e.target.value.trim().toLowerCase(); renderNews();
  });
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () { navigator.serviceWorker.register("sw.js").catch(function () {}); });
  }
  load();
})();
