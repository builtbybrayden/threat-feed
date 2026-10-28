/* Dashboard logic. Feed content is UNTRUSTED: every value from the JSON is
   inserted with textContent, never innerHTML, and links are rendered only when
   they use an http/https scheme. No third-party code, no CDN. */
"use strict";

(function () {
  var state = {
    items: [], threats: [], candidates: [], stats: null, repo: null,
    first_run: null, last_run: null,
    view: "news",
    newsQuery: "", newsTags: new Set(),
    threatCoverage: "all", threatEco: null,      // coverage: all | gap | covered
    threatSort: "score", queueSort: "score",     // score | published | modified
    dismissed: new Set(), showDismissed: false
  };

  // Per-device dismissals (localStorage). Not shared across devices — that would
  // need a repo-side ignore list; this is an instant, reversible local hide.
  var DISMISS_KEY = "tf-dismissed-v1";
  function loadDismissed() {
    try { return new Set(JSON.parse(localStorage.getItem(DISMISS_KEY) || "[]")); }
    catch (e) { return new Set(); }
  }
  function saveDismissed() {
    try { localStorage.setItem(DISMISS_KEY, JSON.stringify(Array.from(state.dismissed))); }
    catch (e) { /* private mode / blocked storage: dismissals just won't persist */ }
  }

  // Canonical ecosystem quick-filter order + display labels (Threats board).
  var ECO_ORDER = ["pypi", "npm", "maven", "go", "rubygems", "nuget", "composer", "rust", "swift", "actions", "php", "web", "supply-chain"];
  var ECO_LABEL = {
    pypi: "PyPI", npm: "npm", maven: "Maven / Java", go: "Go", rubygems: "RubyGems",
    nuget: "NuGet", composer: "Composer / PHP", rust: "Rust", swift: "Swift",
    actions: "Actions", php: "PHP", web: "Web", "supply-chain": "Supply chain"
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
  // Mirrors config.yaml feed.roundup_min_cves: a post naming this many CVEs is a
  // multi-topic roundup, so per-post KEV/EPSS/PoC signals are suppressed.
  var ROUNDUP_MIN_CVES = 3;

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
  // EPSS often sits at 0.999x for actively-exploited CVEs; rounding those to a
  // flat "100%" made the whole queue look identical. Floor to real precision so
  // 0.99999 reads 99.99% and only an exact 1.0 shows 100%.
  function epssPct(x) {
    if (x == null) return "";
    if (x >= 1) return "100%";
    var p = x * 100;
    if (p >= 99) return (Math.floor(p * 100) / 100) + "%";   // 99.99, 99.98, ...
    if (p >= 10) return (Math.round(p * 10) / 10) + "%";      // 42.3
    return (Math.round(p * 100) / 100) + "%";                 // 2.34
  }
  function dateShort(iso) {
    if (!iso) return "";
    var t = Date.parse(iso); if (isNaN(t)) return "";
    return new Date(t).toISOString().slice(0, 10);           // YYYY-MM-DD
  }
  // Sort a copy of a CVE list by the chosen key (score keeps server order).
  function sortCves(arr, by) {
    if (by === "score") return arr;
    var key = by === "modified" ? "modified" : "published";
    return arr.slice().sort(function (a, b) {
      return String(b[key] || "").localeCompare(String(a[key] || ""));
    });
  }

  // ---- KPI header -------------------------------------------------------
  function renderKpis() {
    var s = state.stats; if (!s) return;
    var host = document.getElementById("kpis"); host.textContent = "";
    [
      ["n crit", s.actively_exploited_appsec, "AppSec CVEs exploited in the wild", "exploited"],
      ["n warn", s.newly_exploited, "Newly added to CISA KEV · " + (s.newly_exploited_days || 30) + "d", "newly"],
      ["n poc", s.public_poc, "With public exploit code (PoC)", "poc"],
      ["n", s.open_gaps, "Missing a Nuclei template", "gaps"]
    ].forEach(function (k) {
      var b = el("div", "kpi clickable");
      b.setAttribute("role", "button"); b.setAttribute("tabindex", "0");
      b.appendChild(el("div", k[0], k[1]));
      b.appendChild(el("div", "l", k[2]));
      b.addEventListener("click", function () { openKpiDetail(k[3]); });
      b.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openKpiDetail(k[3]); } });
      host.appendChild(b);
    });
  }
  // Explains each headline metric: what it counts and where the number comes from.
  function openKpiDetail(key) {
    var s = state.stats || {};
    var M = {
      exploited: {
        n: s.actively_exploited_appsec, label: "AppSec CVEs exploited in the wild",
        what: "CVEs that are both application-security relevant and listed in CISA's Known Exploited Vulnerabilities (KEV) catalog — i.e. confirmed exploited in the wild.",
        how: [["CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
              ["AppSec classifier (ecosystem / CWE / CPE)", null]],
        jump: "threats"
      },
      newly: {
        n: s.newly_exploited, label: "Newly added to CISA KEV · " + (s.newly_exploited_days || 30) + "d",
        what: "AppSec CVEs whose CISA KEV dateAdded falls within the last " + (s.newly_exploited_days || 30) + " days — the ones that just started being exploited.",
        how: [["CISA KEV dateAdded", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]],
        jump: "threats"
      },
      poc: {
        n: s.public_poc, label: "With public exploit code (PoC)",
        what: "AppSec CVEs for which a public proof-of-concept exploit repo is known.",
        how: [["nomi-sec PoC-in-GitHub index", "https://github.com/nomi-sec/PoC-in-GitHub"]],
        jump: "threats"
      },
      gaps: {
        n: s.open_gaps, label: "Missing a Nuclei template",
        what: "Detection candidates: AppSec CVEs that have no Nuclei template yet, are remotely/HTTP-detectable, and carry a priority signal (KEV, high EPSS, or a watchlist product).",
        how: [["ProjectDiscovery nuclei-templates (coverage)", "https://github.com/projectdiscovery/nuclei-templates"],
              ["FIRST EPSS", "https://www.first.org/epss/"]],
        jump: "queue"
      }
    };
    var m = M[key]; if (!m) return;
    openModal(function (body) {
      var h = el("div", "detail-head");
      h.appendChild(el("div", "kpi-detail-n", m.n == null ? "—" : m.n));
      h.appendChild(el("div", "detail-prod", m.label));
      body.appendChild(h);
      body.appendChild(el("p", "detail-desc", m.what));
      body.appendChild(el("h3", "detail-h", "Where this comes from"));
      var ul = el("ul", "kpi-sources");
      m.how.forEach(function (src) {
        var li = el("li");
        if (src[1]) li.appendChild(link(src[1], src[0], "src-link")); else li.appendChild(el("span", null, src[0]));
        ul.appendChild(li);
      });
      body.appendChild(ul);
      var links = el("div", "detail-links");
      var jb = el("button", "btn primary", m.jump === "queue" ? "View detection queue" : "View on Threats board");
      jb.type = "button";
      jb.addEventListener("click", function () { closeModal(); selectView(m.jump); });
      links.appendChild(jb);
      body.appendChild(links);
    });
  }

  // ---- NEWS -------------------------------------------------------------
  function newsTagCounts() {
    var set = {};
    state.items.forEach(function (it) { (it.tags || []).forEach(function (t) { set[t] = (set[t] || 0) + 1; }); });
    return Object.keys(set).sort(function (a, b) { return set[b] - set[a]; }).map(function (t) { return [t, set[t]]; });
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
    body.appendChild(head);

    var h = el("div", "p-title"); h.appendChild(link(it.url, it.title)); body.appendChild(h);
    if (it.summary) { var s = it.summary.length > 220 ? it.summary.slice(0, 220).trim() + "…" : it.summary; body.appendChild(el("p", "p-text", s)); }
    if (it.cves && it.cves.length) {
      var cr = el("div", "cve-row");
      it.cves.slice(0, 6).forEach(function (c) { cr.appendChild(el("span", "cve-chip", c)); });
      body.appendChild(cr);
    }
    var stats = el("div", "p-stats");
    // On a multi-CVE roundup, KEV/EPSS/PoC are inherited from the single hottest
    // linked CVE and overstate the article, so show a plain "N CVEs" tag instead.
    // On single-vuln posts those signals describe the one CVE, so keep them.
    if (it.cves && it.cves.length >= ROUNDUP_MIN_CVES) {
      stats.appendChild(el("span", "tag-pill multi", it.cves.length + " CVEs"));
    } else {
      if (it.kev) stats.appendChild(statItem("KEV", null, "kev"));
      if (it.epss != null) stats.appendChild(statItem("EPSS", epssPct(it.epss)));
      if ((it.tags || []).indexOf("has-PoC") !== -1) stats.appendChild(statItem("PoC", null, "poc"));
    }
    (it.tags || []).forEach(function (t) {
      if (["KEV", "has-PoC", "has-CVE", "research", "watchlist"].indexOf(t) !== -1) return;
      stats.appendChild(el("span", "tag-pill" + (t === "AI-sec" ? " ai" : ""), t));
    });
    if (stats.childNodes.length) body.appendChild(stats);
    post.appendChild(body);
    post.classList.add("clickable");
    post.addEventListener("click", cardClick(function () { openNewsDetail(it); }));
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
    // Ecosystems present in the data, in canonical order, with any extras appended.
    var counts = {};
    state.threats.forEach(function (t) { (t.ecosystems || []).forEach(function (e) { counts[e] = (counts[e] || 0) + 1; }); });
    var present = Object.keys(counts);
    var ordered = ECO_ORDER.filter(function (e) { return counts[e]; });
    present.forEach(function (e) { if (ordered.indexOf(e) === -1) ordered.push(e); });
    return ordered.map(function (e) { return [e, counts[e]]; });
  }
  function ecoChip(label, eco, active, count) {
    var c = el("button", "chip eco", label); c.type = "button";
    c.setAttribute("aria-pressed", active ? "true" : "false");
    if (count != null) { var n = el("span", "chip-n", count); c.appendChild(n); }
    c.addEventListener("click", function () {
      state.threatEco = (eco && state.threatEco === eco) ? null : eco; // single-select, toggle off
      renderThreatChips(); renderThreats();
    });
    return c;
  }
  // A small labeled group of single-select pills.
  function pillGroup(host, label, options, current, onPick) {
    var g = el("div", "filter-group");
    g.appendChild(el("div", "filter-group-label", label));
    var row = el("div", "chips-row");
    options.forEach(function (o) {
      var b = el("button", "chip", o[1]); b.type = "button";
      b.setAttribute("aria-pressed", current === o[0] ? "true" : "false");
      b.addEventListener("click", function () { onPick(o[0]); });
      row.appendChild(b);
    });
    g.appendChild(row); host.appendChild(g);
  }
  var COVERAGE_OPTS = [["all", "All"], ["gap", "No template"], ["covered", "Has template"]];
  var SORT_OPTS = [["score", "Priority"], ["published", "Date published"], ["modified", "Date modified"]];
  function renderThreatChips() {
    var host = document.getElementById("threat-chips"); host.textContent = "";
    pillGroup(host, "Template coverage", COVERAGE_OPTS, state.threatCoverage, function (v) {
      state.threatCoverage = v; renderThreatChips(); renderThreats();
    });
    pillGroup(host, "Sort by", SORT_OPTS, state.threatSort, function (v) {
      state.threatSort = v; renderThreatChips(); renderThreats();
    });
    var g = el("div", "filter-group");
    g.appendChild(el("div", "filter-group-label", "Ecosystem"));
    var row = el("div", "chips-row");
    row.appendChild(ecoChip("All", null, state.threatEco === null, null));
    threatEcosystems().forEach(function (p) {
      row.appendChild(ecoChip(ECO_LABEL[p[0]] || p[0], p[0], state.threatEco === p[0], p[1]));
    });
    g.appendChild(row); host.appendChild(g);
    updateThreatFilterLabel();
  }
  function threatFilterSummary() {
    var parts = [];
    if (state.threatCoverage === "gap") parts.push("No template");
    else if (state.threatCoverage === "covered") parts.push("Has template");
    if (state.threatEco) parts.push(ECO_LABEL[state.threatEco] || state.threatEco);
    if (state.threatSort !== "score") parts.push(state.threatSort === "published" ? "by published" : "by modified");
    return parts.join(" · ");
  }
  function updateThreatFilterLabel() {
    var badge = document.getElementById("threat-filter-active"); if (!badge) return;
    var s = threatFilterSummary(); badge.textContent = s; badge.hidden = !s;
  }
  function threatMatch(t) {
    if (state.threatCoverage === "gap" && t.coverage !== "gap") return false;
    if (state.threatCoverage === "covered" && t.coverage === "gap") return false;
    if (state.threatEco && (t.ecosystems || []).indexOf(state.threatEco) === -1) return false;
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
    if (t.epss != null) stats.appendChild(statItem("EPSS", epssPct(t.epss)));
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
    if (t.advisory_url) act.appendChild(link(t.advisory_url, "GitHub advisory", "btn"));
    if (t.coverage === "gap" && t.is_candidate) act.appendChild(el("span", "issue-ref", "in detection queue"));
    v.appendChild(act);
    v.classList.add("clickable");
    v.setAttribute("role", "button"); v.setAttribute("tabindex", "0");
    v.addEventListener("click", cardClick(function () { openThreatDetail(t); }));
    v.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openThreatDetail(t); } });
    return v;
  }
  function renderThreats() {
    var host = document.getElementById("threats"); host.textContent = "";
    var shown = sortCves(state.threats.filter(threatMatch), state.threatSort);
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
    if (c.epss != null) stats.appendChild(statItem("EPSS", epssPct(c.epss)));
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
    var isD = state.dismissed.has(c.cve_id);
    var db = el("button", "btn ghost", isD ? "Restore" : "Dismiss"); db.type = "button";
    db.addEventListener("click", function (e) { e.stopPropagation(); toggleDismiss(c.cve_id); });
    act.appendChild(db);
    v.appendChild(act);
    if (isD) v.classList.add("is-dismissed");
    v.classList.add("clickable");
    v.setAttribute("role", "button"); v.setAttribute("tabindex", "0");
    v.addEventListener("click", cardClick(function () { openCandidateDetail(c); }));
    v.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openCandidateDetail(c); } });
    return v;
  }
  function renderQueue() {
    var host = document.getElementById("queue"); host.textContent = "";
    var ctl = document.getElementById("queue-controls");
    if (ctl) {
      ctl.textContent = "";
      var g = el("div", "filter-group inline");
      g.appendChild(el("div", "filter-group-label", "Sort by"));
      var row = el("div", "chips-row");
      SORT_OPTS.forEach(function (o) {
        var b = el("button", "chip", o[1]); b.type = "button";
        b.setAttribute("aria-pressed", state.queueSort === o[0] ? "true" : "false");
        b.addEventListener("click", function () { state.queueSort = o[0]; renderQueue(); });
        row.appendChild(b);
      });
      g.appendChild(row); ctl.appendChild(g);
      var dCount = state.candidates.length - visibleCandidates().length;
      if (dCount) {
        var t = el("button", "chip dismissed-toggle", (state.showDismissed ? "Hide" : "Show") + " dismissed (" + dCount + ")");
        t.type = "button";
        t.addEventListener("click", function () { state.showDismissed = !state.showDismissed; renderQueue(); });
        ctl.appendChild(t);
      }
    }
    var list = sortCves(state.showDismissed ? state.candidates : visibleCandidates(), state.queueSort);
    document.getElementById("queue-empty").hidden = list.length !== 0;
    list.forEach(function (c) { host.appendChild(queueCard(c)); });
  }

  // ---- DETAIL MODAL + ISSUE TRACKING ------------------------------------
  // The site is static, so we can't create issues from the page (no token in a
  // public page). Instead each button opens GitHub's own new-issue form,
  // prefilled — you submit it there with one click. The hidden marker matches
  // the auto-filer's, so a manual issue and an auto-filed one won't duplicate.
  function issueHref(kind, info) {
    var repo = state.repo || "builtbybrayden/threat-feed";
    var marker = info.cve_id ? "<!-- threat-feed:" + info.cve_id + " -->\n\n" : "";
    var label, title, lines = [];
    if (kind === "research") {
      label = "research";
      title = "[research] " + (info.cve_id || info.title || "").slice(0, 90);
      lines.push("## Deep-research task", "");
    } else {
      label = "nuclei-candidate";
      title = "[nuclei-candidate] " + (info.cve_id || "") + (info.product ? " (" + info.product + ")" : "");
      lines.push("## Detection template needed", "");
    }
    if (info.cve_id) lines.push("**CVE:** " + info.cve_id);
    if (info.product) lines.push("**Product:** " + info.product);
    if (info.ecosystems && info.ecosystems.length) lines.push("**Ecosystem:** " + info.ecosystems.join(", "));
    var sig = [];
    if (info.kev) sig.push("in CISA KEV");
    if (info.epss != null) sig.push("EPSS " + Math.round(info.epss * 100) + "%");
    if (info.cvss_score != null) sig.push("CVSS " + info.cvss_score);
    if (info.coverage) sig.push(info.coverage === "gap" ? "no Nuclei template" : "template exists");
    if (sig.length) lines.push("**Signals:** " + sig.join(" · "));
    if (info.description) lines.push("", info.description);
    lines.push("", "### Links");
    if (info.advisory_url) lines.push("- GitHub advisory: " + info.advisory_url);
    if (info.cve_id) lines.push("- NVD: https://nvd.nist.gov/vuln/detail/" + info.cve_id);
    if (info.url) lines.push("- Source: " + info.url);
    if (info.brief) lines.push("- Detection brief (in repo): " + info.brief);
    lines.push("", "### Checklist");
    if (kind === "research") {
      lines.push("- [ ] Root cause & affected versions", "- [ ] Confirm remote/HTTP detectability", "- [ ] Decide whether a template is worth building");
    } else {
      lines.push("- [ ] Identify a fingerprint or behavioral check", "- [ ] Write the Nuclei template", "- [ ] Validate against a local lab target only");
    }
    var body = marker + lines.join("\n");
    return "https://github.com/" + repo + "/issues/new?title=" + encodeURIComponent(title) +
      "&labels=" + encodeURIComponent(label) + "&body=" + encodeURIComponent(body);
  }
  function detailActions(info, opts) {
    var wrap = el("div", "detail-actions");
    if (info.issue_number) {
      wrap.appendChild(link("https://github.com/" + (state.repo || "builtbybrayden/threat-feed") + "/issues/" + info.issue_number,
        "View issue #" + info.issue_number, "btn primary"));
      return wrap;
    }
    if (opts.research) wrap.appendChild(link(issueHref("research", info), "Deep-research issue", "btn primary"));
    if (opts.template) wrap.appendChild(link(issueHref("template", info), "Template-needed issue", "btn"));
    return wrap;
  }
  function openModal(build) {
    var overlay = document.getElementById("detail-overlay");
    var body = document.getElementById("detail-body");
    body.textContent = ""; build(body);
    overlay.hidden = false; document.body.classList.add("modal-open");
    document.getElementById("detail-panel").scrollTop = 0;
  }
  function closeModal() {
    document.getElementById("detail-overlay").hidden = true;
    document.body.classList.remove("modal-open");
  }
  function openThreatDetail(t) {
    openModal(function (body) {
      var h = el("div", "detail-head");
      h.appendChild(el("div", "detail-id", t.cve_id));
      h.appendChild(el("div", "detail-prod", (t.vendor ? t.vendor + " / " : "") + (t.product || "unknown product")));
      body.appendChild(h);

      var stats = el("div", "p-stats");
      stats.appendChild(el("span", scoreClass(t.score, "p-score"), Math.round(t.score)));
      if (t.kev) stats.appendChild(statItem(t.kev_added ? "KEV · " + String(t.kev_added).slice(0, 4) : "KEV", null, "kev"));
      if (t.epss != null) stats.appendChild(statItem("EPSS", epssPct(t.epss)));
      if (t.cvss_score != null) stats.appendChild(statItem("CVSS", t.cvss_score));
      if (t.has_poc) stats.appendChild(statItem("PoC", null, "poc"));
      stats.appendChild(el("span", "cov " + (t.coverage === "gap" ? "gap" : "covered"), t.coverage === "gap" ? "No template" : "Covered"));
      (t.ecosystems || []).forEach(function (e) { stats.appendChild(el("span", "tag-pill eco", ECO_LABEL[e] || e)); });
      (t.vuln_classes || []).forEach(function (c) { stats.appendChild(el("span", "tag-pill", c)); });
      (t.cwe || []).forEach(function (c) { stats.appendChild(el("span", "tag-pill", c)); });
      body.appendChild(stats);

      if (t.description) body.appendChild(el("p", "detail-desc", t.description));

      if (t.sources && t.sources.length) {
        var sl = el("div", "src-links");
        t.sources.forEach(function (s) {
          var wrap = el("div"); wrap.appendChild(link(s.url, s.title));
          wrap.appendChild(el("span", "src-from", "  — " + s.source)); sl.appendChild(wrap);
        });
        body.appendChild(sl);
      }

      var links = el("div", "detail-links");
      if (t.advisory_url) links.appendChild(link(t.advisory_url, t.ghsa_id || "GitHub advisory", "btn"));
      links.appendChild(link("https://nvd.nist.gov/vuln/detail/" + t.cve_id, "NVD", "btn"));
      if (t.is_candidate && t.brief) links.appendChild(link(t.brief, "Detection brief", "btn"));
      body.appendChild(links);

      body.appendChild(el("h3", "detail-h", "Track this"));
      body.appendChild(el("p", "detail-hint", "Opens a prefilled issue on GitHub — review and submit it there."));
      body.appendChild(detailActions({
        cve_id: t.cve_id, product: t.product, ecosystems: t.ecosystems, cvss_score: t.cvss_score,
        epss: t.epss, kev: t.kev, coverage: t.coverage, advisory_url: t.advisory_url,
        description: t.description, brief: t.brief, issue_number: t.issue_number
      }, { research: true, template: true }));
    });
  }
  function openNewsDetail(it) {
    openModal(function (body) {
      var m = sourceMeta(it.source);
      var h = el("div", "detail-head");
      h.appendChild(el("div", "detail-prod", it.source + " · @" + m.h + " · " + fmtAge(it.published)));
      h.appendChild(el("div", "detail-article-title", it.title));
      body.appendChild(h);
      if (it.summary) body.appendChild(el("p", "detail-desc", it.summary));
      if (it.cves && it.cves.length) {
        var cr = el("div", "cve-row");
        it.cves.forEach(function (c) { cr.appendChild(el("span", "cve-chip", c)); });
        body.appendChild(cr);
      }
      var links = el("div", "detail-links");
      links.appendChild(link(it.url, "Open article", "btn"));
      body.appendChild(links);

      body.appendChild(el("h3", "detail-h", "Track this"));
      body.appendChild(el("p", "detail-hint", "Opens a prefilled issue on GitHub — review and submit it there."));
      body.appendChild(detailActions({
        cve_id: (it.cves && it.cves[0]) || null, title: it.title, url: it.url,
        description: it.summary, epss: it.epss, kev: it.kev
      }, { research: true, template: !!(it.cves && it.cves.length) }));
    });
  }
  function openCandidateDetail(c) {
    openModal(function (body) {
      var h = el("div", "detail-head");
      h.appendChild(el("div", "detail-id", c.cve_id));
      h.appendChild(el("div", "detail-prod", (c.vendor ? c.vendor + " / " : "") + (c.product || "unknown product")));
      body.appendChild(h);

      var stats = el("div", "p-stats");
      stats.appendChild(el("span", scoreClass(c.score, "p-score"), Math.round(c.score)));
      if (c.kev) stats.appendChild(statItem(c.kev_added ? "KEV · " + String(c.kev_added).slice(0, 4) : "KEV", null, "kev"));
      if (c.epss != null) stats.appendChild(statItem("EPSS", epssPct(c.epss)));
      if (c.cvss_score != null) stats.appendChild(statItem("CVSS", c.cvss_score));
      if (c.detectability && c.detectability.has_poc) stats.appendChild(statItem("PoC", null, "poc"));
      stats.appendChild(el("span", "cov gap", "No template"));
      (c.ecosystems || []).forEach(function (e) { stats.appendChild(el("span", "tag-pill eco", ECO_LABEL[e] || e)); });
      (c.cwe || []).forEach(function (cw) { stats.appendChild(el("span", "tag-pill", cw)); });
      body.appendChild(stats);

      var dates = [];
      if (c.published) dates.push("Published " + dateShort(c.published));
      if (c.modified) dates.push("Modified " + dateShort(c.modified));
      if (dates.length) body.appendChild(el("p", "detail-dates", dates.join("  ·  ")));

      var d = c.detectability || {};
      var grid = el("div", "meta-grid");
      function row(k, val) { grid.appendChild(el("div", "k", k)); grid.appendChild(el("div", "v", val)); }
      row("Detectability", d.likely_http ? "HTTP" : (d.remote_network ? "remote (AV:N)" : "local"));
      row("Template type", d.suggested_template_type || "?");
      if (c.cwe && c.cwe.length) row("CWE", c.cwe.join(", "));
      body.appendChild(grid);

      if (c.candidate_reasons && c.candidate_reasons.length) {
        var det = el("details", "why"); det.setAttribute("open", "");
        det.appendChild(el("summary", null, "Why it's a candidate"));
        var ul = el("ul"); c.candidate_reasons.forEach(function (r) { ul.appendChild(el("li", null, r)); });
        det.appendChild(ul); body.appendChild(det);
      }

      var links = el("div", "detail-links");
      links.appendChild(link(c.brief, "Detection brief", "btn"));
      links.appendChild(link("https://nvd.nist.gov/vuln/detail/" + c.cve_id, "NVD", "btn"));
      if (c.issue_number != null) links.appendChild(link("https://github.com/" + (state.repo || "builtbybrayden/threat-feed") + "/issues/" + c.issue_number, "Issue #" + c.issue_number, "btn"));
      body.appendChild(links);

      body.appendChild(el("h3", "detail-h", "Track this"));
      body.appendChild(el("p", "detail-hint", "Opens a prefilled issue on GitHub — review and submit it there."));
      body.appendChild(detailActions({
        cve_id: c.cve_id, product: c.product, ecosystems: c.ecosystems, cvss_score: c.cvss_score,
        epss: c.epss, kev: c.kev, coverage: "gap", description: c.description || "", brief: c.brief, issue_number: c.issue_number
      }, { research: true, template: true }));

      var dz = el("div", "detail-dismiss");
      var isD = state.dismissed.has(c.cve_id);
      var db = el("button", "btn ghost", isD ? "Restore to queue" : "Dismiss — not relevant"); db.type = "button";
      db.addEventListener("click", function () { toggleDismiss(c.cve_id); closeModal(); });
      dz.appendChild(db);
      body.appendChild(dz);
    });
  }
  function visibleCandidates() {
    return state.candidates.filter(function (c) { return !state.dismissed.has(c.cve_id); });
  }
  function toggleDismiss(cve) {
    if (state.dismissed.has(cve)) state.dismissed.delete(cve); else state.dismissed.add(cve);
    saveDismissed();
    renderQueue(); renderRailGaps();
    setGapBadge(visibleCandidates().length);
  }
  // A click anywhere on a card opens its detail, except on a real link/button.
  function cardClick(open) {
    return function (e) { if (e.target.closest("a,button")) return; open(); };
  }

  // ---- RAIL -------------------------------------------------------------
  function renderRailGaps() {
    var card = document.getElementById("rail-gaps"); card.textContent = "";
    card.appendChild(el("h2", null, "Top detection gaps"));
    var cands = visibleCandidates();
    if (!cands.length) { card.appendChild(el("p", "rail-foot", "No open gaps.")); return; }
    cands.slice(0, 5).forEach(function (c, i) {
      var row = el("div", "gap-item");
      row.appendChild(el("div", "gap-rank", i + 1));
      var mid = el("div");
      mid.appendChild(el("div", "g-cve", c.cve_id));
      if (c.product) mid.appendChild(el("div", "g-prod", c.product));
      row.appendChild(mid);
      row.appendChild(el("div", "g-score", Math.round(c.score)));
      row.addEventListener("click", function () { openCandidateDetail(c); });  // open the card, not the whole queue
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
      row.addEventListener("click", function () { selectView("news"); state.newsTags = new Set([p[0]]); renderNews(); });
      card.appendChild(row);
    });
  }

  // ---- footers / disclaimers --------------------------------------------
  function renderFooters() {
    var age = state.last_run ? fmtAge(state.last_run) : null;
    var un = document.getElementById("updated-nav");
    if (un) un.textContent = age ? "as of " + age + " ago" : "";
    var foot = document.getElementById("main-foot");
    if (foot) {
      var parts = [];
      if (age) parts.push("Live · data as of " + age + " ago");
      if (state.first_run) parts.push("tracking since " + dateShort(state.first_run));
      parts.push("public sources only, refreshed every 6h");
      foot.textContent = parts.join("  ·  ");
    }
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
      state.repo = data.repo || null;
      state.first_run = data.first_run || null;
      state.last_run = data.last_run || data.generated || null;
      state.dismissed = loadDismissed();
      setGapBadge(visibleCandidates().length);
      renderFooters();
      renderKpis();
      renderNews();
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
  (function () {
    var overlay = document.getElementById("detail-overlay");
    document.getElementById("detail-close").addEventListener("click", closeModal);
    overlay.addEventListener("click", function (e) { if (e.target === overlay) closeModal(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !overlay.hidden) closeModal(); });
  })();
  (function () {
    var ft = document.getElementById("threat-filter-toggle");
    if (!ft) return;
    ft.addEventListener("click", function () {
      var panel = document.getElementById("threat-chips");
      var open = panel.hidden;              // about to open if currently hidden
      panel.hidden = !open;
      ft.setAttribute("aria-expanded", open ? "true" : "false");
      ft.classList.toggle("is-open", open);
    });
  })();
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () { navigator.serviceWorker.register("sw.js").catch(function () {}); });
  }
  load();
})();
