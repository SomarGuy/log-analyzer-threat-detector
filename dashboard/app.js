/* Log Analyzer dashboard. Vanilla JS, no dependencies, no HTML string injection: all text is
   inserted with textContent, because log lines contain attacker-controlled strings (<script>, SQL, ...). */
(function () {
  "use strict";

  var SEV = ["critical", "high", "medium", "low"];
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  var SEV_COLOR = { critical: "#ff5f5f", high: "#ffa31a", medium: "#62d4e8", low: "#7f9a87" };
  var SEV_SHORT = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };
  var DEFAULT_URL = "data/alerts.json";
  var MONO = "Tailmono, 'IBM Plex Mono', 'DejaVu Sans Mono', monospace";

  var data = null;                 // loaded report
  var state = freshState();
  var cursorId = null;             // alert highlighted by j/k
  var lastFocus = null;
  var openId = null;               // alert shown in the drawer
  var hover = null;                // hovered timeline bin index
  var bins = [];                   // timeline bins for current data
  var replayMs = null;             // time of the last event shown in the tail (drawn on the timeline)

  function freshState() {
    return { sev: {}, q: "", source: "", tactic: "", rule: "", ip: "", incident: "", technique: "", range: null,
             sort: "severity", dir: -1 };
  }

  // ------------------------------------------------------------------ tiny DOM helpers
  function $(id) { return document.getElementById(id); }
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    (kids || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function sevBadge(sev) { return h("span", { class: "sev-badge sev-" + sev, text: sev }); }
  function each(list, fn) { Array.prototype.forEach.call(list, fn); }
  function repeat(ch, n) { var s = ""; for (var i = 0; i < n; i++) s += ch; return s; }
  // block meter like htop: filled cells + empty cells as two spans so they can be coloured separately
  function meterBar(frac, cells, cls) {
    var on = frac > 0 ? Math.max(1, Math.round(frac * cells)) : 0;
    return [h("span", { class: "fillc" + (cls ? " " + cls : ""), text: repeat("█", on) }), h("span", { class: "emp", text: repeat("░", cells - on) })];
  }

  // ------------------------------------------------------------------ time helpers (timestamps are naive wall-clock)
  var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  function toDate(ts) { return new Date(ts); }                      // no zone suffix => local, so no shifting
  function fmt(ts) {
    var d = toDate(ts);
    return DAYS[d.getDay()] + " " + MONTHS[d.getMonth()] + " " + d.getDate() + ", " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function fmtShort(ts) {
    var d = toDate(ts);
    return DAYS[d.getDay()] + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function fmtClock(ts) {
    var d = toDate(ts);
    return DAYS[d.getDay()] + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function clockMs(ms) {
    var d = new Date(ms);
    return DAYS[d.getDay()] + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function dur(sec) {
    if (sec < 1) return "instant";
    if (sec < 90) return Math.round(sec) + " s";
    if (sec < 5400) return Math.round(sec / 60) + " min";
    return (sec / 3600).toFixed(1) + " h";
  }

  // ------------------------------------------------------------------ loading
  function load(url) {
    fetch(url, { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(init).catch(function (err) {
      showError("Could not load " + url + " (" + err.message + "). If you opened index.html directly from disk, browsers block " +
        "fetch() on file:// URLs: run `python -m http.server` in this folder, or use \"Load your own alerts.json\".");
      $("dataset-meta").textContent = "No data loaded";
    });
  }
  function showError(msg) { var e = $("error"); e.textContent = msg; e.hidden = false; }
  function validate(d) {
    if (!d || typeof d !== "object") throw new Error("not a JSON object");
    if (!Array.isArray(d.alerts) || !d.summary || !d.meta) throw new Error("missing alerts/summary/meta: is this a loganalyzer report?");
    d.incidents = d.incidents || []; d.rules = d.rules || [];
    d.alerts.forEach(function (a) {
      if (!SEV_RANK[a.severity]) throw new Error("alert " + a.id + " has unknown severity " + a.severity);
      ["source_ips", "users", "hosts", "mitre", "timeline", "evidence", "recommended_response", "log_sources"].forEach(function (k) { a[k] = a[k] || []; });
      a.details = a.details || {};
    });
    return d;
  }

  function init(d) {
    try { data = validate(d); } catch (e) { showError("Invalid report file: " + e.message); return; }
    $("error").hidden = true;
    state = freshState();
    hideDrawer(true);
    buildBanner(); buildKpis(); buildFilters(); buildIps(); buildIncidents(); buildMitre(); buildRules(); buildBins();
    cursorId = null;
    renderAll();
    tailReset();
    var m = /alert=([A-Za-z0-9-]+)/.exec(location.hash);
    if (m) { var a = byId(m[1]); if (a) { cursorId = a.id; updateCursor(); openDrawer(a); } }
  }
  function byId(id) { for (var i = 0; i < data.alerts.length; i++) if (data.alerts[i].id === id) return data.alerts[i]; return null; }

  // ------------------------------------------------------------------ static sections
  function buildBanner() {
    var b = $("banner"), meta = data.meta;
    if (meta.synthetic) {
      b.className = "banner synthetic";
      var note = (meta.synthetic_notice || "This report is labelled synthetic.").replace(/^SYNTHETIC DATA:\s*/, "");
      $("banner-text").textContent = " " + note.charAt(0).toUpperCase() + note.slice(1);
      b.firstElementChild.textContent = "SYNTHETIC DATA.";
    } else {
      b.className = "banner real";
      $("banner-text").textContent = " This report was loaded from your own file and is not labelled synthetic. Processing happens entirely in your browser; nothing is uploaded.";
      b.firstElementChild.textContent = "YOUR DATA.";
    }
    var s = data.summary;
    $("dataset-meta").textContent = "span: " + (s.time_range && s.time_range[0] ? fmtShort(s.time_range[0]) + " to " + fmtShort(s.time_range[1]) : "no events") +
      "   sources: " + Object.keys(s.events_by_source || {}).sort().map(function (k) { return k + " " + s.events_by_source[k].toLocaleString(); }).join(", ");
    $("foot-meta").textContent = "Report generated " + meta.generated_at + " by " + meta.tool + " v" + meta.version + " (schema v" + data.schema_version + "). Inputs: " +
      (meta.inputs || []).map(function (i) { return i.path.split("/").pop() + " (" + i.parsed + "/" + i.lines + " lines parsed)"; }).join(", ");
    var sc = s.severity_counts, bar = $("sb-counts"); clear(bar);
    SEV.forEach(function (k) { bar.appendChild(h("span", { class: k, text: SEV_SHORT[k].toLowerCase() + ":" + (sc[k] || 0) })); });
  }

  function buildKpis() {
    var box = $("kpis"); clear(box);
    var s = data.summary, sc = s.severity_counts, total = Math.max(1, Math.max.apply(null, SEV.map(function (k) { return sc[k] || 0; })));
    SEV.forEach(function (k) {
      var btn = h("button", { type: "button", class: "meter kpi", "data-sev": k, "data-kpi": k, "aria-pressed": "false", title: "Filter to " + k + " alerts (" + (SEV.indexOf(k) + 1) + ")",
        onclick: function () { toggleSev(k); } },
        [h("span", { class: "lbl", text: k })].concat([h("span", { class: "br", text: "[" })], meterBar((sc[k] || 0) / total, 24), [h("span", { class: "br", text: "]" }), h("span", { class: "n", text: String(sc[k] || 0) })]));
      btn.style.setProperty("--c", SEV_COLOR[k]);
      box.appendChild(btn);
    });
    var stats = h("div", { class: "stat-col" });
    [["Total alerts", String(s.alerts_total)], ["Incidents", String(s.incidents_total)], ["Events analysed", s.events_total.toLocaleString()]].forEach(function (r) {
      stats.appendChild(h("div", { class: "kpi static stat" }, [h("span", { class: "lbl", text: r[0] }), h("span", { class: "n", text: r[1] })]));
    });
    box.appendChild(stats);
  }

  function uniqSorted(list) { return Array.from(new Set(list)).sort(); }
  function fillSelect(sel, values, firstLabel) {
    while (sel.options.length > 1) sel.remove(1);
    sel.options[0].textContent = firstLabel;
    values.forEach(function (v) { sel.appendChild(h("option", { value: v, text: v })); });
  }
  function buildFilters() {
    var chips = $("f-sev"); clear(chips);
    SEV.forEach(function (s, i) {
      chips.appendChild(h("button", { type: "button", class: "chip", "data-sev": s, "aria-pressed": "false", title: "Toggle " + s + " (" + (i + 1) + ")",
        onclick: function () { toggleSev(s); } }, [SEV_SHORT[s].toLowerCase()]));
      chips.lastChild.style.setProperty("--c", SEV_COLOR[s]);
    });
    fillSelect($("f-source"), uniqSorted([].concat.apply([], data.alerts.map(function (a) { return a.log_sources; }))), "all log sources");
    fillSelect($("f-tactic"), uniqSorted([].concat.apply([], data.alerts.map(function (a) { return a.mitre.map(function (m) { return m.tactic; }); }))), "all tactics");
    var rules = {};
    data.alerts.forEach(function (a) { rules[a.rule_id] = a.title; });
    var sel = $("f-rule"); while (sel.options.length > 1) sel.remove(1);
    sel.options[0].textContent = "all rules";
    Object.keys(rules).sort().forEach(function (id) {
      var rule = (data.rules || []).filter(function (r) { return r.id === id; })[0];
      sel.appendChild(h("option", { value: id, text: id + (rule ? " " + rule.name : "") }));
    });
    $("f-search").value = "";
  }

  function buildIps() {
    var ol = $("top-ips"); clear(ol);
    var rows = data.summary.top_attackers.slice(0, 7);
    var max = Math.max.apply(null, rows.map(function (r) { return r.events; }).concat([1]));
    if (!rows.length) ol.appendChild(h("li", { class: "muted", text: "No alerts with a source IP." }));
    rows.forEach(function (r) {
      var bar = h("span", { class: "ip-bar" }, meterBar(r.events / max, 14));
      bar.style.setProperty("--c", SEV_COLOR[r.max_severity]);
      var btn = h("button", { type: "button", class: "ip-row", "data-ip": r.ip, "aria-pressed": "false", title: "Filter alerts to " + r.ip,
        onclick: function () { state.ip = state.ip === r.ip ? "" : r.ip; renderAll(); } }, [
        h("div", { class: "ip-top" }, [
          h("span", null, [h("span", { class: "ip-addr", text: r.ip }), h("span", { class: "tag", text: r.internal ? "internal" : "external" })]),
          sevBadge(r.max_severity)]),
        h("div", { class: "ip-top ip-sub" }, [bar, h("span", { text: r.events.toLocaleString() + " events, " + r.alerts + " alert" + (r.alerts === 1 ? "" : "s") })])]);
      ol.appendChild(h("li", null, [btn]));
    });
  }

  function buildIncidents() {
    var ul = $("incidents"); clear(ul);
    if (!data.incidents.length) ul.appendChild(h("li", { class: "muted", text: "No correlated incidents." }));
    data.incidents.forEach(function (inc) {
      var btn = h("button", { type: "button", class: "inc", "data-inc": inc.id, "aria-pressed": "false",
        onclick: function () { state.incident = state.incident === inc.id ? "" : inc.id; renderAll(); } }, [
        h("div", { class: "t" }, [sevBadge(inc.severity), h("span", { class: "mono", text: inc.id }), h("span", { text: (inc.source_ips[0] || inc.hosts[0] || "") })]),
        h("div", { class: "s", text: inc.alert_ids.length + (inc.alert_ids.length === 1 ? " alert | " : " alerts | ") + fmtShort(inc.first_seen) + " to " + fmtShort(inc.last_seen) + " | " + inc.tactics.join(" > "), title: inc.tactics.join(" > ") })]);
      btn.style.setProperty("--c", SEV_COLOR[inc.severity]);
      ul.appendChild(h("li", null, [btn]));
    });
  }

  function techUrl(id) { return "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/"; }
  function buildMitre() {
    var tb = $("mitre-table").tBodies[0]; clear(tb);
    function pick(m) { state.technique = state.technique === m.id ? "" : m.id; renderAll(); }
    data.summary.mitre.forEach(function (m) {
      var tr = h("tr", { "data-tech": m.id, tabindex: "0", onclick: function (e) { if (e.target.tagName !== "A") pick(m); },
        onkeydown: function (e) { if (e.key === "Enter" && e.target === tr) pick(m); } }, [
        h("td", { text: m.tactic }),
        h("td", null, [h("a", { href: techUrl(m.id), target: "_blank", rel: "noopener noreferrer", class: "mono", text: m.id })]),
        h("td", { text: m.name }),
        h("td", { class: "num", text: String(m.alerts) }),
        h("td", null, [sevBadge(m.max_severity)])]);
      tb.appendChild(tr);
    });
    if (!tb.rows.length) tb.appendChild(h("tr", { class: "static-row" }, [h("td", { colspan: "5", class: "muted", text: "No techniques observed." })]));
  }

  function buildRules() {
    $("rule-count").textContent = String((data.rules || []).length);
    var tb = $("rules-table").tBodies[0]; clear(tb);
    (data.rules || []).forEach(function (r) {
      var params = Object.keys(r.params || {}).map(function (k) { return k + "=" + JSON.stringify(r.params[k]); }).join(", ");
      tb.appendChild(h("tr", { class: "static-row" }, [
        h("td", { class: "mono", text: r.id }), h("td", { text: r.name }), h("td", null, [sevBadge(r.severity)]),
        h("td", { text: r.sources.join(", ") }), h("td", { class: "mono", text: r.mitre.join(", ") }), h("td", { class: "mono muted", text: params || "(none)" })]));
    });
  }

  // ------------------------------------------------------------------ filtering
  function matches(a) {
    var anySev = SEV.some(function (s) { return state.sev[s]; });
    if (anySev && !state.sev[a.severity]) return false;
    if (state.source && a.log_sources.indexOf(state.source) < 0) return false;
    if (state.rule && a.rule_id !== state.rule) return false;
    if (state.tactic && !a.mitre.some(function (m) { return m.tactic === state.tactic; })) return false;
    if (state.technique && !a.mitre.some(function (m) { return m.id === state.technique; })) return false;
    if (state.ip && a.source_ips.indexOf(state.ip) < 0) return false;
    if (state.incident && a.incident_id !== state.incident) return false;
    if (state.range) {
      var t = toDate(a.first_seen).getTime();
      if (t < state.range[0] || t >= state.range[1]) return false;
    }
    if (state.q) {
      var hay = [a.id, a.title, a.rule_id, a.description, a.source_ips.join(" "), a.users.join(" "), a.hosts.join(" "),
        a.mitre.map(function (m) { return m.id + " " + m.name + " " + m.tactic; }).join(" ")].join(" ").toLowerCase();
      if (state.q.toLowerCase().split(/\s+/).some(function (w) { return w && hay.indexOf(w) < 0; })) return false;
    }
    return true;
  }
  function filtered() {
    var list = data.alerts.filter(matches);
    var k = state.sort, d = state.dir;
    list.sort(function (a, b) {
      var r;
      if (k === "severity") r = SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.first_seen < b.first_seen ? 1 : -1);
      else if (k === "count") r = a.count - b.count;
      else r = a.first_seen < b.first_seen ? -1 : a.first_seen > b.first_seen ? 1 : 0;
      return r * d;
    });
    return list;
  }
  function toggleSev(s) { state.sev[s] = !state.sev[s]; renderAll(); }
  function resetFilters() { state = freshState(); $("f-search").value = ""; renderAll(); }

  // ------------------------------------------------------------------ rendering
  function renderAll() {
    var list = filtered();
    if (!list.some(function (a) { return a.id === cursorId; })) cursorId = list.length ? list[0].id : null;
    renderTable(list);
    renderActive(list);
    drawTimeline();
  }

  function ipCell(a) {
    if (!a.source_ips.length) return "-";
    return a.source_ips.slice(0, 2).join(", ") + (a.source_ips.length > 2 ? " +" + (a.source_ips.length - 2) : "");
  }

  function renderTable(list) {
    var tb = $("alert-table").tBodies[0]; clear(tb);
    list.forEach(function (a) {
      var tr = h("tr", { "data-id": a.id, tabindex: a.id === cursorId ? "0" : "-1", onclick: function () { cursorId = a.id; updateCursor(); openDrawer(a); },
        onkeydown: function (e) { if (e.key === "Enter" && e.target === tr) { e.preventDefault(); cursorId = a.id; openDrawer(a); } } }, [
        h("td", { class: "cur-col", "aria-hidden": "true" }),
        h("td", null, [sevBadge(a.severity)]),
        h("td", { class: "mono", text: fmt(a.first_seen) }),
        h("td", { class: "mono", text: a.rule_id }),
        h("td", null, [h("button", { type: "button", class: "linklike", text: a.title, tabindex: "-1" }),
          h("span", { class: "sub", text: a.id + (a.incident_id ? " | " + a.incident_id : "") + " | " + a.mitre.map(function (m) { return m.id; }).join(", ") })]),
        h("td", { class: "hide-sm chip-ip", text: ipCell(a) }),
        h("td", { class: "num hide-sm", text: a.count.toLocaleString() })]);
      tb.appendChild(tr);
    });
    updateCursor(true);
    $("empty").hidden = list.length > 0;
    $("result-count").textContent = list.length + " of " + data.alerts.length + " shown";
    each(document.querySelectorAll("button.sort"), function (b) {
      var on = b.getAttribute("data-sort") === state.sort;
      b.classList.toggle("on", on);
      b.setAttribute("data-dir", on ? (state.dir > 0 ? "↑" : "↓") : "");
    });
  }

  // highlight the j/k row without rebuilding the table
  function updateCursor(noScroll) {
    var sc = $("alert-scroll"), curRow = null;
    each($("alert-table").tBodies[0].rows, function (tr) {
      var on = tr.getAttribute("data-id") === cursorId;
      tr.classList.toggle("cur", on);
      tr.setAttribute("tabindex", on ? "0" : "-1");
      if (on) { tr.setAttribute("aria-current", "true"); curRow = tr; } else tr.removeAttribute("aria-current");
    });
    if (curRow && !noScroll) {
      var head = $("alert-table").tHead.offsetHeight;
      var top = curRow.offsetTop, bottom = top + curRow.offsetHeight;
      if (top - head < sc.scrollTop) sc.scrollTop = Math.max(0, top - head);
      else if (bottom > sc.scrollTop + sc.clientHeight) sc.scrollTop = bottom - sc.clientHeight;
    }
  }
  function move(how) {
    if (!data) return;
    var list = filtered();
    if (!list.length) return;
    var i = -1;
    list.forEach(function (a, n) { if (a.id === cursorId) i = n; });
    if (how === "first") i = 0; else if (how === "last") i = list.length - 1;
    else i = Math.min(list.length - 1, Math.max(0, i + how));
    cursorId = list[i].id;
    updateCursor();
    if (!$("drawer").hidden) openDrawer(list[i], true);   // keep reading: j/k flips through alerts
  }

  function renderActive(list) {
    var box = $("active-filters"); clear(box);
    function pill(label, clearFn) {
      box.appendChild(h("span", { class: "pill" }, [label, h("button", { type: "button", "aria-label": "Remove filter " + label, text: "x", onclick: function () { clearFn(); renderAll(); } })]));
    }
    if (state.ip) pill("ip " + state.ip, function () { state.ip = ""; });
    if (state.incident) pill("incident " + state.incident, function () { state.incident = ""; });
    if (state.technique) pill("technique " + state.technique, function () { state.technique = ""; });
    if (state.range) pill("hour " + fmtShort(localIso(state.range[0])), function () { state.range = null; });
    SEV.forEach(function (s) {
      var on = !!state.sev[s];
      each(document.querySelectorAll('[data-sev="' + s + '"][aria-pressed]'), function (el) { el.setAttribute("aria-pressed", on ? "true" : "false"); el.classList.toggle("active", on); });
    });
    $("f-source").value = state.source; $("f-tactic").value = state.tactic; $("f-rule").value = state.rule;
    each(document.querySelectorAll(".ip-row"), function (el) { var on = el.getAttribute("data-ip") === state.ip; el.classList.toggle("active", on); el.setAttribute("aria-pressed", on ? "true" : "false"); });
    each(document.querySelectorAll(".inc"), function (el) { var on = el.getAttribute("data-inc") === state.incident; el.classList.toggle("active", on); el.setAttribute("aria-pressed", on ? "true" : "false"); });
    each(document.querySelectorAll("#mitre-table tbody tr[data-tech]"), function (el) { el.classList.toggle("active", el.getAttribute("data-tech") === state.technique); });
  }
  function localIso(ms) { var d = new Date(ms); return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":00"; }

  // ------------------------------------------------------------------ timeline chart (canvas)
  function buildBins() {
    var tr = data.summary.time_range;
    bins = [];
    var times = data.alerts.map(function (a) { return toDate(a.first_seen).getTime(); });
    var vol = data.summary.volume_by_hour || [];
    var all = times.concat(vol.map(function (v) { return toDate(v.hour).getTime(); }));
    if (tr && tr.length === 2 && tr[0]) all.push(toDate(tr[0]).getTime(), toDate(tr[1]).getTime());
    var lg = $("timeline-legend"); clear(lg);
    if (!all.length) return;
    var step = 3600000;
    var lo = Math.min.apply(null, all), hi = Math.max.apply(null, all);
    var span = (hi - lo) / 86400000;
    if (span > 10) step = 6 * 3600000;
    if (span > 60) step = 86400000;
    var d0 = new Date(lo); d0.setMinutes(0, 0, 0);
    if (step >= 86400000) d0.setHours(0);
    var start = d0.getTime();
    var n = Math.floor((hi - start) / step) + 1;
    for (var i = 0; i < n; i++) bins.push({ t0: start + i * step, t1: start + (i + 1) * step, sev: { critical: 0, high: 0, medium: 0, low: 0 }, total: 0, vol: 0, alerts: [] });
    function bin(t) { return bins[Math.min(bins.length - 1, Math.max(0, Math.floor((t - start) / step)))]; }
    data.alerts.forEach(function (a) { var b = bin(toDate(a.first_seen).getTime()); b.sev[a.severity]++; b.total++; b.alerts.push(a); });
    vol.forEach(function (v) { bin(toDate(v.hour).getTime()).vol += v.total; });
    SEV.slice().reverse().forEach(function (s) { var sp = h("span", { text: s }); sp.style.setProperty("--c", SEV_COLOR[s]); lg.appendChild(sp); });
    var sp = h("span", { text: "log volume" }); sp.style.setProperty("--c", "#1f5a33"); lg.appendChild(sp);
  }

  var geo = null;
  function xForTime(t) {
    if (!geo || !bins.length) return null;
    var t0 = bins[0].t0, t1 = bins[bins.length - 1].t1;
    return geo.L + geo.pw * Math.min(1, Math.max(0, (t - t0) / (t1 - t0)));
  }
  function drawTimeline() {
    var cv = $("timeline");
    var rect = cv.getBoundingClientRect();
    if (!rect.width) return;
    var dpr = window.devicePixelRatio || 1;
    cv.width = Math.round(rect.width * dpr); cv.height = Math.round(rect.height * dpr);
    var g = cv.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    var W = rect.width, H = rect.height;
    g.clearRect(0, 0, W, H);
    var L = 30, R = 6, T = 6, B = 24;
    var pw = W - L - R, ph = H - T - B;
    geo = { L: L, R: R, T: T, B: B, pw: pw, ph: ph, W: W, H: H };
    if (!data || !bins.length) { g.fillStyle = "#6f8f78"; g.font = "12px " + MONO; g.fillText("no data", L, H / 2); return; }
    var maxA = Math.max.apply(null, bins.map(function (b) { return b.total; }).concat([1]));
    var maxV = Math.max.apply(null, bins.map(function (b) { return b.vol; }).concat([1]));
    var yMax = Math.max(4, Math.ceil(maxA * 1.15));
    var bw = pw / bins.length;
    var C = { grid: "#1b3d26", text: "#6f8f78" };
    g.font = "11px " + MONO; g.textBaseline = "middle"; g.textAlign = "right";
    var ticks = Math.min(4, yMax);
    g.setLineDash([2, 4]);
    for (var i = 0; i <= ticks; i++) {
      var v = Math.round(yMax * i / ticks), y = T + ph - ph * v / yMax;
      g.strokeStyle = C.grid; g.lineWidth = 1; g.beginPath(); g.moveTo(L, y + .5); g.lineTo(W - R, y + .5); g.stroke();
      g.fillStyle = C.text; g.fillText(String(v), L - 6, y);
    }
    g.setLineDash([]);
    // log volume as a dim stepped area
    g.beginPath(); g.moveTo(L, T + ph);
    bins.forEach(function (b, i) { var y = T + ph - ph * 0.9 * b.vol / maxV; g.lineTo(L + i * bw, y); g.lineTo(L + (i + 1) * bw, y); });
    g.lineTo(L + pw, T + ph); g.closePath(); g.fillStyle = "rgba(47, 157, 85, 0.17)"; g.fill();
    g.strokeStyle = "rgba(47, 157, 85, 0.5)"; g.lineWidth = 1; g.stroke();
    // alert columns
    var filteredIds = {}; filtered().forEach(function (a) { filteredIds[a.id] = true; });
    bins.forEach(function (b, i) {
      var x = L + i * bw + Math.min(1, bw * 0.12), w = Math.max(1.5, bw - Math.min(2, bw * 0.24));
      var y = T + ph;
      SEV.slice().reverse().forEach(function (s) {
        var cnt = b.alerts.filter(function (a) { return a.severity === s; });
        if (!cnt.length) return;
        var hh = ph * cnt.length / yMax;
        y -= hh;
        var dim = cnt.every(function (a) { return !filteredIds[a.id]; });
        g.globalAlpha = dim ? 0.2 : 1; g.fillStyle = SEV_COLOR[s]; g.fillRect(x, y, w, hh - 1); g.globalAlpha = 1;
      });
      if (hover === i) { g.strokeStyle = "#ffb000"; g.lineWidth = 1; g.strokeRect(L + i * bw + .5, T + .5, bw - 1, ph - 1); }
    });
    // x labels at each local midnight (or start)
    g.textAlign = "left"; g.textBaseline = "top"; g.fillStyle = C.text;
    var lastLabel = -100;
    bins.forEach(function (b, i) {
      var d = new Date(b.t0);
      var isMidnight = d.getHours() === 0;
      if (isMidnight || i === 0 || b.t1 - b.t0 >= 86400000) {
        var x = L + i * bw;
        if (x - lastLabel < 70 && i !== 0) return;
        g.strokeStyle = C.grid; g.beginPath(); g.moveTo(x + .5, T + ph); g.lineTo(x + .5, T + ph + 5); g.stroke();
        g.fillText(DAYS[d.getDay()] + " " + MONTHS[d.getMonth()] + " " + d.getDate(), x + 2, T + ph + 8);
        lastLabel = x;
      }
    });
    // where the event tail is right now
    if (replayMs !== null) {
      var rx = xForTime(replayMs);
      if (rx !== null) {
        g.strokeStyle = "#5dff8a"; g.lineWidth = 1; g.beginPath(); g.moveTo(Math.round(rx) + .5, T); g.lineTo(Math.round(rx) + .5, T + ph); g.stroke();
        g.fillStyle = "#5dff8a"; g.fillRect(Math.round(rx) - 2, T, 5, 3);
      }
    }
  }

  function binAt(ev) {
    if (!geo || !bins.length) return -1;
    var r = $("timeline").getBoundingClientRect();
    var x = ev.clientX - r.left - geo.L;
    if (x < 0 || x > geo.pw) return -1;
    return Math.min(bins.length - 1, Math.floor(x / (geo.pw / bins.length)));
  }
  function showTip(ev, i) {
    var tip = $("tooltip");
    if (i < 0) { tip.hidden = true; return; }
    var b = bins[i];
    clear(tip);
    tip.appendChild(h("strong", { text: fmt(localIso(b.t0)).replace(/:\d\d$/, "") + (b.t1 - b.t0 < 86400000 ? "" : " (day)") }));
    var parts = SEV.filter(function (s) { return b.sev[s]; }).map(function (s) { return b.sev[s] + " " + s; });
    tip.appendChild(h("div", { text: parts.length ? parts.join(", ") : "no alerts" }));
    tip.appendChild(h("div", { class: "muted", text: b.vol.toLocaleString() + " log events" }));
    b.alerts.slice(0, 3).forEach(function (a) { tip.appendChild(h("div", { class: "muted", text: "> " + a.rule_id + " " + a.title.slice(0, 34) })); });
    if (b.alerts.length > 3) tip.appendChild(h("div", { class: "muted", text: "+ " + (b.alerts.length - 3) + " more" }));
    tip.hidden = false;
    var wrap = $("timeline").parentNode.getBoundingClientRect();
    var x = ev.clientX - wrap.left + 14, y = ev.clientY - wrap.top + 10;
    if (x + 290 > wrap.width) x = ev.clientX - wrap.left - 290;
    tip.style.left = Math.max(0, x) + "px"; tip.style.top = Math.max(0, y) + "px";
  }

  // ------------------------------------------------------------------ event tail (a replay of the events behind the alerts)
  var tail = { events: [], i: 0, timer: null, manualPause: false, hoverPause: false, follow: true, cursor: null };
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var MAX_TAIL = 90;

  function tailReset() {
    if (tail.timer) { clearTimeout(tail.timer); tail.timer = null; }
    var box = $("tail"); clear(box);
    tail.events = []; tail.i = 0; tail.follow = true; replayMs = null;
    data.alerts.forEach(function (a) { a.timeline.forEach(function (t) { tail.events.push({ ts: t.ts, text: t.event, alert: a }); }); });
    tail.events.sort(function (x, y) { return x.ts < y.ts ? -1 : x.ts > y.ts ? 1 : x.alert.id < y.alert.id ? -1 : 1; });
    tail.cursor = h("div", { class: "tl-sep", "aria-hidden": "true" }, [h("span", { text: "$ tail -f events" }), h("span", { class: "tail-cursor" })]);
    box.appendChild(tail.cursor);
    if (!tail.events.length) { tailLabel(); return; }
    // drop the viewer in just before the first critical alert instead of the quiet start of the week
    var first = null;
    data.alerts.forEach(function (x) { if (!first || SEV_RANK[x.severity] > SEV_RANK[first.severity] || (SEV_RANK[x.severity] === SEV_RANK[first.severity] && x.first_seen < first.first_seen)) first = x; });
    var found = false;
    tail.events.forEach(function (e, n) { if (first && !found && e.alert === first) { found = true; tail.i = Math.max(0, n - 10); } });
    var pre = Math.min(18, tail.events.length - tail.i);
    for (var k = 0; k < pre; k++) tailAppend(tail.events[tail.i++], true);
    if (reduceMotion) tail.manualPause = true;
    tailLabel();
    tailSchedule();
  }
  function tailAppend(ev, quiet) {
    var box = $("tail");
    var line = h("button", { type: "button", class: "tl-line" + (quiet ? "" : " new"), tabindex: "-1", title: ev.alert.id + ": " + ev.text,
      onclick: function () { cursorId = ev.alert.id; if (!filtered().some(function (a) { return a.id === cursorId; })) resetFilters(); updateCursor(); openDrawer(ev.alert); } }, [
      h("span", { class: "ts", text: fmtClock(ev.ts) }),
      h("span", { class: "sv", text: SEV_SHORT[ev.alert.severity] }),
      h("span", { class: "id", text: ev.alert.id }),
      h("span", { class: "ev", text: ev.text })]);
    line.firstChild.nextSibling.style.setProperty("--c", SEV_COLOR[ev.alert.severity]);
    box.insertBefore(line, tail.cursor);
    while (box.children.length > MAX_TAIL + 1) box.removeChild(box.firstChild);
    replayMs = toDate(ev.ts).getTime();
    if (tail.follow) box.scrollTop = box.scrollHeight;
  }
  function tailSep(text) {
    var box = $("tail");
    box.insertBefore(h("div", { class: "tl-sep", text: text }), tail.cursor);
    if (tail.follow) box.scrollTop = box.scrollHeight;
  }
  function tailPaused() { return tail.manualPause || tail.hoverPause; }
  function tailLabel() {
    var n = tail.events.length;
    $("tail-state").textContent = (tail.manualPause ? "paused" : tail.hoverPause ? "paused (mouse over)" : "replay") + " " + Math.min(tail.i, n) + "/" + n;
    $("tail-toggle").textContent = tail.manualPause ? "resume" : "pause";
    $("replay-clock").textContent = replayMs === null ? "replay --:--:--" : (tailPaused() ? "paused " : "replay ") + clockMs(replayMs);
  }
  function tailSchedule() {
    if (tail.timer) clearTimeout(tail.timer);
    tail.timer = null;
    if (tailPaused() || !tail.events.length) return;
    tail.timer = setTimeout(tailTick, 380 + Math.random() * 720);
  }
  function tailTick() {
    tail.timer = null;
    if (tailPaused()) return;
    if (tail.i >= tail.events.length) { tail.i = 0; tailSep("-- end of replay, starting again --"); }
    tailAppend(tail.events[tail.i++], false);
    tailLabel(); drawTimeline();
    tailSchedule();
  }
  function tailToggle() {
    tail.manualPause = !tail.manualPause;
    tailLabel(); tailSchedule(); drawTimeline();
  }

  // ------------------------------------------------------------------ drawer (drill-down)
  function section(title, content) { return h("div", { class: "d-sec" }, [h("h3", { text: title }), content]); }
  function chipRow(items, onclick) {
    return h("div", { class: "chip-row" }, items.map(function (t) { return h("button", { type: "button", class: "chip-btn", text: t, onclick: function () { onclick(t); } }); }));
  }
  function ticketNote(a) {
    var lines = ["[" + a.severity.toUpperCase() + "] " + a.id + ": " + a.title, "Rule: " + a.rule_id + (a.incident_id ? " | Incident: " + a.incident_id : ""),
      "When: " + a.first_seen + " to " + a.last_seen + " (" + a.count + " events)",
      "Source IPs: " + (a.source_ips.join(", ") || "n/a") + " | Accounts: " + (a.users.slice(0, 8).join(", ") || "n/a") + " | Hosts: " + (a.hosts.join(", ") || "n/a"),
      "MITRE ATT&CK: " + a.mitre.map(function (m) { return m.id + " " + m.name; }).join("; "), "", "What was seen: " + a.description, "", "Recommended response:"];
    a.recommended_response.forEach(function (s, i) { lines.push((i + 1) + ". " + s); });
    lines.push("", "Evidence (first lines):"); a.evidence.slice(0, 3).forEach(function (e) { lines.push("  " + e); });
    lines.push("", "Status: open, not yet triaged." + (data.meta.synthetic ? " (Synthetic data example.)" : ""));
    return lines.join("\n");
  }
  function copyText(text, done) {
    function fallback() {
      var ta = h("textarea", { "aria-hidden": "true" }); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(true); } catch (e) { done(false); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
    else fallback();
  }
  function detailValue(v) {
    if (Array.isArray(v)) return v.every(function (x) { return typeof x !== "object"; }) ? v.join("; ") : JSON.stringify(v);
    if (v && typeof v === "object") return JSON.stringify(v);
    return String(v);
  }
  var copyHandler = null;
  function openDrawer(a, keepFocus) {
    if ($("drawer").hidden) lastFocus = document.activeElement;
    openId = a.id;
    $("d-sev").className = "sev-badge sev-" + a.severity; $("d-sev").textContent = a.severity;
    $("d-id").textContent = a.id + (a.incident_id ? " in " + a.incident_id : "");
    $("drawer-title").textContent = a.title;
    var body = $("drawer-body"); clear(body);
    var inc = a.incident_id ? data.incidents.filter(function (i) { return i.id === a.incident_id; })[0] : null;
    body.appendChild(section("What happened", h("p", { text: a.description })));
    var kv = h("dl", { class: "kv" });
    function row(k, v) { kv.appendChild(h("dt", { text: k })); kv.appendChild(h("dd", { text: v })); }
    row("First seen", fmt(a.first_seen)); row("Last seen", fmt(a.last_seen)); row("Duration", dur(a.duration_seconds));
    row("Events", a.count.toLocaleString()); row("Rule", a.rule_id); row("Log source", a.log_sources.join(", ") || "n/a");
    row("Hosts", a.hosts.join(", ") || "n/a"); row("Accounts", a.users.slice(0, 12).join(", ") || "n/a");
    body.appendChild(section("Summary", kv));
    if (a.source_ips.length) body.appendChild(section("Source IPs (click to filter)", chipRow(a.source_ips, function (ip) { state.ip = ip; hideDrawer(); renderAll(); })));
    if (inc) {
      var ul = h("ul", { class: "steps" }, inc.narrative.map(function (n) { return h("li", { text: n }); }));
      body.appendChild(section("Part of " + inc.id + " (" + inc.severity + ")", h("div", null, [h("p", { class: "muted", text: inc.title }), ul,
        h("p", null, [h("button", { type: "button", class: "chip-btn", text: "Show only this incident", onclick: function () { state.incident = inc.id; hideDrawer(); renderAll(); } })])])));
    }
    body.appendChild(section("MITRE ATT&CK", h("div", { class: "chip-row" }, a.mitre.map(function (m) {
      return h("a", { class: "chip-btn", href: techUrl(m.id), target: "_blank", rel: "noopener noreferrer", text: m.id + " " + m.name + " (" + m.tactic + ")" });
    }))));
    var det = Object.keys(a.details);
    if (det.length) {
      var dl = h("dl", { class: "kv" });
      det.forEach(function (k) {
        dl.appendChild(h("dt", { text: k.replace(/_/g, " ") }));
        dl.appendChild(h("dd", { text: detailValue(a.details[k]) }));
      });
      body.appendChild(section("Details", dl));
    }
    var tl = h("ol", { class: "tl" }, a.timeline.map(function (t) {
      var li = h("li", null, [h("time", { text: t.ts.replace("T", " ") + " | " + t.source }), t.event]);
      li.style.setProperty("--c", SEV_COLOR[a.severity]); return li;
    }));
    body.appendChild(section("Timeline (" + a.timeline.length + " of " + a.count + " events shown)", tl));
    body.appendChild(section("Recommended response", h("ol", { class: "steps" }, a.recommended_response.map(function (s) { return h("li", { text: s }); }))));
    body.appendChild(section("Evidence (raw log lines)", h("pre", { class: "evidence", tabindex: "0", text: a.evidence.join("\n") })));
    var msg = h("span", { class: "toast", role: "status" });
    copyHandler = function () { copyText(ticketNote(a), function (ok) { msg.textContent = ok ? "Copied." : "Copy failed: select the text by hand."; }); };
    body.appendChild(h("div", { class: "btn-row" }, [
      h("button", { type: "button", id: "d-copy", class: "btn", text: "Copy as ticket note", onclick: function () { copyHandler(); } }),
      h("button", { type: "button", class: "btn", text: "Copy link", onclick: function () { copyText(location.href.split("#")[0] + "#alert=" + a.id, function (ok) { msg.textContent = ok ? "Link copied." : "Copy failed."; }); } }), msg,
      h("span", { class: "muted keyhint", text: "j / k next alert, c copy note, Esc close" })]));
    $("scrim").hidden = false; $("drawer").hidden = false;
    try { history.replaceState(null, "", "#alert=" + a.id); } catch (e) { /* file:// or sandbox */ }
    body.scrollTop = 0;
    if (!keepFocus) $("d-close").focus();
  }
  function hideDrawer(silent) {
    if ($("drawer").hidden) return;
    $("drawer").hidden = true; $("scrim").hidden = true; openId = null;
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { /* ignore */ }
    if (!silent && lastFocus && lastFocus.focus) lastFocus.focus();
  }
  function toggleHelp(show) {
    var hp = $("help");
    var want = show === undefined ? hp.hidden : show;
    hp.hidden = !want;
    if (want) { lastFocus = document.activeElement; hp.focus(); }
    else if (lastFocus && lastFocus.focus && $("drawer").hidden) lastFocus.focus();
  }

  // ------------------------------------------------------------------ CSV export
  function csvCell(v) {
    var s = String(v === undefined || v === null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;       // neutralise spreadsheet formula injection
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportCsv() {
    if (!data) return;
    var rows = [["id", "severity", "rule", "title", "first_seen", "last_seen", "events", "source_ips", "users", "hosts", "mitre", "incident"]];
    filtered().forEach(function (a) {
      rows.push([a.id, a.severity, a.rule_id, a.title, a.first_seen, a.last_seen, a.count, a.source_ips.join(" "), a.users.join(" "), a.hosts.join(" "),
        a.mitre.map(function (m) { return m.id; }).join(" "), a.incident_id]);
    });
    var blob = new Blob([rows.map(function (r) { return r.map(csvCell).join(","); }).join("\n") + "\n"], { type: "text/csv" });
    var url = URL.createObjectURL(blob);
    var a = h("a", { href: url, download: "alerts-filtered.csv" });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 500);
  }

  // ------------------------------------------------------------------ keyboard
  function isTyping(el) { return el && (el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA"); }
  function act(key, ev) {
    if (!$("help").hidden) { if (key === "?" || key === "Escape") toggleHelp(false); return true; }
    if (key === "?") { toggleHelp(true); return true; }
    if (key === "Escape") { if (!$("drawer").hidden) { hideDrawer(); return true; } return false; }
    if (key === "/") { var s = $("f-search"); hideDrawer(true); s.focus(); s.select(); return true; }
    if (!data) return false;
    var inTable = !ev || ev.target === document.body || $("alert-table").contains(ev.target) || ev.target.closest && (ev.target.closest(".keybar") || ev.target.closest("#drawer"));
    switch (key) {
      case "j": case "ArrowDown": if (key === "ArrowDown" && !inTable) return false; move(1); return true;
      case "k": case "ArrowUp": if (key === "ArrowUp" && !inTable) return false; move(-1); return true;
      case "g": move("first"); return true;
      case "G": move("last"); return true;
      case "o": case "Enter": {
        if (key === "Enter" && ev && ev.target !== document.body && !(ev.target.closest && ev.target.closest(".keybar"))) return false;
        var a = cursorId && byId(cursorId); if (a) { openDrawer(a); return true; } return false;
      }
      case "p": tailToggle(); return true;
      case "e": exportCsv(); return true;
      case "r": resetFilters(); return true;
      case "u": $("file-input").click(); return true;
      case "c": if (!$("drawer").hidden && copyHandler) { copyHandler(); return true; } return false;
      case "1": case "2": case "3": case "4": toggleSev(SEV[+key - 1]); return true;
    }
    return false;
  }

  // ------------------------------------------------------------------ wiring
  function wire() {
    $("filters").addEventListener("submit", function (e) { e.preventDefault(); });
    $("f-search").addEventListener("input", function (e) { state.q = e.target.value.trim(); renderAll(); });
    $("f-source").addEventListener("change", function (e) { state.source = e.target.value; renderAll(); });
    $("f-tactic").addEventListener("change", function (e) { state.tactic = e.target.value; renderAll(); });
    $("f-rule").addEventListener("change", function (e) { state.rule = e.target.value; renderAll(); });
    $("f-reset").addEventListener("click", resetFilters);
    $("f-export").addEventListener("click", exportCsv);
    $("d-close").addEventListener("click", function () { hideDrawer(); });
    $("scrim").addEventListener("click", function () { hideDrawer(); });
    $("help").addEventListener("click", function (e) { if (e.target === $("help")) toggleHelp(false); });
    $("tail-toggle").addEventListener("click", tailToggle);
    var tb = $("tail");
    tb.addEventListener("scroll", function () { tail.follow = tb.scrollHeight - tb.scrollTop - tb.clientHeight < 24; });
    tb.addEventListener("mouseenter", function () { tail.hoverPause = true; tailLabel(); tailSchedule(); });
    tb.addEventListener("mouseleave", function () { tail.hoverPause = false; tailLabel(); tailSchedule(); });
    each(document.querySelectorAll(".keybar button"), function (b) {
      b.addEventListener("click", function () { act(b.getAttribute("data-key"), { target: b }); });
    });
    each(document.querySelectorAll(".sb-windows .win"), function (a) {
      a.addEventListener("click", function () { each(document.querySelectorAll(".sb-windows .win"), function (w) { w.classList.toggle("on", w === a); }); });
    });
    document.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (isTyping(e.target)) {
        if (e.key === "Escape" || (e.key === "Enter" && e.target.id === "f-search")) { e.preventDefault(); e.target.blur(); }
        return;
      }
      if (e.key === "Tab" && !$("drawer").hidden && $("help").hidden) {   // keep focus inside the dialog
        var f = $("drawer").querySelectorAll("button, a[href], pre[tabindex]");
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        return;
      }
      if (act(e.key, e)) e.preventDefault();
    });
    each(document.querySelectorAll("button.sort"), function (b) {
      b.addEventListener("click", function () {
        var k = b.getAttribute("data-sort");
        if (state.sort === k) state.dir = -state.dir; else { state.sort = k; state.dir = k === "time" ? 1 : -1; }
        if (data) renderAll();
      });
    });
    var cv = $("timeline");
    cv.addEventListener("mousemove", function (e) { var i = binAt(e); if (i !== hover) { hover = i; drawTimeline(); } showTip(e, i); });
    cv.addEventListener("mouseleave", function () { hover = null; $("tooltip").hidden = true; drawTimeline(); });
    cv.addEventListener("click", function (e) {
      var i = binAt(e); if (i < 0) return;
      var b = bins[i];
      state.range = state.range && state.range[0] === b.t0 ? null : [b.t0, b.t1];
      renderAll();
      if (state.range) $("alerts-title").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    if (window.ResizeObserver) new ResizeObserver(function () { if (data) drawTimeline(); }).observe(cv.parentNode);
    else window.addEventListener("resize", function () { if (data) drawTimeline(); });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(function () { if (data) drawTimeline(); });

    function readFile(file) {
      var fr = new FileReader();
      fr.onload = function () { try { init(JSON.parse(fr.result)); } catch (err) { showError("Could not read " + file.name + ": " + err.message); } };
      fr.readAsText(file);
    }
    $("file-input").addEventListener("change", function (e) { if (e.target.files[0]) readFile(e.target.files[0]); e.target.value = ""; });
    document.addEventListener("dragover", function (e) { e.preventDefault(); });
    document.addEventListener("drop", function (e) { e.preventDefault(); if (e.dataTransfer.files[0]) readFile(e.dataTransfer.files[0]); });
  }

  wire();
  var qs = new URLSearchParams(location.search);
  load(qs.get("data") && /^[\w./-]+\.json$/.test(qs.get("data")) && qs.get("data").indexOf("..") < 0 ? qs.get("data") : DEFAULT_URL);
})();
