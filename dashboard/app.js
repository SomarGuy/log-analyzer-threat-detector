/* Log Analyzer dashboard. Vanilla JS, no dependencies, no HTML string injection: all text is
   inserted with textContent, because log lines contain attacker-controlled strings (<script>, SQL, ...). */
(function () {
  "use strict";

  var SEV = ["critical", "high", "medium", "low"];
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  var SEV_COLOR = { critical: "#ff4d6d", high: "#ff8a3d", medium: "#f5c542", low: "#5aa9ff" };
  var DEFAULT_URL = "data/alerts.json";

  var data = null;                 // loaded report
  var state = freshState();
  var lastFocus = null;
  var hover = null;                // hovered timeline bin index
  var bins = [];                   // timeline bins for current data

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
        "fetch() on file:// URLs: run `python -m http.server` in this folder, or use \"Load your own alerts.json\" above.");
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
    renderAll();
    var m = /alert=([A-Za-z0-9-]+)/.exec(location.hash);
    if (m) { var a = byId(m[1]); if (a) openDrawer(a); }
  }
  function byId(id) { for (var i = 0; i < data.alerts.length; i++) if (data.alerts[i].id === id) return data.alerts[i]; return null; }

  // ------------------------------------------------------------------ static sections
  function buildBanner() {
    var b = $("banner"), meta = data.meta;
    if (meta.synthetic) {
      b.className = "banner synthetic";
      var note = (meta.synthetic_notice || "This report is labelled synthetic.").replace(/^SYNTHETIC DATA:\s*/, "");
      $("banner-text").textContent = " " + note.charAt(0).toUpperCase() + note.slice(1);
    } else {
      b.className = "banner real";
      $("banner-text").textContent = " This report was loaded from your own file and is not labelled synthetic. Processing happens entirely in your browser; nothing is uploaded.";
      b.firstElementChild.textContent = "YOUR DATA.";
    }
    if (meta.synthetic) b.firstElementChild.textContent = "SYNTHETIC DATA.";
    var s = data.summary;
    $("dataset-meta").textContent = s.events_total.toLocaleString() + " events · " + (s.time_range[0] ? fmtShort(s.time_range[0]) + " → " + fmtShort(s.time_range[1]) : "no events");
    $("foot-meta").textContent = "Report generated " + meta.generated_at + " by " + meta.tool + " v" + meta.version + " · schema v" + data.schema_version + " · inputs: " +
      (meta.inputs || []).map(function (i) { return i.path.split("/").pop() + " (" + i.parsed + "/" + i.lines + " lines parsed)"; }).join(", ");
  }

  function buildKpis() {
    var box = $("kpis"); clear(box);
    var sc = data.summary.severity_counts;
    box.appendChild(h("div", { class: "kpi static" }, [h("span", { class: "n", text: String(data.summary.alerts_total) }), h("span", { class: "l", text: "Total alerts" })]));
    SEV.forEach(function (s) {
      box.appendChild(h("button", { type: "button", class: "kpi", "data-sev": s, "data-kpi": s, "aria-pressed": "false",
        title: "Filter to " + s + " alerts", onclick: function () { toggleSev(s); } },
        [h("span", { class: "n", text: String(sc[s] || 0) }), h("span", { class: "l", text: s })]));
    });
    box.appendChild(h("div", { class: "kpi static" }, [h("span", { class: "n", text: String(data.summary.incidents_total) }), h("span", { class: "l", text: "Incidents" })]));
    box.appendChild(h("div", { class: "kpi static" }, [h("span", { class: "n", text: data.summary.events_total.toLocaleString() }), h("span", { class: "l", text: "Events analysed" })]));
  }

  function uniqSorted(list) { return Array.from(new Set(list)).sort(); }
  function fillSelect(sel, values, firstLabel) {
    while (sel.options.length > 1) sel.remove(1);
    sel.options[0].textContent = firstLabel;
    values.forEach(function (v) { sel.appendChild(h("option", { value: v, text: v })); });
  }
  function buildFilters() {
    var chips = $("f-sev"); clear(chips);
    SEV.forEach(function (s) {
      chips.appendChild(h("button", { type: "button", class: "chip", "data-sev": s, "aria-pressed": "false", style: null,
        onclick: function () { toggleSev(s); } }, [s[0].toUpperCase() + s.slice(1)]));
      chips.lastChild.style.setProperty("--c", SEV_COLOR[s]);
    });
    fillSelect($("f-source"), uniqSorted([].concat.apply([], data.alerts.map(function (a) { return a.log_sources; }))), "All log sources");
    fillSelect($("f-tactic"), uniqSorted([].concat.apply([], data.alerts.map(function (a) { return a.mitre.map(function (m) { return m.tactic; }); }))), "All tactics");
    var rules = {};
    data.alerts.forEach(function (a) { rules[a.rule_id] = a.title; });
    var sel = $("f-rule"); while (sel.options.length > 1) sel.remove(1);
    sel.options[0].textContent = "All rules";
    Object.keys(rules).sort().forEach(function (id) {
      var rule = (data.rules || []).filter(function (r) { return r.id === id; })[0];
      sel.appendChild(h("option", { value: id, text: id + (rule ? " · " + rule.name : "") }));
    });
    $("f-search").value = "";
  }

  function buildIps() {
    var ol = $("top-ips"); clear(ol);
    var rows = data.summary.top_attackers.slice(0, 7);
    var max = Math.max.apply(null, rows.map(function (r) { return r.events; }).concat([1]));
    if (!rows.length) ol.appendChild(h("li", { class: "muted", text: "No alerts with a source IP." }));
    rows.forEach(function (r) {
      var fill = h("i", null, []);
      fill.style.width = Math.max(4, Math.round(100 * r.events / max)) + "%";
      fill.style.setProperty("--c", SEV_COLOR[r.max_severity]);
      var btn = h("button", { type: "button", class: "ip-row", "data-ip": r.ip, "aria-pressed": "false", title: "Filter alerts to " + r.ip,
        onclick: function () { state.ip = state.ip === r.ip ? "" : r.ip; renderAll(); } }, [
        h("div", { class: "ip-top" }, [
          h("span", null, [h("span", { class: "ip-addr", text: r.ip }), h("span", { class: "tag", text: r.internal ? "internal" : "external" })]),
          sevBadge(r.max_severity)]),
        h("div", { class: "bar" }, [fill]),
        h("div", { class: "ip-sub", text: r.alerts + " alert" + (r.alerts === 1 ? "" : "s") + " · " + r.events.toLocaleString() + " events · " + r.rules.join(", ") })]);
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
        h("div", { class: "s", text: inc.tactics.join(" › ") }),
        h("div", { class: "s", text: inc.alert_ids.length + " alerts · " + fmtShort(inc.first_seen) + " → " + fmtShort(inc.last_seen) })]);
      btn.style.setProperty("--c", SEV_COLOR[inc.severity]);
      ul.appendChild(h("li", null, [btn]));
    });
  }

  function buildMitre() {
    var tb = $("mitre-table").tBodies[0]; clear(tb);
    data.summary.mitre.forEach(function (m) {
      var tr = h("tr", { "data-tech": m.id, tabindex: "0", onclick: function (e) { if (e.target.tagName !== "A") { state.technique = state.technique === m.id ? "" : m.id; renderAll(); } },
        onkeydown: function (e) { if (e.key === "Enter") { state.technique = state.technique === m.id ? "" : m.id; renderAll(); } } }, [
        h("td", { text: m.tactic }),
        h("td", null, [h("a", { href: "https://attack.mitre.org/techniques/" + m.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", class: "mono", text: m.id })]),
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

  // ------------------------------------------------------------------ rendering
  function renderAll() {
    var list = filtered();
    renderTable(list);
    renderActive(list);
    drawTimeline();
  }

  function ipCell(a) {
    if (!a.source_ips.length) return "—";
    return a.source_ips.slice(0, 2).join(", ") + (a.source_ips.length > 2 ? " +" + (a.source_ips.length - 2) : "");
  }

  function renderTable(list) {
    var tb = $("alert-table").tBodies[0]; clear(tb);
    list.forEach(function (a) {
      var tr = h("tr", { "data-id": a.id, tabindex: "0", onclick: function () { openDrawer(a); },
        onkeydown: function (e) { if (e.key === "Enter") { e.preventDefault(); openDrawer(a); } } }, [
        h("td", null, [sevBadge(a.severity)]),
        h("td", { class: "mono", text: fmt(a.first_seen) }),
        h("td", { class: "mono", text: a.rule_id }),
        h("td", null, [h("button", { type: "button", class: "linklike", text: a.title, tabindex: "-1" }),
          h("span", { class: "sub", text: a.id + (a.incident_id ? " · " + a.incident_id : "") + " · " + a.mitre.map(function (m) { return m.id; }).join(", ") })]),
        h("td", { class: "hide-sm chip-ip", text: ipCell(a) }),
        h("td", { class: "num hide-sm", text: a.count.toLocaleString() })]);
      tb.appendChild(tr);
    });
    $("empty").hidden = list.length > 0;
    $("result-count").textContent = "Showing " + list.length + " of " + data.alerts.length + " alerts";
    Array.prototype.forEach.call(document.querySelectorAll("button.sort"), function (b) {
      var on = b.getAttribute("data-sort") === state.sort;
      b.classList.toggle("on", on);
      b.setAttribute("data-dir", on ? (state.dir > 0 ? "▲" : "▼") : "");
    });
  }

  function renderActive(list) {
    var box = $("active-filters"); clear(box);
    function pill(label, clearFn) {
      box.appendChild(h("span", { class: "pill" }, [label, h("button", { type: "button", "aria-label": "Remove filter " + label, text: "×", onclick: function () { clearFn(); renderAll(); } })]));
    }
    if (state.ip) pill("IP " + state.ip, function () { state.ip = ""; });
    if (state.incident) pill("Incident " + state.incident, function () { state.incident = ""; });
    if (state.technique) pill("Technique " + state.technique, function () { state.technique = ""; });
    if (state.range) pill("Hour " + fmtShort(localIso(state.range[0])), function () { state.range = null; });
    // reflect state in controls
    SEV.forEach(function (s) {
      var on = !!state.sev[s];
      Array.prototype.forEach.call(document.querySelectorAll('[data-sev="' + s + '"][aria-pressed]'), function (el) { el.setAttribute("aria-pressed", on ? "true" : "false"); el.classList.toggle("active", on); });
    });
    $("f-source").value = state.source; $("f-tactic").value = state.tactic; $("f-rule").value = state.rule;
    Array.prototype.forEach.call(document.querySelectorAll(".ip-row"), function (el) { var on = el.getAttribute("data-ip") === state.ip; el.classList.toggle("active", on); el.setAttribute("aria-pressed", on ? "true" : "false"); });
    Array.prototype.forEach.call(document.querySelectorAll(".inc"), function (el) { var on = el.getAttribute("data-inc") === state.incident; el.classList.toggle("active", on); el.setAttribute("aria-pressed", on ? "true" : "false"); });
    Array.prototype.forEach.call(document.querySelectorAll("#mitre-table tbody tr[data-tech]"), function (el) { el.classList.toggle("active", el.getAttribute("data-tech") === state.technique); });
  }
  function localIso(ms) { var d = new Date(ms); return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":00"; }

  // ------------------------------------------------------------------ timeline chart (canvas)
  function buildBins() {
    var tr = data.summary.time_range;
    bins = [];
    var times = data.alerts.map(function (a) { return toDate(a.first_seen).getTime(); });
    var vol = data.summary.volume_by_hour || [];
    var all = times.concat(vol.map(function (v) { return toDate(v.hour).getTime(); }));
    if (tr && tr.length === 2) all.push(toDate(tr[0]).getTime(), toDate(tr[1]).getTime());
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
    var lg = $("timeline-legend"); clear(lg);
    SEV.slice().reverse().forEach(function (s) { var sp = h("span", { text: s }); sp.style.setProperty("--c", SEV_COLOR[s]); lg.appendChild(sp); });
    var sp = h("span", { text: "log volume" }); sp.style.setProperty("--c", "#4a5878"); lg.appendChild(sp);
  }

  var geo = null;
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
    var L = 34, R = 10, T = 8, B = 30;
    var pw = W - L - R, ph = H - T - B;
    geo = { L: L, R: R, T: T, B: B, pw: pw, ph: ph, W: W, H: H };
    if (!bins.length) { g.fillStyle = "#93a4c3"; g.font = "13px system-ui"; g.fillText("No data", L, H / 2); return; }
    var maxA = Math.max.apply(null, bins.map(function (b) { return b.total; }).concat([1]));
    var maxV = Math.max.apply(null, bins.map(function (b) { return b.vol; }).concat([1]));
    var yMax = Math.max(4, Math.ceil(maxA * 1.15));
    var bw = pw / bins.length;
    var C = { grid: "#22304f", text: "#93a4c3" };
    // gridlines + y labels
    g.font = "11px system-ui, sans-serif"; g.textBaseline = "middle"; g.textAlign = "right";
    var ticks = Math.min(5, yMax);
    for (var i = 0; i <= ticks; i++) {
      var v = Math.round(yMax * i / ticks), y = T + ph - ph * v / yMax;
      g.strokeStyle = C.grid; g.lineWidth = 1; g.beginPath(); g.moveTo(L, y + .5); g.lineTo(W - R, y + .5); g.stroke();
      g.fillStyle = C.text; g.fillText(String(v), L - 6, y);
    }
    // volume area
    g.beginPath(); g.moveTo(L, T + ph);
    bins.forEach(function (b, i) { var y = T + ph - ph * 0.9 * b.vol / maxV; g.lineTo(L + i * bw, y); g.lineTo(L + (i + 1) * bw, y); });
    g.lineTo(L + pw, T + ph); g.closePath(); g.fillStyle = "rgba(120,140,185,0.16)"; g.fill();
    // bars
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
        g.globalAlpha = dim ? 0.22 : 1; g.fillStyle = SEV_COLOR[s]; g.fillRect(x, y, w, hh - 0.5); g.globalAlpha = 1;
      });
      if (hover === i) { g.strokeStyle = "#e7edf8"; g.lineWidth = 1; g.strokeRect(L + i * bw + .5, T + .5, bw - 1, ph - 1); }
    });
    // x labels at each local midnight (or start)
    g.textAlign = "left"; g.textBaseline = "top"; g.fillStyle = C.text;
    var lastLabel = -100;
    bins.forEach(function (b, i) {
      var d = new Date(b.t0);
      var isMidnight = d.getHours() === 0;
      if (isMidnight || i === 0 || b.t1 - b.t0 >= 86400000) {
        var x = L + i * bw;
        if (x - lastLabel < 46 && i !== 0) return;
        g.strokeStyle = C.grid; g.beginPath(); g.moveTo(x + .5, T + ph); g.lineTo(x + .5, T + ph + 5); g.stroke();
        g.fillText(DAYS[d.getDay()] + " " + MONTHS[d.getMonth()] + " " + d.getDate(), x + 2, T + ph + 8);
        lastLabel = x;
      }
    });
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
    b.alerts.slice(0, 3).forEach(function (a) { tip.appendChild(h("div", { class: "muted", text: "• " + a.rule_id + " " + a.title.slice(0, 40) })); });
    if (b.alerts.length > 3) tip.appendChild(h("div", { class: "muted", text: "+ " + (b.alerts.length - 3) + " more" }));
    tip.hidden = false;
    var wrap = $("timeline").parentNode.getBoundingClientRect();
    var x = ev.clientX - wrap.left + 14, y = ev.clientY - wrap.top + 10;
    if (x + 290 > wrap.width) x = ev.clientX - wrap.left - 290;
    tip.style.left = Math.max(0, x) + "px"; tip.style.top = Math.max(0, y) + "px";
  }

  // ------------------------------------------------------------------ drawer
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
    lines.push("", "Status: open, not yet triaged. (Synthetic data example.)");
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
  function openDrawer(a) {
    lastFocus = document.activeElement;
    $("d-sev").className = "sev-badge sev-" + a.severity; $("d-sev").textContent = a.severity;
    $("d-id").textContent = " " + a.id; $("drawer-title").textContent = a.title;
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
      return h("a", { class: "chip-btn", href: "https://attack.mitre.org/techniques/" + m.id.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", text: m.id + " " + m.name + " (" + m.tactic + ")" });
    }))));
    var det = Object.keys(a.details);
    if (det.length) {
      var dl = h("dl", { class: "kv" });
      det.forEach(function (k) {
        var v = a.details[k];
        dl.appendChild(h("dt", { text: k.replace(/_/g, " ") }));
        dl.appendChild(h("dd", { text: detailValue(v) }));
      });
      body.appendChild(section("Details", dl));
    }
    var tl = h("ol", { class: "tl" }, a.timeline.map(function (t) {
      var li = h("li", null, [h("time", { text: t.ts.replace("T", " ") + " · " + t.source }), t.event]);
      li.style.setProperty("--c", SEV_COLOR[a.severity]); return li;
    }));
    body.appendChild(section("Timeline (" + a.timeline.length + " of " + a.count + " events shown)", tl));
    body.appendChild(section("Recommended response", h("ol", { class: "steps" }, a.recommended_response.map(function (s) { return h("li", { text: s }); }))));
    body.appendChild(section("Evidence (raw log lines)", h("pre", { class: "evidence", tabindex: "0", text: a.evidence.join("\n") })));
    var msg = h("span", { class: "toast", role: "status" });
    body.appendChild(h("div", { class: "btn-row" }, [
      h("button", { type: "button", class: "btn", text: "Copy as ticket note", onclick: function () { copyText(ticketNote(a), function (ok) { msg.textContent = ok ? "Copied." : "Copy failed: select the text manually."; }); } }),
      h("button", { type: "button", class: "btn ghost", text: "Copy link", onclick: function () { copyText(location.href.split("#")[0] + "#alert=" + a.id, function (ok) { msg.textContent = ok ? "Link copied." : "Copy failed."; }); } }), msg]));
    $("scrim").hidden = false; $("drawer").hidden = false;
    try { history.replaceState(null, "", "#alert=" + a.id); } catch (e) { /* file:// or sandbox */ }
    $("drawer").scrollTop = 0; body.scrollTop = 0;
    $("d-close").focus();
  }
  function hideDrawer(silent) {
    if ($("drawer").hidden) return;
    $("drawer").hidden = true; $("scrim").hidden = true;
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { /* ignore */ }
    if (!silent && lastFocus && lastFocus.focus) lastFocus.focus();
  }

  // ------------------------------------------------------------------ CSV export
  function csvCell(v) {
    var s = String(v === undefined || v === null ? "" : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;       // neutralise spreadsheet formula injection
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function exportCsv() {
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

  // ------------------------------------------------------------------ wiring
  function wire() {
    $("filters").addEventListener("submit", function (e) { e.preventDefault(); });
    $("f-search").addEventListener("input", function (e) { state.q = e.target.value.trim(); renderAll(); });
    $("f-source").addEventListener("change", function (e) { state.source = e.target.value; renderAll(); });
    $("f-tactic").addEventListener("change", function (e) { state.tactic = e.target.value; renderAll(); });
    $("f-rule").addEventListener("change", function (e) { state.rule = e.target.value; renderAll(); });
    $("f-reset").addEventListener("click", function () { state = freshState(); $("f-search").value = ""; renderAll(); });
    $("f-export").addEventListener("click", exportCsv);
    $("d-close").addEventListener("click", function () { hideDrawer(); });
    $("scrim").addEventListener("click", function () { hideDrawer(); });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !$("drawer").hidden) hideDrawer();
      if (e.key === "Tab" && !$("drawer").hidden) {   // keep focus inside the dialog
        var f = $("drawer").querySelectorAll("button, a[href], pre[tabindex]");
        if (!f.length) return;
        var first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
    Array.prototype.forEach.call(document.querySelectorAll("button.sort"), function (b) {
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
