(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtNum(n) {
    if (n == null) return "0";
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "K";
    return String(Math.round(n));
  }
  function fmtTime(iso) {
    var d = new Date(iso + (iso.endsWith("Z") || /[+-]\d\d:\d\d$/.test(iso) ? "" : "Z"));
    return d.toLocaleTimeString(undefined, { hour12: false });
  }
  // Time-of-day alone (fmtTime) reads fine for "just happened" timestamps
  // (live feed, audit log) but is meaningless for a date that could be a
  // year out, like a license expiry - this includes the actual date too.
  function fmtDate(iso) {
    var d = new Date(iso + (iso.endsWith("Z") || /[+-]\d\d:\d\d$/.test(iso) ? "" : "Z"));
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) +
      ", " + d.toLocaleTimeString(undefined, { hour12: false });
  }
  function fmtDateOnly(iso) {
    var d = new Date(iso + (iso.endsWith("Z") || /[+-]\d\d:\d\d$/.test(iso) ? "" : "Z"));
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function fmtBytes(n) {
    if (!n) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return (n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }
  function fmtMs(n) {
    return n == null ? "—" : (n < 1 ? "<1" : Math.round(n));
  }
  function countryFlag(code) {
    // ISO 3166-1 alpha-2 -> flag emoji: each letter maps to a Regional
    // Indicator Symbol (U+1F1E6 = 'A'). "LAN"/"??" aren't real country
    // codes (private IP / lookup failed) so they get a plain fallback.
    if (!code || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) {
      return code === "LAN" ? "🏠" : "🌐"; // house / globe
    }
    var cc = code.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  }
  function countryLabel(code) {
    return countryFlag(code) + " " + esc(code || "??");
  }
  function getCookie(name) {
    var m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
  }
  var CSRF_COOKIE_NAME = "sentrynet_csrf";
  async function api(path, opts) {
    opts = opts || {};
    var method = (opts.method || "GET").toUpperCase();
    if (method === "POST" || method === "PUT" || method === "PATCH" || method === "DELETE") {
      var csrf = getCookie(CSRF_COOKIE_NAME);
      if (csrf) {
        opts.headers = opts.headers || {};
        opts.headers["X-CSRF-Token"] = csrf;
      }
    }
    var r = await fetch(path, opts);
    if (r.status === 401) { location.href = "/"; throw new Error("auth"); }
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }

  // ── Account / roles ───────────────────────────────────────────────────
  // Purely UX - the server enforces every permission independently (403s
  // on anything a role can't do), this just avoids showing controls that
  // would fail anyway.
  var ROLE_LEVEL = { spectator: 0, operator: 1, administrator: 2, owner: 3 };
  var CURRENT_ROLE = null;
  var CURRENT_USERNAME = null;

  function roleAtLeast(minRole) {
    return CURRENT_ROLE != null && ROLE_LEVEL[CURRENT_ROLE] >= ROLE_LEVEL[minRole];
  }

  function applyRolePermissions() {
    document.querySelectorAll("[data-min-role]").forEach(function (el) {
      el.style.display = roleAtLeast(el.dataset.minRole) ? "" : "none";
    });
  }

  async function loadAccount() {
    try {
      var acc = await api("/api/account");
      CURRENT_ROLE = acc.role;
      CURRENT_USERNAME = acc.username;
      document.getElementById("accountInfo").textContent =
        acc.username + " · " + acc.role.charAt(0).toUpperCase() + acc.role.slice(1);
      applyRolePermissions();
      if (CURRENT_ROLE === "owner") { loadUsers(); loadLicense(); loadFleet(); }
    } catch (e) {}
  }

  document.getElementById("changePasswordBtn").addEventListener("click", async function () {
    var current = prompt("Current password:");
    if (!current) return;
    var next = prompt("New password (10+ characters):");
    if (!next) return;
    try {
      await api("/api/account/password", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      alert("Password changed.");
    } catch (e) { alert("Failed: " + e.message); }
  });

  // ── Clock ──────────────────────────────────────────────────────────────
  function tickClock() {
    document.getElementById("clock").textContent = new Date().toLocaleTimeString(undefined, { hour12: false });
  }
  tickClock();
  setInterval(tickClock, 1000);

  fetch("/api/version").then(function (r) { return r.json(); }).then(function (d) {
    document.getElementById("versionTag").textContent = "v" + d.version;
  }).catch(function () {});

  document.getElementById("logoutBtn").addEventListener("click", async function () {
    try { await api("/logout", { method: "POST" }); } catch (e) {}
    location.href = "/";
  });

  // ── Tabs ───────────────────────────────────────────────────────────────
  document.querySelectorAll(".tab").forEach(function (t) {
    t.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(function (x) { x.classList.remove("active"); });
      document.querySelectorAll(".tab-content").forEach(function (x) { x.classList.remove("active"); });
      t.classList.add("active");
      document.getElementById("tab-" + t.dataset.tab).classList.add("active");
    });
  });

  // ── Bar list rendering (single-hue magnitude ranking) ────────────────────
  function renderBarList(el, items, opts) {
    opts = opts || {};
    if (!items.length) { el.innerHTML = '<div class="empty">No data yet</div>'; return; }
    var valueFmt = opts.formatValue || fmtNum;
    var max = Math.max.apply(null, items.map(function (i) { return i.value; })) || 1;
    el.innerHTML = items.map(function (i) {
      var pct = Math.max(3, Math.round((i.value / max) * 100));
      var label = opts.clickable
        ? '<span class="bar-label" style="cursor:pointer" data-ip="' + esc(i.raw) + '">' + esc(i.label) + "</span>"
        : '<span class="bar-label">' + esc(i.label) + "</span>";
      return '<div class="bar-row">' + label +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
        '<span class="bar-value">' + valueFmt(i.value) + "</span></div>";
    }).join("");
    if (opts.clickable) {
      el.querySelectorAll("[data-ip]").forEach(function (node) {
        node.addEventListener("click", function () { openDrawer(node.dataset.ip); });
      });
    }
  }

  // ── Line chart (per dataviz skill: 2px line, ~10% area wash, hairline grid) ──
  // opts.valueKey: which field on each point holds the plotted value (default "count").
  // opts.formatValue: how to render that value in tooltips/axis (default: plain number).
  // opts.unitLabel: appended to the tooltip value (e.g. "req").
  function renderLineChart(svg, tooltipEl, series, opts) {
    opts = opts || {};
    var valueKey = opts.valueKey || "count";
    var formatValue = opts.formatValue || fmtNum;
    var unitLabel = opts.unitLabel != null ? opts.unitLabel : "req";
    var labelKey = opts.labelKey || "minute";
    var formatLabel = opts.formatLabel || fmtTime;
    var W = 1000, H = 180, padL = 38, padR = 6, padT = 10, padB = 22;
    var plotW = W - padL - padR, plotH = H - padT - padB;
    svg.innerHTML = "";
    if (!series.length) {
      svg.innerHTML = '<text x="500" y="90" text-anchor="middle" fill="var(--text-muted)" font-size="13">No data yet</text>';
      return;
    }
    var max = Math.max.apply(null, series.map(function (p) { return p[valueKey]; })) || 1;
    var niceMax = Math.ceil(max * 1.15 / 5) * 5 || 5;
    var n = series.length;
    function xAt(i) { return padL + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW); }
    function yAt(v) { return padT + plotH - (v / niceMax) * plotH; }

    var svgns = "http://www.w3.org/2000/svg";
    // gridlines (4 horizontal steps)
    for (var g = 0; g <= 4; g++) {
      var gy = padT + (g / 4) * plotH;
      var line = document.createElementNS(svgns, "line");
      line.setAttribute("x1", padL); line.setAttribute("x2", W - padR);
      line.setAttribute("y1", gy); line.setAttribute("y2", gy);
      line.setAttribute("class", g === 4 ? "baseline" : "gridline");
      svg.appendChild(line);
      var val = niceMax * (1 - g / 4);
      var txt = document.createElementNS(svgns, "text");
      txt.setAttribute("x", 4); txt.setAttribute("y", gy + 4);
      txt.setAttribute("font-size", "10"); txt.setAttribute("fill", "var(--text-muted)");
      txt.textContent = formatValue(Math.round(val));
      svg.appendChild(txt);
    }

    var pathD = series.map(function (p, i) { return (i === 0 ? "M" : "L") + xAt(i).toFixed(1) + "," + yAt(p[valueKey]).toFixed(1); }).join(" ");
    var areaD = pathD + " L" + xAt(n - 1).toFixed(1) + "," + (padT + plotH) + " L" + xAt(0).toFixed(1) + "," + (padT + plotH) + " Z";

    var area = document.createElementNS(svgns, "path");
    area.setAttribute("d", areaD); area.setAttribute("class", "area");
    svg.appendChild(area);

    var path = document.createElementNS(svgns, "path");
    path.setAttribute("d", pathD); path.setAttribute("class", "line");
    svg.appendChild(path);

    // sparse x-axis labels (start, mid, end)
    [0, Math.floor(n / 2), n - 1].forEach(function (i) {
      if (i < 0 || i >= n) return;
      var txt = document.createElementNS(svgns, "text");
      txt.setAttribute("x", xAt(i)); txt.setAttribute("y", H - 4);
      txt.setAttribute("font-size", "10"); txt.setAttribute("fill", "var(--text-muted)");
      txt.setAttribute("text-anchor", i === 0 ? "start" : i === n - 1 ? "end" : "middle");
      txt.textContent = formatLabel(series[i][labelKey]);
      svg.appendChild(txt);
    });

    // hover targets - hit area extends well past the 2px line itself
    series.forEach(function (p, i) {
      var hit = document.createElementNS(svgns, "circle");
      hit.setAttribute("cx", xAt(i)); hit.setAttribute("cy", yAt(p[valueKey])); hit.setAttribute("r", 12);
      hit.setAttribute("fill", "transparent");
      hit.addEventListener("mouseenter", function (e) {
        var dot = document.createElementNS(svgns, "circle");
        dot.setAttribute("cx", xAt(i)); dot.setAttribute("cy", yAt(p[valueKey])); dot.setAttribute("r", 4);
        dot.setAttribute("class", "dot"); dot.setAttribute("id", "__hoverdot");
        svg.appendChild(dot);
        tooltipEl.style.display = "block";
        tooltipEl.textContent = formatLabel(p[labelKey]) + " — " + formatValue(p[valueKey]) + (unitLabel ? " " + unitLabel : "");
        var rect = svg.getBoundingClientRect();
        tooltipEl.style.left = (rect.width * (xAt(i) / W)) + "px";
        tooltipEl.style.top = (rect.height * (yAt(p[valueKey]) / H) - 34) + "px";
      });
      hit.addEventListener("mouseleave", function () {
        var d = svg.querySelector("#__hoverdot"); if (d) d.remove();
        tooltipEl.style.display = "none";
      });
      svg.appendChild(hit);
    });
  }

  // ── Dual-line chart: current period (solid, colored) vs. prior period
  // (dashed, muted) sharing one axis - the shape difference (solid vs
  // dashed) carries the series identity so no second saturated hue is
  // needed, and a legend names both (see chart-legend markup in the HTML).
  function renderDualLineChart(svg, tooltipEl, currentSeries, priorSeries) {
    var W = 1000, H = 180, padL = 38, padR = 6, padT = 10, padB = 22;
    var plotW = W - padL - padR, plotH = H - padT - padB;
    svg.innerHTML = "";
    var n = Math.max(currentSeries.length, priorSeries.length);
    if (!n) {
      svg.innerHTML = '<text x="500" y="90" text-anchor="middle" fill="var(--text-muted)" font-size="13">No data yet</text>';
      return;
    }
    var allVals = currentSeries.map(function (p) { return p.count; }).concat(priorSeries.map(function (p) { return p.count; }));
    var max = Math.max.apply(null, allVals) || 1;
    var niceMax = Math.ceil(max * 1.15 / 5) * 5 || 5;
    function xAt(i) { return padL + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW); }
    function yAt(v) { return padT + plotH - (v / niceMax) * plotH; }
    var svgns = "http://www.w3.org/2000/svg";

    for (var g = 0; g <= 4; g++) {
      var gy = padT + (g / 4) * plotH;
      var line = document.createElementNS(svgns, "line");
      line.setAttribute("x1", padL); line.setAttribute("x2", W - padR);
      line.setAttribute("y1", gy); line.setAttribute("y2", gy);
      line.setAttribute("class", g === 4 ? "baseline" : "gridline");
      svg.appendChild(line);
      var txt = document.createElementNS(svgns, "text");
      txt.setAttribute("x", 4); txt.setAttribute("y", gy + 4);
      txt.setAttribute("font-size", "10"); txt.setAttribute("fill", "var(--text-muted)");
      txt.textContent = Math.round(niceMax * (1 - g / 4));
      svg.appendChild(txt);
    }

    function buildPath(series, cls, dashed) {
      if (!series.length) return;
      var d = series.map(function (p, i) { return (i === 0 ? "M" : "L") + xAt(i).toFixed(1) + "," + yAt(p.count).toFixed(1); }).join(" ");
      var path = document.createElementNS(svgns, "path");
      path.setAttribute("d", d);
      path.setAttribute("class", cls);
      if (dashed) { path.setAttribute("stroke-dasharray", "5,4"); path.setAttribute("stroke", "var(--text-muted)"); path.setAttribute("fill", "none"); path.setAttribute("stroke-width", "2"); }
      svg.appendChild(path);
    }
    buildPath(priorSeries, "", true);
    buildPath(currentSeries, "line", false);

    [0, Math.floor(n / 2), n - 1].forEach(function (i) {
      if (i < 0 || i >= n) return;
      var txt = document.createElementNS(svgns, "text");
      txt.setAttribute("x", xAt(i)); txt.setAttribute("y", H - 4);
      txt.setAttribute("font-size", "10"); txt.setAttribute("fill", "var(--text-muted)");
      txt.setAttribute("text-anchor", i === 0 ? "start" : i === n - 1 ? "end" : "middle");
      txt.textContent = (i % 24 || i) + ":00";
      svg.appendChild(txt);
    });

    for (var i = 0; i < n; i++) {
      (function (i) {
        var cur = currentSeries[i], prior = priorSeries[i];
        var y = cur ? yAt(cur.count) : (prior ? yAt(prior.count) : padT + plotH);
        var hit = document.createElementNS(svgns, "circle");
        hit.setAttribute("cx", xAt(i)); hit.setAttribute("cy", y); hit.setAttribute("r", 12);
        hit.setAttribute("fill", "transparent");
        hit.addEventListener("mouseenter", function () {
          tooltipEl.style.display = "block";
          var parts = [];
          if (cur) parts.push("Today " + cur.hour + ":00 — " + cur.count);
          if (prior) parts.push("Yesterday " + prior.hour + ":00 — " + prior.count);
          tooltipEl.textContent = parts.join(" · ");
          var rect = svg.getBoundingClientRect();
          tooltipEl.style.left = (rect.width * (xAt(i) / W)) + "px";
          tooltipEl.style.top = (rect.height * (y / H) - 34) + "px";
        });
        hit.addEventListener("mouseleave", function () { tooltipEl.style.display = "none"; });
        svg.appendChild(hit);
      })(i);
    }
  }

  // ── Overview tab ───────────────────────────────────────────────────────
  async function loadOverview() {
    try {
      var s = await api("/api/stats");
      document.getElementById("stReqMin").textContent = s.requests_per_min.toFixed(1);
      document.getElementById("stUniqueIps").textContent = fmtNum(s.unique_ips_5m);
      document.getElementById("st24h").textContent = fmtNum(s.requests_24h);
      document.getElementById("stFlagged").textContent = fmtNum(s.flagged_active);
      document.getElementById("stBlocked").textContent = fmtNum(s.blocked_count);
      var badge = document.getElementById("flaggedBadge");
      if (s.flagged_active > 0) { badge.style.display = "inline-block"; badge.textContent = s.flagged_active; }
      else badge.style.display = "none";
    } catch (e) {}

    try {
      var ts = await api("/api/timeseries?minutes=60");
      renderLineChart(document.getElementById("lineChart"), document.getElementById("chartTooltip"), ts);
    } catch (e) {}

    try {
      var countries = await api("/api/top-countries?hours=24&limit=10");
      document.getElementById("countryCount").textContent = countries.length;
      renderBarList(document.getElementById("countryList"), countries.map(function (c) { return { label: countryFlag(c.country) + " " + c.country, value: c.count }; }));
    } catch (e) {}

    try {
      var hosts = await api("/api/top-hosts?hours=24&limit=10");
      document.getElementById("hostCount").textContent = hosts.length;
      renderBarList(document.getElementById("hostList"), hosts.map(function (h) { return { label: h.host, value: h.count }; }));
    } catch (e) {}

    try {
      var ips = await api("/api/top-ips?hours=24&limit=10");
      document.getElementById("ipCount").textContent = ips.length;
      renderBarList(document.getElementById("ipList"), ips.map(function (i) { return { label: i.ip + " " + countryFlag(i.country) + " " + i.country, value: i.count, raw: i.ip }; }), { clickable: true });
    } catch (e) {}

    try {
      var devices = await api("/api/device-breakdown?hours=24");
      document.getElementById("deviceCount").textContent = devices.length;
      renderBarList(document.getElementById("deviceList"), devices.map(function (d) { return { label: d.device, value: d.count }; }));
    } catch (e) {}

    try {
      var statuses = await api("/api/status-breakdown?hours=24");
      var colorFor = { "200-299": "var(--good)", "300-399": "var(--series-1)", "400-499": "var(--warning)", "500-599": "var(--critical)" };
      var el = document.getElementById("statusList");
      if (!statuses.length) { el.innerHTML = '<div class="empty">No data yet</div>'; }
      else {
        var max = Math.max.apply(null, statuses.map(function (s) { return s.count; })) || 1;
        el.innerHTML = statuses.map(function (s) {
          var pct = Math.max(3, Math.round((s.count / max) * 100));
          return '<div class="bar-row"><span class="bar-label">' + s.bucket + '</span>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + (colorFor[s.bucket] || "var(--series-1)") + '"></div></div>' +
            '<span class="bar-value">' + fmtNum(s.count) + "</span></div>";
        }).join("");
      }
    } catch (e) {}
  }

  // ── Live feed tab ──────────────────────────────────────────────────────
  var feedOffset = 0;
  var FEED_LIMIT = 60;

  function statusClass(code) {
    if (code >= 500) return "status-5xx";
    if (code >= 400) return "status-4xx";
    if (code >= 300) return "status-3xx";
    return "status-2xx";
  }

  async function loadFeed() {
    var params = new URLSearchParams();
    var host = document.getElementById("fHost").value.trim();
    var ip = document.getElementById("fIp").value.trim();
    var country = document.getElementById("fCountry").value.trim();
    var status = document.getElementById("fStatus").value;
    var device = document.getElementById("fDevice").value;
    var hours = document.getElementById("fHours").value;
    if (host) params.set("host", host);
    if (ip) params.set("ip", ip);
    if (country) params.set("country", country.toUpperCase());
    if (status) params.set("status", status);
    if (device) params.set("device", device);
    params.set("hours", hours);
    params.set("limit", FEED_LIMIT);
    params.set("offset", feedOffset);

    try {
      var rows = await api("/api/requests?" + params.toString());
      var tbody = document.getElementById("reqTableBody");
      if (!rows.length) { tbody.innerHTML = '<tr><td colspan="9" class="empty">No requests match these filters</td></tr>'; return; }
      tbody.innerHTML = rows.map(function (r) {
        return "<tr class=\"req-row\" data-ip=\"" + esc(r.ip) + "\">" +
          '<td class="mono">' + fmtTime(r.ts) + "</td>" +
          '<td class="mono">' + esc(r.ip) + "</td>" +
          '<td class="country-chip">' + countryLabel(r.country) + "</td>" +
          "<td>" + esc(r.host) + "</td>" +
          "<td>" + esc(r.method) + "</td>" +
          '<td class="path-cell" title="' + esc(r.path) + '">' + esc(r.path) + "</td>" +
          '<td><span class="status-pill ' + statusClass(r.status) + '">' + r.status + "</span></td>" +
          "<td>" + esc(r.device || "-") + "</td>" +
          '<td class="mono">' + (r.request_time != null ? Math.round(r.request_time * 1000) : "-") + "</td>" +
          "</tr>";
      }).join("");
      tbody.querySelectorAll("[data-ip]").forEach(function (row) {
        row.addEventListener("click", function () { openDrawer(row.dataset.ip); });
      });
    } catch (e) {}
  }

  document.getElementById("applyFilters").addEventListener("click", function () { feedOffset = 0; loadFeed(); });
  document.getElementById("clearFilters").addEventListener("click", function () {
    ["fHost", "fIp", "fCountry", "fStatus", "fDevice"].forEach(function (id) { document.getElementById(id).value = ""; });
    document.getElementById("fHours").value = "1";
    feedOffset = 0; loadFeed();
  });
  document.getElementById("prevPage").addEventListener("click", function () { feedOffset = Math.max(0, feedOffset - FEED_LIMIT); loadFeed(); });
  document.getElementById("nextPage").addEventListener("click", function () { feedOffset += FEED_LIMIT; loadFeed(); });

  // ── Flagged & Blocked tab ──────────────────────────────────────────────
  var SIGNAL_LABELS = {
    high_rate: "High rate", scanning: "Scanning", scanner_ua: "Scanner UA",
    brute_force: "Brute force", path_scanning: "Path enum", coordinated: "Coordinated",
    tor_exit: "TOR exit", datacenter_ip: "Datacenter IP", no_user_agent: "No UA",
    headless_browser: "Headless browser", robotic_timing: "Robotic timing", slow_requests: "Slow requests",
    waf_payload: "Attack payload", ssh_brute_force: "SSH brute force",
  };
  function signalBadge(s) {
    return '<span class="signal-badge sig-sev-' + (s.severity || 1) + '" title="' + esc(s.detail) + '">' +
      (SIGNAL_LABELS[s.type] || s.type) + "</span>";
  }
  function fmtExpiry(iso) {
    if (!iso) return "permanent";
    var d = new Date(iso);
    var diffMs = d - new Date();
    if (diffMs <= 0) return "expiring…";
    var mins = Math.round(diffMs / 60000);
    if (mins < 60) return "expires in " + mins + "m";
    var hrs = Math.round(mins / 60);
    if (hrs < 48) return "expires in " + hrs + "h";
    return "expires in " + Math.round(hrs / 24) + "d";
  }

  async function loadFlagged() {
    try {
      var rows = await api("/api/flagged?limit=100");
      document.getElementById("flagListCount").textContent = rows.length;
      var el = document.getElementById("flagList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No flagged IPs right now</div>'; }
      else {
        el.innerHTML = rows.map(function (r) {
          var badges = r.signals.map(signalBadge).join("");
          return '<div class="flag-row">' +
            '<div><span class="flag-ip" data-ip="' + esc(r.ip) + '">' + esc(r.ip) + "</span> " +
            '<span class="country-chip">' + countryLabel(r.country) + "</span>" +
            '<div class="flag-meta">last seen ' + fmtTime(r.last_seen) + " · score " + r.score + "</div>" +
            '<div class="signal-badges">' + badges + "</div></div>" +
            (r.is_blocked
              ? (roleAtLeast("operator") ? '<button class="btn btn-sm" data-unblock="' + esc(r.ip) + '">Blocked ✓</button>' : '<span class="mlr-meta">Blocked</span>')
              : (roleAtLeast("operator") ? '<button class="btn btn-sm btn-danger" data-open-block="' + esc(r.ip) + '">Block</button>' : "")) +
            "</div>";
        }).join("");
        wireBlockButtons(el);
        el.querySelectorAll("[data-ip]").forEach(function (n) { n.addEventListener("click", function () { openDrawer(n.dataset.ip); }); });
      }
    } catch (e) {}

    try {
      var arSettings = await api("/api/alert-settings");
      var arToggle = arSettings.filter(function (s) { return s.key === "auto_release_blocks"; });
      renderAlertRows(document.getElementById("autoReleaseBlocksToggle"), arToggle);
    } catch (e) {}

    try {
      var blocked = await api("/api/blocked");
      document.getElementById("blockListCount").textContent = blocked.length;
      var bEl = document.getElementById("blockList");
      if (!blocked.length) { bEl.innerHTML = '<div class="empty">Nothing blocked</div>'; }
      else {
        bEl.innerHTML = blocked.map(function (b) {
          return '<div class="flag-row"><div><span class="flag-ip">' + esc(b.ip) + "</span>" +
            '<div class="flag-meta">' + esc(b.reason || "no reason given") + " · blocked " + fmtTime(b.blocked_at) +
            " by " + esc(b.blocked_by || "?") + " · " + fmtExpiry(b.expires_at) + "</div></div>" +
            (roleAtLeast("operator") ? '<button class="btn btn-sm" data-unblock="' + esc(b.ip) + '">Unblock</button>' : "") + "</div>";
        }).join("");
        wireBlockButtons(bEl);
      }
    } catch (e) {}
  }

  function wireBlockButtons(scope) {
    scope.querySelectorAll("[data-open-block]").forEach(function (btn) {
      btn.addEventListener("click", function (e) {
        e.stopPropagation();
        openBlockModal(btn.dataset.openBlock);
      });
    });
    scope.querySelectorAll("[data-unblock]").forEach(function (btn) {
      btn.addEventListener("click", async function (e) {
        e.stopPropagation();
        var ip = btn.dataset.unblock;
        if (btn.textContent.indexOf("✓") === -1 && !confirm("Unblock " + ip + "?")) return;
        btn.disabled = true;
        try {
          await api("/api/block/" + encodeURIComponent(ip), { method: "DELETE" });
          loadFlagged();
        } catch (e2) { alert("Unblock failed: " + e2.message); btn.disabled = false; }
      });
    });
  }

  // ── Shared block modal (manual block button, flagged rows, drawer) ─────
  var blockModalBackdrop = document.getElementById("blockModalBackdrop");
  var blockModalIp = document.getElementById("blockModalIp");
  var blockModalReason = document.getElementById("blockModalReason");
  var blockModalDuration = document.getElementById("blockModalDuration");
  var blockModalOnSuccess = null;

  function openBlockModal(prefillIp, onSuccess) {
    blockModalIp.value = prefillIp || "";
    blockModalReason.value = "";
    blockModalDuration.value = "";
    blockModalOnSuccess = onSuccess || null;
    blockModalBackdrop.classList.add("open");
    (prefillIp ? blockModalReason : blockModalIp).focus();
  }
  function closeBlockModal() { blockModalBackdrop.classList.remove("open"); }
  document.getElementById("blockModalCancel").addEventListener("click", closeBlockModal);
  blockModalBackdrop.addEventListener("click", function (e) { if (e.target === blockModalBackdrop) closeBlockModal(); });
  document.getElementById("blockModalSubmit").addEventListener("click", async function () {
    var ip = blockModalIp.value.trim();
    if (!ip) { alert("Enter an IP address or CIDR"); return; }
    var payload = { ip: ip, reason: blockModalReason.value.trim() || null };
    if (blockModalDuration.value) payload.duration_hours = parseFloat(blockModalDuration.value);
    var btn = this;
    btn.disabled = true; btn.textContent = "Blocking…";
    try {
      await api("/api/block", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      closeBlockModal();
      loadFlagged();
      if (blockModalOnSuccess) blockModalOnSuccess();
    } catch (e2) {
      alert("Block failed: " + e2.message);
    } finally {
      btn.disabled = false; btn.textContent = "Block";
    }
  });
  document.getElementById("manualBlockBtn").addEventListener("click", function () { openBlockModal(""); });
  document.getElementById("bulkBlockBtn").addEventListener("click", async function () {
    var minScore = parseInt(document.getElementById("bulkBlockScore").value, 10) || 1;
    if (!confirm("Block every currently-flagged IP with score ≥ " + minScore + "?")) return;
    var btn = this;
    btn.disabled = true; btn.textContent = "Blocking…";
    try {
      var res = await api("/api/bulk-block", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ min_score: minScore }) });
      loadFlagged();
      alert("Blocked " + res.blocked_count + " IP(s).");
    } catch (e2) { alert("Bulk block failed: " + e2.message); }
    finally { btn.disabled = false; btn.textContent = "Bulk block"; }
  });

  // ── Allowlist ───────────────────────────────────────────────────────────
  async function loadAllowlist() {
    try {
      var rows = await api("/api/allowed");
      document.getElementById("allowListCount").textContent = rows.length;
      var el = document.getElementById("allowList");
      if (!rows.length) { el.innerHTML = '<div class="empty">Nothing allowlisted</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        return '<div class="mini-list-row"><div><div class="mlr-main">' + esc(r.ip) + "</div>" +
          '<div class="mlr-meta">' + esc(r.reason || "no reason given") + " · added " + fmtTime(r.added_at) + " by " + esc(r.added_by || "?") + "</div></div>" +
          (roleAtLeast("operator") ? '<button class="btn btn-sm" data-unallow="' + esc(r.ip) + '">Remove</button>' : "") + "</div>";
      }).join("");
      el.querySelectorAll("[data-unallow]").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          btn.disabled = true;
          try { await api("/api/allow/" + encodeURIComponent(btn.dataset.unallow), { method: "DELETE" }); loadAllowlist(); }
          catch (e) { alert("Failed: " + e.message); btn.disabled = false; }
        });
      });
    } catch (e) {}
  }
  document.getElementById("addAllowBtn").addEventListener("click", async function () {
    var ip = document.getElementById("allowIpInput").value.trim();
    if (!ip) { alert("Enter an IP or CIDR"); return; }
    var reason = document.getElementById("allowReasonInput").value.trim();
    try {
      await api("/api/allow", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: ip, reason: reason || null }) });
      document.getElementById("allowIpInput").value = ""; document.getElementById("allowReasonInput").value = "";
      loadAllowlist();
    } catch (e) { alert("Failed: " + e.message); }
  });

  // ── Blocked countries ────────────────────────────────────────────────────
  async function loadBlockedCountries() {
    try {
      var rows = await api("/api/blocked-countries");
      document.getElementById("countryBlockCount").textContent = rows.length;
      var el = document.getElementById("countryBlockList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No countries blocked</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        return '<div class="mini-list-row"><div><div class="mlr-main">' + countryLabel(r.country) + "</div>" +
          '<div class="mlr-meta">' + esc(r.reason || "no reason given") + " · blocked " + fmtTime(r.blocked_at) + " by " + esc(r.blocked_by || "?") + "</div></div>" +
          (roleAtLeast("operator") ? '<button class="btn btn-sm" data-uncountry="' + esc(r.country) + '">Unblock</button>' : "") + "</div>";
      }).join("");
      el.querySelectorAll("[data-uncountry]").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          btn.disabled = true;
          try { await api("/api/block-country/" + encodeURIComponent(btn.dataset.uncountry), { method: "DELETE" }); loadBlockedCountries(); }
          catch (e) { alert("Failed: " + e.message); btn.disabled = false; }
        });
      });
    } catch (e) {}
  }
  document.getElementById("addCountryBlockBtn").addEventListener("click", async function () {
    var code = document.getElementById("blockCountryInput").value.trim().toUpperCase();
    if (code.length !== 2) { alert("Enter a 2-letter country code"); return; }
    var reason = document.getElementById("blockCountryReasonInput").value.trim();
    var blockExisting = document.getElementById("blockCountryExisting").checked;
    var btn = this;
    btn.disabled = true; btn.textContent = "Blocking…";
    try {
      var res = await api("/api/block-country", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ country: code, reason: reason || null, block_existing: blockExisting }),
      });
      document.getElementById("blockCountryInput").value = ""; document.getElementById("blockCountryReasonInput").value = "";
      loadBlockedCountries();
      if (res.retroactively_blocked) loadFlagged();
    } catch (e) { alert("Failed: " + e.message); }
    finally { btn.disabled = false; btn.textContent = "Block"; }
  });

  // ── Audit log ────────────────────────────────────────────────────────────
  var AUDIT_ACTION_LABELS = {
    block: "Block", unblock: "Unblock", allow: "Allow", unallow: "Unallow",
    block_country: "Block country", unblock_country: "Unblock country",
  };
  async function loadAuditLog() {
    try {
      var rows = await api("/api/audit-log?limit=50");
      document.getElementById("auditLogCount").textContent = rows.length;
      var el = document.getElementById("auditLogList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No actions recorded yet</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        return '<div class="audit-row">' +
          '<span class="audit-action audit-' + r.action + '">' + (AUDIT_ACTION_LABELS[r.action] || r.action) + "</span>" +
          '<span class="audit-target">' + esc(r.target) + "</span>" +
          '<span class="audit-reason" title="' + esc(r.reason || "") + '">' + esc(r.reason || "—") + "</span>" +
          '<span class="audit-meta">' + esc(r.actor || "?") + " · " + fmtTime(r.ts) + "</span>" +
          "</div>";
      }).join("");
    } catch (e) {}
  }

  // ── Threat intel status ──────────────────────────────────────────────────
  async function loadThreatIntelStatus() {
    try {
      var s = await api("/api/threat-intel-status");
      var el = document.getElementById("threatIntelStatus");
      function item(label, count, refresh, err) {
        return '<div class="ti-item"><div class="ti-val">' + fmtNum(count) + '</div><div class="ti-lbl">' + esc(label) + "</div>" +
          '<div class="ti-sub">' + (refresh ? "refreshed " + fmtTime(refresh) : "not yet refreshed") + "</div>" +
          (err ? '<div class="ti-err">' + esc(err) + "</div>" : "") + "</div>";
      }
      el.innerHTML =
        item("TOR exit nodes tracked", s.tor_count, s.tor_last_refresh, s.tor_last_error) +
        item("Datacenter/cloud ranges tracked", s.dc_count, s.dc_last_refresh, s.dc_last_error) +
        item("Spamhaus DROP/EDROP ranges tracked", s.spamhaus_count, s.spamhaus_last_refresh, s.spamhaus_last_error);
    } catch (e) {}
  }

  var SSH_RESULT_LABELS = { accepted: "Accepted", failed: "Failed", invalid_user: "Invalid user" };
  async function loadSshEvents() {
    try {
      var rows = await api("/api/ssh-events?limit=50");
      document.getElementById("sshEventCount").textContent = rows.length;
      var el = document.getElementById("sshEventList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No SSH activity recorded yet</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        var cls = r.result === "accepted" ? "audit-unblock" : "audit-block";
        return '<div class="audit-row">' +
          '<span class="audit-action ' + cls + '">' + (SSH_RESULT_LABELS[r.result] || r.result) + "</span>" +
          '<span class="audit-target">' + esc(r.username || "?") + "@" + esc(r.ip) + "</span>" +
          '<span class="audit-reason">' + countryLabel(r.country) + "</span>" +
          '<span class="audit-meta">' + fmtTime(r.ts) + "</span>" +
          "</div>";
      }).join("");
    } catch (e) {}
  }

  async function loadSshBanned() {
    try {
      var settings = await api("/api/alert-settings");
      var toggle = settings.filter(function (s) { return s.key === "ssh_auto_ban"; });
      renderAlertRows(document.getElementById("sshAutoBanToggle"), toggle);
    } catch (e) {}

    try {
      var rows = await api("/api/ssh-banned");
      document.getElementById("sshBannedCount").textContent = rows.length;
      var el = document.getElementById("sshBannedList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No SSH bans currently active</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        return '<div class="mini-req"><span class="p1">' + esc(r.ip) + " — " + esc(r.reason || "") + "</span>" +
          '<div class="p2">banned ' + fmtTime(r.banned_at) + " · expires " + fmtExpiry(r.expires_at) +
          (roleAtLeast("operator") ? ' <button class="btn btn-sm" data-unban="' + esc(r.ip) + '" style="margin-left:8px">Unban</button>' : "") + "</div></div>";
      }).join("");
      el.querySelectorAll("[data-unban]").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          try { await api("/api/ssh-banned/" + encodeURIComponent(btn.dataset.unban), { method: "DELETE" }); loadSshBanned(); }
          catch (e) {}
        });
      });
    } catch (e) {}
  }

  async function loadSecurity() {
    loadFlagged();
    loadAllowlist();
    loadBlockedCountries();
    loadAuditLog();
    loadThreatIntelStatus();
    loadSshEvents();
    loadSshBanned();
  }

  // ── Analytics tab ────────────────────────────────────────────────────────
  async function loadAnalytics() {
    try {
      var rt = await api("/api/response-times?hours=24");
      document.getElementById("azAvgMs").textContent = fmtMs(rt.avg_ms);
      document.getElementById("azP95Ms").textContent = fmtMs(rt.p95_ms);
    } catch (e) {}

    try {
      var bot = await api("/api/bot-breakdown?hours=24");
      document.getElementById("azBotPct").textContent = bot.bot_pct + "%";
    } catch (e) {}

    try {
      var nvr = await api("/api/new-vs-returning?hours=24");
      document.getElementById("azNewIps").textContent = fmtNum(nvr.new_ips);
      document.getElementById("azReturningIps").textContent = fmtNum(nvr.returning_ips);
    } catch (e) {}

    try {
      var bw = await api("/api/bandwidth-timeseries?minutes=60");
      var total = bw.reduce(function (acc, p) { return acc + p.bytes; }, 0);
      document.getElementById("bandwidthTotal").textContent = fmtBytes(total);
      renderLineChart(document.getElementById("bandwidthChart"), document.getElementById("bandwidthTooltip"), bw,
        { valueKey: "bytes", formatValue: fmtBytes, unitLabel: "" });
    } catch (e) {}

    try {
      var hc = await api("/api/hourly-comparison");
      renderDualLineChart(document.getElementById("hourlyCompareChart"), document.getElementById("hourlyCompareTooltip"), hc.today, hc.yesterday);
    } catch (e) {}

    try {
      var paths = await api("/api/top-paths?hours=24&limit=10");
      document.getElementById("pathCount").textContent = paths.length;
      renderBarList(document.getElementById("pathList"), paths.map(function (p) { return { label: p.path, value: p.count }; }));
    } catch (e) {}

    try {
      var browsers = await api("/api/browser-breakdown?hours=24");
      document.getElementById("browserCount").textContent = browsers.length;
      renderBarList(document.getElementById("browserList"), browsers.map(function (b) { return { label: b.browser, value: b.count }; }));
    } catch (e) {}

    try {
      var oses = await api("/api/os-breakdown?hours=24");
      document.getElementById("osCount").textContent = oses.length;
      renderBarList(document.getElementById("osList"), oses.map(function (o) { return { label: o.os, value: o.count }; }));
    } catch (e) {}

    try {
      var refs = await api("/api/referrers?hours=24&limit=10");
      document.getElementById("referrerCount").textContent = refs.length;
      renderBarList(document.getElementById("referrerList"), refs.map(function (r) { return { label: r.referrer, value: r.count }; }));
    } catch (e) {}

    try {
      var ssl = await api("/api/ssl-breakdown?hours=24");
      document.getElementById("sslCount").textContent = ssl.length;
      renderBarList(document.getElementById("sslList"), ssl.map(function (s) { return { label: s.protocol, value: s.count }; }));
    } catch (e) {}
  }

  // ── Sites tab ──────────────────────────────────────────────────────────
  var siteHostsPopulated = false;

  async function loadSites() {
    var select = document.getElementById("siteHostSelect");
    if (!siteHostsPopulated) {
      siteHostsPopulated = true; // set before the await so a fast second call can't double-populate
      try {
        var hosts = await api("/api/hosts");
        hosts.forEach(function (h) {
          var opt = document.createElement("option");
          opt.value = h; opt.textContent = h;
          select.appendChild(opt);
        });
      } catch (e) {}
    }

    var host = select.value;
    var hq = host ? "&host=" + encodeURIComponent(host) : "";

    try {
      var s = await api("/api/stats" + (host ? "?host=" + encodeURIComponent(host) : ""));
      document.getElementById("siteReqMin").textContent = s.requests_per_min.toFixed(1);
      document.getElementById("siteUniqueIps").textContent = fmtNum(s.unique_ips_5m);
      document.getElementById("site24h").textContent = fmtNum(s.requests_24h);
    } catch (e) {}

    try {
      var rt = await api("/api/response-times?hours=24" + hq);
      document.getElementById("siteAvgMs").textContent = fmtMs(rt.avg_ms);
    } catch (e) {}

    try {
      var bot = await api("/api/bot-breakdown?hours=24" + hq);
      document.getElementById("siteBotPct").textContent = bot.bot_pct + "%";
    } catch (e) {}

    try {
      var nvr = await api("/api/new-vs-returning?hours=24" + hq);
      document.getElementById("siteNewIps").textContent = fmtNum(nvr.new_ips);
      document.getElementById("siteReturningIps").textContent = fmtNum(nvr.returning_ips);
    } catch (e) {}

    try {
      var ts = await api("/api/timeseries?minutes=60" + hq);
      renderLineChart(document.getElementById("siteLineChart"), document.getElementById("siteChartTooltip"), ts);
    } catch (e) {}

    try {
      var countries = await api("/api/top-countries?hours=24&limit=10" + hq);
      document.getElementById("siteCountryCount").textContent = countries.length;
      renderBarList(document.getElementById("siteCountryList"), countries.map(function (c) { return { label: countryFlag(c.country) + " " + c.country, value: c.count }; }));
    } catch (e) {}

    try {
      var ips = await api("/api/top-ips?hours=24&limit=10" + hq);
      document.getElementById("siteIpCount").textContent = ips.length;
      renderBarList(document.getElementById("siteIpList"), ips.map(function (i) { return { label: i.ip + " " + countryFlag(i.country) + " " + i.country, value: i.count, raw: i.ip }; }), { clickable: true });
    } catch (e) {}

    try {
      var devices = await api("/api/device-breakdown?hours=24" + hq);
      document.getElementById("siteDeviceCount").textContent = devices.length;
      renderBarList(document.getElementById("siteDeviceList"), devices.map(function (d) { return { label: d.device, value: d.count }; }));
    } catch (e) {}

    try {
      var statuses = await api("/api/status-breakdown?hours=24" + hq);
      var colorFor = { "200-299": "var(--good)", "300-399": "var(--series-1)", "400-499": "var(--warning)", "500-599": "var(--critical)" };
      var el = document.getElementById("siteStatusList");
      if (!statuses.length) { el.innerHTML = '<div class="empty">No data yet</div>'; }
      else {
        var max = Math.max.apply(null, statuses.map(function (s) { return s.count; })) || 1;
        el.innerHTML = statuses.map(function (s) {
          var pct = Math.max(3, Math.round((s.count / max) * 100));
          return '<div class="bar-row"><span class="bar-label">' + s.bucket + '</span>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + (colorFor[s.bucket] || "var(--series-1)") + '"></div></div>' +
            '<span class="bar-value">' + fmtNum(s.count) + "</span></div>";
        }).join("");
      }
    } catch (e) {}
  }
  document.getElementById("siteHostSelect").addEventListener("change", loadSites);

  // ── Trends tab ─────────────────────────────────────────────────────────
  var trendsHostsPopulated = false;

  async function loadTrends() {
    var hostSelect = document.getElementById("trendsHostSelect");
    if (!trendsHostsPopulated) {
      trendsHostsPopulated = true;
      try {
        var hosts = await api("/api/hosts");
        hosts.forEach(function (h) {
          var opt = document.createElement("option");
          opt.value = h; opt.textContent = h;
          hostSelect.appendChild(opt);
        });
      } catch (e) {}
    }

    var host = hostSelect.value;
    var days = document.getElementById("trendsDaysSelect").value;
    var q = "?days=" + days + (host ? "&host=" + encodeURIComponent(host) : "");

    try {
      var rows = await api("/api/trends" + q);
      document.getElementById("trendsDayCount").textContent = rows.length;
      document.getElementById("trendsTotalReq").textContent = fmtNum(rows.reduce(function (a, r) { return a + r.total_requests; }, 0));
      var avg5xx = rows.length ? rows.reduce(function (a, r) { return a + r.status_5xx_count; }, 0) / rows.length : 0;
      document.getElementById("trendsAvg5xx").textContent = avg5xx.toFixed(1);

      var labelOpts = { labelKey: "date", formatLabel: fmtDateOnly };
      renderLineChart(document.getElementById("trendsReqChart"), document.getElementById("trendsReqTooltip"), rows,
        Object.assign({ valueKey: "total_requests" }, labelOpts));
      renderLineChart(document.getElementById("trendsIpsChart"), document.getElementById("trendsIpsTooltip"), rows,
        Object.assign({ valueKey: "unique_ips", unitLabel: "IPs" }, labelOpts));
      renderLineChart(document.getElementById("trendsRtChart"), document.getElementById("trendsRtTooltip"),
        rows.filter(function (r) { return r.p95_response_ms != null; }),
        Object.assign({ valueKey: "p95_response_ms", unitLabel: "ms" }, labelOpts));
      renderLineChart(document.getElementById("trends5xxChart"), document.getElementById("trends5xxTooltip"), rows,
        Object.assign({ valueKey: "status_5xx_count", unitLabel: "errors" }, labelOpts));
    } catch (e) {}
  }
  document.getElementById("trendsHostSelect").addEventListener("change", loadTrends);
  document.getElementById("trendsDaysSelect").addEventListener("change", loadTrends);

  // ── Bandwidth reports tab ──────────────────────────────────────────────
  function bwWindowLabel(report) {
    // Read the stored timestamps so legacy windows keep their original label.
    return report.window_start.slice(0, 16).replace("T", " ") + " → " +
      report.window_end.slice(0, 16).replace("T", " ") + " UTC";
  }

  async function loadBandwidth() {
    try {
      var cur = await api("/api/bandwidth-reports/current");
      document.getElementById("bwWindowState").textContent = cur.active ? "In progress" : "Closed";
      document.getElementById("bwCurrentBytes").textContent = fmtBytes(cur.total_bytes);
      document.getElementById("bwCurrentIps").textContent = fmtNum(cur.unique_ips);
      document.getElementById("bwCurrentReq").textContent = fmtNum(cur.total_requests);
    } catch (e) {}

    try {
      var rows = await api("/api/bandwidth-reports/trend?days=180");
      renderLineChart(document.getElementById("bwTrendChart"), document.getElementById("bwTrendTooltip"), rows,
        { valueKey: "total_bytes", formatValue: fmtBytes, unitLabel: "", labelKey: "date", formatLabel: fmtDateOnly });
    } catch (e) {}

    try {
      renderBWReports(await api("/api/bandwidth-reports?limit=90"));
    } catch (e) {}
  }

  function renderBWReports(reports) {
    var body = document.getElementById("bwReportBody");
    document.getElementById("bwReportCount").textContent = reports.length;
    if (!reports.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">No reports yet — they are built automatically after each 06:00 UTC window closes.</td></tr>';
      return;
    }
    body.innerHTML = reports.map(function (r) {
      return "<tr>" +
        "<td>" + esc(bwWindowLabel(r)) + "</td>" +
        "<td>" + fmtBytes(r.total_bytes) + "</td>" +
        "<td>" + fmtNum(r.total_requests) + "</td>" +
        "<td>" + fmtNum(r.unique_ips) + "</td>" +
        "<td>" + esc(r.top_host || "—") + "</td>" +
        "<td>" + (r.top_country ? countryLabel(r.top_country) : "—") + "</td>" +
        "<td>" + fmtNum(r.status_5xx) + "</td>" +
        '<td><button class="btn btn-sm" data-bw-view="' + esc(r.date) + '" type="button">View</button></td>' +
        "</tr>";
    }).join("");
    body.querySelectorAll("[data-bw-view]").forEach(function (btn) {
      btn.addEventListener("click", function () { showBWDetail(btn.dataset.bwView); });
    });
  }

  async function showBWDetail(date) {
    try {
      var r = await api("/api/bandwidth-reports/" + encodeURIComponent(date));
      var d = r.details || {};
      document.getElementById("bwDetailTitle").textContent = "Report · " + bwWindowLabel(r);
      document.getElementById("bwDetailBytes").textContent = fmtBytes(r.total_bytes);
      document.getElementById("bwDetailReq").textContent = fmtNum(r.total_requests);
      document.getElementById("bwDetailIps").textContent = fmtNum(r.unique_ips);
      var botPct = r.total_requests ? Math.round(100 * r.bot_requests / r.total_requests) : 0;
      document.getElementById("bwDetailBotPct").textContent = botPct + "%";

      renderBarList(document.getElementById("bwDetailHosts"),
        (d.top_hosts || []).map(function (h) { return { label: h.host, value: h.requests }; }));
      renderBarList(document.getElementById("bwDetailHostsBytes"),
        (d.hosts_by_bytes || []).map(function (h) { return { label: h.host, value: h.bytes }; }),
        { formatValue: fmtBytes });
      renderBarList(document.getElementById("bwDetailPaths"),
        (d.top_paths || []).map(function (p) { return { label: p.path, value: p.requests }; }));
      renderBarList(document.getElementById("bwDetailCountries"),
        (d.top_countries || []).map(function (c) { return { label: countryFlag(c.country) + " " + c.country, value: c.requests }; }));
      renderBarList(document.getElementById("bwDetailIpsList"),
        (d.top_ips || []).map(function (i) { return { label: i.ip + " " + countryFlag(i.country) + " " + (i.country || ""), value: i.requests, raw: i.ip }; }),
        { clickable: true });

      var statuses = [
        { bucket: "2xx", count: r.status_2xx }, { bucket: "3xx", count: r.status_3xx },
        { bucket: "4xx", count: r.status_4xx }, { bucket: "5xx", count: r.status_5xx }
      ].filter(function (s) { return s.count > 0; });
      var colorFor = { "2xx": "var(--good)", "3xx": "var(--series-1)", "4xx": "var(--warning)", "5xx": "var(--critical)" };
      var el = document.getElementById("bwDetailStatus");
      if (!statuses.length) { el.innerHTML = '<div class="empty">No data</div>'; }
      else {
        var max = Math.max.apply(null, statuses.map(function (s) { return s.count; })) || 1;
        el.innerHTML = statuses.map(function (s) {
          var pct = Math.max(3, Math.round((s.count / max) * 100));
          return '<div class="bar-row"><span class="bar-label">' + s.bucket + "</span>" +
            '<div class="bar-track"><div class="bar-fill" style="width:' + pct + "%;background:" + (colorFor[s.bucket] || "var(--series-1)") + '"></div></div>' +
            '<span class="bar-value">' + fmtNum(s.count) + "</span></div>";
        }).join("");
      }
      var wrap = document.getElementById("bwDetailWrap");
      wrap.style.display = "";
      wrap.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {}
  }

  document.getElementById("bwDetailClose").addEventListener("click", function () {
    document.getElementById("bwDetailWrap").style.display = "none";
  });
  document.getElementById("bwBuildBtn").addEventListener("click", async function () {
    var btn = this;
    btn.disabled = true;
    try { await api("/api/bandwidth-reports/build", { method: "POST" }); } catch (e) {}
    btn.disabled = false;
    loadBandwidth();
  });

  // ── Alerts tab ───────────────────────────────────────────────────────────
  function renderAlertRows(el, items) {
    if (!items.length) { el.innerHTML = '<div class="empty">No categories</div>'; return; }
    el.innerHTML = items.map(function (s) {
      return '<div class="alert-row">' +
        '<div><div class="alert-row-label">' + esc(s.label) + '</div><div class="alert-row-desc">' + esc(s.description) + '</div></div>' +
        '<label class="toggle-switch"><input type="checkbox" data-alert-key="' + esc(s.key) + '"' + (s.enabled ? ' checked' : '') + (roleAtLeast("administrator") ? '' : ' disabled') + '><span class="toggle-slider"></span></label>' +
        '</div>';
    }).join("");
    el.querySelectorAll("[data-alert-key]").forEach(function (input) {
      input.addEventListener("change", async function () {
        var key = input.dataset.alertKey;
        var enabled = input.checked;
        input.disabled = true;
        try {
          await api("/api/alert-settings/" + encodeURIComponent(key), {
            method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: enabled }),
          });
        } catch (e) {
          input.checked = !enabled; // revert on failure
        } finally {
          input.disabled = false;
        }
      });
    });
  }

  async function loadAlerts() {
    try {
      var settings = await api("/api/alert-settings");
      var standard = settings.filter(function (s) { return ["service_health", "site_5xx_degraded", "cert_expiry", "app_error_bursts", "ddos", "digest", "defacement", "scheduled_report", "egress_anomaly"].indexOf(s.key) !== -1; });
      var additional = settings.filter(function (s) { return ["ssh_auto_ban", "auto_release_blocks"].indexOf(s.key) === -1 && standard.indexOf(s) === -1; });
      renderAlertRows(document.getElementById("alertListStandard"), standard);
      renderAlertRows(document.getElementById("alertListAdditional"), additional);
    } catch (e) {}

    try {
      var wh = await api("/api/alert-webhook");
      var status = document.getElementById("webhookStatus");
      status.textContent = wh.configured ? ("Configured, ends in " + wh.masked) : "Not configured - Discord alerts are disabled.";
    } catch (e) {}

    try {
      var ak = await api("/api/abuseipdb-key");
      var akStatus = document.getElementById("abuseIpdbKeyStatus");
      akStatus.textContent = ak.configured ? ("Configured (" + fmtNum(ak.cache_size) + " IPs cached)") : "Not configured - AbuseIPDB lookups are disabled.";
    } catch (e) {}

    try {
      var rs = await api("/api/report-settings");
      document.getElementById("reportRecipientsInput").value = rs.recipients || "";
      document.getElementById("reportCadenceInput").value = rs.cadence || "off";
      document.getElementById("reportSmtpHostInput").value = rs.smtp_host || "";
      document.getElementById("reportSmtpPortInput").value = rs.smtp_port || "587";
      document.getElementById("reportSmtpUserInput").value = rs.smtp_user || "";
      document.getElementById("reportSmtpFromInput").value = rs.smtp_from || "";
      var rsStatus = document.getElementById("reportSettingsStatus");
      var bits = [];
      bits.push(rs.smtp_password_configured ? "SMTP password set" : "SMTP password not set");
      bits.push(rs.last_sent_at ? ("last sent " + fmtTime(rs.last_sent_at)) : "never sent yet");
      rsStatus.textContent = bits.join(" · ");
    } catch (e) {}
  }

  document.getElementById("saveWebhookBtn").addEventListener("click", async function () {
    var input = document.getElementById("webhookUrlInput");
    var btn = document.getElementById("saveWebhookBtn");
    btn.disabled = true;
    try {
      await api("/api/alert-webhook", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: input.value }),
      });
      input.value = "";
      loadAlerts();
    } catch (e) {
      alert("Failed to save - check the URL and try again.");
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("saveAbuseIpdbKeyBtn").addEventListener("click", async function () {
    var input = document.getElementById("abuseIpdbKeyInput");
    var btn = document.getElementById("saveAbuseIpdbKeyBtn");
    btn.disabled = true;
    try {
      await api("/api/abuseipdb-key", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key: input.value }),
      });
      input.value = "";
      loadAlerts();
    } catch (e) {
      alert("Failed to save.");
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("saveReportSettingsBtn").addEventListener("click", async function () {
    var btn = document.getElementById("saveReportSettingsBtn");
    btn.disabled = true;
    try {
      await api("/api/report-settings", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
          cadence: document.getElementById("reportCadenceInput").value,
          recipients: document.getElementById("reportRecipientsInput").value,
          smtp_host: document.getElementById("reportSmtpHostInput").value,
          smtp_port: document.getElementById("reportSmtpPortInput").value,
          smtp_user: document.getElementById("reportSmtpUserInput").value,
          smtp_password: document.getElementById("reportSmtpPasswordInput").value,
          smtp_from: document.getElementById("reportSmtpFromInput").value,
        }),
      });
      document.getElementById("reportSmtpPasswordInput").value = "";
      loadAlerts();
    } catch (e) {
      alert("Failed to save.");
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("sendTestReportBtn").addEventListener("click", async function () {
    var btn = document.getElementById("sendTestReportBtn");
    btn.disabled = true;
    var originalText = btn.textContent;
    btn.textContent = "Sending…";
    try {
      await api("/api/report/send-test", { method: "POST" });
      alert("Test report sent.");
      loadAlerts();
    } catch (e) {
      alert("Failed to send: " + (e.message || "check SMTP settings"));
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  });

  // ── Users tab (Owner only - server also enforces this on every endpoint) ──
  var ROLE_LABELS = { owner: "Owner", administrator: "Administrator", operator: "Operator", spectator: "Spectator" };

  async function loadUsers() {
    try {
      var rows = await api("/api/users");
      document.getElementById("userCount").textContent = rows.length;
      var el = document.getElementById("userList");
      if (!rows.length) { el.innerHTML = '<div class="empty">No users yet</div>'; return; }
      el.innerHTML = rows.map(function (r) {
        var isOwner = r.role === "owner";
        var roleControl = isOwner
          ? '<span class="mlr-meta">Owner</span>'
          : '<select data-role-select="' + esc(r.username) + '" style="width:150px">' +
              ["administrator", "operator", "spectator"].map(function (rl) {
                return '<option value="' + rl + '"' + (r.role === rl ? " selected" : "") + '>' + ROLE_LABELS[rl] + "</option>";
              }).join("") + "</select>";
        var actions = isOwner ? "" :
          '<button class="btn btn-sm" data-reset-pw="' + esc(r.username) + '">Reset password</button> ' +
          '<button class="btn btn-sm btn-danger" data-delete-user="' + esc(r.username) + '">Delete</button>';
        return '<div class="mini-list-row"><div><div class="mlr-main">' + esc(r.username) + "</div>" +
          '<div class="mlr-meta">created ' + fmtTime(r.created_at) + (r.created_by ? " by " + esc(r.created_by) : "") + "</div></div>" +
          '<div style="display:flex;align-items:center;gap:8px">' + roleControl + " " + actions + "</div></div>";
      }).join("");

      el.querySelectorAll("[data-role-select]").forEach(function (sel) {
        sel.addEventListener("change", async function () {
          sel.disabled = true;
          try {
            await api("/api/users/" + encodeURIComponent(sel.dataset.roleSelect), {
              method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role: sel.value }),
            });
          } catch (e) { alert("Failed: " + e.message); loadUsers(); }
          finally { sel.disabled = false; }
        });
      });
      el.querySelectorAll("[data-reset-pw]").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          var pw = prompt("New password for '" + btn.dataset.resetPw + "' (10+ characters):");
          if (!pw) return;
          btn.disabled = true;
          try {
            await api("/api/users/" + encodeURIComponent(btn.dataset.resetPw), {
              method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: pw }),
            });
            alert("Password reset.");
          } catch (e) { alert("Failed: " + e.message); }
          finally { btn.disabled = false; }
        });
      });
      el.querySelectorAll("[data-delete-user]").forEach(function (btn) {
        btn.addEventListener("click", async function () {
          var username = btn.dataset.deleteUser;
          if (!confirm("Delete user '" + username + "'? This immediately ends any session they have open.")) return;
          btn.disabled = true;
          try {
            await api("/api/users/" + encodeURIComponent(username), { method: "DELETE" });
            loadUsers();
          } catch (e) { alert("Failed: " + e.message); btn.disabled = false; }
        });
      });
    } catch (e) {}
  }

  document.getElementById("addUserBtn").addEventListener("click", async function () {
    var username = document.getElementById("newUserUsername").value.trim();
    var password = document.getElementById("newUserPassword").value;
    var role = document.getElementById("newUserRole").value;
    if (!username || !password) { alert("Enter a username and password"); return; }
    var btn = this;
    btn.disabled = true;
    try {
      await api("/api/users", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username, password: password, role: role }),
      });
      document.getElementById("newUserUsername").value = "";
      document.getElementById("newUserPassword").value = "";
      loadUsers();
    } catch (e) { alert("Failed: " + e.message); }
    finally { btn.disabled = false; }
  });

  // ── Community Edition tab (Owner only) ───────────────────────────────────
  async function loadLicense() {
    var el = document.getElementById("licenseStatus");
    try {
      await api("/api/license");
      var rows = [
        ['Edition', '<span class="status-pill status-2xx">Community Edition</span>'],
        ['Activation', 'Not required'],
        ['Features', 'All on-host monitoring and response features enabled'],
        ['Telemetry', 'No entitlement or activation check-ins'],
      ];
      el.innerHTML = rows.map(function (r) {
        return '<div class="mini-list-row"><div class="mlr-main" style="font-weight:600;font-size:0.82rem">' + r[0] + '</div><div>' + r[1] + '</div></div>';
      }).join("");
    } catch (e) {
      el.innerHTML = '<div class="empty">Failed to load edition status</div>';
    }
  }

  // ── Fleet tab (Owner only) ───────────────────────────────────────────────
  async function loadFleet() {
    var tbody = document.getElementById("fleetTableBody");
    try {
      var res = await api("/api/fleet");
      var fleet = res.fleet || [];
      document.getElementById("fleetCount").textContent = fleet.length;
      if (!fleet.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">No fleet data yet</td></tr>';
        return;
      }
      tbody.innerHTML = fleet.map(function (f) {
        var licBadge = (f.license_status === "active" || f.license_status === "community")
          ? '<span class="status-pill status-2xx">' + (f.license_status === "community" ? "Community" : "Active") + '</span>'
          : '<span class="status-pill status-5xx">' + esc(f.license_status) + '</span>';
        var s = f.stats || {};
        var degraded = (s.degraded_services && s.degraded_services.length) ? esc(s.degraded_services.join(", ")) : "—";
        return "<tr>" +
          "<td>" + esc(f.hostname || f.install_id) + "</td>" +
          "<td>" + licBadge + " <span class=\"mono\">…" + esc(f.license_key_suffix) + "</span></td>" +
          "<td class=\"mono\">" + fmtTime(f.last_seen_at) + "</td>" +
          "<td>" + (s.requests_per_hour != null ? fmtNum(s.requests_per_hour) : "—") + "</td>" +
          "<td>" + (s.flagged_active != null ? s.flagged_active : "—") + "</td>" +
          "<td>" + (s.blocked_count != null ? s.blocked_count : "—") + "</td>" +
          "<td>" + degraded + "</td>" +
          "<td>" + esc(s.version || "—") + "</td>" +
          "</tr>";
      }).join("");

      // Cross-reference each install's top_flagged_ips - an IP seen on 2+
      // installs is a real cross-property pattern, not one box's fluke.
      var seenBy = {}; // ip -> [{hostname, score, country}, ...]
      fleet.forEach(function (f) {
        var ips = (f.stats && f.stats.top_flagged_ips) || [];
        ips.forEach(function (entry) {
          (seenBy[entry.ip] = seenBy[entry.ip] || []).push({
            hostname: f.hostname || f.install_id, score: entry.score, country: entry.country,
          });
        });
      });
      var crossFleet = Object.keys(seenBy)
        .map(function (ip) { return { ip: ip, hits: seenBy[ip] }; })
        .filter(function (r) { return r.hits.length >= 2; })
        .sort(function (a, b) { return b.hits.length - a.hits.length; });

      document.getElementById("fleetCrossCount").textContent = crossFleet.length;
      var crossEl = document.getElementById("fleetCrossList");
      crossEl.innerHTML = crossFleet.length ? crossFleet.map(function (r) {
        var country = r.hits[0].country ? countryFlag(r.hits[0].country) + " " + r.hits[0].country : "";
        var boxes = r.hits.map(function (h) { return esc(h.hostname) + " (score " + h.score + ")"; }).join(", ");
        return '<div class="mini-req" style="cursor:pointer" data-ip="' + esc(r.ip) + '">' +
          '<span class="p1">' + esc(r.ip) + ' ' + country + ' — seen on ' + r.hits.length + ' installs</span>' +
          '<div class="p2">' + boxes + '</div></div>';
      }).join("") : '<div class="empty">No IPs currently flagged on more than one install</div>';
      crossEl.querySelectorAll("[data-ip]").forEach(function (node) {
        node.addEventListener("click", function () { openDrawer(node.dataset.ip); });
      });
    } catch (e) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">Failed to load fleet data</td></tr>';
    }
  }

  // ── Infrastructure tab ───────────────────────────────────────────────────
  var CERT_TIER_CLASS = function (days) {
    if (days <= 3) return "status-5xx"; if (days <= 21) return "status-4xx"; return "status-2xx";
  };

  async function loadInfra() {
    try {
      var vol = await api("/api/volumetric-status");
      var trafficLabel = vol.in_ddos ? "Possible DDoS" : (vol.in_spike ? "Spike" : "Normal");
      var trafficColor = vol.in_ddos ? "var(--critical)" : (vol.in_spike ? "var(--warning)" : "var(--good)");
      document.getElementById("infraTrafficStatus").textContent = trafficLabel;
      document.getElementById("infraTrafficStatus").style.color = trafficColor;
    } catch (e) {}

    try {
      var certs = await api("/api/cert-status");
      document.getElementById("certCount").textContent = certs.length;
      var le = certs.filter(function (c) { return c.managed_by === "letsencrypt"; });
      var soonest = le.length ? le.reduce(function (a, b) { return a.days_left < b.days_left ? a : b; }) : null;
      document.getElementById("infraCertSoonest").textContent = soonest ? soonest.days_left + "d" : "—";
      var sorted = certs.slice().sort(function (a, b) { return a.days_left - b.days_left; });
      var tbody = document.getElementById("certTableBody");
      tbody.innerHTML = sorted.length ? sorted.map(function (c) {
        return "<tr><td>" + esc(c.domain) + "</td><td>" + esc(c.managed_by) + "</td>" +
          "<td class=\"mono\">" + fmtTime(c.expires_at) + "</td>" +
          "<td><span class=\"status-pill " + (c.managed_by === "letsencrypt" ? CERT_TIER_CLASS(c.days_left) : "status-2xx") + "\">" + c.days_left + "d</span></td></tr>";
      }).join("") : '<tr><td colspan="4" class="empty">No certs found</td></tr>';
    } catch (e) {}

    try {
      var events = await api("/api/integrity-events?limit=30");
      document.getElementById("integrityCount").textContent = events.length;
      var el = document.getElementById("integrityList");
      el.innerHTML = events.length ? events.map(function (r) {
        return '<div class="audit-row"><span class="audit-action audit-block">' + esc(r.change_type) + "</span>" +
          '<span class="audit-target">' + esc(r.path) + "</span>" +
          '<span class="audit-reason"></span><span class="audit-meta">' + fmtTime(r.ts) + "</span></div>";
      }).join("") : '<div class="empty">No changes detected</div>';
    } catch (e) {}

    try {
      var defEvents = await api("/api/defacement-events?limit=30");
      document.getElementById("defacementCount").textContent = defEvents.length;
      var defEl = document.getElementById("defacementList");
      defEl.innerHTML = defEvents.length ? defEvents.map(function (r) {
        return '<div class="audit-row"><span class="audit-action audit-block">' + esc(r.change_type) + "</span>" +
          '<span class="audit-target">' + esc(r.path) + "</span>" +
          '<span class="audit-reason"></span><span class="audit-meta">' + fmtTime(r.ts) + "</span></div>";
      }).join("") : '<div class="empty">No changes detected</div>';
    } catch (e) {}

    try {
      var res = await api("/api/resource-current");
      document.getElementById("resourceCount").textContent = res.length;
      var tbody2 = document.getElementById("resourceTableBody");
      tbody2.innerHTML = res.length ? res.map(function (r) {
        return "<tr><td>" + esc(r.unit) + "</td><td class=\"mono\">" + fmtBytes(r.memory_bytes) + "</td>" +
          "<td class=\"mono\">" + fmtBytes(r.memory_peak_24h || r.memory_bytes) + "</td>" +
          "<td class=\"mono\">" + (r.cpu_percent != null ? r.cpu_percent + "%" : "—") + "</td></tr>";
      }).join("") : '<tr><td colspan="4" class="empty">No samples yet</td></tr>';
    } catch (e) {}

    try {
      var logs = await api("/api/app-log-events?limit=50");
      document.getElementById("appLogCount").textContent = logs.length;
      var since24h = Date.now() - 24 * 3600 * 1000;
      var errCount24h = logs.filter(function (l) { return new Date(l.ts).getTime() >= since24h; }).length;
      document.getElementById("infraErrorCount24h").textContent = errCount24h;
      var el2 = document.getElementById("appLogList");
      el2.innerHTML = logs.length ? logs.map(function (r) {
        return '<div class="mini-req"><span class="p1">[' + esc(r.unit) + '] ' + esc(r.message.slice(0, 200)) + '</span>' +
          '<div class="p2">' + fmtTime(r.ts) + " · " + esc(r.level) + "</div></div>";
      }).join("") : '<div class="empty">No errors recorded</div>';

      var badge = document.getElementById("infraBadge");
      if (errCount24h > 0) { badge.style.display = "inline-block"; badge.textContent = errCount24h; }
      else badge.style.display = "none";
    } catch (e) {}

    try {
      var egressEvents = await api("/api/egress-events?limit=50");
      document.getElementById("egressCount").textContent = egressEvents.length;
      var egressEl = document.getElementById("egressList");
      egressEl.innerHTML = egressEvents.length ? egressEvents.map(function (r) {
        return '<div class="mini-req"><span class="p1">' + esc(r.process) + " -&gt; " + esc(r.remote_ip) + ":" + r.remote_port + "</span>" +
          '<div class="p2">' + fmtTime(r.ts) + "</div></div>";
      }).join("") : '<div class="empty">No unexpected connections detected</div>';
    } catch (e) {}
  }

  async function loadWatchdog() {
    try {
      var threads = await api("/api/watchdog-status");
      var rows = threads.threads;
      document.getElementById("watchdogCount").textContent = rows.length;
      var aliveCount = rows.filter(function (r) { return r.alive; }).length;
      var totalRestarts = rows.reduce(function (sum, r) { return sum + r.restart_count; }, 0);
      document.getElementById("watchdogAliveCount").textContent = aliveCount + " / " + rows.length;
      document.getElementById("watchdogRestartCount").textContent = totalRestarts;

      var tbody = document.getElementById("watchdogTableBody");
      tbody.innerHTML = rows.length ? rows.map(function (r) {
        return "<tr><td>" + esc(r.name) + "</td>" +
          "<td><span class=\"status-pill " + (r.alive ? "status-2xx" : "status-5xx") + "\">" + (r.alive ? "Alive" : "Dead") + "</span></td>" +
          "<td class=\"mono\">" + r.restart_count + "</td>" +
          "<td class=\"mono\">" + (r.last_restart_at ? fmtTime(r.last_restart_at) : "—") + "</td></tr>";
      }).join("") : '<tr><td colspan="4" class="empty">No threads registered</td></tr>';

      var badge = document.getElementById("watchdogBadge");
      var deadCount = rows.length - aliveCount;
      if (deadCount > 0) { badge.style.display = "inline-block"; badge.textContent = deadCount; }
      else badge.style.display = "none";
    } catch (e) {}
  }

  // ── IP detail drawer ───────────────────────────────────────────────────
  var drawer = document.getElementById("drawer");
  var drawerBackdrop = document.getElementById("drawerBackdrop");

  async function openDrawer(ip) {
    drawer.classList.add("open"); drawerBackdrop.classList.add("open");
    document.getElementById("drawerIp").textContent = ip;
    document.getElementById("drawerMeta").textContent = "Loading…";
    document.getElementById("drawerSignalsSection").style.display = "none";
    document.getElementById("drawerThreatSection").style.display = "none";
    document.getElementById("drawerHosts").innerHTML = "";
    document.getElementById("drawerRequests").innerHTML = "";
    document.getElementById("drawerBlockAction").innerHTML = "";
    try {
      var d = await api("/api/ip/" + encodeURIComponent(ip));
      document.getElementById("drawerMeta").textContent =
        d.allowed ? "Allowlisted · " + (d.allowed.reason || "no reason given") :
        d.blocked ? "Blocked · " + (d.blocked.reason || "no reason given") + " · " + fmtExpiry(d.blocked.expires_at) :
        (d.flagged ? "Flagged · score " + d.flagged.score : "No signals");

      var actionEl = document.getElementById("drawerBlockAction");
      if (!roleAtLeast("operator")) {
        actionEl.innerHTML = "";
      } else if (d.blocked) {
        actionEl.innerHTML = '<button class="btn btn-sm" style="margin-top:10px" data-unblock="' + esc(ip) + '">Unblock</button>';
      } else {
        actionEl.innerHTML = '<button class="btn btn-sm btn-danger" style="margin-top:10px" data-open-block="' + esc(ip) + '">Block this IP</button>';
      }
      wireBlockButtons(actionEl);
      actionEl.querySelectorAll("[data-unblock]").forEach(function (b) {
        b.addEventListener("click", function () { setTimeout(function () { openDrawer(ip); }, 400); });
      });
      actionEl.querySelectorAll("[data-open-block]").forEach(function (b) {
        b.addEventListener("click", function () { /* modal handles its own refresh; drawer catches up on close */ setTimeout(function () { openDrawer(ip); }, 600); });
      });

      if (d.flagged) {
        document.getElementById("drawerSignalsSection").style.display = "block";
        document.getElementById("drawerSignals").innerHTML = d.flagged.signals.map(signalBadge).join("");
      }

      var threatBadges = [];
      if (d.is_tor_exit) threatBadges.push('<span class="signal-badge sig-sev-1" title="Known TOR exit node">TOR exit</span>');
      if (d.datacenter_provider) threatBadges.push('<span class="signal-badge sig-sev-1" title="In ' + esc(d.datacenter_provider) + '\'s published ranges">' + esc(d.datacenter_provider) + "</span>");
      if (threatBadges.length) {
        document.getElementById("drawerThreatSection").style.display = "block";
        document.getElementById("drawerThreat").innerHTML = threatBadges.join("");
      }

      document.getElementById("drawerHosts").innerHTML = d.hosts_hit.map(function (h) {
        return '<div class="mini-req"><span class="p1">' + esc(h.host) + '</span> <span class="p2">' + h.count + " requests</span></div>";
      }).join("") || '<div class="empty">—</div>';

      document.getElementById("drawerRequests").innerHTML = d.recent_requests.map(function (r) {
        return '<div class="mini-req"><span class="p1">' + esc(r.method) + " " + esc(r.path) + '</span>' +
          '<div class="p2">' + fmtTime(r.ts) + " · " + esc(r.host) + " · " + r.status + "</div></div>";
      }).join("") || '<div class="empty">No recent requests</div>';
    } catch (e) {
      document.getElementById("drawerMeta").textContent = "Failed to load";
    }
  }
  document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  drawerBackdrop.addEventListener("click", closeDrawer);
  function closeDrawer() { drawer.classList.remove("open"); drawerBackdrop.classList.remove("open"); }

  // ── Polling ────────────────────────────────────────────────────────────
  // Role is loaded first (and applyRolePermissions() run) so the very first
  // render pass already knows what to show/hide - otherwise every action
  // button would briefly flash hidden until the next poll corrected it.
  loadAccount().then(function () {
    loadOverview();
    loadAnalytics();
    loadFeed();
    loadSecurity();
    loadInfra();
    loadAlerts();
    loadSites();
    loadTrends();
    loadBandwidth();
    if (roleAtLeast("owner")) loadWatchdog();
  });
  setInterval(function () {
    if (document.getElementById("tab-sites").classList.contains("active")) loadSites();
  }, 15000);

  setInterval(function () {
    if (document.getElementById("tab-bandwidth").classList.contains("active")) loadBandwidth();
  }, 60000);
  setInterval(loadAccount, 15000);
  setInterval(function () {
    if (document.getElementById("tab-users").classList.contains("active")) loadUsers();
  }, 15000);
  setInterval(function () {
    if (document.getElementById("tab-license").classList.contains("active")) loadLicense();
  }, 20000);
  setInterval(function () {
    if (document.getElementById("tab-fleet").classList.contains("active")) loadFleet();
  }, 20000);
  setInterval(function () {
    if (document.getElementById("tab-watchdog").classList.contains("active")) loadWatchdog();
  }, 20000);
  setInterval(function () {
    if (document.getElementById("tab-overview").classList.contains("active")) loadOverview();
  }, 10000);
  setInterval(function () {
    if (document.getElementById("tab-analytics").classList.contains("active")) loadAnalytics();
  }, 15000);
  setInterval(function () {
    if (document.getElementById("tab-live").classList.contains("active") && document.getElementById("autoRefresh").checked && feedOffset === 0) loadFeed();
  }, 5000);
  var SECURITY_GROUP_TABS = ["security", "allowlist", "ssh", "countries", "audit"];
  setInterval(function () {
    if (SECURITY_GROUP_TABS.some(function (t) { return document.getElementById("tab-" + t).classList.contains("active"); })) loadSecurity();
  }, 10000);
  setInterval(function () {
    if (document.getElementById("tab-infra").classList.contains("active")) loadInfra();
  }, 20000);
  setInterval(function () {
    if (document.getElementById("tab-alerts").classList.contains("active")) loadAlerts();
  }, 20000);
  // Stat tiles + flagged badge stay fresh regardless of active tab.
  setInterval(async function () {
    try {
      var s = await api("/api/stats");
      document.getElementById("stReqMin").textContent = s.requests_per_min.toFixed(1);
      document.getElementById("stUniqueIps").textContent = fmtNum(s.unique_ips_5m);
      document.getElementById("st24h").textContent = fmtNum(s.requests_24h);
      document.getElementById("stFlagged").textContent = fmtNum(s.flagged_active);
      document.getElementById("stBlocked").textContent = fmtNum(s.blocked_count);
      var badge = document.getElementById("flaggedBadge");
      if (s.flagged_active > 0) { badge.style.display = "inline-block"; badge.textContent = s.flagged_active; }
      else badge.style.display = "none";
    } catch (e) {}
  }, 8000);
})();
