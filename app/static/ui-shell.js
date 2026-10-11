(function () {
  "use strict";

  var pages = {
    overview: ["Overview", "Live traffic, risk signals, and service health at a glance."],
    incidents: ["Incidents", "Correlated security and infrastructure cases ready for triage."],
    search: ["Global Search", "Find evidence across requests, threats, audits, and cases."],
    analytics: ["Analytics", "Performance, bandwidth, audiences, and traffic quality."],
    sites: ["Sites", "Inspect traffic and performance for an individual property."],
    trends: ["Trends", "Long-range traffic, reliability, and audience history."],
    bandwidth: ["Bandwidth", "Daily bandwidth and traffic reports for each 06:00–06:00 UTC window."],
    live: ["Live Feed", "Inspect requests as they arrive across protected properties."],
    security: ["Security", "Triage flagged sources and manage active network blocks."],
    policies: ["Response Policies", "Preview and automate high-confidence network response."],
    allowlist: ["Allowlist", "Manage trusted addresses excluded from automated scoring."],
    ssh: ["SSH Activity", "Review authentication activity and firewall-level bans."],
    countries: ["Blocked Countries", "Control country-level traffic restrictions."],
    audit: ["Audit Log", "Trace operator and automated security actions."],
    infra: ["Infrastructure", "Monitor certificates, services, integrity, and outbound activity."],
    watchdog: ["Watchdog", "Verify background monitors and automatic recovery state."],
    integrations: ["Integrations", "Connect alerts to collaboration, on-call, and SIEM systems."],
    setup: ["Setup & Health", "Secure your account and verify installation readiness."],
    alerts: ["Alerts", "Configure delivery channels, reports, and notification policies."],
    users: ["Users", "Manage console access and role-based permissions."],
    license: ["Edition", "Review Community Edition status and local feature availability."],
    fleet: ["Fleet", "See health and correlated threats across every installation."]
  };

  var sidebar = document.getElementById("sidebar");
  var navToggle = document.getElementById("navToggle");
  var sidebarBackdrop = document.getElementById("sidebarBackdrop");
  var themeToggle = document.getElementById("themeToggle");
  var title = document.getElementById("pageTitle");
  var description = document.getElementById("pageDescription");

  function closeNavigation() {
    document.body.classList.remove("nav-open");
    if (navToggle) navToggle.setAttribute("aria-expanded", "false");
  }

  function openNavigation() {
    document.body.classList.add("nav-open");
    if (navToggle) navToggle.setAttribute("aria-expanded", "true");
  }

  function updatePage(tab) {
    var key = tab.dataset.tab;
    var copy = pages[key] || [tab.textContent.trim(), "SentryNet security operations console."];
    title.textContent = copy[0];
    description.textContent = copy[1];
    document.title = copy[0] + " — SentryNet";
    document.querySelectorAll(".tab").forEach(function (item) {
      if (item === tab) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    document.querySelectorAll(".tab").forEach(function (item) { item.classList.toggle("active", item === tab); });
    document.querySelectorAll(".tab-content").forEach(function (panel) {
      panel.classList.toggle("active", panel.id === "tab-" + key);
    });
    if (history.replaceState) history.replaceState(null, "", "#" + key);
    closeNavigation();
  }

  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () { updatePage(tab); });
  });

  if (navToggle) {
    navToggle.addEventListener("click", function () {
      if (document.body.classList.contains("nav-open")) closeNavigation();
      else openNavigation();
    });
  }
  if (sidebarBackdrop) sidebarBackdrop.addEventListener("click", closeNavigation);

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    if (themeToggle) {
      var next = theme === "light" ? "dark" : "light";
      themeToggle.setAttribute("aria-label", "Switch to " + next + " theme");
      themeToggle.setAttribute("title", "Switch to " + next + " theme");
      themeToggle.textContent = theme === "light" ? "☾" : "☼";
    }
  }

  var initialTheme = document.documentElement.dataset.theme;
  if (initialTheme !== "light" && initialTheme !== "dark") {
    initialTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  applyTheme(initialTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      applyTheme(next);
      try { localStorage.setItem("sentrynet-theme", next); } catch (e) {}
    });
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeNavigation();
  });

  var requested = /^[a-z]+$/.test(location.hash.slice(1)) ? location.hash.slice(1) : "";
  var initialTab = document.querySelector('.tab[data-tab="' + requested + '"]') || document.querySelector(".tab.active");
  if (initialTab) {
    if (requested) initialTab.click();
    else updatePage(initialTab);
  }
})();
