#!/usr/bin/env python3
"""Keyboard-first SentryNet operations console for Debian and Ubuntu."""

from __future__ import annotations

import argparse
import curses
import getpass
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


VIEWS = (
    "Overview", "Threats", "Blocked", "SSH", "Incidents", "Sites",
    "Trends", "Audit", "Alerts", "Users", "Services", "Edition",
)
TREND_WINDOWS = (7, 30, 90, 180, 365)
ROLE_LEVEL = {"spectator": 0, "operator": 1, "administrator": 2, "owner": 3}


class ApiError(RuntimeError):
    """A safe, user-facing API error."""


class SentryNetApi:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ApiError("server must be an http(s) URL without embedded credentials")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ApiError("server URL must not contain a path, query, or fragment")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _csrf_token(self) -> str | None:
        for cookie in self.jar:
            if cookie.name == "sentrynet_csrf":
                return cookie.value
        return None

    def request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
        body = None
        headers = {"Accept": "application/json", "User-Agent": "SentryNet-Terminal/1.5"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if method != "GET":
            csrf = self._csrf_token()
            if csrf:
                headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = json.loads(raw.decode("utf-8"))
                detail = parsed.get("detail") or parsed.get("error") or f"HTTP {exc.code}"
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                detail = f"HTTP {exc.code}"
            raise ApiError(str(detail)) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ApiError(f"cannot reach {self.base_url}: {reason}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError("server returned an unexpected response") from exc

    def login(self, username: str, password: str, totp_code: str | None = None) -> None:
        try:
            self.request("/login", "POST", {"username": username, "password": password, "totp_code": totp_code})
        except ApiError as exc:
            if "Authenticator code required" not in str(exc):
                raise
            code = getpass.getpass("Authenticator code: ").strip()
            if not code:
                raise ApiError("authenticator code is required")
            self.request("/login", "POST", {"username": username, "password": password, "totp_code": code})


def compact_number(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "—"
    if number >= 1_000_000:
        return f"{number / 1_000_000:.1f}m"
    if number >= 1_000:
        return f"{number / 1_000:.1f}k"
    return f"{number:.1f}" if number % 1 else str(int(number))


def bytes_label(value: Any) -> str:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return "—"
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if number < 1024 or suffix == "TB":
            return f"{number:.1f} {suffix}"
        number /= 1024
    return "—"


def short(value: Any, width: int) -> str:
    text = str(value if value not in (None, "") else "—").replace("\n", " ")
    if width <= 1:
        return text[: max(0, width)]
    return text if len(text) <= width else text[: width - 1] + "…"


def date_short(value: Any) -> str:
    text = str(value or "—")
    return text[:16].replace("T", " ")


def sparkline(values: list[float], width: int) -> str:
    if not values or width < 1:
        return ""
    blocks = "▁▂▃▄▅▆▇█"
    values = values[-width:]
    low, high = min(values), max(values)
    if high == low:
        return blocks[3] * len(values)
    return "".join(blocks[min(7, int((value - low) * 7 / (high - low)))] for value in values)


class TerminalApp:
    def __init__(self, api: SentryNetApi, account: dict[str, Any], version: str) -> None:
        self.api = api
        self.account = account
        self.version = version
        self.view = 0
        self.selected = {name: 0 for name in VIEWS}
        self.data: dict[str, Any] = {}
        self.error = ""
        self.message = ""
        self.updated = 0.0
        self.trend_days = 30

    @property
    def name(self) -> str:
        return VIEWS[self.view]

    @property
    def role(self) -> str:
        return str(self.account.get("role") or "spectator")

    def permitted(self, minimum: str) -> bool:
        return ROLE_LEVEL.get(self.role, 0) >= ROLE_LEVEL[minimum]

    def items(self) -> list[dict[str, Any]]:
        value = self.data.get("items", [])
        return value if isinstance(value, list) else []

    def clamp_selection(self) -> None:
        items = self.items()
        self.selected[self.name] = min(self.selected[self.name], max(0, len(items) - 1))

    def refresh(self) -> None:
        try:
            name = self.name
            if name == "Overview":
                self.data = {"stats": self.api.request("/api/stats"), "hosts": self.api.request("/api/top-hosts")}
            elif name == "Threats":
                self.data = {"items": self.api.request("/api/flagged?limit=200")}
            elif name == "Blocked":
                self.data = {"items": self.api.request("/api/blocked")}
            elif name == "SSH":
                self.data = {
                    "items": self.api.request("/api/ssh-banned"),
                    "events": self.api.request("/api/ssh-events?limit=100"),
                }
            elif name == "Incidents":
                self.data = {"items": self.api.request("/api/incidents?limit=200")}
            elif name == "Sites":
                sites = self.api.request("/api/top-hosts?hours=168&limit=50")
                self.data = {"items": sites}
                self._load_site_detail()
            elif name == "Trends":
                self.data = {"items": self.api.request(f"/api/trends?days={self.trend_days}")}
            elif name == "Audit":
                self.data = {"items": self.api.request("/api/audit-log?limit=200")}
            elif name == "Alerts":
                self.data = {
                    "items": self.api.request("/api/alert-settings"),
                    "webhook": self.api.request("/api/alert-webhook"),
                }
            elif name == "Users":
                self.data = {"items": self.api.request("/api/users")}
            elif name == "Services":
                self.data = {"items": self.api.request("/api/resource-current")}
            else:
                self.data = {"license": self.api.request("/api/license"), "items": []}
            self.error = ""
            self.updated = time.time()
            self.clamp_selection()
        except ApiError as exc:
            self.data = {"items": []}
            self.error = str(exc)
            self.updated = time.time()

    def _load_site_detail(self) -> None:
        sites = self.data.get("items", [])
        if not sites:
            return
        index = min(self.selected["Sites"], len(sites) - 1)
        host = str(sites[index].get("host") or "")
        query = urllib.parse.urlencode({"host": host})
        self.data["site_host"] = host
        self.data["site_stats"] = self.api.request("/api/stats?" + query)
        self.data["site_countries"] = self.api.request("/api/top-countries?hours=24&limit=5&" + query)

    @staticmethod
    def put(window: Any, y: int, x: int, text: Any, attr: int = 0) -> None:
        height, width = window.getmaxyx()
        if y < 0 or y >= height or x < 0 or x >= width:
            return
        try:
            window.addnstr(y, x, str(text), max(0, width - x - 1), attr)
        except curses.error:
            pass

    def prompt(self, window: Any, label: str, *, secret: bool = False, default: str = "") -> str | None:
        height, width = window.getmaxyx()
        hint = f" [{default}]" if default else ""
        prefix = f" {label}{hint}: "
        window.timeout(-1)
        try:
            curses.curs_set(1)
            curses.noecho() if secret else curses.echo()
            window.move(height - 2, 0)
            window.clrtoeol()
            self.put(window, height - 2, 0, prefix, curses.A_BOLD | curses.color_pair(3))
            raw = window.getstr(height - 2, min(len(prefix), width - 2), max(1, width - len(prefix) - 2))
            value = raw.decode("utf-8", "replace").strip()
            return value or default
        except (curses.error, KeyboardInterrupt):
            return None
        finally:
            curses.noecho()
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            window.timeout(1000)

    def confirm(self, window: Any, question: str) -> bool:
        answer = self.prompt(window, question + " [y/N]")
        return bool(answer and answer.lower() in {"y", "yes"})

    def box(self, window: Any, y: int, x: int, width: int, label: str, value: str, color: int = 0) -> None:
        if width < 8:
            return
        self.put(window, y, x, "┌" + "─" * (width - 2) + "┐", curses.color_pair(4))
        self.put(window, y + 1, x, "│" + " " * (width - 2) + "│", curses.color_pair(4))
        self.put(window, y + 2, x, "│" + " " * (width - 2) + "│", curses.color_pair(4))
        self.put(window, y + 3, x, "└" + "─" * (width - 2) + "┘", curses.color_pair(4))
        self.put(window, y + 1, x + 2, short(label.upper(), width - 4), curses.color_pair(3))
        self.put(window, y + 2, x + 2, short(value, width - 4), curses.A_BOLD | color)

    def draw_header(self, window: Any) -> int:
        height, width = window.getmaxyx()
        self.put(window, 0, 0, " SENTRYNET ", curses.A_BOLD | curses.color_pair(1))
        self.put(window, 0, 12, f"SECURITY OPERATIONS · {self.account.get('username')} / {self.role}", curses.A_BOLD)
        right = f"● CONNECTED  v{self.version} "
        self.put(window, 0, max(0, width - len(right)), right, curses.color_pair(2))
        self.put(window, 1, 0, "─" * max(0, width - 1), curses.color_pair(4))
        previous = VIEWS[(self.view - 1) % len(VIEWS)]
        following = VIEWS[(self.view + 1) % len(VIEWS)]
        nav = f"  ← {previous.upper()}   [ {self.view + 1:02d}/{len(VIEWS):02d}  {self.name.upper()} ]   {following.upper()} →"
        self.put(window, 2, 0, short(nav, width - 1), curses.A_BOLD | curses.color_pair(3))
        self.put(window, 3, 0, "─" * max(0, width - 1), curses.color_pair(4))
        if height < 16 or width < 56:
            self.put(window, 5, 2, "Terminal too small — use at least 56 × 16.", curses.color_pair(5))
            return height
        return 5

    def draw_overview(self, window: Any, top: int) -> None:
        _, width = window.getmaxyx()
        stats = self.data.get("stats", {})
        cards = (
            ("Requests / min", compact_number(stats.get("requests_per_min"))),
            ("Unique IPs · 5m", compact_number(stats.get("unique_ips_5m"))),
            ("Flagged active", compact_number(stats.get("flagged_active"))),
            ("Blocked", compact_number(stats.get("blocked_count"))),
        )
        card_width = max(11, (width - 6) // 4)
        for index, (label, value) in enumerate(cards):
            self.box(window, top, 1 + index * (card_width + 1), card_width, label, value, curses.color_pair(1 if index == 0 else 0))
        y = top + 5
        self.put(window, y, 2, "TOP SITES · LAST 24 HOURS", curses.A_BOLD | curses.color_pair(3))
        y += 2
        hosts = self.data.get("hosts", [])
        if not hosts:
            self.put(window, y, 2, "No traffic data yet.", curses.color_pair(3))
            return
        maximum = max((float(item.get("count", 0) or 0) for item in hosts[:8]), default=1)
        for item in hosts[:8]:
            label = short(item.get("host"), min(30, max(12, width // 3)))
            value = float(item.get("count", 0) or 0)
            bar_width = max(5, width - len(label) - 17)
            fill = int(bar_width * value / maximum) if maximum else 0
            self.put(window, y, 2, label, curses.A_BOLD)
            self.put(window, y, 4 + len(label), "█" * fill + "░" * (bar_width - fill), curses.color_pair(1))
            self.put(window, y, width - 10, compact_number(value).rjust(8), curses.color_pair(3))
            y += 1

    def draw_table(self, window: Any, top: int, headers: tuple[str, ...], widths: tuple[int, ...],
                   rows: list[tuple[Any, ...]], selectable: bool = True) -> None:
        height, width = window.getmaxyx()
        if not rows:
            self.put(window, top, 2, f"No {self.name.lower()} data available.", curses.color_pair(3))
            return
        usable = max(20, width - 4)
        sizes = list(widths)
        if sizes and sizes[-1] <= 0:
            sizes[-1] = max(10, usable - sum(sizes[:-1]))
        positions = [2]
        for size in sizes[:-1]:
            positions.append(positions[-1] + size)
        for x, header in zip(positions, headers):
            self.put(window, top, x, header, curses.A_BOLD | curses.color_pair(3))
        self.put(window, top + 1, 1, "─" * max(0, width - 2), curses.color_pair(4))
        visible = max(1, height - top - 4)
        selected = self.selected[self.name] if selectable else 0
        start = max(0, min(selected - visible + 1, max(0, len(rows) - visible))) if selectable else 0
        for offset, row in enumerate(rows[start:start + visible]):
            index = start + offset
            y = top + 2 + offset
            active = selectable and index == selected
            attr = curses.A_BOLD | curses.color_pair(1) if active else 0
            if active:
                self.put(window, y, 1, " " * max(0, width - 2), attr)
            for x, size, value in zip(positions, sizes, row):
                self.put(window, y, x, short(value, size - 2), attr)
        if len(rows) > visible:
            self.put(window, top, max(2, width - 18), f"{selected + 1}/{len(rows)}", curses.color_pair(3))

    def draw_rows(self, window: Any, top: int) -> None:
        name, items = self.name, self.items()
        if name == "Threats":
            rows = [(x.get("ip"), x.get("country"), x.get("score"),
                     ("BLOCKED · " if x.get("is_blocked") else "") + ", ".join(map(str, x.get("signals") or []))) for x in items]
            self.draw_table(window, top, ("IP ADDRESS", "COUNTRY", "SCORE", "STATE / SIGNALS"), (23, 10, 8, 0), rows)
        elif name == "Blocked":
            rows = [(x.get("ip"), x.get("reason"), x.get("blocked_by"), date_short(x.get("expires_at") or "Permanent")) for x in items]
            self.draw_table(window, top, ("IP / CIDR", "REASON", "ACTOR", "EXPIRES"), (24, 34, 18, 0), rows)
        elif name == "Incidents":
            rows = [(x.get("severity"), x.get("status"), date_short(x.get("updated_at") or x.get("last_seen")),
                     x.get("title") or x.get("summary") or x.get("category")) for x in items]
            self.draw_table(window, top, ("SEVERITY", "STATUS", "UPDATED", "INCIDENT"), (13, 16, 18, 0), rows)
        elif name == "Audit":
            rows = [(date_short(x.get("ts")), x.get("action"), x.get("target"), x.get("actor"), x.get("reason")) for x in items]
            self.draw_table(window, top, ("TIME", "ACTION", "TARGET", "ACTOR", "REASON"), (18, 18, 25, 18, 0), rows)
        elif name == "Alerts":
            rows = [(("ON" if x.get("enabled") else "OFF"), x.get("label"), x.get("description")) for x in items]
            self.draw_table(window, top, ("STATE", "ALERT / ENFORCEMENT", "DESCRIPTION"), (9, 38, 0), rows)
        elif name == "Users":
            rows = [(x.get("username"), x.get("role"), x.get("created_by"), date_short(x.get("created_at"))) for x in items]
            self.draw_table(window, top, ("USERNAME", "ROLE", "CREATED BY", "CREATED"), (26, 18, 22, 0), rows)
        else:
            rows = [(f"{float(x.get('cpu_percent') or 0):.1f}%", bytes_label(x.get("memory_bytes")),
                     bytes_label(x.get("memory_peak_24h")), x.get("unit")) for x in items]
            self.draw_table(window, top, ("CPU", "MEMORY", "24H PEAK", "SERVICE"), (10, 16, 16, 0), rows)

    def draw_ssh(self, window: Any, top: int) -> None:
        height, width = window.getmaxyx()
        banned = self.items()
        self.put(window, top, 2, f"ACTIVE SSH BANS  {len(banned)}", curses.A_BOLD | curses.color_pair(3))
        y = top + 1
        if banned:
            visible_bans = min(len(banned), max(2, (height - top) // 3))
            selected = self.selected["SSH"]
            start = max(0, min(selected - visible_bans + 1, len(banned) - visible_bans))
            for index, item in enumerate(banned[start:start + visible_bans], start):
                attr = curses.A_BOLD | curses.color_pair(1) if index == selected else 0
                if index == selected:
                    self.put(window, y, 1, " " * max(0, width - 2), attr)
                line = f"{item.get('ip','—'):<24} expires {date_short(item.get('expires_at')):<17}  {item.get('reason') or ''}"
                self.put(window, y, 2, line, attr)
                y += 1
        else:
            self.put(window, y, 2, "No active SSH bans.", curses.color_pair(3))
            y += 1
        y += 1
        self.put(window, y, 2, "RECENT SSH AUTHENTICATION", curses.A_BOLD | curses.color_pair(3))
        y += 1
        self.put(window, y, 1, "─" * max(0, width - 2), curses.color_pair(4))
        y += 1
        for event in self.data.get("events", []):
            if y >= height - 3:
                break
            result = str(event.get("result") or "—").upper()
            attr = curses.color_pair(5) if result == "FAILED" else curses.color_pair(2)
            self.put(window, y, 2, date_short(event.get("ts")), curses.color_pair(3))
            self.put(window, y, 20, short(event.get("ip"), 22))
            self.put(window, y, 43, short(event.get("username"), 20))
            self.put(window, y, 64, result, attr)
            y += 1

    def draw_sites(self, window: Any, top: int) -> None:
        height, width = window.getmaxyx()
        items = self.items()
        list_width = min(48, max(28, width // 2))
        self.put(window, top, 2, "DISCOVERED SITES · 7 DAYS", curses.A_BOLD | curses.color_pair(3))
        visible = max(2, height - top - 5)
        selected = self.selected["Sites"]
        start = max(0, min(selected - visible + 1, max(0, len(items) - visible)))
        for offset, item in enumerate(items[start:start + visible]):
            index, y = start + offset, top + 2 + offset
            attr = curses.A_BOLD | curses.color_pair(1) if index == selected else 0
            if index == selected:
                self.put(window, y, 1, " " * max(0, list_width - 1), attr)
            self.put(window, y, 2, short(item.get("host"), list_width - 13), attr)
            self.put(window, y, list_width - 10, compact_number(item.get("count")).rjust(8), attr)
        if width < 82:
            return
        x = list_width + 3
        self.put(window, top, x, short(self.data.get("site_host"), width - x - 2), curses.A_BOLD | curses.color_pair(3))
        stats = self.data.get("site_stats", {})
        details = (
            ("Requests/min", compact_number(stats.get("requests_per_min"))),
            ("Requests/24h", compact_number(stats.get("requests_24h"))),
            ("Unique IPs/5m", compact_number(stats.get("unique_ips_5m"))),
        )
        y = top + 2
        for label, value in details:
            self.put(window, y, x, f"{label:<18} {value}", curses.A_BOLD)
            y += 2
        self.put(window, y, x, "Top countries", curses.color_pair(3))
        y += 1
        for country in self.data.get("site_countries", []):
            self.put(window, y, x, f"{country.get('country','??'):<5} {compact_number(country.get('count'))}")
            y += 1

    def draw_trends(self, window: Any, top: int) -> None:
        height, width = window.getmaxyx()
        items = self.items()
        self.put(window, top, 2, f"TRAFFIC TRENDS · {self.trend_days} DAYS · {len(items)} DATA DAYS", curses.A_BOLD | curses.color_pair(3))
        if not items:
            self.put(window, top + 2, 2, "No trend rows available.", curses.color_pair(3))
            return
        graph_width = max(12, width - 31)
        series = (
            ("Requests", [float(x.get("total_requests") or 0) for x in items], ""),
            ("Unique IPs", [float(x.get("unique_ips") or 0) for x in items], ""),
            ("p95 latency", [float(x.get("p95_response_ms") or 0) for x in items], " ms"),
            ("5xx errors", [float(x.get("status_5xx_count") or 0) for x in items], ""),
        )
        y = top + 2
        for label, values, unit in series:
            self.put(window, y, 2, f"{label:<13}", curses.color_pair(3))
            self.put(window, y, 16, sparkline(values, graph_width), curses.color_pair(1))
            self.put(window, y, max(18, width - 12), short(compact_number(values[-1]) + unit, 10), curses.A_BOLD)
            y += 2
        y += 1
        self.put(window, y, 2, "RECENT DAYS", curses.A_BOLD | curses.color_pair(3))
        y += 1
        for item in reversed(items[-min(8, max(1, height - y - 3)):]):
            partial = " LIVE" if item.get("partial") else ""
            line = (f"{item.get('date')} {partial:<6}  req {compact_number(item.get('total_requests')):<8} "
                    f"ips {compact_number(item.get('unique_ips')):<7} p95 {compact_number(item.get('p95_response_ms')):>7} ms "
                    f"5xx {compact_number(item.get('status_5xx_count'))}")
            self.put(window, y, 2, line)
            y += 1

    def draw_license(self, window: Any, top: int) -> None:
        item = self.data.get("license", {})
        if not item:
            self.put(window, top, 2, "Edition details require the Owner role.", curses.color_pair(3))
            return
        key = "" if item.get("license_status") == "community" else str(item.get("license_key") or "")
        masked_key = ("••••-" + key[-4:]) if key else None
        status = item.get("license_status") or ("Locked" if item.get("locked") else "Active" if item.get("activated") else "Not activated")
        seats = f"{item['active_seats']} active / {item['max_seats']} allowed" if item.get("active_seats") is not None and item.get("max_seats") is not None else None
        rows = (
            ("Edition", item.get("edition") or status), ("Activation", "Not required"),
            ("License", masked_key), ("Expires", item.get("expires_at")),
            ("Seats", seats), ("Live status", "Connected" if item.get("live") else "Cached"),
            ("Message", item.get("lock_reason") or item.get("message")),
        )
        y = top
        for label, value in rows:
            if value in (None, ""):
                continue
            self.put(window, y, 2, f"{label.upper():<14}", curses.A_BOLD | curses.color_pair(3))
            self.put(window, y, 18, short(value, 80))
            y += 2

    def help_text(self) -> str:
        specific = {
            "Threats": "[b] block selected",
            "Blocked": "[b] block IP  [u] unblock selected",
            "SSH": "[u] lift selected SSH ban",
            "Incidents": "[Enter] advance status",
            "Sites": "[↑/↓] inspect",
            "Trends": "[d] change window",
            "Alerts": "[Space] toggle  [w] webhook",
            "Users": "[n] new  [e] edit  [x] delete",
        }.get(self.name, "[b] block IP")
        return f" [Tab/←/→] view  [↑/↓] select  [r] refresh  {specific}  [q] quit "

    def draw(self, window: Any) -> None:
        window.erase()
        top = self.draw_header(window)
        height, width = window.getmaxyx()
        if top >= height:
            window.refresh()
            return
        if self.error:
            self.put(window, top, 2, "Unable to load this view:", curses.A_BOLD | curses.color_pair(5))
            self.put(window, top + 2, 2, short(self.error, width - 5), curses.color_pair(5))
        elif self.name == "Overview":
            self.draw_overview(window, top)
        elif self.name == "SSH":
            self.draw_ssh(window, top)
        elif self.name == "Sites":
            self.draw_sites(window, top)
        elif self.name == "Trends":
            self.draw_trends(window, top)
        elif self.name == "Edition":
            self.draw_license(window, top)
        else:
            self.draw_rows(window, top)
        if self.message:
            self.put(window, height - 2, 1, short(self.message, width - 3), curses.A_BOLD | curses.color_pair(2))
        elif self.error:
            self.put(window, height - 2, 1, short(self.error, width - 3), curses.color_pair(5))
        else:
            stamp = time.strftime("%H:%M:%S", time.localtime(self.updated)) if self.updated else "—"
            self.put(window, height - 2, 1, f"Updated {stamp}", curses.color_pair(3))
        self.put(window, height - 1, 0, short(self.help_text(), width - 1), curses.color_pair(3))
        window.refresh()

    def selected_item(self) -> dict[str, Any] | None:
        items = self.items()
        if not items:
            return None
        return items[min(self.selected[self.name], len(items) - 1)]

    def set_message(self, text: str) -> None:
        self.message = text
        self.error = ""

    def block_ip(self, window: Any) -> None:
        if not self.permitted("operator"):
            self.set_message("Blocking requires the Operator role or higher.")
            return
        item = self.selected_item() if self.name in {"Threats", "Blocked"} else None
        default = str((item or {}).get("ip") or "")
        ip = self.prompt(window, "IP or CIDR to block", default=default)
        if not ip:
            return
        reason = self.prompt(window, "Reason", default="Manual terminal block")
        duration = self.prompt(window, "Duration hours; blank = permanent")
        try:
            hours = float(duration) if duration else None
            if hours is not None and hours <= 0:
                raise ValueError
        except ValueError:
            self.set_message("Duration must be a positive number of hours.")
            return
        try:
            self.api.request("/api/block", "POST", {"ip": ip, "reason": reason or None, "duration_hours": hours})
            self.set_message(f"Blocked {ip}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Block failed: {exc}")

    def unblock(self, window: Any) -> None:
        item = self.selected_item()
        if not item:
            return
        ip = str(item.get("ip") or "")
        if not self.permitted("operator"):
            self.set_message("Unblocking requires the Operator role or higher.")
            return
        if not self.confirm(window, f"Unblock {ip}?"):
            return
        try:
            if self.name == "SSH":
                self.api.request("/api/ssh-banned/" + urllib.parse.quote(ip, safe=""), "DELETE")
                self.set_message(f"Lifted SSH ban for {ip}.")
            else:
                self.api.request("/api/block/" + urllib.parse.quote(ip, safe=""), "DELETE")
                self.set_message(f"Unblocked {ip}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Unblock failed: {exc}")

    def toggle_alert(self) -> None:
        item = self.selected_item()
        if not item:
            return
        if not self.permitted("administrator"):
            self.set_message("Changing alerts requires the Administrator role or higher.")
            return
        enabled = not bool(item.get("enabled"))
        try:
            self.api.request("/api/alert-settings/" + urllib.parse.quote(str(item["key"]), safe=""), "POST", {"enabled": enabled})
            self.set_message(f"{item.get('label')}: {'enabled' if enabled else 'disabled'}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Alert update failed: {exc}")

    def configure_webhook(self, window: Any) -> None:
        if not self.permitted("administrator"):
            self.set_message("Webhook configuration requires the Administrator role or higher.")
            return
        url = self.prompt(window, "Discord webhook URL; '-' clears it")
        if url is None:
            return
        try:
            self.api.request("/api/alert-webhook", "POST", {"url": "" if url == "-" else url})
            self.set_message("Discord webhook configuration updated.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Webhook update failed: {exc}")

    def create_user(self, window: Any) -> None:
        if not self.permitted("owner"):
            self.set_message("Creating users requires the Owner role.")
            return
        username = self.prompt(window, "New username")
        if not username:
            return
        password = self.prompt(window, "New password", secret=True)
        if not password:
            self.set_message("Password cannot be empty.")
            return
        role = self.prompt(window, "Role: administrator/operator/spectator", default="operator")
        if role not in {"administrator", "operator", "spectator"}:
            self.set_message("Role must be administrator, operator, or spectator.")
            return
        try:
            self.api.request("/api/users", "POST", {"username": username, "password": password, "role": role})
            self.set_message(f"Created {username} as {role}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"User creation failed: {exc}")

    def delete_user(self, window: Any) -> None:
        item = self.selected_item()
        if not item:
            return
        username = str(item.get("username") or "")
        if not self.permitted("owner"):
            self.set_message("Deleting users requires the Owner role.")
            return
        if item.get("role") == "owner":
            self.set_message("The Owner account cannot be deleted.")
            return
        if not self.confirm(window, f"Delete user {username}?"):
            return
        try:
            self.api.request("/api/users/" + urllib.parse.quote(username, safe=""), "DELETE")
            self.set_message(f"Deleted {username}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Delete failed: {exc}")

    def edit_user(self, window: Any) -> None:
        item = self.selected_item()
        if not item:
            return
        username = str(item.get("username") or "")
        if not self.permitted("owner"):
            self.set_message("Editing users requires the Owner role.")
            return
        if item.get("role") == "owner":
            self.set_message("The Owner account cannot be edited here.")
            return
        role = self.prompt(window, "Role: administrator/operator/spectator", default=str(item.get("role") or "operator"))
        if role not in {"administrator", "operator", "spectator"}:
            self.set_message("Role must be administrator, operator, or spectator.")
            return
        password = self.prompt(window, "New password; blank keeps current", secret=True)
        payload: dict[str, Any] = {"role": role}
        if password:
            payload["password"] = password
        try:
            self.api.request("/api/users/" + urllib.parse.quote(username, safe=""), "PUT", payload)
            self.set_message(f"Updated {username}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"User update failed: {exc}")

    def advance_incident(self, window: Any) -> None:
        item = self.selected_item()
        if not item:
            return
        if not self.permitted("operator"):
            self.set_message("Updating incidents requires the Operator role or higher.")
            return
        current = str(item.get("status") or "open")
        following = {"open": "investigating", "investigating": "resolved", "resolved": "open"}.get(current, "investigating")
        incident_id = item.get("id") or item.get("incident_id")
        if not incident_id:
            self.set_message("This incident has no update identifier.")
            return
        if not self.confirm(window, f"Change incident to {following}?"):
            return
        try:
            self.api.request("/api/incidents/" + urllib.parse.quote(str(incident_id), safe=""), "PATCH", {"status": following})
            self.set_message(f"Incident moved to {following}.")
            self.refresh()
        except ApiError as exc:
            self.set_message(f"Incident update failed: {exc}")

    def move_selection(self, delta: int) -> None:
        items = self.items()
        if not items:
            return
        self.selected[self.name] = max(0, min(len(items) - 1, self.selected[self.name] + delta))
        if self.name == "Sites":
            try:
                self._load_site_detail()
                self.error = ""
            except ApiError as exc:
                self.error = str(exc)

    def change_view(self, index: int) -> None:
        self.view = index % len(VIEWS)
        self.message = ""
        self.refresh()

    def run(self, window: Any) -> None:
        curses.curs_set(0)
        curses.noecho()
        curses.use_default_colors()
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_CYAN, -1)
            curses.init_pair(4, curses.COLOR_BLUE, -1)
            curses.init_pair(5, curses.COLOR_RED, -1)
        window.keypad(True)
        window.timeout(1000)
        self.refresh()
        while True:
            self.draw(window)
            key = window.getch()
            if key in (ord("q"), ord("Q")):
                return
            if ord("1") <= key <= ord("9"):
                self.change_view(key - ord("1"))
            elif key == ord("0"):
                self.change_view(9)
            elif key in (curses.KEY_RIGHT, ord("l"), 9):
                self.change_view(self.view + 1)
            elif key in (curses.KEY_LEFT, ord("h"), curses.KEY_BTAB):
                self.change_view(self.view - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.move_selection(1)
            elif key in (curses.KEY_UP, ord("k")):
                self.move_selection(-1)
            elif key in (ord("r"), ord("R")):
                self.message = ""
                self.refresh()
            elif key in (ord("b"), ord("B")):
                self.block_ip(window)
            elif key in (ord("u"), ord("U")) and self.name in {"Blocked", "SSH"}:
                self.unblock(window)
            elif key == ord(" ") and self.name == "Alerts":
                self.toggle_alert()
            elif key in (ord("w"), ord("W")) and self.name == "Alerts":
                self.configure_webhook(window)
            elif key in (ord("n"), ord("N")) and self.name == "Users":
                self.create_user(window)
            elif key in (ord("e"), ord("E")) and self.name == "Users":
                self.edit_user(window)
            elif key in (ord("x"), ord("X")) and self.name == "Users":
                self.delete_user(window)
            elif key in (10, 13, curses.KEY_ENTER) and self.name == "Incidents":
                self.advance_incident(window)
            elif key in (ord("d"), ord("D")) and self.name == "Trends":
                current = TREND_WINDOWS.index(self.trend_days) if self.trend_days in TREND_WINDOWS else 1
                self.trend_days = TREND_WINDOWS[(current + 1) % len(TREND_WINDOWS)]
                self.set_message(f"Trend window changed to {self.trend_days} days.")
                self.refresh()
            elif self.updated and time.time() - self.updated >= 20:
                self.refresh()


def snapshot(api: SentryNetApi, account: dict[str, Any], version: str) -> None:
    stats = api.request("/api/stats")
    blocked = api.request("/api/blocked")
    ssh_banned = api.request("/api/ssh-banned")
    incidents = api.request("/api/incidents?limit=200")
    print(f"SentryNet {version} · {account.get('username')} ({account.get('role')})")
    print(f"Requests/min: {compact_number(stats.get('requests_per_min'))}")
    print(f"Unique IPs (5m): {compact_number(stats.get('unique_ips_5m'))}")
    print(f"Flagged active: {compact_number(stats.get('flagged_active'))}")
    print(f"Web blocks: {len(blocked)}")
    print(f"SSH bans: {len(ssh_banned)}")
    print(f"Open incidents: {sum(1 for item in incidents if item.get('status') != 'resolved')}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="sentrynet-terminal", description="Operate a SentryNet installation from the terminal.")
    parser.add_argument("--server", default=os.getenv("SENTRYNET_TERMINAL_URL", "http://127.0.0.1:8103"), help="SentryNet base URL (default: local port 8103)")
    parser.add_argument("--username", default=os.getenv("SENTRYNET_USERNAME", ""), help="Username; password is always prompted securely")
    parser.add_argument("--snapshot", action="store_true", help="Print one operational overview instead of opening the interactive TUI")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        api = SentryNetApi(args.server, timeout=max(1.0, min(args.timeout, 60.0)))
        username = args.username or input("SentryNet username: ").strip()
        if not username:
            raise ApiError("username is required")
        password = getpass.getpass("Password: ")
        api.login(username, password)
        account = api.request("/api/account")
        version_data = api.request("/api/version")
        version = str(version_data.get("version", "1.5.0"))
        if args.snapshot:
            snapshot(api, account, version)
            return 0
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ApiError("interactive mode requires a TTY (use --snapshot for plain output)")
        curses.wrapper(TerminalApp(api, account, version).run)
        try:
            api.request("/logout", "POST", {})
        except ApiError:
            pass
        return 0
    except (ApiError, KeyboardInterrupt) as exc:
        message = str(exc) if str(exc) else "cancelled"
        print(f"sentrynet-terminal: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
