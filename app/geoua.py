"""GeoIP country lookup + User-Agent parsing, shared by the ingest tailer."""

import ipaddress

import GeoIP
from user_agents import parse as ua_parse

_geoip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)


def country_for_ip(ip: str) -> str:
    if not ip:
        return "??"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "LAN"
    except ValueError:
        return "??"
    try:
        code = _geoip.country_code_by_addr(ip)
        return code or "??"
    except Exception:
        return "??"


# Known non-browser tooling that legitimately identifies itself - not a threat
# signal on its own, just not worth mislabeling as "Browser" device/OS/UA.
_KNOWN_BOTS = ("googlebot", "bingbot", "duckduckbot", "yandexbot", "baiduspider",
               "facebookexternalhit", "twitterbot", "discordbot", "slackbot",
               "uptimerobot", "pingdom", "curl/", "python-requests", "python-urllib",
               "go-http-client", "okhttp", "axios", "node-fetch")

# Actual attack-tool signatures - a much stronger signal, handled separately
# in heuristics.py so the two don't get conflated.
SCANNER_UA_SIGNATURES = ("sqlmap", "nikto", "nmap", "masscan", "gobuster",
                          "dirbuster", "wpscan", "nuclei", "acunetix", "nessus",
                          "openvas", "havij", "zgrab")


def parse_ua(ua_string: str) -> dict:
    ua_string = ua_string or ""
    low = ua_string.lower()
    is_bot = any(b in low for b in _KNOWN_BOTS) or "bot" in low
    if not ua_string:
        return {"device": "Unknown", "os": "Unknown", "browser": "Unknown", "is_bot": False}
    try:
        ua = ua_parse(ua_string)
        device = "Bot" if is_bot else ("Tablet" if ua.is_tablet else "Mobile" if ua.is_mobile else "PC" if ua.is_pc else "Other")
        return {
            "device": device,
            "os": ua.os.family or "Unknown",
            "browser": ua.browser.family or "Unknown",
            "is_bot": is_bot,
        }
    except Exception:
        return {"device": "Unknown", "os": "Unknown", "browser": "Unknown", "is_bot": is_bot}
