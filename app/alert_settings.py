"""
Per-category on/off toggles, controlled from the dashboard's Alerts tab.
Mostly Discord alert categories, plus two enforcement toggles (ssh_auto_ban -
see ssh_ban.py; auto_release_blocks - see main.py's expired-block sweep)
that reuse the same on/off-per-key mechanism since it's generically useful
here, not just for notifications.

Standard categories (real outages/recovery, DDoS, the twice-daily digest,
and SSH auto-ban) default on; additional categories (IP block/ban
notifications, ordinary traffic spikes, SSH brute-force alerts, config-file
changes) default off but can be switched on per-operator without touching
code.

Cached in memory and periodically refreshed (like ingest.py's allow/deny
cache) so the hot paths that check "should this fire?" - some of them
per-request - never hit Postgres directly. A toggle flip from the dashboard
forces an immediate refresh so it takes effect right away.
"""

import threading
import time

from models import AlertSetting

REFRESH_SECONDS = 30

# key -> (default_enabled, label, description)
DEFAULTS = {
    "service_health":    (True,  "Service degraded/down + recovered",
                           "A watched service crashes, hits critical CPU/memory, or comes back."),
    "site_5xx_degraded": (True,  "Site errors (5xx burst) + recovered",
                           "A burst of server errors means the site is actually broken, not just busy."),
    "cert_expiry":       (True,  "TLS certificate expired + renewed",
                           "A Let's Encrypt cert has actually lapsed - Certbot's renewal failed silently."),
    "app_error_bursts":  (True,  "Application error bursts + recovered",
                           "A watched service logs a sustained run of ERROR/CRITICAL lines."),
    "defacement":        (True,  "Possible defacement on a web root",
                           "A top-level file in a discovered web root (index.html/php etc.) was created, "
                           "modified, or deleted - a compromised customer-facing page is a bigger deal than "
                           "an ordinary config file change."),
    "scheduled_report":  (True,  "Scheduled security-summary report (PDF/email)",
                           "Automatic sends on the configured weekly/monthly cadence, once SMTP and at least "
                           "one recipient are set up below. Doesn't affect the 'send test report now' button."),
    "egress_anomaly":    (True,  "Unexpected outbound connection",
                           "This box connected somewhere new (a process/destination pair not seen during its "
                           "baseline learning window) - alert-only, nothing is ever auto-blocked."),
    "ddos":              (True,  "Possible DDoS + resolved",
                           "Sustained, extreme traffic far above baseline - not an ordinary spike."),
    "digest":            (True,  "Twice-daily analytics digest",
                           "Traffic/security + Postgres health summary, posted at 09:00 and 21:00."),
    "ssh_auto_ban":      (True,  "Auto-ban SSH brute-force IPs (24h)",
                           "Blocks the IP at the firewall (SSH port only, auto-detected) for 24 hours after "
                           "6 failed SSH logins in 10 minutes. Skips allowlisted IPs. Separate from the notification "
                           "toggles below - this is the actual enforcement action."),
    "auto_release_blocks": (True, "Auto-release blocked IPs after 30 days",
                           "Manually and automatically blocked IPs with no explicit expiry are released after 30 "
                           "days. Blocks with their own explicit duration (temporary blocks) are never affected - "
                           "they already expire on their own schedule regardless of this setting."),
    "thread_watchdog":   (True,  "Background monitor thread died + restarted",
                           "One of SentryNet's own background threads (access-log tailer, SSH monitor, etc.) "
                           "stopped running unexpectedly and was automatically restarted. Default on - without "
                           "this, a silently-dead monitor thread can go unnoticed indefinitely."),
    "ip_blocks":         (False, "IP block / unblock / ban actions",
                           "Every manual or automatic IP block, unblock, country block, bulk block, and SSH ban."),
    "traffic_spikes":    (False, "Ordinary traffic spikes",
                           "Request volume well above baseline, but not extreme enough to call it a DDoS."),
    "ssh_brute_force":   (False, "SSH brute-force detected",
                           "Repeated failed SSH logins from the same IP."),
    "config_integrity":  (False, "Config file changes",
                           "A watched config file (nginx, systemd units, app secrets) was created, modified, or deleted."),
}

_lock = threading.Lock()
_cache: dict = {}
_last_refresh = 0.0


def ensure_defaults():
    existing = {s.key for s in AlertSetting.select(AlertSetting.key)}
    for key, (enabled, _, _) in DEFAULTS.items():
        if key not in existing:
            AlertSetting.create(key=key, enabled=enabled)


def refresh(force=False):
    global _last_refresh
    now = time.time()
    if not force and now - _last_refresh < REFRESH_SECONDS:
        return
    _last_refresh = now
    fresh = {s.key: s.enabled for s in AlertSetting.select()}
    with _lock:
        _cache.clear()
        _cache.update(fresh)


def is_enabled(key: str) -> bool:
    refresh()
    with _lock:
        if key in _cache:
            return _cache[key]
    return DEFAULTS.get(key, (True, "", ""))[0]


def list_settings() -> list:
    refresh(force=True)
    with _lock:
        return [
            {"key": k, "label": label, "description": desc, "enabled": _cache.get(k, default)}
            for k, (default, label, desc) in DEFAULTS.items()
        ]


def set_enabled(key: str, enabled: bool):
    if key not in DEFAULTS:
        raise KeyError(key)
    row = AlertSetting.get_or_none(AlertSetting.key == key)
    if row:
        row.enabled = enabled
        row.save()
    else:
        AlertSetting.create(key=key, enabled=enabled)
    refresh(force=True)
