"""
Tails `journalctl -u ssh` for auth attempts against this box itself (as
opposed to ingest.py, which watches HTTP traffic via nginx).

6 failed/invalid logins in a row within WINDOW_SECONDS auto-bans the IP at
the firewall for 24h (port 22 only - see ssh_ban.py), unless the
"ssh_auto_ban" setting is switched off. "In a row" means a successful login
from that IP resets its failure streak - so an admin who mistypes their
password a few times before getting in isn't at risk, only a run of
straight failures is. Allowlisted IPs (e.g. the admin's own) are never
counted or banned.
"""

import json
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from models import SshAuthEvent, FlaggedIp
from geoua import country_for_ip
from notify import send_discord_alert
import alert_settings
import ssh_ban
import ingest  # is_ip_allowed - allowlisted IPs (e.g. the admin's own) are never flagged

WINDOW_SECONDS = 600           # rolling window for counting failed/invalid attempts per IP
FAIL_THRESHOLD = 6             # this many failed/invalid attempts in a row within WINDOW_SECONDS -> ban
ALERT_COOLDOWN_SECONDS = 3600  # per-IP - only matters when the "ssh_brute_force" category is switched on

_ACCEPTED_RE = re.compile(r"Accepted \S+ for (\S+) from (\S+) port \d+")
_FAILED_RE = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+) port \d+")
_INVALID_RE = re.compile(r"Invalid user (\S+) from (\S+) port \d+")
_CONN_DROPPED_RE = re.compile(r"Connection (?:closed|reset) by authenticating user (\S+) (\S+) port \d+")

_stop = threading.Event()
_ip_window: dict = defaultdict(lambda: deque())  # ip -> deque of failure timestamps
_last_alerted: dict = {}  # ip -> monotonic time last alerted


def _parse_line(line: str):
    """Returns (username, ip, result) or None. result is accepted|failed|invalid_user."""
    m = _ACCEPTED_RE.search(line)
    if m:
        return m.group(1), m.group(2), "accepted"
    m = _FAILED_RE.search(line)
    if m:
        return m.group(2), m.group(3), "invalid_user" if m.group(1) else "failed"
    m = _INVALID_RE.search(line)
    if m:
        return m.group(1), m.group(2), "invalid_user"
    m = _CONN_DROPPED_RE.search(line)
    if m:
        return m.group(1), m.group(2), "failed"
    return None


def _handle_event(username: str, ip: str, result: str):
    now_dt = datetime.now(timezone.utc)
    country = country_for_ip(ip)
    SshAuthEvent.create(ts=now_dt, ip=ip, country=country, username=username[:255], result=result)

    if result == "accepted":
        # A successful login breaks the failure "streak" - 6 fails then a
        # real login shouldn't still count toward a ban once they're in.
        _ip_window.pop(ip, None)
        # Deliberately no Discord alert here - a legitimate login (almost
        # always the admin's own) would broadcast their real IP and
        # geolocation to the channel on every single connection. Still
        # logged to SshAuthEvent above, so it's visible in the dashboard's
        # SSH Activity panel for anyone who actually has access to look.
        return

    if ingest.is_ip_allowed(ip):
        return

    now = time.time()
    dq = _ip_window[ip]
    dq.append(now)
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()

    if len(dq) < FAIL_THRESHOLD:
        return

    detail = f"{len(dq)} failed/invalid SSH attempts in {WINDOW_SECONDS // 60} min (latest user: {username!r})"
    signal = {"type": "ssh_brute_force", "detail": detail, "severity": 4}
    row = FlaggedIp.get_or_none(FlaggedIp.ip == ip)
    if row:
        try:
            signals = json.loads(row.signals)
        except Exception:
            signals = []
        signals = [s for s in signals if s.get("type") != "ssh_brute_force"] + [signal]
        row.country = country
        row.signals = json.dumps(signals)
        row.score = sum(s.get("severity", 1) for s in signals)
        row.last_seen = now_dt
        row.save()
    else:
        FlaggedIp.create(ip=ip, country=country, signals=json.dumps([signal]),
                          score=signal["severity"], first_seen=now_dt, last_seen=now_dt)

    if alert_settings.is_enabled("ssh_auto_ban"):
        ssh_ban.ban_ip(ip, detail)

    if not alert_settings.is_enabled("ssh_brute_force"):
        return
    last = _last_alerted.get(ip, 0)
    if now - last >= ALERT_COOLDOWN_SECONDS:
        _last_alerted[ip] = now
        send_discord_alert(
            f":rotating_light: **SSH brute-force detected**: `{ip}` ({country})\n{detail}"
        )


def _run():
    while not _stop.is_set():
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager", "-o", "cat"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
            while not _stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                parsed = _parse_line(line)
                if parsed:
                    try:
                        _handle_event(*parsed)
                    except Exception as e:
                        print(f"[ssh-monitor] failed to handle event: {e}")
            proc.terminate()
        except Exception as e:
            print(f"[ssh-monitor] journalctl tail failed, retrying in 10s: {e}")
            _stop.wait(10)


def start():
    t = threading.Thread(target=_run, daemon=True, name="ssh-monitor")
    t.start()
    return t


def stop():
    _stop.set()
