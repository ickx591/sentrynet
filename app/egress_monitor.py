"""
Outbound/egress connection monitoring. Everything else in this codebase
watches inbound traffic and SSH - "this server is phoning home somewhere it
shouldn't" is a much stronger compromise signal than inbound blocking alone,
and it's the one thing purely inbound-focused monitoring can never catch
(a reverse shell, a C2 beacon, data exfiltration all show up here first).

Baseline-then-alert, not alert-on-first-sight: a fresh server makes many
legitimate outbound connections (apt/dpkg, the license check-in, Discord
webhook posts, threat_intel.py's own TOR/AWS/GCP/Spamhaus fetches) that
would otherwise flood day-one alerts. For BASELINE_WINDOW_SECONDS after
this monitor's baseline was first established (persisted across restarts,
not reset by them), every (process, remote_ip, remote_port) tuple seen is
recorded as known-good, never alerted. After the window, only genuinely
new tuples not already in the baseline trigger an alert - and each tuple
only alerts once, not on every poll it stays open.

Alert-only, never auto-block - mirrors ssh_monitor.py/ssh_ban.py's
philosophy but more strongly here: auto-blocking egress risks breaking a
legitimate app calling a new external API for the first time, which is a
worse outcome than a missed alert. A static allowlist
(config/egress_allowlist.txt, same convention as config/watched_files.txt)
lets an admin mark expected destinations as never-alert regardless of
baseline timing, for exactly that "new integration" case.

Data source: `ss -tnp` (already the tool family this codebase uses
elsewhere for port detection) - no new Python dependency. "Outbound" is
inferred heuristically: a connection whose LOCAL port falls in this box's
ephemeral port range is one we initiated (a listening service's local port
is its fixed listen port - e.g. 443/5432 - never ephemeral). Not a perfect
signal, but the standard practical approach, and it correctly excludes
ordinary inbound traffic to nginx/Postgres/etc.
"""

import json
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from models import EgressEvent
from notify import send_discord_alert
import alert_settings

SCRIPT_DIR = Path(__file__).parent
BASELINE_FILE = SCRIPT_DIR / ".egress_baseline.json"
ALLOWLIST_FILE = SCRIPT_DIR / "config" / "egress_allowlist.txt"

CHECK_INTERVAL_SECONDS = 60
BASELINE_WINDOW_SECONDS = 48 * 3600

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')

_stop = threading.Event()
_lock = threading.Lock()
_baseline_started_at = None


def _load_ephemeral_range():
    try:
        lo, hi = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
        return int(lo), int(hi)
    except Exception:
        return (32768, 60999)  # Linux default - used if /proc is unreadable for any reason


_EPHEMERAL_RANGE = _load_ephemeral_range()


def _load_allowlist() -> set:
    # One IP or "ip:port" per line - '#' comments and blank lines ignored.
    try:
        lines = ALLOWLIST_FILE.read_text().splitlines()
        return {l.strip() for l in lines if l.strip() and not l.strip().startswith("#")}
    except Exception:
        return set()


def _is_allowlisted(remote_ip: str, remote_port: int, allowlist: set) -> bool:
    return remote_ip in allowlist or f"{remote_ip}:{remote_port}" in allowlist


def _load_baseline() -> dict:
    try:
        return json.loads(BASELINE_FILE.read_text())
    except Exception:
        return {}


def _save_baseline(data: dict):
    try:
        BASELINE_FILE.write_text(json.dumps(data))
    except Exception as e:
        print(f"[egress-monitor] failed to save baseline: {e}")


def _current_outbound_connections() -> set:
    """Returns {(process, remote_ip, remote_port)} for connections this box
    appears to have initiated - see module docstring for the heuristic."""
    tuples = set()
    try:
        out = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        print(f"[egress-monitor] ss failed: {e}")
        return tuples

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        local_addr, peer_addr = parts[3], parts[4]
        try:
            local_port = int(local_addr.rsplit(":", 1)[-1])
        except ValueError:
            continue
        if not (_EPHEMERAL_RANGE[0] <= local_port <= _EPHEMERAL_RANGE[1]):
            continue  # local port is a fixed listen port -> this is inbound, not egress

        try:
            remote_ip, remote_port_s = peer_addr.rsplit(":", 1)
            remote_port = int(remote_port_s)
        except ValueError:
            continue
        remote_ip = remote_ip.strip("[]")  # IPv6 brackets
        if remote_ip in ("127.0.0.1", "::1"):
            continue  # loopback - not egress

        proc_match = _PROCESS_RE.search(line)
        process = proc_match.group(1) if proc_match else "unknown"
        tuples.add((process, remote_ip, remote_port))
    return tuples


def _check_once():
    global _baseline_started_at
    now = datetime.now(timezone.utc)
    baseline = _load_baseline()

    if _baseline_started_at is None:
        started = baseline.get("baseline_started_at")
        if started:
            try:
                _baseline_started_at = datetime.fromisoformat(started)
            except ValueError:
                _baseline_started_at = now
        else:
            _baseline_started_at = now
    in_baseline = (now - _baseline_started_at).total_seconds() < BASELINE_WINDOW_SECONDS

    allowlist = _load_allowlist()
    current = _current_outbound_connections()
    known = {tuple(t) for t in baseline.get("tuples", [])}

    new_tuples = []
    for key in current:
        if key in known:
            continue
        process, remote_ip, remote_port = key
        if in_baseline or _is_allowlisted(remote_ip, remote_port, allowlist):
            known.add(key)
            continue
        new_tuples.append(key)
        known.add(key)  # only alert once per tuple, not on every poll it stays open

    _save_baseline({"tuples": [list(t) for t in known], "baseline_started_at": _baseline_started_at.isoformat()})

    if not new_tuples:
        return

    alerts_on = alert_settings.is_enabled("egress_anomaly")
    for process, remote_ip, remote_port in new_tuples:
        EgressEvent.create(ts=now, process=process, remote_ip=remote_ip, remote_port=remote_port)
        if alerts_on:
            send_discord_alert(
                f":satellite: **New outbound connection**: `{process}` -> `{remote_ip}:{remote_port}`\n"
                f"Not seen during this box's baseline learning window - if this is expected, "
                f"add it to `config/egress_allowlist.txt`."
            )


def _run():
    # First check happens right away in the background (not blocking
    # main.py's startup), same as threat_intel.py/integrity_monitor.py.
    try:
        _check_once()
    except Exception as e:
        print(f"[egress-monitor] check failed: {e}")
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        try:
            _check_once()
        except Exception as e:
            print(f"[egress-monitor] check failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="egress-monitor")
    t.start()
    return t


def stop():
    _stop.set()
