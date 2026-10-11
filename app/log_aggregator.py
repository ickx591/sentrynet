"""
Lightweight substitute for full log centralization: tails journalctl across
every custom service (plus nginx/postgres) in one merged stream, and stores
only the lines that look like something actually broke (syslog priority
err/crit, or a traceback/exception-shaped message) - not every line. Powers
the dashboard's "Application Errors" panel plus a sustained-burst Discord
alert: a single error line doesn't page anyone, but ERROR_BURST_THRESHOLD+
errors from the same unit within ERROR_BURST_WINDOW_SECONDS means it's
actually degraded, not just having a blip - and a matching "recovered" alert
fires once it's been quiet for RECOVERY_QUIET_SECONDS.
"""

import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from models import AppLogEvent
from notify import send_discord_alert
import alert_settings

# One systemd unit name per line (no ".service" suffix) - '#' comments and
# blank lines ignored. Re-read only at process start (edit, then restart the
# service to pick up changes). Ships with just "nginx" - add your own app
# services here after install.
WATCHED_UNITS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "watched_units.txt")


def _load_watched_units() -> list:
    try:
        lines = Path(WATCHED_UNITS_FILE).read_text().splitlines()
        units = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return units or ["nginx"]
    except Exception:
        return ["nginx"]


WATCHED_UNITS = _load_watched_units()

ERROR_PRIORITY_MAX = 3  # syslog: 0=emerg .. 3=err .. 7=debug; <=3 counts as "error"
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\)|(?<![A-Za-z])Exception(?![A-Za-z])|CRITICAL", re.IGNORECASE)

ERROR_BURST_WINDOW_SECONDS = 300   # 5 min
ERROR_BURST_THRESHOLD = 5          # this many errors in the window = sustained problem, not a blip
RECOVERY_QUIET_SECONDS = 600       # 10 min with no further errors before declaring it recovered
RECOVERY_CHECK_INTERVAL = 60

_stop = threading.Event()
_error_timestamps: dict = defaultdict(deque)  # unit -> deque of error timestamps
_unit_erroring: dict = {}                     # unit -> bool, currently in a "degraded" alert
_last_error_time: dict = {}                   # unit -> monotonic time of most recent error


def _extract_message(entry: dict) -> str:
    msg = entry.get("MESSAGE", "")
    if isinstance(msg, list):
        try:
            msg = bytes(msg).decode("utf-8", errors="replace")
        except Exception:
            msg = str(msg)
    return str(msg)[:2000]


def _handle_entry(entry: dict):
    unit = (entry.get("_SYSTEMD_UNIT") or entry.get("UNIT") or "unknown").removesuffix(".service")
    message = _extract_message(entry)
    try:
        priority = int(entry.get("PRIORITY", 6))
    except (TypeError, ValueError):
        priority = 6

    is_error = priority <= ERROR_PRIORITY_MAX or bool(_TRACEBACK_RE.search(message))
    if not is_error or not message.strip():
        return

    level = "critical" if priority <= 2 or "CRITICAL" in message else "error"
    now = datetime.now(timezone.utc)
    AppLogEvent.create(ts=now, unit=unit, level=level, message=message)

    wall_now = time.time()
    _last_error_time[unit] = wall_now
    dq = _error_timestamps[unit]
    dq.append(wall_now)
    while dq and wall_now - dq[0] > ERROR_BURST_WINDOW_SECONDS:
        dq.popleft()

    if len(dq) >= ERROR_BURST_THRESHOLD and not _unit_erroring.get(unit):
        _unit_erroring[unit] = True
        if alert_settings.is_enabled("app_error_bursts"):
            send_discord_alert(
                f":warning: **Service degraded**: `{unit}` logged {len(dq)} errors in the last "
                f"{ERROR_BURST_WINDOW_SECONDS // 60} min. Latest:\n```{message[:500]}```"
            )


def _recovery_sweep_loop():
    # Unlike _run() below (and every other monitor's loop), this had no
    # try/except at all - an exception here (e.g. from alert_settings or
    # send_discord_alert misbehaving) would silently kill this thread with
    # nothing catching it, and nothing would ever have noticed either
    # (until watchdog.py, which needs both this and start() below returning
    # both threads it spawns - see start()'s docstring).
    while not _stop.wait(RECOVERY_CHECK_INTERVAL):
        try:
            wall_now = time.time()
            for unit, erroring in list(_unit_erroring.items()):
                if not erroring:
                    continue
                last = _last_error_time.get(unit, 0)
                if wall_now - last >= RECOVERY_QUIET_SECONDS:
                    _unit_erroring[unit] = False
                    if alert_settings.is_enabled("app_error_bursts"):
                        send_discord_alert(f":white_check_mark: **Service recovered**: `{unit}` has been quiet for {RECOVERY_QUIET_SECONDS // 60} min.")
        except Exception as e:
            print(f"[log-aggregator] recovery sweep failed: {e}")


def _run():
    import subprocess
    while not _stop.is_set():
        try:
            args = ["journalctl", "-f", "-n", "0", "--no-pager", "-o", "json"]
            for u in WATCHED_UNITS:
                args += ["-u", u]
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            while not _stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                try:
                    _handle_entry(entry)
                except Exception as e:
                    print(f"[log-aggregator] failed to handle entry: {e}")
            proc.terminate()
        except Exception as e:
            print(f"[log-aggregator] journalctl tail failed, retrying in 10s: {e}")
            _stop.wait(10)


def start():
    """Returns a {name: Thread} dict, not a bare Thread like every other
    module's start() - this is the one module that spawns two threads, and
    the previous version only ever returned the first one (`t`), leaving the
    recovery-sweep thread invisible to anything that only captured the
    return value. watchdog.py's registration loop special-cases a dict
    return to register both under distinct names."""
    t = threading.Thread(target=_run, daemon=True, name="log-aggregator")
    t.start()
    r = threading.Thread(target=_recovery_sweep_loop, daemon=True, name="log-aggregator-recovery")
    r.start()
    return {"log-aggregator": t, "log-aggregator-recovery": r}


def stop():
    _stop.set()
