"""
Periodic per-systemd-unit memory/CPU sampling via `systemctl show`'s cgroup
properties, plus an `is-active` check. Powers the resource-trend view and a
service-health state machine: each unit is "ok", "degraded" (critical/leak-
level resource usage), or "down" (not active). Discord only hears about
transitions - once when a unit gets worse, once when it fully recovers - not
a running commentary while it stays in either bad state.

A resource spike alone can't distinguish "real leak" from "a known,
scheduled batch job legitimately working hard for a while" - both look
identical as "elevated for several consecutive samples". config/
resource_maintenance_windows.txt lets an admin declare the latter for a
specific unit (e.g. a cron-triggered data-refresh job that runs every few
hours and takes longer than MEMORY_SUSTAIN_SAMPLES/CPU_SUSTAIN_SAMPLES to
finish) so it's excluded from leak/CPU-critical detection entirely during
its known window - the real numbers still get recorded for the resource-
trend view, just never counted toward "degraded" or fed into the rolling
baseline (so the spike itself never skews what "normal" looks like).
"""

import subprocess
import statistics
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from models import ServiceResourceSample
from notify import send_discord_alert
import alert_settings
from log_aggregator import WATCHED_UNITS

SCRIPT_DIR = Path(__file__).parent
MAINTENANCE_WINDOWS_FILE = SCRIPT_DIR / "config" / "resource_maintenance_windows.txt"

SAMPLE_INTERVAL_SECONDS = 60
ROLLING_SAMPLE_COUNT = 60  # 1 hour of history at the sample interval above
LEAK_MULTIPLIER = 3.0
LEAK_MIN_BYTES = 100 * 1024 * 1024  # ignore tiny services - noise, not a leak
MEMORY_SUSTAIN_SAMPLES = 3  # consecutive elevated samples before it counts as a leak, not
                            # a scheduled batch job's brief spike (e.g. a cron-triggered
                            # pipeline step) - a real leak is still elevated minutes later,
                            # a passing spike isn't
CPU_CRITICAL_PERCENT = 90.0
CPU_SUSTAIN_SAMPLES = 3  # consecutive samples pegged before it counts as "degraded", not a brief burst

_stop = threading.Event()
_last_cpu: dict = {}       # unit -> (cpu_ns, wall_time)
_memory_history: dict = defaultdict(lambda: deque(maxlen=ROLLING_SAMPLE_COUNT))
_memory_high_streak: dict = defaultdict(int)
_cpu_high_streak: dict = defaultdict(int)
_unit_state: dict = {}     # unit -> "ok" | "degraded" | "down"


def _is_active(unit: str) -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", f"{unit}.service"],
                            capture_output=True, text=True, timeout=5)
        # "reloading" is a real, non-disruptive ActiveState systemd reports
        # for the brief window a `systemctl reload` takes to apply (e.g. a
        # cert renewal deploy hook reloading nginx) - the unit's master
        # process never stops, so treating this as "down" was a confirmed
        # false-positive: a sample landing during that window fired a
        # "Service down" alert immediately followed by "recovered" on the
        # very next sample, for a reload that never actually took anything
        # offline.
        return r.stdout.strip() in ("active", "reloading")
    except Exception:
        return True  # unknown - don't false-positive a "down" alert on a systemctl hiccup


CGROUP_BASE = Path("/sys/fs/cgroup/system.slice")


def _read_cgroup_props(unit: str):
    try:
        r = subprocess.run(
            ["systemctl", "show", f"{unit}.service", "--property=MemoryCurrent,CPUUsageNSec"],
            capture_output=True, text=True, timeout=5,
        )
        props = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                props[k] = v
        mem = int(props.get("MemoryCurrent", "")) if props.get("MemoryCurrent", "").isdigit() else None
        cpu_ns = int(props.get("CPUUsageNSec", "")) if props.get("CPUUsageNSec", "").isdigit() else None

        # Prefer anon (actual heap/allocation memory) over MemoryCurrent's
        # raw total: under cgroup v2, MemoryCurrent also counts reclaimable
        # page cache, so a unit that reads or logs a lot (e.g. this app's
        # own journalctl-tailing threads) can inflate it by gigabytes with
        # no real memory pressure at all - confirmed cause of a false
        # "possible memory leak" alert, where anon was in line with the
        # unit's normal baseline while MemoryCurrent had climbed into the
        # gigabytes purely from page cache. Falls back to MemoryCurrent if
        # memory.stat isn't readable (e.g. cgroup v1).
        try:
            stat_text = (CGROUP_BASE / f"{unit}.service" / "memory.stat").read_text()
            for line in stat_text.splitlines():
                if line.startswith("anon "):
                    mem = int(line.split()[1])
                    break
        except Exception:
            pass

        return mem, cpu_ns
    except Exception:
        return None, None


def _apply_state_transition(unit: str, new_state: str, reason: str = ""):
    prev = _unit_state.get(unit, "ok")
    if new_state == prev:
        return
    _unit_state[unit] = new_state
    if not alert_settings.is_enabled("service_health"):
        return

    if new_state == "down":
        send_discord_alert(f":red_circle: **Service down**: `{unit}` is not active.")
    elif new_state == "degraded" and prev == "ok":
        send_discord_alert(f":warning: **Service degraded**: `{unit}`\n{reason}")
    elif new_state == "ok" and prev in ("down", "degraded"):
        send_discord_alert(f":white_check_mark: **Service recovered**: `{unit}` is back to normal (was {prev}).")
    # degraded<->down transitions besides the ones above are intentionally
    # silent - the unit already has an active alert out for being unwell;
    # only a full recovery to "ok" or an outright "down" gets a new post.


def get_unit_states() -> dict:
    return dict(_unit_state)


def _load_maintenance_windows() -> dict:
    """unit -> (interval_hours, duration_minutes). One line per unit:
    "<unit>  every:<N>h  for:<M>m" - '#' comments and blank lines ignored.
    Matches a plain "runs every N hours, takes about M minutes" schedule
    (e.g. cron's `0 */4 * * *`), not full cron syntax - that's all this
    codebase's own scheduled jobs actually need."""
    windows = {}
    try:
        lines = MAINTENANCE_WINDOWS_FILE.read_text().splitlines()
    except Exception:
        return windows
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        unit, every_part, for_part = parts
        try:
            interval_hours = int(every_part.split(":", 1)[1].rstrip("hH"))
            duration_minutes = int(for_part.split(":", 1)[1].rstrip("mM"))
        except (IndexError, ValueError):
            continue
        if interval_hours > 0 and duration_minutes > 0:
            windows[unit] = (interval_hours, duration_minutes)
    return windows


def _in_maintenance_window(unit: str, now, windows: dict) -> bool:
    win = windows.get(unit)
    if not win:
        return False
    interval_hours, duration_minutes = win
    return now.hour % interval_hours == 0 and now.minute < duration_minutes


def _sample_once():
    now = datetime.now(timezone.utc)
    wall_now = time.time()
    maintenance_windows = _load_maintenance_windows()
    for unit in WATCHED_UNITS:
        if not _is_active(unit):
            _apply_state_transition(unit, "down")
            continue

        # Resource trending doesn't apply cleanly to the web server or
        # database themselves (no fixed baseline the way an app service
        # has) - just track up/down for those. Prefix match on "postgresql"
        # rather than a hardcoded version suffix so this doesn't silently
        # stop matching after a Postgres upgrade.
        if unit in ("nginx", "apache2", "httpd") or unit.startswith("postgresql"):
            _apply_state_transition(unit, "ok")
            continue

        mem, cpu_ns = _read_cgroup_props(unit)
        if mem is None:
            continue

        cpu_percent = None
        prev = _last_cpu.get(unit)
        if prev is not None and cpu_ns is not None:
            prev_ns, prev_wall = prev
            wall_delta = wall_now - prev_wall
            if wall_delta > 0:
                cpu_percent = round(max(0.0, (cpu_ns - prev_ns) / 1e9 / wall_delta * 100), 2)
        if cpu_ns is not None:
            _last_cpu[unit] = (cpu_ns, wall_now)

        ServiceResourceSample.create(ts=now, unit=unit, memory_bytes=mem, cpu_percent=cpu_percent)

        if _in_maintenance_window(unit, now, maintenance_windows):
            # A known, scheduled batch job is expected to be working hard
            # right now - the real numbers are still recorded above for the
            # resource-trend view, but never counted toward "degraded" and
            # never fed into the rolling baseline, so the spike can't skew
            # what "normal" looks like once the window closes.
            _memory_high_streak[unit] = 0
            _cpu_high_streak[unit] = 0
            _apply_state_transition(unit, "ok")
            continue

        history = _memory_history[unit]
        degraded_reason = None
        is_memory_spiking = False
        baseline = None

        if len(history) >= 10 and mem >= LEAK_MIN_BYTES:
            baseline = statistics.median(history)
            if baseline > 0 and mem >= baseline * LEAK_MULTIPLIER:
                is_memory_spiking = True
        history.append(mem)

        if is_memory_spiking:
            _memory_high_streak[unit] += 1
        else:
            _memory_high_streak[unit] = 0

        if _memory_high_streak[unit] >= MEMORY_SUSTAIN_SAMPLES:
            span_min = len(history) * SAMPLE_INTERVAL_SECONDS // 60
            span_label = f"{span_min}m" if span_min < 60 else f"{span_min // 60}h"
            degraded_reason = (
                f"Possible memory leak: {mem // (1024*1024)}MB vs. its own recent median "
                f"{int(baseline) // (1024*1024)}MB, sustained for {_memory_high_streak[unit]}+ min "
                f"(baseline from the last ~{span_label} of samples)."
            )

        if cpu_percent is not None and cpu_percent >= CPU_CRITICAL_PERCENT:
            _cpu_high_streak[unit] += 1
        else:
            _cpu_high_streak[unit] = 0
        if degraded_reason is None and _cpu_high_streak[unit] >= CPU_SUSTAIN_SAMPLES:
            degraded_reason = f"CPU at {cpu_percent}% for {_cpu_high_streak[unit]} consecutive samples."

        _apply_state_transition(unit, "degraded" if degraded_reason else "ok", degraded_reason or "")


def _run():
    while not _stop.wait(SAMPLE_INTERVAL_SECONDS):
        try:
            _sample_once()
        except Exception as e:
            print(f"[resource-monitor] sample failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="resource-monitor")
    t.start()
    return t


def stop():
    _stop.set()
