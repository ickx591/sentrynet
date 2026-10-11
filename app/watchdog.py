"""
Supervises every other module's background thread(s) and restarts one that
has silently died. Nothing else in SentryNet calls .is_alive() on any of
these threads - a background monitor thread that dies on an uncaught
exception (a malformed log line, a transient network error that escapes a
narrower try/except, etc.) would otherwise stop doing its job permanently,
with no crash, no alert, and nothing to notice or restart it. This module is
the general mechanism that catches that failure mode for every background
thread SentryNet runs.

Usage: main.py's startup event calls register(name, thread, restart_fn) once
per module, right after that module's own start() call, then watchdog.start()
once every module is registered. `thread` may be a single Thread or a list of
Threads (log_aggregator.py spawns two - see below); `restart_fn` must be a
zero-arg callable that (re)starts fresh thread(s) and returns them in the same
shape main.py originally captured (single Thread, or a {name: Thread} dict).

log_aggregator.py is registered as ONE combined entry covering both of its
threads (tailer + recovery-sweep), not two separate ones: its restart_fn
(log_aggregator.start()) always (re)spawns both threads together as a pair.
Registering them as two independent entries would mean detecting just ONE of
them dead and calling that same shared restart_fn would spawn a fresh PAIR of
threads while the registry only ever updates the one entry that triggered the
restart - leaving the other slot still pointing at the old thread object,
with the freshly spawned duplicate never tracked or stopped anywhere.
Treating them as one unit (dead if EITHER sub-thread has died, restart
replaces both tracked references at once) avoids that entirely.
"""

import threading
from datetime import datetime, timezone

from models import AppLogEvent
from notify import send_discord_alert
import alert_settings

CHECK_INTERVAL_SECONDS = 60

_stop = threading.Event()
_lock = threading.Lock()
_registry: dict = {}  # name -> {"threads": [Thread, ...], "restart_fn": callable, "restart_count": int, "last_restart_at": str|None}


def register(name: str, thread, restart_fn):
    """`thread` is a single Thread for every module except log_aggregator.py,
    which passes a list of its two threads (see module docstring)."""
    threads = thread if isinstance(thread, list) else [thread]
    with _lock:
        _registry[name] = {
            "threads": threads,
            "restart_fn": restart_fn,
            "restart_count": 0,
            "last_restart_at": None,
        }


def _normalize_restart_result(result) -> list:
    """restart_fn's return shape mirrors the module's own start(): a bare
    Thread for every module except log_aggregator.py, which returns a
    {name: Thread} dict - normalize either into a plain list of threads."""
    if isinstance(result, dict):
        return list(result.values())
    return [result]


def _check_once():
    with _lock:
        names = list(_registry.keys())
    for name in names:
        with _lock:
            entry = _registry.get(name)
        if entry is None:
            continue
        if all(t.is_alive() for t in entry["threads"]):
            continue

        # At least one of this entry's threads has died - restart the whole
        # entry (see module docstring for why log_aggregator's pair is
        # restarted together rather than independently).
        try:
            fresh = entry["restart_fn"]()
        except Exception as e:
            print(f"[watchdog] failed to restart '{name}': {e}")
            continue

        now = datetime.now(timezone.utc)
        with _lock:
            entry["threads"] = _normalize_restart_result(fresh)
            entry["restart_count"] += 1
            entry["last_restart_at"] = now.isoformat()
            restart_count = entry["restart_count"]

        try:
            AppLogEvent.create(
                ts=now, unit=name, level="critical",
                message=(f"Background thread '{name}' was found dead and has been "
                          f"restarted (restart #{restart_count} for this process lifetime).")
            )
        except Exception as e:
            print(f"[watchdog] failed to log restart for '{name}': {e}")

        if alert_settings.is_enabled("thread_watchdog"):
            send_discord_alert(
                f":rotating_light: **Background thread restarted**: `{name}` had stopped "
                f"running and was automatically restarted (restart #{restart_count})."
            )


def status() -> list:
    with _lock:
        return [
            {
                "name": name,
                "alive": all(t.is_alive() for t in entry["threads"]),
                "restart_count": entry["restart_count"],
                "last_restart_at": entry["last_restart_at"],
            }
            for name, entry in sorted(_registry.items())
        ]


def _run():
    # Same shape as every other monitor's loop: check first, then wait - a
    # bug in one check cycle must never kill the watchdog itself, which is
    # the one thread nothing else supervises.
    while not _stop.is_set():
        try:
            _check_once()
        except Exception as e:
            print(f"[watchdog] check cycle failed: {e}")
        _stop.wait(CHECK_INTERVAL_SECONDS)


def start():
    t = threading.Thread(target=_run, daemon=True, name="watchdog")
    t.start()
    return t


def stop():
    _stop.set()
