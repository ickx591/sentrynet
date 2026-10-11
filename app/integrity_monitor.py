"""
Watches a defined set of critical config files (nginx configs, systemd unit
files, and each app's .env/.admin.json/config.json) for unexpected changes.

Never stores or alerts with file CONTENTS - only path + SHA-256 hash - so
this is safe to run even against files that hold secrets (.env.postgres
etc.). A hash change just means "this file is different now"; the operator
still has to go look at it themselves.

Runs on a slow poll (not a filesystem watch) since these files change rarely
and correctness matters more than sub-second latency here.
"""

import glob
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from models import IntegrityEvent
from notify import send_discord_alert
import alert_settings

SCRIPT_DIR = Path(__file__).parent
BASELINE_FILE = SCRIPT_DIR / ".integrity_baseline.json"
WATCHED_GLOBS_FILE = SCRIPT_DIR / "config" / "watched_files.txt"
CHECK_INTERVAL_SECONDS = 300


def _load_watched_globs() -> list:
    # One glob pattern per line - '#' comments and blank lines ignored.
    # Ships with just the universal nginx/systemd paths; add your own apps'
    # secret-file globs (e.g. /srv/myapp/.env*) after install.
    try:
        lines = WATCHED_GLOBS_FILE.read_text().splitlines()
        globs = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return globs or ["/etc/nginx/nginx.conf"]
    except Exception:
        return ["/etc/nginx/nginx.conf"]


WATCHED_GLOBS = _load_watched_globs()

_stop = threading.Event()


def _current_files() -> set:
    files = set()
    for pattern in WATCHED_GLOBS:
        for p in glob.glob(pattern):
            if Path(p).is_file():
                files.add(p)
    return files


def _hash_file(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _load_baseline() -> dict:
    try:
        return json.loads(BASELINE_FILE.read_text())
    except Exception:
        return {}


def _save_baseline(baseline: dict):
    try:
        BASELINE_FILE.write_text(json.dumps(baseline))
    except Exception as e:
        print(f"[integrity-monitor] failed to save baseline: {e}")


def _check_once(first_run: bool):
    baseline = _load_baseline()
    current_paths = _current_files()
    new_baseline = {}
    changes = []

    for path in current_paths:
        new_hash = _hash_file(path)
        if new_hash is None:
            continue
        new_baseline[path] = new_hash
        old_hash = baseline.get(path)
        if old_hash is None:
            if not first_run:
                changes.append(("created", path, None, new_hash))
        elif old_hash != new_hash:
            changes.append(("modified", path, old_hash, new_hash))

    if not first_run:
        for path, old_hash in baseline.items():
            if path not in current_paths:
                changes.append(("deleted", path, old_hash, None))

    _save_baseline(new_baseline)

    if first_run:
        print(f"[integrity-monitor] baseline established: {len(new_baseline)} files tracked")
        return

    now = datetime.now(timezone.utc)
    alerts_on = alert_settings.is_enabled("config_integrity")
    for change_type, path, old_hash, new_hash in changes:
        IntegrityEvent.create(ts=now, path=path, change_type=change_type,
                               old_hash=old_hash, new_hash=new_hash)
        if alerts_on:
            send_discord_alert(
                f":warning: **Config file {change_type}**: `{path}`\n"
                f"(hash only - contents are never logged; go check it directly)"
            )


def _run():
    _check_once(first_run=True)
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        try:
            _check_once(first_run=False)
        except Exception as e:
            print(f"[integrity-monitor] check failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="integrity-monitor")
    t.start()
    return t


def stop():
    _stop.set()
