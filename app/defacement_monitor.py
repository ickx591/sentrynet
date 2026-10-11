"""
Watches the top-level files of each discovered web root (nginx `root` /
Apache `DocumentRoot`) for unexpected changes. A defaced customer-facing
page is a meaningfully different, more urgent event than an ordinary config
file touch, so this gets its own model, baseline file, and alert category
rather than being folded into integrity_monitor.py's "config_integrity"
alert - same hash/baseline/diff/poll shape as that module, on its own
thread.

Deliberately non-recursive: only a web root's top-level files are watched,
not everything under it. Recursing into asset/upload/cache directories that
regenerate themselves as part of normal operation would make this noisy to
the point of being ignored; a defacement almost always replaces or adds a
top-level page, so that's what's watched.

Web root discovery re-runs hourly (vhosts rarely change, but shouldn't need
a restart when a customer adds one); the hash check itself runs on the
same 300s cadence as integrity_monitor.py.
"""

import glob
import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from models import DefacementEvent
from notify import send_discord_alert
import alert_settings

SCRIPT_DIR = Path(__file__).parent
BASELINE_FILE = SCRIPT_DIR / ".defacement_baseline.json"
CHECK_INTERVAL_SECONDS = 300
DISCOVERY_INTERVAL_SECONDS = 3600

_NGINX_ROOT_RE = re.compile(r"root\s+([^;]+);")
_APACHE_DOCROOT_RE = re.compile(r"DocumentRoot\s+(\S+)")

_stop = threading.Event()
_lock = threading.Lock()
_web_roots: set = set()
_last_discovery = 0.0


def _discover_web_roots() -> set:
    roots = set()
    for conf_glob, rx in (
        ("/etc/nginx/sites-enabled/*", _NGINX_ROOT_RE),
        ("/etc/apache2/sites-enabled/*", _APACHE_DOCROOT_RE),
    ):
        for conf_path in glob.glob(conf_glob):
            try:
                text = Path(conf_path).read_text(errors="ignore")
            except Exception:
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = rx.search(stripped)
                if m:
                    root = m.group(1).strip().strip('"').strip("'")
                    if root and Path(root).is_dir():
                        roots.add(root)
    return roots


def _refresh_web_roots(force=False):
    global _last_discovery, _web_roots
    now = time.time()
    if not force and now - _last_discovery < DISCOVERY_INTERVAL_SECONDS:
        return
    _last_discovery = now
    with _lock:
        _web_roots = _discover_web_roots()


def _current_files() -> set:
    with _lock:
        roots = set(_web_roots)
    files = set()
    for root in roots:
        try:
            for p in glob.glob(str(Path(root) / "*")):
                if Path(p).is_file():
                    files.add(p)
        except Exception:
            continue
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
        print(f"[defacement-monitor] failed to save baseline: {e}")


def _check_once(first_run: bool):
    _refresh_web_roots(force=first_run)
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
        print(f"[defacement-monitor] baseline established: {len(new_baseline)} files across {len(_web_roots)} web roots tracked")
        return

    now = datetime.now(timezone.utc)
    alerts_on = alert_settings.is_enabled("defacement")
    for change_type, path, old_hash, new_hash in changes:
        DefacementEvent.create(ts=now, path=path, change_type=change_type,
                                old_hash=old_hash, new_hash=new_hash)
        if alerts_on:
            send_discord_alert(
                f":rotating_light: **Possible defacement - web root file {change_type}**: `{path}`\n"
                f"(hash only - go check the live page directly)"
            )


def get_status() -> dict:
    with _lock:
        return {"web_roots": sorted(_web_roots)}


def _run():
    _check_once(first_run=True)
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        try:
            _check_once(first_run=False)
        except Exception as e:
            print(f"[defacement-monitor] check failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="defacement-monitor")
    t.start()
    return t


def stop():
    _stop.set()
