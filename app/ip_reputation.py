"""
AbuseIPDB per-IP reputation lookups - a different shape from threat_intel.py's
bulk TOR/datacenter/Spamhaus lists (those are periodic bulk pulls; this is an
authenticated, rate-limited, on-demand single-IP query). Optional - fully
inert until an API key is configured, same "bring your own credentials"
shape as the Discord webhook in notify.py.

Only meant to be called from heuristics.py for IPs already flagged by at
least one other signal (never as a standalone/first check) - AbuseIPDB's
free tier caps daily requests, so quota is spent only on already-somewhat-
suspicious traffic, not every request that hits the site.
"""

import os
import queue
import threading
import time
import requests
from env_store import update as update_environment

_lock = threading.Lock()

API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

CACHE_TTL_SECONDS = 24 * 3600
LOOKUP_TIMEOUT = 8
API_URL = "https://api.abuseipdb.com/api/v2/check"

_MISS = object()  # sentinel: "not cached / expired", distinct from a cached None

_cache: dict = {}  # ip -> (confidence_score_or_None, expires_at_wall_time)
_lookup_queue = queue.Queue(maxsize=1000)
_pending: set[str] = set()


def get_api_key() -> str:
    with _lock:
        return API_KEY


def set_api_key(key: str):
    """In-memory only - use persist_api_key to also survive a restart."""
    global API_KEY
    with _lock:
        API_KEY = (key or "").strip()


def persist_api_key(key: str):
    key = (key or "").strip()
    update_environment({"ABUSEIPDB_API_KEY": key})
    set_api_key(key)


def _cached(ip: str):
    with _lock:
        entry = _cache.get(ip)
        if entry and entry[1] > time.time():
            return entry[0]
        if entry:
            _cache.pop(ip, None)
    return _MISS


def is_bad_reputation(ip: str):
    """Returns AbuseIPDB's confidence score (0-100) if the key is configured
    and the IP has a nonzero abuse confidence, else None (not configured, IP
    is clean, or lookup failed). Cached both ways for CACHE_TTL_SECONDS so
    repeated calls for the same IP don't re-spend quota."""
    key = get_api_key()
    if not key:
        return None

    cached = _cached(ip)
    if cached is not _MISS:
        return cached

    with _lock:
        if ip in _pending:
            return None
        _pending.add(ip)
    try:
        _lookup_queue.put_nowait((ip, key))
    except queue.Full:
        with _lock:
            _pending.discard(ip)
        print("[ip-reputation] lookup queue full; dropping lookup")
    return None


def _lookup_worker():
    while True:
        ip, key = _lookup_queue.get()
        try:
            score = None
            resp = requests.get(
                API_URL,
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=LOOKUP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            confidence = data.get("abuseConfidenceScore")
            if isinstance(confidence, int) and confidence > 0:
                score = confidence
            with _lock:
                _cache[ip] = (score, time.time() + CACHE_TTL_SECONDS)
        except Exception as e:
            print(f"[ip-reputation] AbuseIPDB lookup failed for {ip}: {e}")
        finally:
            with _lock:
                _pending.discard(ip)
            _lookup_queue.task_done()


threading.Thread(target=_lookup_worker, daemon=True, name="ip-reputation").start()


def get_status() -> dict:
    with _lock:
        return {"configured": bool(API_KEY), "cache_size": len(_cache),
                "pending": len(_pending)}
