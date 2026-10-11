"""
Tails the active webserver's JSON access log (nginx or Apache - see
webserver_backend.py) from wherever it currently ends, parses each line,
enriches with GeoIP/UA, runs it through the threat heuristics, and batches
inserts into Postgres.

Runs as a background thread inside the FastAPI process (started from
main.py's startup event) - same pattern as sports-app-version-4/server.py's
_status_loop.
"""

import ipaddress
import json
import os
import time
import threading
import tempfile
from collections import deque
from datetime import datetime, timedelta, timezone

from models import Request, FlaggedIp, BlockedIp, AllowedIp, BlockedCountry, BlockAudit
from geoua import country_for_ip, parse_ua
from heuristics import score_request
from notify import send_discord_alert
import alert_settings
import webserver_backend

ACCESS_LOG = webserver_backend.ACCESS_LOG
BATCH_SIZE = 50
BATCH_FLUSH_SECONDS = 3
AUTO_BLOCK_SCORE = 5        # sum of active signals' severities that triggers auto-block
BLOCKLIST_RELOAD_INTERVAL = 30  # seconds between blocklist re-applications when auto-blocking
ALLOW_DENY_REFRESH_SECONDS = 30  # how often the in-memory allow/block-country sets are refreshed from Postgres

_stop = threading.Event()
_last_reload = 0.0
_reload_lock = threading.Lock()
_reload_timer = None
_blocklist_dirty = False
CHECKPOINT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ingest_checkpoint.json")

# In-memory caches refreshed periodically from Postgres, so the hot ingest
# path never hits the DB per-request just to check "is this IP allowlisted"
# or "is this country blocked".
_allowed_networks: list = []          # list of ipaddress.ip_network
_blocked_countries: set = set()
_last_allow_deny_refresh = 0.0


def _refresh_allow_deny_cache(force=False):
    global _allowed_networks, _blocked_countries, _last_allow_deny_refresh
    now = time.time()
    if not force and now - _last_allow_deny_refresh < ALLOW_DENY_REFRESH_SECONDS:
        return
    _last_allow_deny_refresh = now
    nets = []
    for a in AllowedIp.select(AllowedIp.ip):
        try:
            nets.append(ipaddress.ip_network(a.ip, strict=False))
        except ValueError:
            continue
    _allowed_networks = nets
    _blocked_countries = {c.country for c in BlockedCountry.select(BlockedCountry.country)}


def is_ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _allowed_networks:
        if addr.version == net.version and addr in net:
            return True
    return False


# ── Volumetric / DDoS baseline detection ────────────────────────────────────
# Distinct from heuristics.py's per-IP scoring: this looks at TOTAL traffic
# volume across every IP combined, so a genuinely distributed flood (many
# IPs, each individually under every per-IP threshold) still gets caught.
# EWMA baseline, checked periodically. Ordinary spikes (someone got linked
# on social media, a legit event started) are tracked for the dashboard's
# /api/volumetric-status but deliberately don't page anyone - only a
# sustained, extreme spike (the DDOS_* thresholds below) is worth a Discord
# alert, and even then only once on the way in and once on the way out.
VOLUMETRIC_WINDOW_SECONDS = 60
VOLUMETRIC_CHECK_INTERVAL = 30
VOLUMETRIC_SPIKE_MULTIPLIER = 4.0
VOLUMETRIC_MIN_FLOOR = 30   # requests/window below this never counts as a "spike" - a quiet box's tiny baseline would otherwise false-positive on ordinary noise
VOLUMETRIC_EWMA_ALPHA = 0.1

# DDoS tier: much higher multiplier/floor than an ordinary spike, and it has
# to stay there for DDOS_SUSTAIN_CHECKS consecutive checks (not just one
# reading) before it's treated as an actual attack rather than a brief burst.
DDOS_SPIKE_MULTIPLIER = 10.0
DDOS_MIN_FLOOR = 150
DDOS_SUSTAIN_CHECKS = 3  # * VOLUMETRIC_CHECK_INTERVAL = ~90s sustained before alerting

_request_timestamps: deque = deque()  # every request, globally, last VOLUMETRIC_WINDOW_SECONDS
_volumetric_baseline = None
_volumetric_in_spike = False
_last_volumetric_check = 0.0
_ddos_consecutive_hits = 0
_in_ddos = False


def _check_volumetric(now: float):
    global _volumetric_baseline, _volumetric_in_spike, _last_volumetric_check
    global _ddos_consecutive_hits, _in_ddos
    if now - _last_volumetric_check < VOLUMETRIC_CHECK_INTERVAL:
        return
    _last_volumetric_check = now
    while _request_timestamps and now - _request_timestamps[0] > VOLUMETRIC_WINDOW_SECONDS:
        _request_timestamps.popleft()
    current = len(_request_timestamps)

    if _volumetric_baseline is None:
        _volumetric_baseline = float(current)
        return

    was_in_spike = _volumetric_in_spike
    _volumetric_in_spike = current >= VOLUMETRIC_MIN_FLOOR and current >= _volumetric_baseline * VOLUMETRIC_SPIKE_MULTIPLIER

    if alert_settings.is_enabled("traffic_spikes"):
        if _volumetric_in_spike and not was_in_spike:
            send_discord_alert(
                f":chart_with_upwards_trend: **Traffic spike**: {current} requests/{VOLUMETRIC_WINDOW_SECONDS}s "
                f"(baseline ~{round(_volumetric_baseline)})"
            )
        elif was_in_spike and not _volumetric_in_spike:
            send_discord_alert(f":white_check_mark: **Traffic spike resolved**: back to {current} requests/{VOLUMETRIC_WINDOW_SECONDS}s")

    is_ddos_level = current >= DDOS_MIN_FLOOR and current >= _volumetric_baseline * DDOS_SPIKE_MULTIPLIER
    if is_ddos_level:
        _ddos_consecutive_hits += 1
    else:
        _ddos_consecutive_hits = 0

    if _ddos_consecutive_hits >= DDOS_SUSTAIN_CHECKS and not _in_ddos:
        _in_ddos = True
        if alert_settings.is_enabled("ddos"):
            send_discord_alert(
                f":rotating_light: **Possible DDoS**: {current} requests/{VOLUMETRIC_WINDOW_SECONDS}s, "
                f"sustained - baseline is only ~{round(_volumetric_baseline)}"
            )
    elif not is_ddos_level and _in_ddos:
        _in_ddos = False
        if alert_settings.is_enabled("ddos"):
            send_discord_alert(f":white_check_mark: **Traffic back to normal**: {current} requests/{VOLUMETRIC_WINDOW_SECONDS}s")

    # Only adapt the baseline while NOT in a spike - otherwise the baseline
    # would chase the attack and "normalize" it, defeating the point.
    if not _volumetric_in_spike:
        _volumetric_baseline = (VOLUMETRIC_EWMA_ALPHA * current) + ((1 - VOLUMETRIC_EWMA_ALPHA) * _volumetric_baseline)


def get_volumetric_status() -> dict:
    return {
        "current_per_window": len(_request_timestamps),
        "window_seconds": VOLUMETRIC_WINDOW_SECONDS,
        "baseline": round(_volumetric_baseline, 1) if _volumetric_baseline is not None else None,
        "in_spike": _volumetric_in_spike,
        "in_ddos": _in_ddos,
    }


# ── 5xx error-rate degradation ───────────────────────────────────────────────
# A traffic spike isn't necessarily bad (could just be real visitors), but a
# burst of server errors means something is actually broken - so this is
# tracked and alerted separately, as a "degraded" signal rather than a
# traffic-volume one.
FIVEXX_WINDOW_SECONDS = 300
FIVEXX_CHECK_INTERVAL = 30
FIVEXX_MIN_COUNT = 15     # fewer than this in the window is never worth paging over
FIVEXX_MIN_RATE = 0.15    # 5xx must also be at least this fraction of all requests in the window

_5xx_timestamps: deque = deque()
_all_timestamps: deque = deque()
_last_5xx_check = 0.0
_in_5xx_degraded = False


def _note_status(status: int, now: float):
    _all_timestamps.append(now)
    if status >= 500:
        _5xx_timestamps.append(now)


def _check_5xx(now: float):
    global _last_5xx_check, _in_5xx_degraded
    if now - _last_5xx_check < FIVEXX_CHECK_INTERVAL:
        return
    _last_5xx_check = now
    while _5xx_timestamps and now - _5xx_timestamps[0] > FIVEXX_WINDOW_SECONDS:
        _5xx_timestamps.popleft()
    while _all_timestamps and now - _all_timestamps[0] > FIVEXX_WINDOW_SECONDS:
        _all_timestamps.popleft()

    err_count = len(_5xx_timestamps)
    total = len(_all_timestamps)
    rate = (err_count / total) if total else 0.0
    is_degraded = err_count >= FIVEXX_MIN_COUNT and rate >= FIVEXX_MIN_RATE

    if is_degraded and not _in_5xx_degraded:
        _in_5xx_degraded = True
        if alert_settings.is_enabled("site_5xx_degraded"):
            send_discord_alert(
                f":warning: **Site degraded**: {err_count} HTTP 5xx responses in the last "
                f"{FIVEXX_WINDOW_SECONDS // 60} min ({round(rate * 100)}% of traffic)"
            )
    elif not is_degraded and _in_5xx_degraded:
        _in_5xx_degraded = False
        if alert_settings.is_enabled("site_5xx_degraded"):
            send_discord_alert(":white_check_mark: **Site back to normal**: 5xx rate has recovered")


def is_ip_covered_by_block(ip: str) -> bool:
    """True if `ip` is already blocked, either by an exact match or by an
    existing CIDR block that covers it - prevents redundant duplicate block
    rows (e.g. auto-blocking single IPs one by one inside a /24 someone
    already blocked as a range)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for b in BlockedIp.select(BlockedIp.ip):
        try:
            net = ipaddress.ip_network(b.ip, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def _save_checkpoint(inode, offset):
    fd, temporary = tempfile.mkstemp(prefix=".ingest-checkpoint.", dir=os.path.dirname(CHECKPOINT_FILE))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"inode": inode, "offset": offset}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, CHECKPOINT_FILE)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _open_log(path, initial=False):
    # errors="replace": a single malformed byte in the access log (garbage
    # bytes in a request path/header from a bot or a malformed request -
    # confirmed cause of the 2026-07-13 22:46 incident, a stray 0xc0 byte)
    # must not be allowed to raise out of readline() - that took down the
    # tailer thread entirely, silently, with nothing left to restart it,
    # and no new traffic was recorded for the next ~10 hours until someone
    # noticed. Replacing the bad byte with U+FFFD keeps that one line's
    # non-UTF8 field slightly mangled but keeps the tailer running.
    f = open(path, "r", errors="replace")
    inode = os.fstat(f.fileno()).st_ino
    restored = False
    if initial:
        try:
            with open(CHECKPOINT_FILE) as checkpoint_file:
                checkpoint = json.load(checkpoint_file)
            if checkpoint.get("inode") == inode:
                offset = int(checkpoint.get("offset", 0))
                if 0 <= offset <= os.fstat(f.fileno()).st_size:
                    f.seek(offset)
                    restored = True
        except Exception:
            pass
    if initial and not restored:
        f.seek(0, os.SEEK_END)
    return f


def _parse_line(line: str):
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if webserver_backend.WEBSERVER == "apache":
        d = webserver_backend.normalize_apache_fields(d)
    ts_raw = d.get("ts")
    try:
        ts = datetime.fromisoformat(ts_raw)
    except (TypeError, ValueError):
        ts = datetime.now(timezone.utc)
    request_time = None
    if d.get("request_time") not in (None, "-"):
        request_time = float(d.get("request_time")) / webserver_backend.REQUEST_TIME_DIVISOR
    return {
        "ts": ts,
        "ip": d.get("ip") or "0.0.0.0",
        "host": d.get("host") or "-",
        "method": d.get("method") or "GET",
        "path": (d.get("path") or "")[:2000],
        "query": (d.get("query") or "")[:2000] or None,
        "status": int(d.get("status") or 0),
        "bytes": int(d.get("bytes") or 0),
        "referer": (d.get("referer") or "")[:2000] or None,
        "user_agent": (d.get("ua") or "")[:1000] or None,
        "request_time": request_time,
        "ssl_protocol": d.get("ssl") or None,
    }


def _flush(batch, flagged_touch):
    if batch:
        Request.insert_many(batch).execute()
        batch.clear()
    if flagged_touch:
        now = datetime.now(timezone.utc)
        for ip, (country, signals) in flagged_touch.items():
            score = sum(s.get("severity", 1) for s in signals)
            row = FlaggedIp.get_or_none(FlaggedIp.ip == ip)
            if row:
                row.country = country
                row.signals = json.dumps(signals)
                row.score = score
                row.last_seen = now
                row.save()
            else:
                FlaggedIp.create(ip=ip, country=country, signals=json.dumps(signals),
                                  score=score, first_seen=now, last_seen=now)
            if score >= AUTO_BLOCK_SCORE and not is_ip_covered_by_block(ip):
                sig_types = ", ".join(s["type"] for s in signals)
                _auto_block(ip, f"auto-blocked (score {score}): {sig_types}", score=score)
        flagged_touch.clear()


def _schedule_blocklist_locked(delay):
    global _reload_timer
    if _reload_timer is None:
        _reload_timer = threading.Timer(delay, _apply_pending_blocklist)
        _reload_timer.daemon = True
        _reload_timer.start()


def _apply_pending_blocklist():
    global _last_reload, _reload_timer, _blocklist_dirty
    with _reload_lock:
        _reload_timer = None
        if not _blocklist_dirty:
            return
        _blocklist_dirty = False
    try:
        webserver_backend.regenerate_blocklist()
        with _reload_lock:
            _last_reload = time.time()
    except Exception as e:
        print(f"[ingest] blocklist update failed: {e}")
        with _reload_lock:
            _blocklist_dirty = True
            _schedule_blocklist_locked(BLOCKLIST_RELOAD_INTERVAL)


def _regenerate_blocklist():
    global _blocklist_dirty
    with _reload_lock:
        _blocklist_dirty = True
        delay = max(0.0, BLOCKLIST_RELOAD_INTERVAL - (time.time() - _last_reload))
        _schedule_blocklist_locked(delay)


def _auto_block_ttl(score: int):
    """Severity-tiered auto-block lifetime, keyed off the same FlaggedIp score
    that triggered the block (AUTO_BLOCK_SCORE=5 is the floor to auto-block at
    all). Low-confidence blocks (a single borderline signal) self-heal fast
    instead of sitting permanently blocked on what might have been a false
    positive; IPs with enough stacked signals to clear score 12 (multiple
    independent signals, not just one strong one) stay blocked indefinitely.
    _auto_block_country is deliberately not covered by this - country-level
    blocks are coarser and rarer, with less need for auto-expiry churn."""
    if score >= 12:
        return None
    if score >= 8:
        return datetime.now(timezone.utc) + timedelta(days=7)
    return datetime.now(timezone.utc) + timedelta(hours=24)


def _auto_block(ip: str, reason: str, score: int = 12):
    if BlockedIp.get_or_none(BlockedIp.ip == ip):
        return
    now = datetime.now(timezone.utc)
    expires_at = _auto_block_ttl(score)
    BlockedIp.insert(
        ip=ip, reason=reason, blocked_at=now, blocked_by="auto", expires_at=expires_at,
    ).on_conflict_ignore().execute()
    BlockAudit.create(ts=now, action="block", target=ip, reason=reason, actor="auto")
    _regenerate_blocklist()
    if alert_settings.is_enabled("ip_blocks"):
        expiry_note = f"\nExpires: {expires_at.isoformat()}" if expires_at else "\nPermanent (score >= 12)"
        send_discord_alert(f":no_entry: **IP auto-blocked**: `{ip}`\nReason: {reason}{expiry_note}")


def _auto_block_country(ip: str, country: str):
    if BlockedIp.get_or_none(BlockedIp.ip == ip):
        return
    reason = f"auto-blocked: country {country} is on the blocked-countries list"
    now = datetime.now(timezone.utc)
    BlockedIp.insert(
        ip=ip, reason=reason, blocked_at=now, blocked_by="auto", expires_at=None,
    ).on_conflict_ignore().execute()
    BlockAudit.create(ts=now, action="block", target=ip, reason=reason, actor="auto")
    _regenerate_blocklist()


def _run():
    # Wait for the log file to exist (fresh box edge case).
    while not os.path.exists(ACCESS_LOG) and not _stop.is_set():
        time.sleep(1)
    if _stop.is_set():
        return

    _refresh_allow_deny_cache(force=True)

    f = _open_log(ACCESS_LOG, initial=True)
    inode = os.fstat(f.fileno()).st_ino
    batch = []
    flagged_touch = {}
    last_flush = time.time()

    while not _stop.is_set():
        try:
            line = f.readline()
            if not line:
                # Detect logrotate (file replaced) by inode change.
                try:
                    if os.stat(ACCESS_LOG).st_ino != inode:
                        f.close()
                        f = _open_log(ACCESS_LOG, initial=False)
                        inode = os.fstat(f.fileno()).st_ino
                        continue
                except FileNotFoundError:
                    pass
                if batch or flagged_touch:
                    _flush(batch, flagged_touch)
                    _save_checkpoint(inode, f.tell())
                    last_flush = time.time()
                _refresh_allow_deny_cache()
                time.sleep(0.5)
                continue

            parsed = _parse_line(line)
            if not parsed:
                continue

            parsed["country"] = country_for_ip(parsed["ip"])
            ua_info = parse_ua(parsed["user_agent"])
            parsed["device"] = ua_info["device"]
            parsed["os"] = ua_info["os"]
            parsed["browser"] = ua_info["browser"]
            parsed["is_bot"] = ua_info["is_bot"]

            now_mono = time.time()
            _request_timestamps.append(now_mono)
            _check_volumetric(now_mono)
            _note_status(parsed["status"], now_mono)
            _check_5xx(now_mono)

            if is_ip_allowed(parsed["ip"]):
                # Still logged for visibility (so allowlisted traffic shows up in
                # stats/feed like anyone else's) - just never scored, flagged, or
                # auto-blocked.
                batch.append(parsed)
            else:
                if parsed["country"] in _blocked_countries and not is_ip_covered_by_block(parsed["ip"]):
                    _auto_block_country(parsed["ip"], parsed["country"])

                signals = score_request(parsed["ip"], parsed["path"], parsed["status"],
                                         parsed["method"], parsed["user_agent"], parsed["request_time"], parsed["query"],
                                         parsed["host"])
                if signals:
                    flagged_touch[parsed["ip"]] = (parsed["country"], signals)

                batch.append(parsed)

            if len(batch) >= BATCH_SIZE or time.time() - last_flush >= BATCH_FLUSH_SECONDS:
                _flush(batch, flagged_touch)
                _save_checkpoint(inode, f.tell())
                last_flush = time.time()
                _refresh_allow_deny_cache()
        except Exception as e:
            # Whatever this is, it must not be allowed to end the thread -
            # there is no supervisor to restart it (see main.py's startup
            # event: ingest.start() runs once), so an uncaught exception
            # here means silent, permanent loss of traffic recording until
            # someone notices and restarts the service by hand (exactly
            # what happened on 2026-07-13). Log it and keep going.
            print(f"[ingest] tailer error, continuing: {type(e).__name__}: {e}")
            time.sleep(0.5)


def start():
    t = threading.Thread(target=_run, daemon=True, name="access-log-tailer")
    t.start()
    return t


def stop():
    _stop.set()
    with _reload_lock:
        if _reload_timer is not None:
            _reload_timer.cancel()
