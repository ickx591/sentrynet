"""
Twice-daily Discord summary (09:00 and 21:00 UTC) - the only "routine" post
SentryNet makes. Every other Discord alert only fires on a state change
(a service going down/degraded, or recovering) - this is the one heartbeat
that posts regardless, combining traffic/security stats since the last
digest with a snapshot of SentryNet's own Postgres health.
"""

import threading
from datetime import datetime, timedelta, timezone

from models import db, Request, FlaggedIp, BlockedIp
from notify import send_discord_alert
import alert_settings

DIGEST_HOURS = (9, 21)
CHECK_INTERVAL_SECONDS = 60
DIGEST_WINDOW_HOURS = 12  # matches the 12h gap between 09:00 and 21:00

_stop = threading.Event()
_last_fired_key = None  # (date, hour) already posted - guards against double-firing


def _traffic_summary(since) -> str:
    total = Request.select().where(Request.ts >= since).count()
    unique_ips = Request.select(Request.ip).where(Request.ts >= since).distinct().count()

    cursor = db.execute_sql(
        "SELECT country, count(*) FROM requests WHERE ts >= %s AND country IS NOT NULL "
        "GROUP BY country ORDER BY count(*) DESC LIMIT 3",
        (since,),
    )
    top_countries = ", ".join(f"{c} {n}" for c, n in cursor.fetchall()) or "n/a"

    cursor = db.execute_sql(
        "SELECT host, count(*) FROM requests WHERE ts >= %s GROUP BY host ORDER BY count(*) DESC LIMIT 3",
        (since,),
    )
    top_hosts = ", ".join(f"{h} ({n})" for h, n in cursor.fetchall()) or "n/a"

    cursor = db.execute_sql(
        "SELECT status / 100, count(*) FROM requests WHERE ts >= %s GROUP BY status / 100",
        (since,),
    )
    by_class = dict(cursor.fetchall())
    total_for_pct = sum(by_class.values()) or 1
    status_line = ", ".join(
        f"{cls}xx {round(100 * n / total_for_pct)}%"
        for cls, n in sorted(by_class.items())
    ) or "n/a"

    new_flagged = FlaggedIp.select().where(FlaggedIp.first_seen >= since).count()
    new_blocked = BlockedIp.select().where(BlockedIp.blocked_at >= since).count()

    return (
        f":bar_chart: **Traffic & security** (last {DIGEST_WINDOW_HOURS}h)\n"
        f"Requests: **{total}** · Unique IPs: **{unique_ips}**\n"
        f"Top countries: {top_countries}\n"
        f"Top hosts: {top_hosts}\n"
        f"Status: {status_line}\n"
        f"Flagged IPs: {new_flagged} new · Blocked: {new_blocked} new"
    )


def _db_health_summary() -> str:
    cursor = db.execute_sql("SHOW max_connections")
    max_conn = int(cursor.fetchone()[0])
    cursor = db.execute_sql("SELECT count(*) FROM pg_stat_activity")
    total_conn = cursor.fetchone()[0]
    pct = round(100 * total_conn / max_conn) if max_conn else 0

    cursor = db.execute_sql("SELECT sum(blks_hit), sum(blks_read) FROM pg_stat_database")
    hit, read = cursor.fetchone()
    hit, read = hit or 0, read or 0
    hit_ratio = round(100 * hit / (hit + read), 1) if (hit + read) else None

    cursor = db.execute_sql("SELECT pg_size_pretty(pg_database_size(current_database()))")
    size = cursor.fetchone()[0]

    conn_emoji = "\U0001f7e2" if pct < 70 else ("\U0001f7e1" if pct < 90 else "\U0001f534")

    return (
        f":elephant: **Postgres health**\n"
        f"{conn_emoji} Connections: **{total_conn}/{max_conn}** ({pct}%)\n"
        f"Cache hit ratio: {hit_ratio}%" + (f"\nDatabase size: {size}" if size else "")
    )


def _post_digest():
    if not alert_settings.is_enabled("digest"):
        return
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=DIGEST_WINDOW_HOURS)
    send_discord_alert(_traffic_summary(since) + "\n\n" + _db_health_summary())


def _run():
    global _last_fired_key
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        now = datetime.now(timezone.utc)
        if now.hour in DIGEST_HOURS and now.minute < 2:
            key = (now.date(), now.hour)
            if key != _last_fired_key:
                _last_fired_key = key
                try:
                    _post_digest()
                except Exception as e:
                    print(f"[digest] failed to post: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="digest")
    t.start()
    return t


def stop():
    _stop.set()
