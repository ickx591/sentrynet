"""
Aggregates yesterday's requests into one DailyStatRollup row per host (plus
one combined all-hosts row), so long-term trends survive past the 30-day
window that cleanup_old_requests.py hard-deletes raw `requests` rows within.
Run daily via cron (see /etc/cron.d/sentrynet-rollup), scheduled before that
same cleanup job - not that the two could actually race (this only reads
yesterday's data, cleanup only deletes 30-day-old data), just good hygiene
to keep them ordered.

Deliberately a standalone cron script, not an in-process thread like every
other background job SentryNet runs: it's a one-shot batch aggregation with
no continuous state or live-alerting need, so it has no business being
another thing for watchdog.py to supervise - if a run fails, the cron log
shows it, which is a much smaller blast radius than a silently-dead
background thread.
"""

import argparse
from datetime import datetime, timedelta, timezone

from models import db, DailyStatRollup
from db_backend import init_db, close_db

NUMERIC_ROLLUP_SQL = """
    SELECT date_trunc('day', ts) AS day, host,
           COUNT(*) AS total_requests, COUNT(DISTINCT ip) AS unique_ips,
           SUM(CASE WHEN is_bot THEN 1 ELSE 0 END) AS bot_requests,
           AVG(request_time) AS avg_response_time,
           PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY request_time) AS p95_response_time,
           SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS status_5xx_count
    FROM requests WHERE ts >= %s AND ts < %s GROUP BY date_trunc('day', ts), ROLLUP(host)
"""

TOP_COUNTRY_SQL = """
    SELECT DISTINCT ON (host) host, country FROM (
        SELECT host, country, COUNT(*) AS n FROM requests
        WHERE ts >= %s AND ts < %s AND country IS NOT NULL GROUP BY host, country
    ) sub ORDER BY host, n DESC
"""


def rollup_day(day_start: datetime):
    """day_start must be a UTC midnight; rolls up [day_start, day_start + 1 day).

    Deletes this day's existing rows first, then re-inserts fresh ones,
    rather than an ON CONFLICT upsert: the combined all-hosts row has
    host=NULL, and Postgres never considers two NULLs equal for a unique
    constraint's conflict detection, so ON CONFLICT (date, host) would
    silently insert a duplicate combined row on every re-run instead of
    replacing it. Delete+insert sidesteps that entirely."""
    day_end = day_start + timedelta(days=1)

    top_country_by_host = {}
    for host, country in db.execute_sql(TOP_COUNTRY_SQL, (day_start, day_end)).fetchall():
        top_country_by_host[host] = country

    rows = list(db.execute_sql(NUMERIC_ROLLUP_SQL, (day_start, day_end)).fetchall())

    DailyStatRollup.delete().where(DailyStatRollup.date == day_start).execute()

    rows_written = 0
    for day, host, total, unique_ips, bot_requests, avg_rt, p95_rt, status_5xx in rows:
        # ROLLUP(host) emits one extra row per group with host=NULL - the
        # combined all-hosts total for that day. Real per-host rows use
        # that same host's top_country; the combined row has no single
        # "top country" so top_country stays NULL for it.
        DailyStatRollup.create(
            date=day, host=host,
            total_requests=total, unique_ips=unique_ips, bot_requests=bot_requests or 0,
            avg_response_time=avg_rt, p95_response_time=p95_rt,
            status_5xx_count=status_5xx or 0,
            top_country=top_country_by_host.get(host) if host else None,
        )
        rows_written += 1
    return rows_written


def main():
    parser = argparse.ArgumentParser(description="Build immutable daily SentryNet trend rollups.")
    parser.add_argument("--backfill", type=int, metavar="DAYS", help="rebuild the last DAYS completed UTC days")
    args = parser.parse_args()
    if args.backfill is not None and not 1 <= args.backfill <= 730:
        parser.error("--backfill must be between 1 and 730 days")

    init_db()
    try:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        days = args.backfill or 1
        total = 0
        for offset in range(days, 0, -1):
            day_start = today - timedelta(days=offset)
            written = rollup_day(day_start)
            total += written
            if args.backfill:
                print(f"{day_start.date()}: {written} rows")
        if args.backfill:
            print(f"Backfill complete: {total} rows across {days} completed day(s).")
        else:
            print(f"Rolled up {total} rows (hosts + combined total) for {(today - timedelta(days=1)).date()}.")
    finally:
        close_db()


if __name__ == "__main__":
    main()
