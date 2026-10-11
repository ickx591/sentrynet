"""
Freezes one "monitoring window" of traffic into a self-contained
BandwidthReport row: total bandwidth used, how many unique IPs showed up,
and full breakdowns of which sites/paths/countries/IPs drove the traffic.

The window is deliberately offset from a calendar day. It runs from 06:00 UTC
until 06:00 UTC the next day - a complete 24-hour window. A report's `date` is
the window's *start* (06:00 UTC); the automatic run shortly after 06:00 UTC
captures the window that just closed.

Run daily via cron (see /etc/cron.d/sentrynet-bandwidth), after the window
closes. The whole point of freezing the breakdown into `details` is that the
report stays readable after cleanup_old_requests.py eventually deletes the
raw rows it was built from.

Deliberately a standalone cron script (same reasoning as rollup_daily.py),
not an in-process thread - a one-shot batch aggregation with no continuous
state or live-alerting need.
"""

import json
import sys
from datetime import datetime, timedelta, timezone

from models import db, BandwidthReport
from db_backend import init_db, close_db

WINDOW_START_HOUR = 6    # window opens 06:00 UTC...
WINDOW_HOURS = 24        # ...and closes 06:00 UTC the next day
TOP_LIMIT = 20           # rows kept per breakdown list in `details`

TOTALS_SQL = """
    SELECT COUNT(*) AS total_requests,
           COUNT(DISTINCT ip) AS unique_ips,
           COALESCE(SUM(bytes), 0) AS total_bytes,
           COALESCE(SUM(CASE WHEN is_bot THEN 1 ELSE 0 END), 0) AS bot_requests,
           AVG(request_time) AS avg_response_time,
           COALESCE(SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END), 0) AS s2,
           COALESCE(SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END), 0) AS s3,
           COALESCE(SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END), 0) AS s4,
           COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0) AS s5
    FROM requests WHERE ts >= %s AND ts < %s
"""

HOSTS_SQL = """
    SELECT host, COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
    FROM requests WHERE ts >= %s AND ts < %s
    GROUP BY host ORDER BY n DESC LIMIT 50
"""

PATHS_SQL = """
    SELECT path, COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
    FROM requests WHERE ts >= %s AND ts < %s
    GROUP BY path ORDER BY n DESC LIMIT 50
"""

COUNTRIES_SQL = """
    SELECT country, COUNT(*) AS n
    FROM requests WHERE ts >= %s AND ts < %s AND country IS NOT NULL
    GROUP BY country ORDER BY n DESC LIMIT %s
"""

IPS_SQL = """
    SELECT ip, country, COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
    FROM requests WHERE ts >= %s AND ts < %s
    GROUP BY ip, country ORDER BY n DESC LIMIT %s
"""

HOURLY_SQL = """
    SELECT date_trunc('hour', ts) AS hour,
           COUNT(*) AS n, COALESCE(SUM(bytes), 0) AS b
    FROM requests WHERE ts >= %s AND ts < %s
    GROUP BY hour ORDER BY hour
"""


def window_start_for_date(day: datetime) -> datetime:
    """Given any datetime, return the 06:00 UTC window start for that date."""
    return day.replace(hour=WINDOW_START_HOUR, minute=0, second=0,
                       microsecond=0, tzinfo=timezone.utc)


def latest_completed_window_start(now: datetime = None) -> datetime:
    """The most recent window whose end (06:00 UTC) is already in the past."""
    now = now or datetime.now(timezone.utc)
    start = window_start_for_date(now)
    # Step back a day until this window has fully closed. Handles both "today's
    # window hasn't opened yet" (before 06:00) and "today's window is still
    # running" (after 06:00) in one loop.
    while start + timedelta(hours=WINDOW_HOURS) > now:
        start -= timedelta(days=1)
    return start


def aggregate(window_start: datetime, window_end: datetime) -> dict:
    """Compute the full report for [window_start, window_end) without storing
    it - shared by build_report() and the dashboard's live "current window"
    view."""
    totals = db.execute_sql(TOTALS_SQL, (window_start, window_end)).fetchone()
    (total_requests, unique_ips, total_bytes, bot_requests, avg_rt,
     s2, s3, s4, s5) = totals

    hosts = [(h, n, int(b or 0)) for h, n, b in
             db.execute_sql(HOSTS_SQL, (window_start, window_end)).fetchall()]
    paths = [(p, n, int(b or 0)) for p, n, b in
             db.execute_sql(PATHS_SQL, (window_start, window_end)).fetchall()]
    countries = [(c, n) for c, n in
                 db.execute_sql(COUNTRIES_SQL, (window_start, window_end, TOP_LIMIT)).fetchall()]
    ips = [(ip, c, n, int(b or 0)) for ip, c, n, b in
           db.execute_sql(IPS_SQL, (window_start, window_end, TOP_LIMIT)).fetchall()]
    hourly = [{"hour": h.isoformat(), "requests": n, "bytes": int(b or 0)}
              for h, n, b in db.execute_sql(HOURLY_SQL, (window_start, window_end)).fetchall()]

    top_hosts = [{"host": h, "requests": n, "bytes": b} for h, n, b in hosts[:TOP_LIMIT]]
    hosts_by_bytes = sorted(
        ({"host": h, "requests": n, "bytes": b} for h, n, b in hosts),
        key=lambda x: x["bytes"], reverse=True,
    )[:TOP_LIMIT]
    top_paths = [{"path": p, "requests": n, "bytes": b} for p, n, b in paths[:TOP_LIMIT]]
    top_countries = [{"country": c, "requests": n} for c, n in countries]
    top_ips = [{"ip": ip, "country": c, "requests": n, "bytes": b} for ip, c, n, b in ips]

    return {
        "window_start": window_start,
        "window_end": window_end,
        "total_bytes": int(total_bytes or 0),
        "total_requests": total_requests or 0,
        "unique_ips": unique_ips or 0,
        "bot_requests": bot_requests or 0,
        "human_requests": (total_requests or 0) - (bot_requests or 0),
        "status_2xx": s2 or 0,
        "status_3xx": s3 or 0,
        "status_4xx": s4 or 0,
        "status_5xx": s5 or 0,
        "avg_response_time": float(avg_rt) if avg_rt is not None else None,
        "top_host": top_hosts[0]["host"] if top_hosts else None,
        "top_host_bytes": hosts_by_bytes[0]["bytes"] if hosts_by_bytes else 0,
        "top_country": top_countries[0]["country"] if top_countries else None,
        "top_path": top_paths[0]["path"] if top_paths else None,
        "details": {
            "top_hosts": top_hosts,
            "hosts_by_bytes": hosts_by_bytes,
            "top_paths": top_paths,
            "top_countries": top_countries,
            "top_ips": top_ips,
            "hourly": hourly,
        },
    }


def build_report(window_start: datetime) -> dict:
    """Aggregate the window starting at `window_start` (06:00 UTC) and store
    it, replacing any existing row for that window.

    Delete-then-insert rather than an upsert: same reason as rollup_daily.py,
    keeping the two rollup jobs' write pattern consistent."""
    window_end = window_start + timedelta(hours=WINDOW_HOURS)
    data = aggregate(window_start, window_end)

    # A pre-upgrade report for this date may use the legacy 16:00 start. Remove
    # any report keyed to the same UTC date so rebuilding cannot leave duplicate
    # old/new windows in the dashboard.
    report_day = window_start.replace(hour=0, minute=0, second=0, microsecond=0)
    next_day = report_day + timedelta(days=1)
    with db.atomic():
        (BandwidthReport.delete()
         .where((BandwidthReport.date >= report_day) & (BandwidthReport.date < next_day))
         .execute())
        BandwidthReport.create(
            date=window_start,
            window_start=window_start,
            window_end=window_end,
            total_bytes=data["total_bytes"],
            total_requests=data["total_requests"],
            unique_ips=data["unique_ips"],
            bot_requests=data["bot_requests"],
            human_requests=data["human_requests"],
            status_2xx=data["status_2xx"],
            status_3xx=data["status_3xx"],
            status_4xx=data["status_4xx"],
            status_5xx=data["status_5xx"],
            avg_response_time=data["avg_response_time"],
            top_host=data["top_host"],
            top_host_bytes=data["top_host_bytes"],
            top_country=data["top_country"],
            top_path=data["top_path"],
            details=json.dumps(data["details"]),
            created_at=datetime.now(timezone.utc),
        )
    return data


def _cli():
    args = sys.argv[1:]
    backfill = None
    target = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--backfill":
            i += 1
            backfill = int(args[i]) if i < len(args) else 30
        else:
            target = a
        i += 1

    latest = latest_completed_window_start()

    if backfill is not None:
        for n in range(backfill):
            start = latest - timedelta(days=n)
            data = build_report(start)
            print(f"{start.date()} 06:00-06:00 UTC: "
                  f"{data['total_requests']} requests, {data['total_bytes']} bytes, "
                  f"{data['unique_ips']} unique IPs")
        return

    if target:
        try:
            day = datetime.strptime(target, "%Y-%m-%d")
        except ValueError:
            print(f"error: expected YYYY-MM-DD, got {target!r}", file=sys.stderr)
            sys.exit(2)
        start = window_start_for_date(day)
    else:
        start = latest

    data = build_report(start)
    print(f"Built report for {start.date()} 06:00-06:00 UTC: "
          f"{data['total_requests']} requests, {data['total_bytes']} bytes, "
          f"{data['unique_ips']} unique IPs, top site {data['top_host']!r}")


if __name__ == "__main__":
    init_db()
    _cli()
    close_db()
