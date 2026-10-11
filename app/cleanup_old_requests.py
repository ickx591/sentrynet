"""
Deletes old rows across every unbounded-growth table so Postgres storage
doesn't grow forever. Run daily via cron - see /etc/cron.d/sentrynet-cleanup.

Retention windows differ by how long a table's data actually stays useful:
- Routine operational data (requests, resource samples, app logs) is only
  really useful for recent trend-watching/debugging, so it gets the
  shorter RETENTION_DAYS window.
- Security/forensic logs (SSH auth, config integrity, defacement, egress)
  are kept for SECURITY_LOG_RETENTION_DAYS instead - "was this IP doing
  this last month too" or "exactly when did this file first change" has
  real investigative value well past a typical debugging window.
- block_audit (the full block/unblock/allow history) is deliberately never
  touched here - it's the one place to see "why was this IP unblocked, and
  by whom", and an audit trail isn't supposed to expire.
- flagged_ips isn't a real time-series (one row per IP, updated in place),
  so it clears by staleness (no activity in FLAG_STALE_DAYS) instead of by
  row age.
"""

from datetime import datetime, timedelta, timezone

from models import (
    Request, FlaggedIp, ServiceResourceSample, AppLogEvent,
    SshAuthEvent, IntegrityEvent, DefacementEvent, EgressEvent,
)
from db_backend import init_db, close_db

RETENTION_DAYS = 30
SECURITY_LOG_RETENTION_DAYS = 90
FLAG_STALE_DAYS = 7


def _delete_older_than(model, ts_field, days, label):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = model.delete().where(ts_field < cutoff).execute()
    print(f"Deleted {deleted} {label} older than {days} days.")


if __name__ == "__main__":
    init_db()

    _delete_older_than(Request, Request.ts, RETENTION_DAYS, "request rows")

    flag_cutoff = datetime.now(timezone.utc) - timedelta(days=FLAG_STALE_DAYS)
    deleted_flags = FlaggedIp.delete().where(FlaggedIp.last_seen < flag_cutoff).execute()
    print(f"Deleted {deleted_flags} stale flagged-IP entries (no activity in {FLAG_STALE_DAYS} days).")

    _delete_older_than(ServiceResourceSample, ServiceResourceSample.ts, RETENTION_DAYS, "resource-sample rows")
    _delete_older_than(AppLogEvent, AppLogEvent.ts, RETENTION_DAYS, "app-log-event rows")

    _delete_older_than(SshAuthEvent, SshAuthEvent.ts, SECURITY_LOG_RETENTION_DAYS, "SSH auth-event rows")
    _delete_older_than(IntegrityEvent, IntegrityEvent.ts, SECURITY_LOG_RETENTION_DAYS, "config-integrity-event rows")
    _delete_older_than(DefacementEvent, DefacementEvent.ts, SECURITY_LOG_RETENTION_DAYS, "defacement-event rows")
    _delete_older_than(EgressEvent, EgressEvent.ts, SECURITY_LOG_RETENTION_DAYS, "egress-event rows")

    close_db()
