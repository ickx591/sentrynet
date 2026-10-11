"""Local fleet adapter for SentryNet Community Edition.

Commercial releases historically used the licensing service as a fleet
broker.  The GitHub edition never sends telemetry to that service.  The Fleet
view remains useful by reporting this node locally, and the rest of SentryNet
continues to operate with every on-host monitoring and response feature.
"""

import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from models import Request as ReqLog, FlaggedIp, BlockedIp
import resource_monitor

SCRIPT_DIR = Path(__file__).parent
VERSION = (SCRIPT_DIR / "VERSION").read_text().strip()


def _top_flagged_ips(limit: int = 15) -> list:
    rows = (FlaggedIp.select(FlaggedIp.ip, FlaggedIp.score, FlaggedIp.country)
            .order_by(FlaggedIp.score.desc()).limit(limit))
    return [{"ip": row.ip, "score": row.score, "country": row.country} for row in rows]


def _collect_snapshot_stats() -> dict:
    now = datetime.now(timezone.utc)
    request_count = ReqLog.select().where(ReqLog.ts >= now - timedelta(hours=1)).count()
    flagged_count = FlaggedIp.select().where(
        FlaggedIp.last_seen >= now - timedelta(minutes=10)
    ).count()
    unit_states = resource_monitor.get_unit_states()
    return {
        "requests_per_hour": request_count,
        "flagged_active": flagged_count,
        "blocked_count": BlockedIp.select().count(),
        "degraded_services": sorted(name for name, state in unit_states.items() if state != "ok"),
        "license_status": "community",
        "version": VERSION,
        "top_flagged_ips": _top_flagged_ips(),
    }


def get_fleet() -> list:
    """Return this installation without making an external network request."""
    return [{
        "hostname": socket.gethostname(),
        "install_id": "local-community-node",
        "license_key_suffix": "FREE",
        "license_status": "community",
        "last_seen_at": datetime.now(timezone.utc).isoformat(),
        "stats": _collect_snapshot_stats(),
    }]


def start():
    return None


def stop():
    return None
