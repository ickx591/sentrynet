"""SentryNet operations layer: cases, search, policies, and diagnostics."""

import json
import os
import shutil
import socket
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from models import (
    AppLogEvent, BlockAudit, BlockedIp, DefacementEvent, EgressEvent,
    FlaggedIp, Incident, IntegrityEvent, Request as ReqLog, ResponsePolicy,
    SavedView, SshAuthEvent, db,
)

SCRIPT_DIR = Path(__file__).parent
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _incident(source_ref, category, severity, title, summary, event_time):
    row = Incident.get_or_none(Incident.source_ref == source_ref)
    if row is None:
        Incident.create(
            source_ref=source_ref, category=category, severity=severity,
            title=title[:255], summary=summary, status="open",
            created_at=event_time, updated_at=event_time,
        )
        return
    if row.status != "resolved" and event_time > row.updated_at:
        row.severity = severity
        row.summary = summary
        row.updated_at = event_time
        row.save()


def sync_incidents():
    """Materialize recent raw findings into a durable, triageable queue."""
    cutoff = utcnow() - timedelta(days=7)
    for row in FlaggedIp.select().where(FlaggedIp.last_seen >= cutoff).order_by(FlaggedIp.last_seen.desc()).limit(250):
        severity = "critical" if row.score >= 15 else "high" if row.score >= 10 else "medium" if row.score >= 5 else "low"
        try:
            signal_names = ", ".join(s.get("type", "signal") for s in json.loads(row.signals)[:4])
        except Exception:
            signal_names = "security heuristics"
        _incident(f"flagged:{row.ip}", "threat", severity, f"Suspicious activity from {row.ip}",
                  f"Risk score {row.score}; {signal_names}", row.last_seen)

    sources = (
        (DefacementEvent, "defacement", "critical", lambda r: f"Web content {r.change_type}: {r.path}", lambda r: "A monitored web-root file changed."),
        (IntegrityEvent, "integrity", "high", lambda r: f"Configuration {r.change_type}: {r.path}", lambda r: "A monitored configuration file changed."),
        (EgressEvent, "egress", "high", lambda r: f"Unexpected outbound connection from {r.process}", lambda r: f"Connected to {r.remote_ip}:{r.remote_port}."),
        (AppLogEvent, "application", "critical", lambda r: f"{r.unit}: {r.level} event", lambda r: r.message[:1000]),
    )
    for model, category, default_severity, title_fn, summary_fn in sources:
        for row in model.select().where(model.ts >= cutoff).order_by(model.ts.desc()).limit(100):
            severity = "critical" if getattr(row, "level", "") == "critical" else default_severity
            _incident(f"{category}:{row.id}", category, severity, title_fn(row), summary_fn(row), row.ts)

    for row in SshAuthEvent.select().where(
        (SshAuthEvent.ts >= cutoff) & (SshAuthEvent.result != "accepted")
    ).order_by(SshAuthEvent.ts.desc()).limit(100):
        _incident(f"ssh:{row.id}", "ssh", "medium", f"SSH authentication failure from {row.ip}",
                  f"Result: {row.result}; username: {row.username or 'unknown'}", row.ts)


def serialize_incident(row):
    return {
        "id": str(row.id), "source_ref": row.source_ref, "category": row.category,
        "severity": row.severity, "title": row.title, "summary": row.summary,
        "status": row.status, "assignee": row.assignee, "notes": row.notes,
        "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat(),
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
    }


def list_incidents(status=None, severity=None, category=None, query=None, limit=200):
    sync_incidents()
    q = Incident.select()
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if category:
        q = q.where(Incident.category == category)
    if query:
        term = query.strip()
        q = q.where((Incident.title.contains(term)) | (Incident.summary.contains(term)) | (Incident.source_ref.contains(term)))
    rows = list(q.order_by(Incident.updated_at.desc()).limit(limit))
    rows.sort(key=lambda r: (r.status == "resolved", -SEVERITY_ORDER.get(r.severity, 0), -r.updated_at.timestamp()))
    return [serialize_incident(r) for r in rows]


def update_incident(incident_id, status=None, assignee=None, notes=None):
    row = Incident.get_or_none(Incident.id == incident_id)
    if row is None:
        return None
    if status is not None:
        row.status = status
        row.resolved_at = utcnow() if status == "resolved" else None
    if assignee is not None:
        row.assignee = assignee.strip() or None
    if notes is not None:
        row.notes = notes.strip() or None
    row.updated_at = utcnow()
    row.save()
    return serialize_incident(row)


def global_search(term, limit=50):
    term = (term or "").strip()
    if len(term) < 2:
        return []
    per_type = max(5, min(25, limit // 4))
    results = []
    for r in (ReqLog.select().where(
        (ReqLog.ip.contains(term)) | (ReqLog.host.contains(term)) | (ReqLog.path.contains(term))
    ).order_by(ReqLog.ts.desc()).limit(per_type)):
        results.append({"type": "request", "title": f"{r.method} {r.path}", "meta": f"{r.ip} · {r.host} · {r.status}", "timestamp": r.ts.isoformat(), "target": r.ip})
    for r in (FlaggedIp.select().where(FlaggedIp.ip.contains(term)).order_by(FlaggedIp.last_seen.desc()).limit(per_type)):
        results.append({"type": "threat", "title": r.ip, "meta": f"{r.country or '??'} · risk score {r.score}", "timestamp": r.last_seen.isoformat(), "target": r.ip})
    for r in (BlockAudit.select().where(
        (BlockAudit.target.contains(term)) | (BlockAudit.reason.contains(term)) | (BlockAudit.actor.contains(term))
    ).order_by(BlockAudit.ts.desc()).limit(per_type)):
        results.append({"type": "audit", "title": f"{r.action}: {r.target}", "meta": f"{r.actor or 'system'} · {r.reason or 'No reason'}", "timestamp": r.ts.isoformat(), "target": r.target})
    for r in (Incident.select().where(
        (Incident.title.contains(term)) | (Incident.summary.contains(term)) | (Incident.source_ref.contains(term))
    ).order_by(Incident.updated_at.desc()).limit(per_type)):
        results.append({"type": "incident", "title": r.title, "meta": f"{r.severity} · {r.status}", "timestamp": r.updated_at.isoformat(), "target": str(r.id)})
    results.sort(key=lambda r: r["timestamp"], reverse=True)
    return results[:limit]


def serialize_policy(row):
    try:
        countries = json.loads(row.countries)
    except Exception:
        countries = []
    return {
        "id": str(row.id), "name": row.name, "enabled": row.enabled,
        "dry_run": row.dry_run, "min_score": row.min_score, "countries": countries,
        "duration_hours": row.duration_hours, "created_by": row.created_by,
        "managed_by_fleet": row.managed_by_fleet, "fleet_policy_id": row.fleet_policy_id,
        "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
        "last_match_count": row.last_match_count,
    }


def policy_matches(row):
    try:
        countries = {c.upper() for c in json.loads(row.countries)}
    except Exception:
        countries = set()
    cutoff = utcnow() - timedelta(minutes=30)
    q = FlaggedIp.select().where((FlaggedIp.score >= row.min_score) & (FlaggedIp.last_seen >= cutoff))
    if countries:
        q = q.where(FlaggedIp.country.in_(countries))
    blocked = {b.ip for b in BlockedIp.select(BlockedIp.ip)}
    return [r for r in q.order_by(FlaggedIp.score.desc()) if r.ip not in blocked]


def run_policy(row, actor="policy-engine"):
    matches = policy_matches(row)
    row.last_run_at = utcnow()
    row.last_match_count = len(matches)
    row.save()
    if row.dry_run:
        return matches, 0
    from webserver_backend import regenerate_blocklist
    expires = utcnow() + timedelta(hours=row.duration_hours) if row.duration_hours else None
    inserted = 0
    for match in matches:
        count = (BlockedIp.insert(
            ip=match.ip, reason=f"policy: {row.name} (score {match.score})",
            blocked_at=utcnow(), blocked_by=actor, expires_at=expires,
        ).on_conflict_ignore().execute())
        if count:
            inserted += 1
            BlockAudit.create(ts=utcnow(), action="block", target=match.ip,
                              reason=f"policy: {row.name} (score {match.score})", actor=actor)
    if inserted:
        regenerate_blocklist()
    return matches, inserted


def diagnostics():
    checks = []
    def add(key, label, status, detail, action=None):
        checks.append({"key": key, "label": label, "status": status, "detail": detail, "action": action})
    try:
        db.execute_sql("SELECT 1").fetchone()
        add("database", "PostgreSQL", "ok", "Database connection is healthy.")
    except Exception as exc:
        add("database", "PostgreSQL", "critical", str(exc), "Check DATABASE_URL and PostgreSQL service state.")
    try:
        last = ReqLog.select().order_by(ReqLog.ts.desc()).first()
        if not last:
            add("traffic", "Traffic ingestion", "warning", "No requests have been recorded.", "Enable the sentrynet_json access-log format on at least one site.")
        else:
            age = max(0, int((utcnow() - last.ts).total_seconds()))
            status = "ok" if age < 300 else "warning"
            add("traffic", "Traffic ingestion", status, f"Last request was {age} seconds ago.", "Verify access-log path and format." if status != "ok" else None)
    except Exception as exc:
        add("traffic", "Traffic ingestion", "critical", str(exc))
    log_path = os.environ.get("ACCESS_LOG_PATH", "/var/log/nginx/access.log")
    add("access_log", "Access log", "ok" if os.path.isfile(log_path) and os.access(log_path, os.R_OK) else "critical",
        f"{log_path} is readable." if os.path.isfile(log_path) and os.access(log_path, os.R_OK) else f"Cannot read {log_path}.",
        "Check ACCESS_LOG_PATH and file permissions.")
    free = shutil.disk_usage(SCRIPT_DIR).free
    add("disk", "Disk capacity", "ok" if free >= 2 * 1024**3 else "warning", f"{free / 1024**3:.1f} GB free.", "Free disk space or shorten retention." if free < 2 * 1024**3 else None)
    webserver = os.environ.get("WEBSERVER", "nginx")
    binary = "apache2ctl" if webserver == "apache" else "nginx"
    try:
        cmd = [binary, "configtest"] if webserver == "apache" else [binary, "-t"]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        add("webserver", f"{webserver.title()} configuration", "ok" if result.returncode == 0 else "critical",
            "Configuration test passed." if result.returncode == 0 else "Configuration test failed.", "Run the config test manually for full output.")
    except Exception as exc:
        add("webserver", f"{webserver.title()} configuration", "warning", str(exc))
    add("identity", "Server identity", "ok", f"{socket.gethostname()} · SentryNet {(SCRIPT_DIR / 'VERSION').read_text().strip()}")
    return {"generated_at": utcnow().isoformat(), "checks": checks,
            "summary": {s: sum(1 for c in checks if c["status"] == s) for s in ("ok", "warning", "critical")}}


_stop = threading.Event()


def _policy_loop():
    while not _stop.wait(60):
        try:
            for policy in ResponsePolicy.select().where(ResponsePolicy.enabled == True):
                run_policy(policy)
        except Exception as exc:
            print(f"[response-policy] evaluation failed: {exc}")
        finally:
            try:
                if not db.is_closed():
                    db.close()
            except Exception:
                pass


def start():
    _stop.clear()
    thread = threading.Thread(target=_policy_loop, daemon=True, name="response-policy-engine")
    thread.start()
    return thread


def stop():
    _stop.set()
