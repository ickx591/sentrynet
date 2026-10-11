"""
Scheduled security-summary PDF, emailed on a configurable cadence (weekly/
monthly/off) - a customer-facing deliverable good for the agency persona's
own clients, distinct from the operator-facing Discord digest in digest.py.

Deliberately does NOT refactor digest.py (already working, alert-critical) -
duplicates its small set of aggregation queries, but returns plain data (a
dict) rather than a pre-rendered Discord string, so the same numbers can
feed a PDF (and, if wanted later, other formats).

Fully inert until an SMTP host + at least one recipient are configured -
same "bring your own credentials" shape as the Discord webhook and
AbuseIPDB key: SentryNet never runs its own outbound mail relay. The
"scheduled_report" alert-settings toggle is the master switch for
*automatic* sends only - the dashboard's "send test report now" button
calls send_report() directly and always works once SMTP/recipients are
configured, regardless of that toggle or the cadence setting.
"""

import os
import smtplib
import threading
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from fpdf import FPDF

from models import db, Request, FlaggedIp, BlockedIp
from env_store import update as update_environment
import alert_settings
import cert_monitor
import resource_monitor

SCRIPT_DIR = Path(__file__).parent
_ENV_FILE = SCRIPT_DIR / ".env.postgres"
_lock = threading.Lock()

CHECK_INTERVAL_SECONDS = 3600  # cadence is day-granularity, hourly checks are plenty
CADENCE_DAYS = {"weekly": 7, "monthly": 30}

_ENV_KEYS = (
    "REPORT_CADENCE", "REPORT_RECIPIENTS", "REPORT_SMTP_HOST", "REPORT_SMTP_PORT",
    "REPORT_SMTP_USER", "REPORT_SMTP_PASSWORD", "REPORT_SMTP_FROM", "REPORT_LAST_SENT_AT",
)

_settings = {
    "cadence": os.environ.get("REPORT_CADENCE", "off").strip() or "off",
    "recipients": os.environ.get("REPORT_RECIPIENTS", "").strip(),
    "smtp_host": os.environ.get("REPORT_SMTP_HOST", "").strip(),
    "smtp_port": os.environ.get("REPORT_SMTP_PORT", "587").strip() or "587",
    "smtp_user": os.environ.get("REPORT_SMTP_USER", "").strip(),
    "smtp_password": os.environ.get("REPORT_SMTP_PASSWORD", "").strip(),
    "smtp_from": os.environ.get("REPORT_SMTP_FROM", "").strip(),
    "last_sent_at": os.environ.get("REPORT_LAST_SENT_AT", "").strip() or None,
}

_stop = threading.Event()


def get_settings() -> dict:
    """Never returns the raw SMTP password - just whether one is set."""
    with _lock:
        s = dict(_settings)
    s["smtp_password_configured"] = bool(s.pop("smtp_password", ""))
    return s


def persist_settings(**updates):
    """In-memory update + rewrite .env.postgres so it survives a restart -
    same shape as notify.py's persist_webhook_url, generalized to several keys."""
    with _lock:
        for k, v in updates.items():
            if k in _settings:
                _settings[k] = v
        snapshot = dict(_settings)

    env_map = {
        "REPORT_CADENCE": snapshot["cadence"],
        "REPORT_RECIPIENTS": snapshot["recipients"],
        "REPORT_SMTP_HOST": snapshot["smtp_host"],
        "REPORT_SMTP_PORT": snapshot["smtp_port"],
        "REPORT_SMTP_USER": snapshot["smtp_user"],
        "REPORT_SMTP_PASSWORD": snapshot["smtp_password"],
        "REPORT_SMTP_FROM": snapshot["smtp_from"],
        "REPORT_LAST_SENT_AT": snapshot["last_sent_at"] or "",
    }
    update_environment(env_map)


def _collect_report_data(since, until) -> dict:
    total = Request.select().where((Request.ts >= since) & (Request.ts < until)).count()
    unique_ips = (Request.select(Request.ip)
                  .where((Request.ts >= since) & (Request.ts < until))
                  .distinct().count())

    cursor = db.execute_sql(
        "SELECT country, count(*) FROM requests WHERE ts >= %s AND ts < %s AND country IS NOT NULL "
        "GROUP BY country ORDER BY count(*) DESC LIMIT 5",
        (since, until),
    )
    top_countries = cursor.fetchall()

    cursor = db.execute_sql(
        "SELECT host, count(*) FROM requests WHERE ts >= %s AND ts < %s GROUP BY host ORDER BY count(*) DESC LIMIT 5",
        (since, until),
    )
    top_hosts = cursor.fetchall()

    cursor = db.execute_sql(
        "SELECT status / 100, count(*) FROM requests WHERE ts >= %s AND ts < %s GROUP BY status / 100",
        (since, until),
    )
    status_breakdown = dict(cursor.fetchall())

    new_flagged = FlaggedIp.select().where((FlaggedIp.first_seen >= since) & (FlaggedIp.first_seen < until)).count()
    new_blocked = BlockedIp.select().where((BlockedIp.blocked_at >= since) & (BlockedIp.blocked_at < until)).count()

    top_flagged = list(
        FlaggedIp.select().where(FlaggedIp.last_seen >= since).order_by(FlaggedIp.score.desc()).limit(10)
    )

    certs = cert_monitor.get_status()
    expiring_soon = [c for c in certs if c["days_left"] <= 14]

    unit_states = resource_monitor.get_unit_states()
    unhealthy = {u: s for u, s in unit_states.items() if s != "ok"}

    return {
        "since": since, "until": until,
        "total_requests": total, "unique_ips": unique_ips,
        "top_countries": top_countries, "top_hosts": top_hosts,
        "status_breakdown": status_breakdown,
        "new_flagged": new_flagged, "new_blocked": new_blocked,
        "top_flagged": [{"ip": f.ip, "country": f.country, "score": f.score} for f in top_flagged],
        "expiring_certs": expiring_soon,
        "unhealthy_services": unhealthy,
    }


def _build_pdf(data: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "SentryNet Security Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Period: {data['since'].strftime('%Y-%m-%d')} to {data['until'].strftime('%Y-%m-%d')}",
              new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Traffic", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 6, f"Requests: {data['total_requests']}    Unique IPs: {data['unique_ips']}",
              new_x="LMARGIN", new_y="NEXT")
    if data["top_countries"]:
        pdf.cell(0, 6, "Top countries: " + ", ".join(f"{c} ({n})" for c, n in data["top_countries"]),
                  new_x="LMARGIN", new_y="NEXT")
    if data["top_hosts"]:
        pdf.cell(0, 6, "Top hosts: " + ", ".join(f"{h} ({n})" for h, n in data["top_hosts"]),
                  new_x="LMARGIN", new_y="NEXT")
    if data["status_breakdown"]:
        total_for_pct = sum(data["status_breakdown"].values()) or 1
        status_line = ", ".join(
            f"{cls}xx {round(100 * n / total_for_pct)}%" for cls, n in sorted(data["status_breakdown"].items())
        )
        pdf.cell(0, 6, "Status codes: " + status_line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Security", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 6, f"New flagged IPs: {data['new_flagged']}    New blocked IPs: {data['new_blocked']}",
              new_x="LMARGIN", new_y="NEXT")
    if data["top_flagged"]:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 6, "Most-flagged IPs this period:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for f in data["top_flagged"]:
            pdf.cell(0, 5, f"  {f['ip']} ({f['country'] or 'unknown'}) - score {f['score']}",
                      new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    if data["expiring_certs"] or data["unhealthy_services"]:
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Infrastructure highlights", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for c in data["expiring_certs"]:
            pdf.cell(0, 5, f"  Cert expiring soon: {c['domain']} ({c['days_left']}d left)",
                      new_x="LMARGIN", new_y="NEXT")
        for unit, state in data["unhealthy_services"].items():
            pdf.cell(0, 5, f"  Service {state}: {unit}", new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


def _send_email(pdf_bytes: bytes, recipients: list, subject: str, body: str, s: dict):
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = s["smtp_from"] or s["smtp_user"]
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body))
    attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename="sentrynet-report.pdf")
    msg.attach(attachment)

    with smtplib.SMTP(s["smtp_host"], int(s["smtp_port"] or 587), timeout=20) as server:
        server.starttls()
        if s["smtp_user"]:
            server.login(s["smtp_user"], s["smtp_password"])
        server.sendmail(msg["From"], recipients, msg.as_string())


def send_report(now=None):
    """Builds and emails a report right now, regardless of cadence/toggle -
    used both by the scheduler (once its own gating passes) and the
    dashboard's immediate test-send button. Returns (ok, message)."""
    now = now or datetime.now(timezone.utc)
    with _lock:
        s = dict(_settings)

    recipients = [r.strip() for r in s["recipients"].split(",") if r.strip()]
    if not s["smtp_host"] or not recipients:
        return False, "SMTP host and at least one recipient must be configured"

    days = CADENCE_DAYS.get(s["cadence"], 7)
    since = now - timedelta(days=days)

    try:
        data = _collect_report_data(since, now)
        pdf_bytes = _build_pdf(data)
        subject = f"SentryNet security summary - {now.strftime('%Y-%m-%d')}"
        body = (
            f"Attached: SentryNet's security summary for {since.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}.\n"
            f"Requests: {data['total_requests']}, new flagged IPs: {data['new_flagged']}, "
            f"new blocked: {data['new_blocked']}."
        )
        _send_email(pdf_bytes, recipients, subject, body, s)
    except Exception as e:
        return False, str(e)

    persist_settings(last_sent_at=now.isoformat())
    return True, "sent"


def _maybe_send_scheduled():
    if not alert_settings.is_enabled("scheduled_report"):
        return
    with _lock:
        s = dict(_settings)
    cadence = s["cadence"]
    if cadence not in CADENCE_DAYS:
        return

    now = datetime.now(timezone.utc)
    last_sent = s.get("last_sent_at")
    if last_sent:
        try:
            last_dt = datetime.fromisoformat(last_sent)
            if (now - last_dt).total_seconds() < CADENCE_DAYS[cadence] * 86400:
                return
        except ValueError:
            pass

    ok, msg = send_report(now=now)
    if not ok:
        print(f"[report] scheduled send failed: {msg}")


def _run():
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        try:
            _maybe_send_scheduled()
        except Exception as e:
            print(f"[report] scheduler check failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="report-scheduler")
    t.start()
    return t


def stop():
    _stop.set()
