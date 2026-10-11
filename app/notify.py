"""Discord alerts for SentryNet.

Webhook URL comes from the DISCORD_WEBHOOK_URL env var (set in
.env.postgres, loaded by systemd's EnvironmentFile=) at startup, but can also
be viewed/changed live from the dashboard's Alerts tab - persist_webhook_url
rewrites .env.postgres (so it survives a restart) and updates the in-memory
value immediately (so it takes effect without one). Optional - if unset,
alerts are silently skipped and SentryNet works fine without Discord.
"""

import json
import ipaddress
import os
import queue
import socket
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from models import IntegrationConfig, db
from env_store import update as update_environment

_lock = threading.Lock()
_delivery_queue = queue.Queue(maxsize=1000)

WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()


def get_webhook_url() -> str:
    with _lock:
        return WEBHOOK_URL


def set_webhook_url(url: str):
    """In-memory only - use persist_webhook_url to also survive a restart."""
    global WEBHOOK_URL
    with _lock:
        WEBHOOK_URL = (url or "").strip()


def persist_webhook_url(url: str):
    url = (url or "").strip()
    update_environment({"DISCORD_WEBHOOK_URL": url})
    set_webhook_url(url)


def send_discord_alert(content: str):
    """Queue alert delivery so a slow destination never stalls monitoring."""
    try:
        _delivery_queue.put_nowait(str(content))
    except queue.Full:
        print("[notifications] delivery queue full; dropping alert")


def _deliver_alert(content: str):
    url = get_webhook_url()
    if url:
        try:
            resp = requests.post(
                url,
                json={"content": content[:1900]},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10,
            )
            resp.raise_for_status()
        except Exception as e:
            print(f"[discord-alert] failed to send: {e}")
    dispatch_integrations(content)


def _delivery_worker():
    while True:
        content = _delivery_queue.get()
        try:
            _deliver_alert(content)
        finally:
            try:
                if not db.is_closed():
                    db.close()
            except Exception:
                pass
            _delivery_queue.task_done()


threading.Thread(target=_delivery_worker, daemon=True, name="notification-delivery").start()


def _safe_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or len(url) > 2048
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)):
            return False
        # Integration delivery runs from a root service. Do not let an
        # administrator-controlled webhook become a route to localhost,
        # RFC1918 services, or cloud instance-metadata endpoints. Resolve
        # both when saving and immediately before delivery to also catch
        # ordinary DNS changes.
        addresses = {item[4][0] for item in socket.getaddrinfo(
            parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )}
        if not addresses:
            return False
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (not ip.is_global or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified or ip.is_reserved):
                return False
        return True
    except Exception:
        return False


def list_integrations() -> list:
    rows = IntegrationConfig.select().order_by(IntegrationConfig.name)
    result = []
    for row in rows:
        try:
            config = json.loads(row.config)
        except Exception:
            config = {}
        masked = dict(config)
        if masked.get("routing_key"):
            masked["routing_key"] = "••••" + masked["routing_key"][-4:]
        result.append({"key": row.key, "kind": row.kind, "name": row.name,
                       "enabled": row.enabled, "config": masked,
                       "updated_at": row.updated_at.isoformat()})
    return result


def save_integration(key: str, kind: str, name: str, enabled: bool, config: dict):
    if kind not in {"slack", "teams", "pagerduty", "webhook", "siem"}:
        raise ValueError("Unsupported integration type")
    config = dict(config or {})
    existing = IntegrationConfig.get_or_none(IntegrationConfig.key == key)
    if existing:
        try:
            old_config = json.loads(existing.config)
        except Exception:
            old_config = {}
        if str(config.get("routing_key", "")).startswith("••••"):
            config["routing_key"] = old_config.get("routing_key", "")
    url = config.get("url", "")
    if kind != "pagerduty" and not _safe_http_url(url):
        raise ValueError("A valid HTTP(S) webhook URL is required")
    if kind == "pagerduty" and not config.get("routing_key"):
        raise ValueError("PagerDuty routing key is required")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if existing:
        existing.kind, existing.name, existing.enabled = kind, name, enabled
        existing.config, existing.updated_at = json.dumps(config), now
        existing.save()
        return existing
    return IntegrationConfig.create(key=key, kind=kind, name=name, enabled=enabled,
                                    config=json.dumps(config), created_at=now, updated_at=now)


def delete_integration(key: str):
    return IntegrationConfig.delete().where(IntegrationConfig.key == key).execute()


def dispatch_integrations(content: str):
    """Fan an existing SentryNet alert out to every enabled destination."""
    try:
        rows = list(IntegrationConfig.select().where(IntegrationConfig.enabled == True))
    except Exception:
        return
    for row in rows:
        try:
            config = json.loads(row.config)
            headers = {"User-Agent": "SentryNet/1.5", "Content-Type": "application/json"}
            if row.kind != "pagerduty" and not _safe_http_url(config.get("url", "")):
                raise ValueError("webhook destination is no longer a safe public address")
            if row.kind == "slack":
                requests.post(config["url"], json={"text": content[:3900]}, headers=headers,
                              timeout=10, allow_redirects=False).raise_for_status()
            elif row.kind == "teams":
                requests.post(config["url"], json={"text": content[:3900]}, headers=headers,
                              timeout=10, allow_redirects=False).raise_for_status()
            elif row.kind == "pagerduty":
                payload = {"routing_key": config["routing_key"], "event_action": "trigger",
                           "payload": {"summary": content[:1024], "source": "SentryNet", "severity": "warning"}}
                requests.post("https://events.pagerduty.com/v2/enqueue", json=payload, headers=headers, timeout=10).raise_for_status()
            else:
                payload = {"source": "sentrynet", "timestamp": datetime.now(timezone.utc).isoformat(), "message": content}
                requests.post(config["url"], json=payload, headers=headers,
                              timeout=10, allow_redirects=False).raise_for_status()
        except Exception as exc:
            print(f"[integration:{row.key}] delivery failed: {exc}")
