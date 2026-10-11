"""
Watches every TLS cert on the box for expiry - both Certbot-managed
(Let's Encrypt, auto-renews ~30 days out) and the self-signed ones used for
DDoS-Guard-fronted sites (10-year validity, never need renewal).

Only the Let's Encrypt certs get alerts, and only once one has actually
expired - that means Certbot's renewal has been silently failing and the
site is genuinely broken for visitors right now. Days-remaining is still
shown on the dashboard for anyone who wants a heads-up, but Discord is
reserved for "down" (expired) and its matching "back online" (renewed)
alert, not a pre-emptive countdown.
"""

import glob
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from notify import send_discord_alert
import alert_settings

CHECK_INTERVAL_SECONDS = 12 * 3600

_stop = threading.Event()
_lock = threading.Lock()
_status: list = []
_expired: set = set()  # domains currently alerted as expired


def _load_cert_expiry(path: str):
    try:
        data = Path(path).read_bytes()
        cert = x509.load_pem_x509_certificate(data)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        return not_after
    except Exception:
        return None


def _check_once():
    global _status
    now = datetime.now(timezone.utc)
    results = []

    for cert_path in sorted(glob.glob("/etc/letsencrypt/live/*/cert.pem")):
        domain = Path(cert_path).parent.name
        not_after = _load_cert_expiry(cert_path)
        if not_after is None:
            continue
        days_left = (not_after - now).days
        results.append({"domain": domain, "managed_by": "letsencrypt", "expires_at": not_after.isoformat(), "days_left": days_left})

        if days_left <= 0 and domain not in _expired:
            _expired.add(domain)
            if alert_settings.is_enabled("cert_expiry"):
                send_discord_alert(
                    f":x: **Certificate expired**: `{domain}` is down for HTTPS visitors right now.\n"
                    f"Certbot's renewal has failed silently - check `certbot renew --dry-run`."
                )
        elif days_left > 0 and domain in _expired:
            _expired.discard(domain)
            if alert_settings.is_enabled("cert_expiry"):
                send_discord_alert(f":white_check_mark: **Certificate renewed**: `{domain}` is valid again ({days_left} day(s) left).")

    self_signed_globs = ["/etc/nginx/ssl-selfsigned/*.crt", "/etc/apache2/ssl-selfsigned/*.crt"]
    seen_paths = set()
    for pattern in self_signed_globs:
        for cert_path in sorted(glob.glob(pattern)):
            if cert_path in seen_paths:
                continue
            seen_paths.add(cert_path)
            domain = Path(cert_path).stem
            not_after = _load_cert_expiry(cert_path)
            if not_after is None:
                continue
            days_left = (not_after - now).days
            results.append({"domain": domain, "managed_by": "self-signed", "expires_at": not_after.isoformat(), "days_left": days_left})

    with _lock:
        _status = results


def get_status() -> list:
    with _lock:
        return list(_status)


def _run():
    _check_once()
    while not _stop.wait(CHECK_INTERVAL_SECONDS):
        try:
            _check_once()
        except Exception as e:
            print(f"[cert-monitor] check failed: {e}")


def start():
    t = threading.Thread(target=_run, daemon=True, name="cert-monitor")
    t.start()
    return t


def stop():
    _stop.set()
