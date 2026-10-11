"""
SentryNet — self-hosted network security and monitoring dashboard for
Debian and Ubuntu web servers.

Shows who's connecting to every vhost on this server (IP, country, device,
vhost, status) sourced from the active webserver's JSON access log (nginx
or Apache - see webserver_backend.py), with automatic threat heuristics
(heuristics.py) and a manual IP-block tool enforced at the webserver level.
"""

import asyncio
import functools
import ipaddress
import json
import os
import secrets
import sys
import threading
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

SCRIPT_DIR = Path(__file__).parent
os.chdir(SCRIPT_DIR)
sys.path.insert(0, str(SCRIPT_DIR))

from models import (
    db, Request as ReqLog, FlaggedIp, BlockedIp, AllowedIp, BlockedCountry, BlockAudit,
    SshAuthEvent, IntegrityEvent, DefacementEvent, EgressEvent, AppLogEvent,
    ServiceResourceSample, User, DailyStatRollup, BandwidthReport, Incident, SavedView, ResponsePolicy,
)
from db_backend import init_db, close_db
from notify import send_discord_alert, get_webhook_url, persist_webhook_url
import notify
import alert_settings
import bandwidth_report
import license
import fleet_client
import users
import webserver_backend
import ingest
import threat_intel
import ip_reputation
import ssh_monitor
import ssh_ban
import integrity_monitor
import defacement_monitor
import egress_monitor
import cert_monitor
import log_aggregator
import resource_monitor
import digest
import report
import watchdog
import operations
import oidc_auth
import passkeys
import session_security

init_db()

VERSION = (SCRIPT_DIR / "VERSION").read_text().strip()
ADMIN_FILE = SCRIPT_DIR / ".admin.json"
SESSIONS_FILE = SCRIPT_DIR / ".sessions.json"
SESSION_COOKIE = "sentrynet_session"
CSRF_COOKIE = "sentrynet_csrf"
OIDC_STATE_COOKIE = "sentrynet_oidc_state"
SESSION_MAX_AGE_SECONDS = 86400
RECENT_AUTH_SECONDS = 300
PUBLIC_PATHS = {"/login", "/login.html", "/api/version", "/api/auth/options", "/auth/oidc/start", "/auth/oidc/callback",
                "/api/auth/passkey/options", "/api/auth/passkey/verify"}
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_VERSIONED_UI_ASSETS = ("app.css", "auth.css", "ui-shell.js", "operations-ui.js", "dashboard.js")


def _html_page(filename: str) -> str:
    """Read an HTML shell and cache-bust every first-party UI asset."""
    html = (SCRIPT_DIR / filename).read_text(encoding="utf-8")
    static_dir = SCRIPT_DIR / "static"
    for asset in _VERSIONED_UI_ASSETS:
        path = static_dir / asset
        if path.exists():
            html = html.replace(f'/static/{asset}"', f'/static/{asset}?v={int(path.stat().st_mtime)}"')
    return html


def _csv_cell(value):
    """Prevent spreadsheet formula execution when an export is opened."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _bootstrap_admin():
    """First-run only: generate a random username/password so there's never
    a default/known credential. Printed once to the service log - operator
    reads it via `journalctl -u sentrynet -n 50` after first start."""
    if ADMIN_FILE.exists():
        return
    username = "admin_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(16)
    ADMIN_FILE.write_text(json.dumps({"username": username, "password": password}))
    os.chmod(ADMIN_FILE, 0o600)
    print("=" * 70)
    print("SentryNet: first run, generated admin credentials:")
    print(f"  username: {username}")
    print(f"  password: {password}")
    print(f"  (saved to {ADMIN_FILE}, shown only this once in the log)")
    print("=" * 70)


_bootstrap_admin()

_sessions_lock = threading.Lock()
_sessions: Dict[str, dict] = {}


def _load_sessions():
    global _sessions
    try:
        loaded = json.loads(SESSIONS_FILE.read_text())
        _sessions = loaded if isinstance(loaded, dict) else {}
    except Exception:
        _sessions = {}


def _save_sessions():
    try:
        fd, temporary = tempfile.mkstemp(prefix=".sessions.", dir=SCRIPT_DIR)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(json.dumps(_sessions))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, SESSIONS_FILE)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
    except Exception as e:
        print(f"Warning: could not save sessions: {e}")


_load_sessions()

# Sessions created before multi-user support lack a "role" field - drop them
# rather than guess, so nobody is silently treated as any particular role
# after an upgrade. Whoever held one just logs in again, once.
def _session_age_seconds(session: dict) -> Optional[float]:
    return session_security.age_seconds(session)


def _session_valid(session: dict) -> bool:
    return session_security.valid(session, SESSION_MAX_AGE_SECONDS)


_stale_session_tokens = [t for t, s in _sessions.items() if not isinstance(s, dict) or not _session_valid(s)]
if _stale_session_tokens:
    with _sessions_lock:
        for _t in _stale_session_tokens:
            _sessions.pop(_t, None)
        _save_sessions()


def _make_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc).isoformat()
    with _sessions_lock:
        _sessions[token] = {
            "username": username,
            "role": role,
            "created_at": now,
            "authenticated_at": now,
        }
        _save_sessions()
    return token


def _invalidate_sessions_for(username: str, except_token: Optional[str] = None):
    """Force-logout every session belonging to a user - used when the Owner
    changes someone's role/password, or deletes them, so it takes effect
    immediately rather than only on that user's next login."""
    with _sessions_lock:
        for token, sess in list(_sessions.items()):
            if sess.get("username") == username and token != except_token:
                _sessions.pop(token, None)
        _save_sessions()


def _update_session_roles(username: str, role: str):
    """Live role change for every currently-open session of this user."""
    with _sessions_lock:
        changed = False
        for sess in _sessions.values():
            if sess.get("username") == username:
                sess["role"] = role
                changed = True
        if changed:
            _save_sessions()


def _make_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _get_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    with _sessions_lock:
        session = _sessions.get(token)
        if isinstance(session, dict) and _session_valid(session):
            return dict(session)
        if token in _sessions:
            _sessions.pop(token, None)
            _save_sessions()
    return None


def _require_recent_auth(request: Request):
    session = _get_session(request.cookies.get(SESSION_COOKIE))
    if not session or not session_security.recently_authenticated(session, RECENT_AUTH_SECONDS):
        raise HTTPException(status_code=403, detail="Please sign in again before changing authentication factors")


def _cookie_flags(request: Request, http_only: bool = True, max_age: int = SESSION_MAX_AGE_SECONDS) -> str:
    # 24h, not the 30-day cookie the sports apps use - this tool can see every
    # visitor's IP/traffic across the whole server and unblock/block IPs, so a
    # stolen cookie here is worth a lot more than a stolen streaming session.
    # http_only=False for the CSRF cookie specifically - the whole point of
    # the double-submit pattern is that JS has to be able to read it back.
    # Proxy headers are normalized by uvicorn only for trusted proxy peers.
    # Reading the raw header here would let a direct client influence cookie
    # behavior.
    is_https = request.url.scheme == "https"
    parts = ["Path=/", "SameSite=Lax", f"Max-Age={max_age}"]
    if http_only:
        parts.insert(1, "HttpOnly")
    if is_https:
        parts.append("Secure")
    return "; ".join(parts)


_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_FAILURES = 5
_LOGIN_MAX_TRACKED_KEYS = 10_000
_login_failures_lock = threading.Lock()
_login_failures: Dict[str, list] = {}


def _client_ip(request: Request) -> str:
    # Uvicorn already honors forwarding headers only from its configured
    # trusted proxies (127.0.0.1 by default), so request.client is normally
    # the real remote address behind nginx/Apache.  Only fall back to
    # X-Real-IP when the immediate peer is loopback; trusting it from an
    # arbitrary direct client would make the login throttle trivial to
    # bypass and would poison the audit trail.
    peer = request.client.host if request.client else "unknown"
    try:
        trusted_peer = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        trusted_peer = False
    if trusted_peer:
        real_ip = request.headers.get("x-real-ip", "").strip()
        try:
            return str(ipaddress.ip_address(real_ip)) if real_ip else peer
        except ValueError:
            pass
    return peer


def _login_rate_limited(ip: str) -> bool:
    now = time.time()
    with _login_failures_lock:
        recent = [t for t in _login_failures.get(ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
        if recent:
            _login_failures[ip] = recent
        else:
            _login_failures.pop(ip, None)
        return len(recent) >= _LOGIN_MAX_FAILURES


def _record_login_failure(ip: str):
    with _login_failures_lock:
        if ip not in _login_failures and len(_login_failures) >= _LOGIN_MAX_TRACKED_KEYS:
            _login_failures.pop(next(iter(_login_failures)))
        _login_failures.setdefault(ip, []).append(time.time())


def _clear_login_failures(ip: str):
    with _login_failures_lock:
        _login_failures.pop(ip, None)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            if request.url.path.startswith("/static/"):
                return await call_next(request)
            if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
                return await call_next(request)
            token = request.cookies.get(SESSION_COOKIE)
            if _get_session(token):
                if request.method in _MUTATING_METHODS:
                    # Double-submit CSRF check: the cookie is readable by
                    # our own JS but not by a cross-site attacker page, so a
                    # forged cross-site request can't reproduce a matching
                    # header even though the cookie itself rides along.
                    csrf_cookie = request.cookies.get(CSRF_COOKIE)
                    csrf_header = request.headers.get("x-csrf-token")
                    if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
                        return JSONResponse({"error": "Missing or invalid CSRF token"}, status_code=403)
                return await call_next(request)
            if request.url.path == "/":
                return HTMLResponse(_html_page("login.html"))
            return JSONResponse({"error": "Not authenticated"}, status_code=401)
        finally:
            try:
                db.close()
            except Exception:
                pass


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "object-src 'none'; form-action 'self'; connect-src 'self'; "
            "img-src 'self' data:; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'",
        )
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response


def _release_pooled_connection():
    try:
        if not db.is_closed():
            db.close()
    except Exception:
        pass


def _close_db_after(fn):
    """Wrap a sync endpoint so its pooled Postgres connection is checked
    back into the pool at the end of the SAME call/thread that opened it.
    AuthMiddleware's db.close() above runs on the event-loop thread via
    async def dispatch(), which never held a connection in the first place -
    PooledPostgresqlDatabase tracks the checked-out connection per-thread,
    and every sync route handler runs on its own separate anyio worker
    thread (Starlette's run_in_threadpool). Without this, every distinct
    worker thread that ever touched the DB permanently held its connection
    checked out until max_connections was exhausted."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        finally:
            _release_pooled_connection()
    return wrapper


def _current_username(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE)
    return (_get_session(token) or {}).get("username", "unknown")


def _current_role(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    return (_get_session(token) or {}).get("role")


class DBSafeRoute(APIRoute):
    def __init__(self, path, endpoint, **kwargs):
        if not asyncio.iscoroutinefunction(endpoint):
            endpoint = _close_db_after(endpoint)
        super().__init__(path, endpoint, **kwargs)


app = FastAPI(title="SentryNet", version=VERSION)
app.router.route_class = DBSafeRoute
app.add_middleware(AuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=str(SCRIPT_DIR / "static")), name="static")


@app.get("/api/version")
def api_version():
    return {"version": VERSION}


@app.get("/api/auth/options")
def api_auth_options():
    return oidc_auth.public_options()


@app.get("/auth/oidc/start")
def oidc_start(request: Request):
    callback = str(request.base_url).rstrip("/") + "/auth/oidc/callback"
    try:
        browser_binding = secrets.token_urlsafe(32)
        response = RedirectResponse(oidc_auth.begin(callback, browser_binding), status_code=302)
        response.headers.append(
            "Set-Cookie",
            f"{OIDC_STATE_COOKIE}={browser_binding}; {_cookie_flags(request, max_age=600)}",
        )
        return response
    except Exception as exc:
        return RedirectResponse("/?sso_error=" + quote(str(exc)), status_code=302)


@app.get("/auth/oidc/callback")
def oidc_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None,
                  error: Optional[str] = None):
    if error or not code or not state:
        return RedirectResponse("/?sso_error=" + quote(error or "Invalid SSO response"), status_code=302)
    try:
        user = oidc_auth.finish(code, state, request.cookies.get(OIDC_STATE_COOKIE))
    except Exception as exc:
        return RedirectResponse("/?sso_error=" + quote(str(exc)), status_code=302)
    token, csrf_token = _make_session(user.username, user.role), _make_csrf_token()
    response = RedirectResponse("/", status_code=302)
    response.headers.append("Set-Cookie", f"{OIDC_STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
    response.headers.append("Set-Cookie", f"{SESSION_COOKIE}={token}; {_cookie_flags(request)}")
    response.headers.append("Set-Cookie", f"{CSRF_COOKIE}={csrf_token}; {_cookie_flags(request, http_only=False)}")
    return response


def _webauthn_context(request: Request):
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.hostname
    origin = f"{scheme}://{host}"
    return request.url.hostname, origin


class PasskeyUserRequest(BaseModel):
    username: str


class PasskeyFinishRequest(BaseModel):
    credential: dict
    label: Optional[str] = None


@app.post("/api/auth/passkey/options")
def passkey_login_options(req: PasskeyUserRequest, request: Request):
    ip = _client_ip(request)
    if _login_rate_limited(ip) or users.username_rate_limited(req.username):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Please try again in a few minutes.")
    rp_id, origin = _webauthn_context(request)
    return passkeys.authentication_options(req.username, rp_id, origin)


@app.post("/api/auth/passkey/verify")
def passkey_login_verify(req: PasskeyFinishRequest, request: Request):
    ip = _client_ip(request)
    if _login_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Please try again in a few minutes.")
    try:
        user = passkeys.finish_authentication(req.credential)
    except Exception:
        _record_login_failure(ip)
        raise HTTPException(status_code=401, detail="Passkey verification failed")
    _clear_login_failures(ip)
    users.clear_username_failures(user.username)
    token, csrf_token = _make_session(user.username, user.role), _make_csrf_token()
    response = JSONResponse({"ok": True})
    response.headers.append("Set-Cookie", f"{SESSION_COOKIE}={token}; {_cookie_flags(request)}")
    response.headers.append("Set-Cookie", f"{CSRF_COOKIE}={csrf_token}; {_cookie_flags(request, http_only=False)}")
    return response


@app.post("/api/account/passkeys/options")
def passkey_register_options(request: Request):
    _require_recent_auth(request)
    rp_id, origin = _webauthn_context(request)
    return passkeys.registration_options(_current_username(request), rp_id, origin)


@app.post("/api/account/passkeys")
def passkey_register(req: PasskeyFinishRequest, request: Request):
    _require_recent_auth(request)
    try:
        row = passkeys.finish_registration(_current_username(request), req.credential, req.label or "Passkey")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "id": str(row.id), "label": row.label}


@app.get("/api/account/passkeys")
def passkey_list(request: Request):
    from models import PasskeyCredential
    rows = PasskeyCredential.select().where(PasskeyCredential.username == _current_username(request)).order_by(PasskeyCredential.created_at.desc())
    return [{"id": r.id, "label": r.label, "created_at": r.created_at.isoformat(),
             "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None} for r in rows]


@app.delete("/api/account/passkeys/{credential_id}")
def passkey_delete(credential_id: int, request: Request):
    _require_recent_auth(request)
    from models import PasskeyCredential
    count = PasskeyCredential.delete().where((PasskeyCredential.id == credential_id) & (PasskeyCredential.username == _current_username(request))).execute()
    return {"ok": bool(count)}


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


@app.post("/login")
def login(req: LoginRequest, request: Request):
    ip = _client_ip(request)
    if _login_rate_limited(ip) or users.username_rate_limited(req.username):
        print(f"[auth] RATE LIMITED login attempt from {ip} (user={req.username!r})")
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Please try again in a few minutes.")

    user = User.get_or_none(User.username == req.username)
    password_ok = users.verify_password(req.password, user.password_hash if user else None)
    if user and password_ok:
        mfa = users.mfa_for(user.username)
        if mfa and mfa.enabled:
            if not req.totp_code:
                return JSONResponse({"detail": "Authenticator code required", "mfa_required": True}, status_code=401)
            if not users.verify_totp(mfa.secret, req.totp_code):
                _record_login_failure(ip)
                users.record_username_failure(req.username)
                return JSONResponse({"detail": "Invalid authenticator code", "mfa_required": True}, status_code=401)
        _clear_login_failures(ip)
        users.clear_username_failures(req.username)
        token = _make_session(user.username, user.role)
        csrf_token = _make_csrf_token()
        print(f"[auth] login OK: user={req.username!r} role={user.role} ip={ip}")
        resp = JSONResponse({"ok": True})
        resp.headers.append("Set-Cookie", f"{SESSION_COOKIE}={token}; {_cookie_flags(request)}")
        resp.headers.append("Set-Cookie", f"{CSRF_COOKIE}={csrf_token}; {_cookie_flags(request, http_only=False)}")
        return resp

    _record_login_failure(ip)
    users.record_username_failure(req.username)
    # Deliberately logs the *attempted* username on failure - this is the
    # one place brute-force attempts against this tool would show up, and
    # journalctl is where you'd look for it.
    print(f"[auth] FAILED login attempt: user={req.username!r} ip={ip}")
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with _sessions_lock:
            _sessions.pop(token, None)
            _save_sessions()
    resp = JSONResponse({"ok": True})
    resp.headers.append("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0")
    resp.headers.append("Set-Cookie", f"{CSRF_COOKIE}=; Path=/; Max-Age=0")
    return resp


# ── Account & user management ────────────────────────────────────────────────

@app.get("/api/account")
def api_account(request: Request):
    username = _current_username(request)
    mfa = users.mfa_for(username)
    return {"username": username, "role": _current_role(request), "mfa_enabled": bool(mfa and mfa.enabled)}


class MfaCodeRequest(BaseModel):
    code: str


@app.get("/api/account/mfa")
def api_mfa_status(request: Request):
    row = users.mfa_for(_current_username(request))
    return {"enabled": bool(row and row.enabled), "pending": bool(row and not row.enabled)}


@app.post("/api/account/mfa/setup")
def api_mfa_setup(request: Request):
    _require_recent_auth(request)
    username = _current_username(request)
    secret = users.generate_mfa_secret()
    now = datetime.now(timezone.utc)
    from models import MfaCredential
    row = MfaCredential.get_or_none(MfaCredential.username == username)
    if row:
        if row.enabled:
            raise HTTPException(status_code=409, detail="Disable the current authenticator with a valid code before replacing it")
        row.secret, row.enabled, row.created_at, row.confirmed_at = secret, False, now, None
        row.save()
    else:
        MfaCredential.create(username=username, secret=secret, enabled=False, created_at=now)
    from urllib.parse import quote
    uri = f"otpauth://totp/{quote('SentryNet:' + username)}?secret={secret}&issuer=SentryNet&digits=6&period=30"
    return {"secret": secret, "otpauth_uri": uri}


@app.post("/api/account/mfa/enable")
def api_mfa_enable(req: MfaCodeRequest, request: Request):
    username, ip = _current_username(request), _client_ip(request)
    if _login_rate_limited(ip) or users.username_rate_limited(username):
        raise HTTPException(status_code=429, detail="Too many failed verification attempts. Please try again later.")
    row = users.mfa_for(username)
    if not row or not users.verify_totp(row.secret, req.code):
        _record_login_failure(ip)
        users.record_username_failure(username)
        raise HTTPException(status_code=400, detail="Invalid authenticator code")
    _clear_login_failures(ip)
    users.clear_username_failures(username)
    row.enabled = True
    row.confirmed_at = datetime.now(timezone.utc)
    row.save()
    return {"ok": True}


@app.delete("/api/account/mfa")
def api_mfa_disable(req: MfaCodeRequest, request: Request):
    username, ip = _current_username(request), _client_ip(request)
    if _login_rate_limited(ip) or users.username_rate_limited(username):
        raise HTTPException(status_code=429, detail="Too many failed verification attempts. Please try again later.")
    row = users.mfa_for(username)
    if not row or not row.enabled or not users.verify_totp(row.secret, req.code):
        _record_login_failure(ip)
        users.record_username_failure(username)
        raise HTTPException(status_code=400, detail="Invalid authenticator code")
    _clear_login_failures(ip)
    users.clear_username_failures(username)
    row.delete_instance()
    return {"ok": True}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/account/password")
def api_change_password(req: ChangePasswordRequest, request: Request):
    username = _current_username(request)
    ip = _client_ip(request)
    if _login_rate_limited(ip) or users.username_rate_limited(username):
        raise HTTPException(status_code=429, detail="Too many failed verification attempts. Please try again later.")
    user = User.get_or_none(User.username == username)
    if not user or not users.verify_password(req.current_password, user.password_hash):
        _record_login_failure(ip)
        users.record_username_failure(username)
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    err = users.validate_password(req.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    user.password_hash = users.hash_password(req.new_password)
    user.save()
    _clear_login_failures(ip)
    users.clear_username_failures(username)
    token = request.cookies.get(SESSION_COOKIE)
    _invalidate_sessions_for(username, except_token=token)
    return {"ok": True}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str


@app.get("/api/users")
def api_list_users(request: Request):
    users.require_role(_current_role(request), "owner")
    rows = User.select().order_by(User.created_at.asc())
    return [{"username": r.username, "role": r.role, "created_at": r.created_at.isoformat(),
             "created_by": r.created_by} for r in rows]


@app.post("/api/users")
def api_create_user(req: CreateUserRequest, request: Request):
    users.require_role(_current_role(request), "owner")
    if req.role not in users.ASSIGNABLE_ROLES:
        raise HTTPException(status_code=400, detail="Role must be administrator, operator, or spectator")
    err = users.validate_username(req.username) or users.validate_password(req.password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    if User.get_or_none(User.username == req.username):
        raise HTTPException(status_code=409, detail="A user with that username already exists")
    User.create(
        username=req.username,
        password_hash=users.hash_password(req.password),
        role=req.role,
        created_at=datetime.now(timezone.utc),
        created_by=_current_username(request),
    )
    return {"ok": True, "username": req.username, "role": req.role}


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    password: Optional[str] = None


@app.put("/api/users/{username}")
def api_update_user(username: str, req: UpdateUserRequest, request: Request):
    users.require_role(_current_role(request), "owner")
    target = User.get_or_none(User.username == username)
    if not target:
        raise HTTPException(status_code=404, detail="No such user")
    if target.role == "owner":
        raise HTTPException(status_code=400, detail="The Owner account can't be modified through this API")
    if req.role is not None:
        if req.role not in users.ASSIGNABLE_ROLES:
            raise HTTPException(status_code=400, detail="Role must be administrator, operator, or spectator")
        target.role = req.role
        _update_session_roles(username, req.role)
    if req.password is not None:
        err = users.validate_password(req.password)
        if err:
            raise HTTPException(status_code=400, detail=err)
        target.password_hash = users.hash_password(req.password)
        _invalidate_sessions_for(username)
    target.save()
    return {"ok": True, "username": target.username, "role": target.role}


@app.delete("/api/users/{username}")
def api_delete_user(username: str, request: Request):
    users.require_role(_current_role(request), "owner")
    target = User.get_or_none(User.username == username)
    if not target:
        raise HTTPException(status_code=404, detail="No such user")
    if target.role == "owner":
        raise HTTPException(status_code=400, detail="The Owner account can't be deleted")
    target.delete_instance()
    _invalidate_sessions_for(username)
    return {"ok": True, "username": username}


@app.get("/api/license")
def api_license(request: Request):
    users.require_role(_current_role(request), "owner")
    return license.get_status()


@app.get("/api/fleet")
def api_fleet(request: Request):
    users.require_role(_current_role(request), "owner")
    return {"fleet": fleet_client.get_fleet()}


@app.get("/api/watchdog-status")
def api_watchdog_status(request: Request):
    users.require_role(_current_role(request), "owner")
    return {"threads": watchdog.status()}


@app.get("/", response_class=HTMLResponse)
def index():
    # Query-string asset versions prevent stale UI after a deploy, even when
    # a reverse proxy or CDN applies its own aggressive static-file cache.
    return _html_page("dashboard.html")


# ── Dashboard data API ─────────────────────────────────────────────────────

from peewee import fn

def _since(hours: float = None, minutes: float = None) -> datetime:
    now = datetime.now(timezone.utc)
    if minutes is not None:
        return now - timedelta(minutes=minutes)
    return now - timedelta(hours=hours or 1)


@app.get("/api/stats")
def api_stats(host: Optional[str] = None):
    now = datetime.now(timezone.utc)
    req_1m_q = ReqLog.select().where(ReqLog.ts >= now - timedelta(minutes=1))
    req_5m_q = ReqLog.select().where(ReqLog.ts >= now - timedelta(minutes=5))
    unique_ips_5m_q = ReqLog.select(fn.COUNT(fn.DISTINCT(ReqLog.ip))).where(ReqLog.ts >= now - timedelta(minutes=5))
    req_24h_q = ReqLog.select().where(ReqLog.ts >= now - timedelta(hours=24))
    if host:
        req_1m_q = req_1m_q.where(ReqLog.host == host)
        req_5m_q = req_5m_q.where(ReqLog.host == host)
        unique_ips_5m_q = unique_ips_5m_q.where(ReqLog.host == host)
        req_24h_q = req_24h_q.where(ReqLog.host == host)
    req_1m = req_1m_q.count()
    req_5m = req_5m_q.count()
    unique_ips_5m = unique_ips_5m_q.scalar()
    req_24h = req_24h_q.count()
    # Flagged/blocked counts are IP-level, not per-request - not meaningfully
    # filterable by host (a flagged IP may have hit several sites), so these
    # stay global regardless of the host param.
    flagged_active = FlaggedIp.select().where(FlaggedIp.last_seen >= now - timedelta(minutes=10)).count()
    blocked_count = BlockedIp.select().count()
    return {
        "requests_1m": req_1m,
        "requests_per_min": req_5m / 5.0,
        "unique_ips_5m": unique_ips_5m or 0,
        "requests_24h": req_24h,
        "flagged_active": flagged_active,
        "blocked_count": blocked_count,
    }


@app.get("/api/hosts")
def api_hosts():
    since = _since(hours=24 * 7)
    rows = (ReqLog.select(ReqLog.host).where(ReqLog.ts >= since)
            .group_by(ReqLog.host).order_by(ReqLog.host))
    return [r.host for r in rows]


@app.get("/api/trends")
def api_trends(days: int = Query(90, ge=1, le=730), host: Optional[str] = None):
    # Deliberately not capped at 30 days like every requests-backed endpoint -
    # rollup_daily.py's whole point is surviving past cleanup_old_requests.py's
    # retention window, so this is the one place longer history is available.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # "days" includes today's live partial day. Restrict stored rollups to
    # completed days so an accidental/manual same-day rollup can never appear
    # twice beside the live row below.
    since = today - timedelta(days=days - 1)
    q = DailyStatRollup.select().where(
        (DailyStatRollup.date >= since) & (DailyStatRollup.date < today)
    )
    q = q.where(DailyStatRollup.host == host) if host else q.where(DailyStatRollup.host.is_null(True))
    rows = q.order_by(DailyStatRollup.date)
    result = [{
        "date": r.date.date().isoformat(),
        "total_requests": r.total_requests,
        "unique_ips": r.unique_ips,
        "bot_requests": r.bot_requests,
        "avg_response_ms": round(r.avg_response_time * 1000, 1) if r.avg_response_time is not None else None,
        "p95_response_ms": round(r.p95_response_time * 1000, 1) if r.p95_response_time is not None else None,
        "status_5xx_count": r.status_5xx_count,
        "top_country": r.top_country,
    } for r in rows]

    # Show useful trends on day one instead of waiting for the first 04:00
    # rollup. This row is intentionally computed from raw requests and is
    # replaced by the immutable nightly rollup after the day closes.
    host_clause = " AND host = %s" if host else ""
    params = (today, now, host) if host else (today, now)
    live = db.execute_sql(f"""
        SELECT COUNT(*), COUNT(DISTINCT ip),
               SUM(CASE WHEN is_bot THEN 1 ELSE 0 END),
               AVG(request_time),
               PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY request_time),
               SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END)
        FROM requests WHERE ts >= %s AND ts < %s{host_clause}
    """, params).fetchone()
    if live and live[0]:
        country = db.execute_sql(f"""
            SELECT country FROM requests
            WHERE ts >= %s AND ts < %s AND country IS NOT NULL{host_clause}
            GROUP BY country ORDER BY COUNT(*) DESC LIMIT 1
        """, params).fetchone()
        result.append({
            "date": today.date().isoformat(),
            "total_requests": live[0],
            "unique_ips": live[1],
            "bot_requests": live[2] or 0,
            "avg_response_ms": round(live[3] * 1000, 1) if live[3] is not None else None,
            "p95_response_ms": round(live[4] * 1000, 1) if live[4] is not None else None,
            "status_5xx_count": live[5] or 0,
            "top_country": country[0] if country else None,
            "partial": True,
        })
    return result


def _bandwidth_summary(r: BandwidthReport) -> dict:
    return {
        "date": r.date.date().isoformat(),
        "window_start": r.window_start.isoformat(),
        "window_end": r.window_end.isoformat(),
        "total_bytes": r.total_bytes,
        "total_requests": r.total_requests,
        "unique_ips": r.unique_ips,
        "bot_requests": r.bot_requests,
        "human_requests": r.human_requests,
        "status_2xx": r.status_2xx,
        "status_3xx": r.status_3xx,
        "status_4xx": r.status_4xx,
        "status_5xx": r.status_5xx,
        "avg_response_ms": round(r.avg_response_time * 1000, 1) if r.avg_response_time is not None else None,
        "top_host": r.top_host,
        "top_host_bytes": r.top_host_bytes,
        "top_country": r.top_country,
        "top_path": r.top_path,
    }


def _bandwidth_current_window(now: datetime):
    """Return the continuous 06:00-06:00 UTC window containing ``now``."""
    start = bandwidth_report.window_start_for_date(now)
    if now < start:
        start -= timedelta(days=1)
    end = start + timedelta(hours=bandwidth_report.WINDOW_HOURS)
    return start, end, start <= now < end


@app.get("/api/bandwidth-reports")
def api_bandwidth_reports(limit: int = Query(30, ge=1, le=365), offset: int = Query(0, ge=0)):
    q = (BandwidthReport.select()
         .order_by(BandwidthReport.date.desc()).limit(limit).offset(offset))
    return [_bandwidth_summary(r) for r in q]


# Registered before /api/bandwidth-reports/{date} so "trend"/"current" aren't
# swallowed as a date value by the dynamic route (FastAPI matches in order).
@app.get("/api/bandwidth-reports/trend")
def api_bandwidth_report_trend(days: int = Query(90, ge=1, le=730)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (BandwidthReport.select().where(BandwidthReport.date >= since)
            .order_by(BandwidthReport.date))
    return [{
        "date": r.date.date().isoformat(),
        "total_bytes": r.total_bytes,
        "total_requests": r.total_requests,
        "unique_ips": r.unique_ips,
    } for r in rows]


@app.get("/api/bandwidth-reports/current")
def api_bandwidth_report_current():
    now = datetime.now(timezone.utc)
    start, end, active = _bandwidth_current_window(now)
    data = bandwidth_report.aggregate(start, end)
    data["window_start"] = start.isoformat()
    data["window_end"] = end.isoformat()
    data["active"] = active
    return data


@app.post("/api/bandwidth-reports/build")
def api_bandwidth_report_build(request: Request, report_date: Optional[str] = None):
    users.require_role(_current_role(request), "administrator")
    if report_date:
        try:
            day = datetime.strptime(report_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD")
        start = bandwidth_report.window_start_for_date(day)
    else:
        start = bandwidth_report.latest_completed_window_start()
    data = bandwidth_report.build_report(start)
    return {
        "ok": True,
        "date": start.date().isoformat(),
        "total_bytes": data["total_bytes"],
        "total_requests": data["total_requests"],
        "unique_ips": data["unique_ips"],
    }


@app.get("/api/bandwidth-reports/{report_date}")
def api_bandwidth_report_detail(report_date: str):
    try:
        day = datetime.strptime(report_date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD")
    start = bandwidth_report.window_start_for_date(day)
    row = BandwidthReport.get_or_none(BandwidthReport.date == start)
    if not row:
        # Preserve access to reports made before the 06:00-06:00 migration,
        # whose key used the legacy 16:00 start on the same UTC date.
        day_start = start.replace(hour=0)
        day_end = day_start + timedelta(days=1)
        row = (BandwidthReport.select()
               .where((BandwidthReport.date >= day_start) & (BandwidthReport.date < day_end))
               .order_by(BandwidthReport.date.desc()).first())
    if not row:
        raise HTTPException(status_code=404, detail="no report for that window")
    out = _bandwidth_summary(row)
    try:
        out["details"] = json.loads(row.details or "{}")
    except (ValueError, TypeError):
        out["details"] = {}
    return out


@app.get("/api/timeseries")
def api_timeseries(minutes: int = Query(60, ge=5, le=1440), host: Optional[str] = None):
    since = _since(minutes=minutes)
    bucket = fn.date_trunc("minute", ReqLog.ts)
    q = ReqLog.select(bucket.alias("bucket"), fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(bucket).order_by(bucket)
    return [{"minute": r.bucket.isoformat(), "count": r.count} for r in rows]


@app.get("/api/top-countries")
def api_top_countries(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(15, ge=1, le=50), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.country, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.country).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit)
    return [{"country": r.country or "??", "count": r.count} for r in rows]


@app.get("/api/top-hosts")
def api_top_hosts(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(15, ge=1, le=50)):
    since = _since(hours=hours)
    rows = (ReqLog.select(ReqLog.host, fn.COUNT(ReqLog.id).alias("count"))
            .where(ReqLog.ts >= since)
            .group_by(ReqLog.host).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit))
    return [{"host": r.host, "count": r.count} for r in rows]


@app.get("/api/top-ips")
def api_top_ips(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(15, ge=1, le=50), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.ip, ReqLog.country, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.ip, ReqLog.country).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit)
    return [{"ip": r.ip, "country": r.country or "??", "count": r.count} for r in rows]


@app.get("/api/device-breakdown")
def api_device_breakdown(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.device, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.device).order_by(fn.COUNT(ReqLog.id).desc())
    return [{"device": r.device or "Unknown", "count": r.count} for r in rows]


@app.get("/api/status-breakdown")
def api_status_breakdown(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    bucket = (ReqLog.status / 100).cast("int") * 100
    q = ReqLog.select(bucket.alias("bucket"), fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(bucket).order_by(bucket)
    return [{"bucket": f"{r.bucket}-{r.bucket+99}", "count": r.count} for r in rows]


@app.get("/api/bandwidth-timeseries")
def api_bandwidth_timeseries(minutes: int = Query(60, ge=5, le=1440), host: Optional[str] = None):
    since = _since(minutes=minutes)
    bucket = fn.date_trunc("minute", ReqLog.ts)
    q = ReqLog.select(bucket.alias("bucket"), fn.SUM(ReqLog.bytes).alias("bytes")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(bucket).order_by(bucket)
    return [{"minute": r.bucket.isoformat(), "bytes": int(r.bytes or 0)} for r in rows]


@app.get("/api/top-paths")
def api_top_paths(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(15, ge=1, le=50), host: Optional[str] = None):
    since = _since(hours=hours)
    q = (ReqLog.select(ReqLog.path, fn.COUNT(ReqLog.id).alias("count"), fn.SUM(ReqLog.bytes).alias("bytes"))
         .where(ReqLog.ts >= since))
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.path).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit)
    return [{"path": r.path, "count": r.count, "bytes": int(r.bytes or 0)} for r in rows]


@app.get("/api/response-times")
def api_response_times(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    cursor = db.execute_sql("""
        SELECT
            AVG(request_time) AS avg_rt,
            PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY request_time) AS p50,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY request_time) AS p95,
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY request_time) AS p99,
            COUNT(*) AS n
        FROM requests
        WHERE ts >= %s AND request_time IS NOT NULL""" + (" AND host = %s" if host else "") + """
    """, (since, host) if host else (since,))
    avg_rt, p50, p95, p99, n = cursor.fetchone()
    return {
        "avg_ms": round(avg_rt * 1000, 1) if avg_rt is not None else None,
        "p50_ms": round(p50 * 1000, 1) if p50 is not None else None,
        "p95_ms": round(p95 * 1000, 1) if p95 is not None else None,
        "p99_ms": round(p99 * 1000, 1) if p99 is not None else None,
        "sample_count": n or 0,
    }


@app.get("/api/browser-breakdown")
def api_browser_breakdown(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(10, ge=1, le=30), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.browser, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.browser).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit)
    return [{"browser": r.browser or "Unknown", "count": r.count} for r in rows]


@app.get("/api/os-breakdown")
def api_os_breakdown(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(10, ge=1, le=30), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.os, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.os).order_by(fn.COUNT(ReqLog.id).desc()).limit(limit)
    return [{"os": r.os or "Unknown", "count": r.count} for r in rows]


@app.get("/api/bot-breakdown")
def api_bot_breakdown(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    bot_q = ReqLog.select().where((ReqLog.ts >= since) & (ReqLog.is_bot == True))
    human_q = ReqLog.select().where((ReqLog.ts >= since) & (ReqLog.is_bot == False))
    if host:
        bot_q = bot_q.where(ReqLog.host == host)
        human_q = human_q.where(ReqLog.host == host)
    bot_count = bot_q.count()
    human_count = human_q.count()
    total = bot_count + human_count
    return {
        "bot_count": bot_count,
        "human_count": human_count,
        "bot_pct": round(100 * bot_count / total, 1) if total else 0.0,
    }


@app.get("/api/referrers")
def api_referrers(hours: float = Query(24, ge=0.1, le=720), limit: int = Query(15, ge=1, le=50), host: Optional[str] = None):
    since = _since(hours=hours)
    # Grouping by exact referer text overcounts distinct URLs on the same
    # domain (query strings vary) - so pull a generous sample of the top raw
    # referer strings, then re-bucket those by netloc in Python. Sample size
    # (500) is comfortably above `limit` so common domains aren't cut off by
    # only sampling the single most common exact URL for each.
    q = (ReqLog.select(ReqLog.referer, fn.COUNT(ReqLog.id).alias("count"))
         .where((ReqLog.ts >= since) & ReqLog.referer.is_null(False) & (ReqLog.referer != "-")))
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.referer).order_by(fn.COUNT(ReqLog.id).desc()).limit(500)
    domain_counts: Dict[str, int] = {}
    for r in rows:
        try:
            netloc = urlparse(r.referer).netloc or r.referer
        except Exception:
            netloc = r.referer
        domain_counts[netloc] = domain_counts.get(netloc, 0) + r.count
    top = sorted(domain_counts.items(), key=lambda x: -x[1])[:limit]
    return [{"referrer": d, "count": c} for d, c in top]


@app.get("/api/ssl-breakdown")
def api_ssl_breakdown(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    q = ReqLog.select(ReqLog.ssl_protocol, fn.COUNT(ReqLog.id).alias("count")).where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    rows = q.group_by(ReqLog.ssl_protocol).order_by(fn.COUNT(ReqLog.id).desc())
    return [{"protocol": r.ssl_protocol or "None (plain HTTP)", "count": r.count} for r in rows]


@app.get("/api/new-vs-returning")
def api_new_vs_returning(hours: float = Query(24, ge=0.1, le=720), host: Optional[str] = None):
    since = _since(hours=hours)
    # "new" = this IP's all-time first request (to this host, if filtered)
    # falls inside the window; "returning" = it was already making requests
    # before the window started.
    host_clause = " AND host = %s" if host else ""
    inner_params = (since, host) if host else (since,)
    outer_host_params = (host,) if host else ()
    cursor = db.execute_sql(f"""
        SELECT
            COUNT(*) FILTER (WHERE first_seen >= %s) AS new_ips,
            COUNT(*) FILTER (WHERE first_seen <  %s) AS returning_ips
        FROM (
            SELECT ip, MIN(ts) AS first_seen
            FROM requests
            WHERE ip IN (SELECT DISTINCT ip FROM requests WHERE ts >= %s{host_clause})
            {host_clause}
            GROUP BY ip
        ) sub
    """, (since, since) + inner_params + outer_host_params)
    new_ips, returning_ips = cursor.fetchone()
    return {"new_ips": new_ips or 0, "returning_ips": returning_ips or 0}


@app.get("/api/hourly-comparison")
def api_hourly_comparison(host: Optional[str] = None):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    # requests.ts is stored as naive UTC (see models.py) - strip tzinfo here
    # too so the comparison below isn't naive-vs-aware (Postgres also returns
    # naive datetimes for a "timestamp without time zone" column).
    today_start_naive = today_start.replace(tzinfo=None)
    yesterday_start_naive = yesterday_start.replace(tzinfo=None)
    host_clause = " AND host = %s" if host else ""
    params = (yesterday_start_naive, host) if host else (yesterday_start_naive,)
    cursor = db.execute_sql(f"""
        SELECT date_trunc('hour', ts) AS hour, COUNT(*) AS count
        FROM requests
        WHERE ts >= %s{host_clause}
        GROUP BY hour ORDER BY hour
    """, params)
    today, yesterday = {}, {}
    for hour, count in cursor.fetchall():
        (today if hour >= today_start_naive else yesterday)[hour.hour] = count
    return {
        "today": [{"hour": h, "count": today.get(h, 0)} for h in range(now.hour + 1)],
        "yesterday": [{"hour": h, "count": yesterday.get(h, 0)} for h in range(24)],
    }


@app.get("/api/requests")
def api_requests(
    host: Optional[str] = None,
    ip: Optional[str] = None,
    country: Optional[str] = None,
    status: Optional[int] = None,
    device: Optional[str] = None,
    hours: float = Query(1, ge=0.05, le=720),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    since = _since(hours=hours)
    q = ReqLog.select().where(ReqLog.ts >= since)
    if host:
        q = q.where(ReqLog.host == host)
    if ip:
        q = q.where(ReqLog.ip == ip)
    if country:
        q = q.where(ReqLog.country == country)
    if status:
        q = q.where(ReqLog.status == status)
    if device:
        q = q.where(ReqLog.device == device)
    q = q.order_by(ReqLog.ts.desc()).limit(limit).offset(offset)
    return [{
        "ts": r.ts.isoformat(), "ip": r.ip, "country": r.country, "host": r.host,
        "method": r.method, "path": r.path, "status": r.status, "bytes": r.bytes,
        "referer": r.referer, "user_agent": r.user_agent, "device": r.device,
        "os": r.os, "browser": r.browser, "is_bot": r.is_bot,
        "request_time": r.request_time,
    } for r in q]


@app.get("/api/flagged")
def api_flagged(limit: int = Query(100, ge=1, le=500)):
    blocked_ips = {b.ip for b in BlockedIp.select(BlockedIp.ip)}
    rows = FlaggedIp.select().order_by(FlaggedIp.last_seen.desc()).limit(limit)
    return [{
        "ip": r.ip, "country": r.country, "score": r.score,
        "signals": json.loads(r.signals), "first_seen": r.first_seen.isoformat(),
        "last_seen": r.last_seen.isoformat(), "is_blocked": r.ip in blocked_ips,
    } for r in rows]


@app.get("/api/ip/{ip:path}")
def api_ip_detail(ip: str):
    flagged = FlaggedIp.get_or_none(FlaggedIp.ip == ip)
    blocked = BlockedIp.get_or_none(BlockedIp.ip == ip)
    allowed = AllowedIp.get_or_none(AllowedIp.ip == ip)
    recent = (ReqLog.select().where(ReqLog.ip == ip)
              .order_by(ReqLog.ts.desc()).limit(100))
    hosts = (ReqLog.select(ReqLog.host, fn.COUNT(ReqLog.id).alias("count"))
             .where(ReqLog.ip == ip).group_by(ReqLog.host).order_by(fn.COUNT(ReqLog.id).desc()))
    return {
        "ip": ip,
        "flagged": ({"score": flagged.score, "signals": json.loads(flagged.signals),
                     "first_seen": flagged.first_seen.isoformat(), "last_seen": flagged.last_seen.isoformat()}
                    if flagged else None),
        "blocked": ({"reason": blocked.reason, "blocked_at": blocked.blocked_at.isoformat(),
                     "blocked_by": blocked.blocked_by,
                     "expires_at": blocked.expires_at.isoformat() if blocked.expires_at else None}
                    if blocked else None),
        "allowed": ({"reason": allowed.reason, "added_at": allowed.added_at.isoformat(),
                     "added_by": allowed.added_by} if allowed else None),
        "is_tor_exit": threat_intel.is_tor_exit(ip),
        "datacenter_provider": threat_intel.is_datacenter(ip),
        "hosts_hit": [{"host": h.host, "count": h.count} for h in hosts],
        "recent_requests": [{
            "ts": r.ts.isoformat(), "host": r.host, "method": r.method, "path": r.path,
            "status": r.status, "user_agent": r.user_agent,
        } for r in recent],
    }


# ── Block / unblock ─────────────────────────────────────────────────────────

def _regenerate_blocklist():
    webserver_backend.regenerate_blocklist()


class BlockRequest(BaseModel):
    ip: str  # bare IP or CIDR, e.g. "1.2.3.4" or "1.2.3.0/24"
    reason: Optional[str] = None
    duration_hours: Optional[float] = None  # omitted/null = permanent


@app.post("/api/block")
def api_block(req: BlockRequest, request: Request):
    users.require_role(_current_role(request), "operator")
    try:
        ipaddress.ip_network(req.ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP address or CIDR")

    username = _current_username(request)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=req.duration_hours) if req.duration_hours else None
    BlockedIp.insert(ip=req.ip, reason=req.reason, blocked_at=now,
                      blocked_by=username, expires_at=expires_at).on_conflict_ignore().execute()
    try:
        _regenerate_blocklist()
    except RuntimeError as e:
        BlockedIp.delete().where(BlockedIp.ip == req.ip).execute()
        raise HTTPException(status_code=500, detail=str(e))
    BlockAudit.create(ts=now, action="block", target=req.ip, reason=req.reason, actor=username)
    if alert_settings.is_enabled("ip_blocks"):
        send_discord_alert(
            f":no_entry: **IP blocked**: `{req.ip}`\n"
            f"Reason: {req.reason or '(none given)'}\n" +
            (f"Expires: {expires_at.isoformat()}\n" if expires_at else "Permanent\n") +
            f"By: {username}"
        )
    return {"ok": True, "ip": req.ip, "expires_at": expires_at.isoformat() if expires_at else None}


@app.delete("/api/block/{ip:path}")
def api_unblock(ip: str, request: Request):
    users.require_role(_current_role(request), "operator")
    blocked = BlockedIp.get_or_none(BlockedIp.ip == ip)
    BlockedIp.delete().where(BlockedIp.ip == ip).execute()
    try:
        _regenerate_blocklist()
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    username = _current_username(request)
    reason = blocked.reason if blocked else None
    BlockAudit.create(ts=datetime.now(timezone.utc), action="unblock", target=ip, reason=reason, actor=username)
    if alert_settings.is_enabled("ip_blocks"):
        send_discord_alert(
            f":white_check_mark: **IP unblocked**: `{ip}`" +
            (f"\nWas blocked for: {reason}" if reason else "") +
            f"\nBy: {username}"
        )
    return {"ok": True, "ip": ip}


@app.get("/api/blocked")
def api_blocked():
    rows = BlockedIp.select().order_by(BlockedIp.blocked_at.desc())
    return [{"ip": r.ip, "reason": r.reason, "blocked_at": r.blocked_at.isoformat(),
             "blocked_by": r.blocked_by,
             "expires_at": r.expires_at.isoformat() if r.expires_at else None} for r in rows]


# ── Allowlist ────────────────────────────────────────────────────────────────

class AllowRequest(BaseModel):
    ip: str
    reason: Optional[str] = None


@app.post("/api/allow")
def api_allow(req: AllowRequest, request: Request):
    users.require_role(_current_role(request), "operator")
    try:
        ipaddress.ip_network(req.ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP address or CIDR")
    username = _current_username(request)
    now = datetime.now(timezone.utc)
    AllowedIp.insert(ip=req.ip, reason=req.reason, added_at=now, added_by=username).on_conflict_ignore().execute()
    BlockAudit.create(ts=now, action="allow", target=req.ip, reason=req.reason, actor=username)
    ingest._refresh_allow_deny_cache(force=True)
    return {"ok": True, "ip": req.ip}


@app.delete("/api/allow/{ip:path}")
def api_unallow(ip: str, request: Request):
    users.require_role(_current_role(request), "operator")
    AllowedIp.delete().where(AllowedIp.ip == ip).execute()
    username = _current_username(request)
    BlockAudit.create(ts=datetime.now(timezone.utc), action="unallow", target=ip, reason=None, actor=username)
    ingest._refresh_allow_deny_cache(force=True)
    return {"ok": True, "ip": ip}


@app.get("/api/allowed")
def api_allowed_list():
    rows = AllowedIp.select().order_by(AllowedIp.added_at.desc())
    return [{"ip": r.ip, "reason": r.reason, "added_at": r.added_at.isoformat(),
             "added_by": r.added_by} for r in rows]


# ── Country blocking ─────────────────────────────────────────────────────────

class BlockCountryRequest(BaseModel):
    country: str
    reason: Optional[str] = None
    block_existing: bool = True  # also retroactively block IPs already seen from this country (last 24h)


@app.post("/api/block-country")
def api_block_country(req: BlockCountryRequest, request: Request):
    users.require_role(_current_role(request), "operator")
    code = req.country.strip().upper()
    if len(code) != 2 or not code.isalpha():
        raise HTTPException(status_code=400, detail="Country must be a 2-letter ISO code")
    username = _current_username(request)
    now = datetime.now(timezone.utc)
    BlockedCountry.insert(country=code, reason=req.reason, blocked_at=now, blocked_by=username).on_conflict_ignore().execute()
    BlockAudit.create(ts=now, action="block_country", target=code, reason=req.reason, actor=username)
    ingest._refresh_allow_deny_cache(force=True)

    blocked_now = 0
    if req.block_existing:
        recent_ips = (ReqLog.select(ReqLog.ip).distinct()
                      .where((ReqLog.country == code) & (ReqLog.ts >= now - timedelta(hours=24))))
        for row in recent_ips:
            if ingest.is_ip_covered_by_block(row.ip):
                continue
            reason = f"country block: {code}"
            BlockedIp.insert(ip=row.ip, reason=reason, blocked_at=now,
                              blocked_by=username, expires_at=None).on_conflict_ignore().execute()
            BlockAudit.create(ts=now, action="block", target=row.ip, reason=reason, actor=username)
            blocked_now += 1
    if blocked_now:
        try:
            _regenerate_blocklist()
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
    if alert_settings.is_enabled("ip_blocks"):
        send_discord_alert(
            f":no_entry: **Country blocked**: `{code}`\n"
            f"Reason: {req.reason or '(none given)'}\n"
            f"Retroactively blocked {blocked_now} existing IP(s).\n"
            f"By: {username}"
        )
    return {"ok": True, "country": code, "retroactively_blocked": blocked_now}


@app.delete("/api/block-country/{code}")
def api_unblock_country(code: str, request: Request):
    users.require_role(_current_role(request), "operator")
    code = code.strip().upper()
    BlockedCountry.delete().where(BlockedCountry.country == code).execute()
    username = _current_username(request)
    BlockAudit.create(ts=datetime.now(timezone.utc), action="unblock_country", target=code, reason=None, actor=username)
    ingest._refresh_allow_deny_cache(force=True)
    if alert_settings.is_enabled("ip_blocks"):
        send_discord_alert(f":white_check_mark: **Country unblocked**: `{code}`\nBy: {username}")
    return {"ok": True, "country": code}


@app.get("/api/blocked-countries")
def api_blocked_countries():
    rows = BlockedCountry.select().order_by(BlockedCountry.blocked_at.desc())
    return [{"country": r.country, "reason": r.reason, "blocked_at": r.blocked_at.isoformat(),
             "blocked_by": r.blocked_by} for r in rows]


# ── Bulk actions & audit log ─────────────────────────────────────────────────

class BulkBlockRequest(BaseModel):
    min_score: Optional[int] = None
    ips: Optional[List[str]] = None
    reason: Optional[str] = None


@app.post("/api/bulk-block")
def api_bulk_block(req: BulkBlockRequest, request: Request):
    users.require_role(_current_role(request), "operator")
    username = _current_username(request)
    targets = set(req.ips or [])
    if req.min_score is not None:
        flagged = FlaggedIp.select(FlaggedIp.ip).where(FlaggedIp.score >= req.min_score)
        targets.update(f.ip for f in flagged)
    if not targets:
        raise HTTPException(status_code=400, detail="No matching IPs to block")

    now = datetime.now(timezone.utc)
    blocked = []
    for ip in targets:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ingest.is_ip_covered_by_block(ip):
            continue
        reason = req.reason or (f"bulk block (score >= {req.min_score})" if req.min_score is not None else "bulk block")
        BlockedIp.insert(ip=ip, reason=reason, blocked_at=now, blocked_by=username,
                          expires_at=None).on_conflict_ignore().execute()
        BlockAudit.create(ts=now, action="block", target=ip, reason=reason, actor=username)
        blocked.append(ip)

    if blocked:
        try:
            _regenerate_blocklist()
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=str(e))
        if alert_settings.is_enabled("ip_blocks"):
            send_discord_alert(f":no_entry: **Bulk block**: {len(blocked)} IP(s)\nBy: {username}")
    return {"ok": True, "blocked_count": len(blocked), "blocked": blocked}


@app.get("/api/audit-log")
def api_audit_log(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    rows = BlockAudit.select().order_by(BlockAudit.ts.desc()).limit(limit).offset(offset)
    return [{"ts": r.ts.isoformat(), "action": r.action, "target": r.target,
             "reason": r.reason, "actor": r.actor} for r in rows]


@app.get("/api/threat-intel-status")
def api_threat_intel_status():
    return threat_intel.get_status()


# ── Alert settings ───────────────────────────────────────────────────────────

class AlertSettingRequest(BaseModel):
    enabled: bool


@app.get("/api/alert-settings")
def api_alert_settings():
    return alert_settings.list_settings()


@app.post("/api/alert-settings/{key}")
def api_set_alert_setting(key: str, req: AlertSettingRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    try:
        alert_settings.set_enabled(key, req.enabled)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown alert category")
    return {"ok": True, "key": key, "enabled": req.enabled}


class WebhookRequest(BaseModel):
    url: str


@app.get("/api/alert-webhook")
def api_get_alert_webhook():
    url = get_webhook_url()
    return {"configured": bool(url), "masked": ("…" + url[-6:]) if len(url) > 6 else None}


@app.post("/api/alert-webhook")
def api_set_alert_webhook(req: WebhookRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    url = req.url.strip()
    if url and not url.startswith(("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/")):
        raise HTTPException(status_code=400, detail="Doesn't look like a Discord webhook URL")
    persist_webhook_url(url)
    return {"ok": True, "configured": bool(url)}


class AbuseIpdbKeyRequest(BaseModel):
    key: str


@app.get("/api/abuseipdb-key")
def api_get_abuseipdb_key():
    status = ip_reputation.get_status()
    return {"configured": status["configured"], "cache_size": status["cache_size"]}


@app.post("/api/abuseipdb-key")
def api_set_abuseipdb_key(req: AbuseIpdbKeyRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    ip_reputation.persist_api_key(req.key.strip())
    return {"ok": True, "configured": bool(req.key.strip())}


class ReportSettingsRequest(BaseModel):
    cadence: str
    recipients: str = ""
    smtp_host: str = ""
    smtp_port: str = "587"
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""


@app.get("/api/report-settings")
def api_get_report_settings():
    return report.get_settings()


@app.post("/api/report-settings")
def api_set_report_settings(req: ReportSettingsRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    if req.cadence not in ("off", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="cadence must be 'off', 'weekly', or 'monthly'")
    updates = {
        "cadence": req.cadence,
        "recipients": req.recipients.strip(),
        "smtp_host": req.smtp_host.strip(),
        "smtp_port": req.smtp_port.strip() or "587",
        "smtp_user": req.smtp_user.strip(),
        "smtp_from": req.smtp_from.strip(),
    }
    # Blank password on the wire means "leave the stored one alone" (mirrors
    # never echoing it back in GET) - only overwrite it if a new one was sent.
    if req.smtp_password.strip():
        updates["smtp_password"] = req.smtp_password.strip()
    report.persist_settings(**updates)
    return {"ok": True}


@app.post("/api/report/send-test")
def api_report_send_test(request: Request):
    users.require_role(_current_role(request), "administrator")
    ok, msg = report.send_report()
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"ok": True, "message": msg}


@app.get("/api/volumetric-status")
def api_volumetric_status():
    return ingest.get_volumetric_status()


# ── Infrastructure: SSH, config integrity, certs, app logs, resources ──────

@app.get("/api/ssh-events")
def api_ssh_events(limit: int = Query(100, ge=1, le=500), result: Optional[str] = None):
    q = SshAuthEvent.select()
    if result:
        q = q.where(SshAuthEvent.result == result)
    rows = q.order_by(SshAuthEvent.ts.desc()).limit(limit)
    return [{"ts": r.ts.isoformat(), "ip": r.ip, "country": r.country,
             "username": r.username, "result": r.result} for r in rows]


@app.get("/api/ssh-banned")
def api_ssh_banned():
    return ssh_ban.list_banned()


@app.delete("/api/ssh-banned/{ip}")
def api_ssh_unban(ip: str, request: Request):
    users.require_role(_current_role(request), "operator")
    username = _current_username(request)
    ssh_ban.unban_ip(ip, actor=username)
    return {"ok": True, "ip": ip}


@app.get("/api/integrity-events")
def api_integrity_events(limit: int = Query(100, ge=1, le=500)):
    rows = IntegrityEvent.select().order_by(IntegrityEvent.ts.desc()).limit(limit)
    return [{"ts": r.ts.isoformat(), "path": r.path, "change_type": r.change_type,
             "old_hash": r.old_hash, "new_hash": r.new_hash} for r in rows]


@app.get("/api/defacement-events")
def api_defacement_events(limit: int = Query(100, ge=1, le=500)):
    rows = DefacementEvent.select().order_by(DefacementEvent.ts.desc()).limit(limit)
    return [{"ts": r.ts.isoformat(), "path": r.path, "change_type": r.change_type,
             "old_hash": r.old_hash, "new_hash": r.new_hash} for r in rows]


@app.get("/api/egress-events")
def api_egress_events(limit: int = Query(100, ge=1, le=500)):
    rows = EgressEvent.select().order_by(EgressEvent.ts.desc()).limit(limit)
    return [{"ts": r.ts.isoformat(), "process": r.process,
             "remote_ip": r.remote_ip, "remote_port": r.remote_port} for r in rows]


@app.get("/api/cert-status")
def api_cert_status():
    return cert_monitor.get_status()


@app.get("/api/app-log-events")
def api_app_log_events(limit: int = Query(100, ge=1, le=500), unit: Optional[str] = None, level: Optional[str] = None):
    q = AppLogEvent.select()
    if unit:
        q = q.where(AppLogEvent.unit == unit)
    if level:
        q = q.where(AppLogEvent.level == level)
    rows = q.order_by(AppLogEvent.ts.desc()).limit(limit)
    return [{"ts": r.ts.isoformat(), "unit": r.unit, "level": r.level, "message": r.message} for r in rows]


@app.get("/api/resource-current")
def api_resource_current():
    """Latest sample + a rough 24h peak per unit - one row per service for a
    table view rather than a chart (per-unit trend charts are a lot of chart
    chrome for ~18 mostly-flat lines)."""
    cursor = db.execute_sql("""
        SELECT DISTINCT ON (unit) unit, ts, memory_bytes, cpu_percent
        FROM service_resource_samples
        ORDER BY unit, ts DESC
    """)
    latest = {row[0]: {"unit": row[0], "ts": row[1].isoformat(), "memory_bytes": row[2], "cpu_percent": row[3]} for row in cursor.fetchall()}

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    cursor = db.execute_sql("""
        SELECT unit, MAX(memory_bytes) FROM service_resource_samples WHERE ts >= %s GROUP BY unit
    """, (since.replace(tzinfo=None),))
    for unit, peak in cursor.fetchall():
        if unit in latest:
            latest[unit]["memory_peak_24h"] = peak

    return sorted(latest.values(), key=lambda r: -(r["memory_bytes"] or 0))


@app.get("/api/resource-timeseries")
def api_resource_timeseries(unit: str, hours: float = Query(24, ge=0.1, le=168)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (ServiceResourceSample.select()
            .where((ServiceResourceSample.unit == unit) & (ServiceResourceSample.ts >= since))
            .order_by(ServiceResourceSample.ts))
    return [{"ts": r.ts.isoformat(), "memory_bytes": r.memory_bytes, "cpu_percent": r.cpu_percent} for r in rows]


# ── Operations center: incidents, search, policies, integrations, setup ────

class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None


@app.get("/api/incidents")
def api_incidents(status: Optional[str] = None, severity: Optional[str] = None,
                  category: Optional[str] = None, q: Optional[str] = None,
                  limit: int = Query(200, ge=1, le=500)):
    return operations.list_incidents(status, severity, category, q, limit)


@app.patch("/api/incidents/{incident_id}")
def api_update_incident(incident_id: str, req: IncidentUpdateRequest, request: Request):
    users.require_role(_current_role(request), "operator")
    if req.status is not None and req.status not in {"open", "investigating", "resolved"}:
        raise HTTPException(status_code=400, detail="Invalid incident status")
    row = operations.update_incident(incident_id, req.status, req.assignee, req.notes)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@app.get("/api/search")
def api_global_search(q: str = Query(..., min_length=2, max_length=200),
                      limit: int = Query(50, ge=1, le=200)):
    return {"query": q, "results": operations.global_search(q, limit)}


@app.get("/api/search/export")
def api_search_export(q: str = Query(..., min_length=2, max_length=200)):
    import csv
    import io
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["type", "timestamp", "title", "meta", "target"])
    writer.writeheader()
    for row in operations.global_search(q, 200):
        writer.writerow({key: _csv_cell(value) for key, value in row.items()})
    safe_name = "".join(c for c in q if c.isalnum() or c in "-_")[:30] or "search"
    return Response(output.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="sentrynet-{safe_name}.csv"'})


class SavedViewRequest(BaseModel):
    name: str
    query: dict


@app.get("/api/saved-views")
def api_saved_views(request: Request):
    rows = SavedView.select().where(SavedView.owner == _current_username(request)).order_by(SavedView.name)
    return [{"id": str(r.id), "name": r.name, "query": json.loads(r.query), "created_at": r.created_at.isoformat()} for r in rows]


@app.post("/api/saved-views")
def api_save_view(req: SavedViewRequest, request: Request):
    name = req.name.strip()
    if not name or len(name) > 80:
        raise HTTPException(status_code=400, detail="View name must be 1-80 characters")
    now = datetime.now(timezone.utc)
    row = (SavedView.insert(owner=_current_username(request), name=name, query=json.dumps(req.query), created_at=now)
           .on_conflict(conflict_target=[SavedView.owner, SavedView.name], update={SavedView.query: json.dumps(req.query)})
           .execute())
    return {"ok": True, "id": str(row)}


@app.delete("/api/saved-views/{view_id}")
def api_delete_view(view_id: str, request: Request):
    count = SavedView.delete().where((SavedView.id == view_id) & (SavedView.owner == _current_username(request))).execute()
    return {"ok": bool(count)}


class PolicyRequest(BaseModel):
    name: str
    enabled: bool = False
    dry_run: bool = True
    min_score: int = 8
    countries: List[str] = []
    duration_hours: Optional[int] = None


@app.get("/api/policies")
def api_policies():
    return [operations.serialize_policy(r) for r in ResponsePolicy.select().order_by(ResponsePolicy.name)]


@app.post("/api/policies")
def api_create_policy(req: PolicyRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    if not req.name.strip() or not 1 <= req.min_score <= 100:
        raise HTTPException(status_code=400, detail="Policy name and score between 1-100 are required")
    row = ResponsePolicy.create(name=req.name.strip(), enabled=req.enabled, dry_run=req.dry_run,
                                min_score=req.min_score, countries=json.dumps([c.upper() for c in req.countries]),
                                duration_hours=req.duration_hours, created_by=_current_username(request))
    return operations.serialize_policy(row)


@app.put("/api/policies/{policy_id}")
def api_update_policy(policy_id: str, req: PolicyRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    row = ResponsePolicy.get_or_none(ResponsePolicy.id == policy_id)
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    if row.managed_by_fleet:
        raise HTTPException(status_code=409, detail="This policy is managed by Fleet")
    row.name, row.enabled, row.dry_run, row.min_score = req.name.strip(), req.enabled, req.dry_run, req.min_score
    row.countries, row.duration_hours = json.dumps([c.upper() for c in req.countries]), req.duration_hours
    row.save()
    return operations.serialize_policy(row)


@app.delete("/api/policies/{policy_id}")
def api_delete_policy(policy_id: str, request: Request):
    users.require_role(_current_role(request), "administrator")
    row = ResponsePolicy.get_or_none(ResponsePolicy.id == policy_id)
    if row and row.managed_by_fleet:
        raise HTTPException(status_code=409, detail="This policy is managed by Fleet")
    return {"ok": bool(ResponsePolicy.delete().where(ResponsePolicy.id == policy_id).execute())}


@app.post("/api/policies/{policy_id}/run")
def api_run_policy(policy_id: str, request: Request):
    users.require_role(_current_role(request), "administrator")
    row = ResponsePolicy.get_or_none(ResponsePolicy.id == policy_id)
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    matches, enforced = operations.run_policy(row, _current_username(request))
    return {"matched": len(matches), "enforced": enforced,
            "targets": [{"ip": m.ip, "country": m.country, "score": m.score} for m in matches[:100]],
            "dry_run": row.dry_run}


class IntegrationRequest(BaseModel):
    key: str
    kind: str
    name: str
    enabled: bool = False
    config: dict


@app.get("/api/integrations")
def api_integrations(request: Request):
    users.require_role(_current_role(request), "administrator")
    return notify.list_integrations()


@app.post("/api/integrations")
def api_save_integration(req: IntegrationRequest, request: Request):
    users.require_role(_current_role(request), "administrator")
    try:
        row = notify.save_integration(req.key.strip(), req.kind, req.name.strip(), req.enabled, req.config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "key": row.key}


@app.delete("/api/integrations/{key}")
def api_delete_integration(key: str, request: Request):
    users.require_role(_current_role(request), "administrator")
    return {"ok": bool(notify.delete_integration(key))}


@app.post("/api/integrations/test")
def api_test_integrations(request: Request):
    users.require_role(_current_role(request), "administrator")
    notify.dispatch_integrations(f"SentryNet integration test from {_current_username(request)}")
    return {"ok": True}


class OidcSettingsRequest(BaseModel):
    issuer: str
    client_id: str
    client_secret: str
    default_role: str = "spectator"
    enabled: bool = False


@app.get("/api/oidc-settings")
def api_oidc_settings(request: Request):
    users.require_role(_current_role(request), "owner")
    row = oidc_auth.get_settings()
    if not row:
        return {"configured": False, "enabled": False, "issuer": "", "client_id": "", "client_secret": "", "default_role": "spectator"}
    return {"configured": True, "enabled": row.enabled, "issuer": row.issuer,
            "client_id": row.client_id, "client_secret": "••••" + row.client_secret[-4:],
            "default_role": row.default_role}


@app.post("/api/oidc-settings")
def api_save_oidc_settings(req: OidcSettingsRequest, request: Request):
    users.require_role(_current_role(request), "owner")
    try:
        oidc_auth.save_settings(req.issuer, req.client_id, req.client_secret, req.default_role, req.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True}


@app.get("/api/diagnostics")
def api_diagnostics(request: Request):
    users.require_role(_current_role(request), "administrator")
    return operations.diagnostics()


@app.get("/api/update-status")
def api_update_status(request: Request):
    users.require_role(_current_role(request), "administrator")
    return {"current_version": VERSION, "channel": os.environ.get("SENTRYNET_UPDATE_CHANNEL", "stable"),
            "manifest_url": os.environ.get("SENTRYNET_UPDATE_MANIFEST_URL", ""),
            "managed_updates": bool(os.environ.get("SENTRYNET_UPDATE_MANIFEST_URL"))}


# ── Expired temporary-block sweep ────────────────────────────────────────────
# Separate lightweight thread rather than folded into ingest.py's tailer loop -
# this is about BlockedIp rows (API/data-model concern), not log parsing, and
# keeping it decoupled means a slow Postgres round-trip here can never delay
# processing of the access-log tail.
_EXPIRED_BLOCK_SWEEP_INTERVAL = 60
_AUTO_RELEASE_BLOCKS_DAYS = 30
_expired_sweep_stop = threading.Event()


def _expired_block_sweep_loop():
    while not _expired_sweep_stop.wait(_EXPIRED_BLOCK_SWEEP_INTERVAL):
        try:
            now = datetime.now(timezone.utc)
            to_release = [(b, "temporary block expired") for b in BlockedIp.select().where(
                BlockedIp.expires_at.is_null(False) & (BlockedIp.expires_at <= now)
            )]

            # Manual blocks with no explicit duration, and every automatic
            # block (ingest.py's _auto_block/_auto_block_country always set
            # expires_at=None), are otherwise permanent - this setting caps
            # their real-world lifetime so a years-old block doesn't sit
            # there forever unreviewed. Explicit temporary blocks (handled
            # above) are never affected, whether shorter or longer than this
            # window - that's the admin's own explicit choice, not this
            # blanket default.
            if alert_settings.is_enabled("auto_release_blocks"):
                aged_cutoff = now - timedelta(days=_AUTO_RELEASE_BLOCKS_DAYS)
                to_release += [(b, f"auto-released after {_AUTO_RELEASE_BLOCKS_DAYS} days")
                               for b in BlockedIp.select().where(
                                   BlockedIp.expires_at.is_null() & (BlockedIp.blocked_at <= aged_cutoff)
                               )]

            if not to_release:
                continue
            for b, reason in to_release:
                BlockAudit.create(ts=now, action="unblock", target=b.ip, reason=reason, actor="auto")
            BlockedIp.delete().where(BlockedIp.id.in_([b.id for b, _ in to_release])).execute()
            _regenerate_blocklist()
            if alert_settings.is_enabled("ip_blocks"):
                for b, reason in to_release:
                    send_discord_alert(f":alarm_clock: **Block released**: `{b.ip}` is unblocked ({reason}).")
        except Exception as e:
            print(f"[expired-block-sweep] error: {e}")


def _start_expired_block_sweep():
    t = threading.Thread(target=_expired_block_sweep_loop, daemon=True, name="expired-block-sweep")
    t.start()
    return t


# ── Startup / shutdown ────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    from models import db as _db, ALL_MODELS
    _db.create_tables(ALL_MODELS, safe=True)
    # Peewee's safe create does not alter existing columns. These idempotent
    # migrations keep older installs compatible with counters above 2 GiB.
    _db.execute_sql("ALTER TABLE requests ALTER COLUMN bytes TYPE bigint")
    _db.execute_sql("ALTER TABLE service_resource_samples ALTER COLUMN memory_bytes TYPE bigint")
    users.ensure_owner_bootstrapped()
    alert_settings.ensure_defaults()
    # Every X.start() below is registered with watchdog right after it runs,
    # so a thread that silently dies later (the exact 2026-07-13 incident
    # class - see watchdog.py) gets detected and restarted instead of nothing
    # ever noticing. log_aggregator.start() returns a {name: Thread} dict
    # (it spawns two threads) rather than a bare Thread like every other
    # module - registered as one combined watchdog entry, see watchdog.py's
    # module docstring for why.
    watchdog.register("access-log-tailer", ingest.start(), ingest.start)
    watchdog.register("threat-intel-refresh", threat_intel.start(), threat_intel.start)
    watchdog.register("ssh-ban-sweep", ssh_ban.start(), ssh_ban.start)
    watchdog.register("ssh-monitor", ssh_monitor.start(), ssh_monitor.start)
    watchdog.register("integrity-monitor", integrity_monitor.start(), integrity_monitor.start)
    watchdog.register("defacement-monitor", defacement_monitor.start(), defacement_monitor.start)
    watchdog.register("egress-monitor", egress_monitor.start(), egress_monitor.start)
    watchdog.register("cert-monitor", cert_monitor.start(), cert_monitor.start)
    watchdog.register("log-aggregator", list(log_aggregator.start().values()), log_aggregator.start)
    watchdog.register("resource-monitor", resource_monitor.start(), resource_monitor.start)
    watchdog.register("digest", digest.start(), digest.start)
    watchdog.register("report-scheduler", report.start(), report.start)
    watchdog.register("response-policy-engine", operations.start(), operations.start)
    watchdog.register("expired-block-sweep", _start_expired_block_sweep(), _start_expired_block_sweep)
    watchdog.start()


@app.on_event("shutdown")
def shutdown():
    # Stopped first/early: watchdog's own loop must exit before or alongside
    # everything it supervises, otherwise a thread going away as PART of this
    # same shutdown sequence could be misread as an unexpected death and
    # trigger a pointless restart-during-shutdown (harmless, but noisy).
    watchdog.stop()
    fleet_client.stop()
    operations.stop()
    ingest.stop()
    threat_intel.stop()
    ssh_ban.stop()
    ssh_monitor.stop()
    integrity_monitor.stop()
    defacement_monitor.stop()
    egress_monitor.stop()
    cert_monitor.stop()
    log_aggregator.stop()
    resource_monitor.stop()
    digest.stop()
    report.stop()
    _expired_sweep_stop.set()
    close_db()
