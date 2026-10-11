"""
User accounts, roles, and password hashing for SentryNet's dashboard login.

Four fixed, strictly-nested roles:
  spectator     - read-only: every chart/list/log, no actions.
  operator      - spectator + block/unblock/allow/unallow/country actions + SSH unban.
  administrator - operator + alert-settings/webhook changes.
  owner         - administrator + user management. Exactly one, forever -
                  the account created at install time (see
                  ensure_owner_bootstrapped()). Can't be created, demoted,
                  or deleted through the API.

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib hashlib, no extra
dependency), 600,000 iterations (OWASP's current minimum for this
algorithm), stored as a self-describing string so the iteration count can
be raised later without invalidating existing hashes.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from fastapi import HTTPException

from models import MfaCredential, User

SCRIPT_DIR = Path(__file__).parent
ADMIN_FILE = SCRIPT_DIR / ".admin.json"

ROLE_LEVEL = {"spectator": 0, "operator": 1, "administrator": 2, "owner": 3}
ROLES = list(ROLE_LEVEL.keys())
ASSIGNABLE_ROLES = {"administrator", "operator", "spectator"}  # never "owner"

_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 600_000

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
_RESERVED_USERNAMES = {"auto"}  # the actor sentinel for background/system actions
_MIN_PASSWORD_LENGTH = 10

# Per-username login throttling, alongside main.py's existing per-IP one.
# Real, human-chosen usernames (unlike the old single random admin_xxxx
# account) are guessable, so a distributed/rotating-IP brute force against
# one known username needs its own independent throttle.
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_FAILURES = 5
_LOGIN_MAX_TRACKED_KEYS = 10_000
_username_failures_lock = threading.Lock()
_username_failures: Dict[str, list] = {}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _verify_against(password: str, stored_hash: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = stored_hash.split("$")
        if algo != _PBKDF2_ALGO:
            return False
        iterations = int(iterations)
        # A corrupted or attacker-modified database value must not turn one
        # login attempt into an effectively unbounded CPU job.
        if not 100_000 <= iterations <= 2_000_000:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        if not 8 <= len(salt) <= 64 or len(expected) != 32:
            return False
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return secrets.compare_digest(actual, expected)


# A fixed dummy hash to check against when the username doesn't exist at
# all, so a login attempt takes roughly the same time either way and can't
# be used to enumerate valid usernames via response timing.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def verify_password(password: str, stored_hash: Optional[str]) -> bool:
    if stored_hash is None:
        _verify_against(password, _DUMMY_HASH)
        return False
    return _verify_against(password, stored_hash)


def validate_username(username: str) -> Optional[str]:
    if not _USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, numbers, underscore, hyphen only."
    if username.lower() in _RESERVED_USERNAMES:
        return f"'{username}' is a reserved name and can't be used for a login."
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password) < _MIN_PASSWORD_LENGTH:
        return f"Password must be at least {_MIN_PASSWORD_LENGTH} characters."
    return None


def username_rate_limited(username: str) -> bool:
    now = time.time()
    key = username.lower()
    with _username_failures_lock:
        recent = [t for t in _username_failures.get(key, []) if now - t < _LOGIN_WINDOW_SECONDS]
        if recent:
            _username_failures[key] = recent
        else:
            _username_failures.pop(key, None)
        return len(recent) >= _LOGIN_MAX_FAILURES


def record_username_failure(username: str):
    key = username.lower()
    with _username_failures_lock:
        if key not in _username_failures and len(_username_failures) >= _LOGIN_MAX_TRACKED_KEYS:
            _username_failures.pop(next(iter(_username_failures)))
        _username_failures.setdefault(key, []).append(time.time())


def clear_username_failures(username: str):
    with _username_failures_lock:
        _username_failures.pop(username.lower(), None)


def generate_mfa_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp(secret: str, timestamp: float) -> str:
    padded = secret.upper() + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded)
    counter = int(timestamp // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def verify_totp(secret: str, code: str, at_time: Optional[float] = None) -> bool:
    if not code or not re.fullmatch(r"\d{6}", str(code).strip()):
        return False
    now = time.time() if at_time is None else at_time
    return any(secrets.compare_digest(_totp(secret, now + offset * 30), str(code).strip()) for offset in (-1, 0, 1))


def mfa_for(username: str):
    return MfaCredential.get_or_none(MfaCredential.username == username)


def require_role(role: Optional[str], min_role: str):
    if ROLE_LEVEL.get(role, -1) < ROLE_LEVEL[min_role]:
        raise HTTPException(status_code=403, detail="Insufficient permissions for this action")


def ensure_owner_bootstrapped():
    """Runs once at startup, right after create_tables. Migrates the
    pre-multi-user single admin account (.admin.json, written by
    main.py's _bootstrap_admin()) into the first, permanent Owner row - or,
    if that file is somehow already gone, mints a fresh one in the exact
    same log format install.sh's credential-capture grep expects."""
    if User.get_or_none(User.role == "owner"):
        return

    if ADMIN_FILE.exists():
        try:
            admin = json.loads(ADMIN_FILE.read_text())
            username = admin["username"]
            password = admin["password"]
        except Exception as e:
            print(f"[users] could not read {ADMIN_FILE} during Owner migration: {e}")
            return
        User.create(
            username=username,
            password_hash=hash_password(password),
            role="owner",
            created_at=datetime.now(timezone.utc),
            created_by=None,
        )
        try:
            ADMIN_FILE.unlink()
        except Exception as e:
            print(f"[users] warning: migrated Owner but could not remove {ADMIN_FILE}: {e}")
        print(f"[users] migrated existing admin account '{username}' into the Owner role")
        return

    # Defensive fallback: no .admin.json at all (shouldn't happen -
    # _bootstrap_admin() always creates one on first run before this ever
    # runs) - mint a fresh Owner account the same way that function does.
    username = "admin_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(16)
    User.create(
        username=username,
        password_hash=hash_password(password),
        role="owner",
        created_at=datetime.now(timezone.utc),
        created_by=None,
    )
    print("=" * 70)
    print("SentryNet: first run, generated admin credentials:")
    print(f"  username: {username}")
    print(f"  password: {password}")
    print("  (shown only this once in the log)")
    print("=" * 70)
