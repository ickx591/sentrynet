"""Small, dependency-light OpenID Connect client for SentryNet SSO."""

import base64
import hashlib
import json
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from models import OidcIdentity, OidcSettings, User
import users

_states = {}
_lock = threading.Lock()
_cache = {}
_MAX_PENDING_STATES = 10_000


def _b64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def get_settings():
    return OidcSettings.get_or_none(OidcSettings.key == "primary")


def public_options():
    row = get_settings()
    return {"oidc_enabled": bool(row and row.enabled), "oidc_label": "Continue with SSO"}


def save_settings(issuer, client_id, client_secret, default_role, enabled):
    issuer = issuer.strip().rstrip("/")
    if not issuer.startswith("https://"):
        raise ValueError("OIDC issuer must use HTTPS")
    if default_role not in users.ASSIGNABLE_ROLES:
        raise ValueError("Default role must be administrator, operator, or spectator")
    row = get_settings()
    if row and client_secret.startswith("••••"):
        client_secret = row.client_secret
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if row:
        row.issuer, row.client_id, row.client_secret = issuer, client_id.strip(), client_secret
        row.default_role, row.enabled, row.updated_at = default_role, enabled, now
        row.save()
    else:
        row = OidcSettings.create(key="primary", issuer=issuer, client_id=client_id.strip(),
                                  client_secret=client_secret, default_role=default_role,
                                  enabled=enabled, updated_at=now)
    _cache.clear()
    return row


def _document(url, cache_key):
    cached = _cache.get(cache_key)
    if cached and time.time() - cached[0] < 600:
        return cached[1]
    response = requests.get(url, timeout=10, headers={"User-Agent": "SentryNet/1.5"})
    response.raise_for_status()
    data = response.json()
    _cache[cache_key] = (time.time(), data)
    return data


def discovery(row):
    return _document(row.issuer + "/.well-known/openid-configuration", "discovery:" + row.issuer)


def begin(callback_url, browser_binding):
    row = get_settings()
    if not row or not row.enabled:
        raise ValueError("SSO is not enabled")
    doc = discovery(row)
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    with _lock:
        now = time.time()
        for key, value in list(_states.items()):
            if now - value["created"] > 600:
                _states.pop(key, None)
        while len(_states) >= _MAX_PENDING_STATES:
            _states.pop(next(iter(_states)))
        _states[state] = {"nonce": nonce, "verifier": verifier, "created": now,
                          "callback": callback_url,
                          "browser_binding": hashlib.sha256(browser_binding.encode()).hexdigest()}
    params = {"client_id": row.client_id, "response_type": "code", "scope": "openid email profile",
              "redirect_uri": callback_url, "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return doc["authorization_endpoint"] + "?" + urlencode(params)


def _verify_id_token(token, row, doc, expected_nonce):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed identity token")
    header, claims = json.loads(_b64(parts[0])), json.loads(_b64(parts[1]))
    if header.get("alg") != "RS256":
        raise ValueError("OIDC provider must sign ID tokens with RS256")
    jwks = _document(doc["jwks_uri"], "jwks:" + doc["jwks_uri"])
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"), None)
    if not key:
        _cache.pop("jwks:" + doc["jwks_uri"], None)
        jwks = _document(doc["jwks_uri"], "jwks:" + doc["jwks_uri"])
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"), None)
    if not key:
        raise ValueError("OIDC signing key not found")
    public_key = rsa.RSAPublicNumbers(int.from_bytes(_b64(key["e"]), "big"), int.from_bytes(_b64(key["n"]), "big")).public_key()
    public_key.verify(_b64(parts[2]), (parts[0] + "." + parts[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
    now = int(time.time())
    audience = claims.get("aud", [])
    audience = [audience] if isinstance(audience, str) else audience
    if claims.get("iss", "").rstrip("/") != row.issuer or row.client_id not in audience:
        raise ValueError("OIDC issuer or audience mismatch")
    if len(audience) > 1 and claims.get("azp") != row.client_id:
        raise ValueError("OIDC authorized-party mismatch")
    try:
        expired = int(claims.get("exp", 0)) <= now
        not_yet_valid = int(claims.get("nbf", 0)) > now + 60
    except (TypeError, ValueError):
        raise ValueError("OIDC token has invalid time claims")
    if expired or not_yet_valid or claims.get("nonce") != expected_nonce:
        raise ValueError("OIDC token expired or nonce mismatch")
    return claims


def finish(code, state, browser_binding):
    with _lock:
        pending = _states.pop(state, None)
    if not pending or time.time() - pending["created"] > 600:
        raise ValueError("SSO session expired; please start again")
    actual_binding = hashlib.sha256((browser_binding or "").encode()).hexdigest()
    if not secrets.compare_digest(actual_binding, pending["browser_binding"]):
        raise ValueError("SSO browser binding mismatch; please start again")
    row = get_settings()
    if not row or not row.enabled:
        raise ValueError("SSO is not enabled")
    doc = discovery(row)
    response = requests.post(doc["token_endpoint"], data={"grant_type":"authorization_code", "code":code,
        "redirect_uri":pending["callback"], "client_id":row.client_id, "client_secret":row.client_secret,
        "code_verifier":pending["verifier"]}, timeout=15, headers={"Accept":"application/json"})
    response.raise_for_status()
    claims = _verify_id_token(response.json()["id_token"], row, doc, pending["nonce"])
    subject = row.issuer + "|" + claims["sub"]
    identity = OidcIdentity.get_or_none(OidcIdentity.subject == subject)
    if identity:
        user = User.get_or_none(User.username == identity.username)
        if user:
            return user
    base = claims.get("preferred_username") or (claims.get("email") or "").split("@")[0] or "sso_user"
    base = re.sub(r"[^A-Za-z0-9_-]", "_", base)[:24]
    if len(base) < 3:
        base = "sso_" + base
    username, suffix = base, 1
    while User.get_or_none(User.username == username):
        suffix += 1
        username = f"{base[:27]}_{suffix}"
    user = User.create(username=username, password_hash=users.hash_password(secrets.token_urlsafe(48)),
                       role=row.default_role, created_at=datetime.now(timezone.utc), created_by="oidc")
    OidcIdentity.create(subject=subject, issuer=row.issuer, username=username,
                        email=claims.get("email"), created_at=datetime.now(timezone.utc))
    return user
