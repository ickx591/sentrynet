"""WebAuthn passkey registration and authentication using cryptography."""

import base64
import hashlib
import json
import secrets
import struct
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from models import PasskeyCredential, User

_pending = {}
_lock = threading.Lock()
_MAX_PENDING_CHALLENGES = 10_000


def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _remember(challenge, purpose, username, rp_id, origin):
    with _lock:
        now = time.time()
        for key, item in list(_pending.items()):
            if now - item["created"] > 300:
                _pending.pop(key, None)
        while len(_pending) >= _MAX_PENDING_CHALLENGES:
            _pending.pop(next(iter(_pending)))
        _pending[challenge] = {"purpose": purpose, "username": username, "rp_id": rp_id,
                               "origin": origin, "created": now}


def _consume(client_data_b64, purpose):
    raw = b64d(client_data_b64)
    client = json.loads(raw)
    challenge = client.get("challenge")
    with _lock:
        pending = _pending.pop(challenge, None)
    if not pending or pending["purpose"] != purpose or time.time() - pending["created"] > 300:
        raise ValueError("Passkey challenge expired")
    expected_type = "webauthn.create" if purpose == "register" else "webauthn.get"
    if client.get("type") != expected_type or client.get("origin") != pending["origin"]:
        raise ValueError("Passkey origin validation failed")
    return raw, pending


def _cbor(data, pos=0):
    initial = data[pos]; pos += 1
    major, value = initial >> 5, initial & 31
    if value == 24: value, pos = data[pos], pos + 1
    elif value == 25: value, pos = int.from_bytes(data[pos:pos+2], "big"), pos + 2
    elif value == 26: value, pos = int.from_bytes(data[pos:pos+4], "big"), pos + 4
    elif value == 27: value, pos = int.from_bytes(data[pos:pos+8], "big"), pos + 8
    if major == 0: return value, pos
    if major == 1: return -1 - value, pos
    if major == 2: return data[pos:pos+value], pos + value
    if major == 3: return data[pos:pos+value].decode(), pos + value
    if major == 4:
        out = []
        for _ in range(value): item, pos = _cbor(data, pos); out.append(item)
        return out, pos
    if major == 5:
        out = {}
        for _ in range(value): key, pos = _cbor(data, pos); item, pos = _cbor(data, pos); out[key] = item
        return out, pos
    if major == 7 and value in (20, 21): return value == 21, pos
    if major == 7 and value == 22: return None, pos
    raise ValueError("Unsupported authenticator CBOR value")


def _auth_data(raw, expected_rp, require_attested=False):
    if len(raw) < 37 or raw[:32] != hashlib.sha256(expected_rp.encode()).digest():
        raise ValueError("Passkey relying-party validation failed")
    flags, counter = raw[32], int.from_bytes(raw[33:37], "big")
    if not flags & 0x01:
        raise ValueError("User presence was not verified")
    if not flags & 0x04:
        raise ValueError("Passkey user verification was not performed")
    if not require_attested:
        return {"counter": counter, "flags": flags}
    if not flags & 0x40 or len(raw) < 55:
        raise ValueError("Authenticator did not return credential data")
    length = int.from_bytes(raw[53:55], "big")
    credential_id = raw[55:55+length]
    cose, _ = _cbor(raw, 55 + length)
    return {"counter": counter, "flags": flags, "credential_id": credential_id, "cose": cose}


def _public_key(cose):
    if cose.get(1) == 2 and cose.get(3) == -7:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()).public_key()
    if cose.get(1) == 3 and cose.get(3) == -257:
        return rsa.RSAPublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-1], "big")).public_key()
    raise ValueError("Authenticator key type is not supported")


def registration_options(username, rp_id, origin):
    challenge = b64e(secrets.token_bytes(32))
    _remember(challenge, "register", username, rp_id, origin)
    existing = PasskeyCredential.select().where(PasskeyCredential.username == username)
    return {"challenge": challenge, "rp": {"name":"SentryNet", "id":rp_id},
            "user": {"id":b64e(hashlib.sha256(username.encode()).digest()[:16]), "name":username, "displayName":username},
            "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
            "timeout":60000, "attestation":"none",
            "authenticatorSelection":{"residentKey":"preferred","userVerification":"required"},
            "excludeCredentials":[{"type":"public-key","id":r.credential_id} for r in existing]}


def finish_registration(username, payload, label="Passkey"):
    client_raw, pending = _consume(payload["response"]["clientDataJSON"], "register")
    if pending["username"] != username:
        raise ValueError("Passkey user mismatch")
    attestation, _ = _cbor(b64d(payload["response"]["attestationObject"]))
    parsed = _auth_data(attestation["authData"], pending["rp_id"], True)
    public = _public_key(parsed["cose"])
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    credential_id = b64e(parsed["credential_id"])
    if PasskeyCredential.get_or_none(PasskeyCredential.credential_id == credential_id):
        raise ValueError("This passkey is already registered")
    return PasskeyCredential.create(username=username, credential_id=credential_id, public_key_pem=pem,
                                    sign_count=parsed["counter"], label=(label or "Passkey")[:80],
                                    created_at=datetime.now(timezone.utc))


def authentication_options(username, rp_id, origin):
    # Always return the same response shape. Returning 404 for an unknown
    # user (or a user without passkeys) exposed account and factor status.
    user_exists = bool(User.get_or_none(User.username == username))
    credentials = (list(PasskeyCredential.select().where(PasskeyCredential.username == username))
                   if user_exists else [])
    challenge = b64e(secrets.token_bytes(32))
    _remember(challenge, "authenticate", username, rp_id, origin)
    return {"challenge":challenge, "rpId":rp_id, "timeout":60000, "userVerification":"required",
            "allowCredentials":[{"type":"public-key","id":c.credential_id} for c in credentials]}


def finish_authentication(payload):
    client_raw, pending = _consume(payload["response"]["clientDataJSON"], "authenticate")
    credential = PasskeyCredential.get_or_none(PasskeyCredential.credential_id == payload["id"])
    if not credential or credential.username != pending["username"]:
        raise ValueError("Passkey is not registered for this user")
    auth_raw = b64d(payload["response"]["authenticatorData"])
    parsed = _auth_data(auth_raw, pending["rp_id"])
    signed = auth_raw + hashlib.sha256(client_raw).digest()
    signature = b64d(payload["response"]["signature"])
    public = serialization.load_pem_public_key(credential.public_key_pem.encode())
    if isinstance(public, ec.EllipticCurvePublicKey):
        public.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    elif isinstance(public, rsa.RSAPublicKey):
        public.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported passkey type")
    if credential.sign_count and parsed["counter"] and parsed["counter"] <= credential.sign_count:
        raise ValueError("Authenticator counter did not advance")
    credential.sign_count = max(credential.sign_count, parsed["counter"])
    credential.last_used_at = datetime.now(timezone.utc)
    credential.save()
    return User.get(User.username == credential.username)
