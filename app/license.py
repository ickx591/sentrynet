"""Community Edition metadata.

The public GitHub build has no activation, entitlement check, remote
validation, expiry, feature gate, or license-server dependency.  This module
keeps the small compatibility surface used by the dashboard and terminal so
they can identify the build without treating "no key" as an error.
"""

EDITION = "Community Edition"


def activate(_license_key: str = "") -> tuple[bool, str]:
    """Compatibility helper for older automation; activation is unnecessary."""
    return True, "SentryNet Community Edition does not require activation."


def get_credentials():
    """There are intentionally no license-server credentials."""
    return None


def get_status() -> dict:
    return {
        "activated": True,
        "edition": EDITION,
        "license_key": "Not required",
        "license_status": "community",
        "locked": False,
        "lock_reason": None,
        "live": True,
        "expires_at": None,
        "max_seats": None,
        "active_seats": None,
        "this_install_active": True,
    }


def is_locked() -> bool:
    return False


def lock_reason() -> str:
    return ""


def start():
    """Retained for API compatibility; no background thread is required."""
    return None


def stop():
    return None
