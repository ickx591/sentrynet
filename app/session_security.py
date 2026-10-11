"""Pure session lifetime checks shared by middleware and tests."""

from datetime import datetime, timezone


def age_seconds(session: dict, field: str = "created_at", now=None):
    try:
        created = datetime.fromisoformat(session[field])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        return (current - created.astimezone(timezone.utc)).total_seconds()
    except (KeyError, TypeError, ValueError):
        return None


def valid(session: dict, max_age_seconds: int, now=None) -> bool:
    age = age_seconds(session, now=now)
    return bool("role" in session and age is not None and 0 <= age < max_age_seconds)


def recently_authenticated(session: dict, max_age_seconds: int, now=None) -> bool:
    field = "authenticated_at" if session.get("authenticated_at") else "created_at"
    age = age_seconds(session, field=field, now=now)
    return bool(age is not None and 0 <= age < max_age_seconds)
