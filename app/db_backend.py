"""
Postgres connection setup for SentryNet - reads DATABASE_URL from
.env.postgres.

systemd loads .env.postgres via EnvironmentFile=, but cron/manual invocations
spawn with a bare environment - so this also falls back to reading the file
directly, once, at import time.
"""

import os
from urllib.parse import urlparse

from playhouse.pool import PooledPostgresqlDatabase
from peewee import InterfaceError, OperationalError

from models import db

_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.postgres")


def _load_env_file_fallback():
    if not os.path.exists(_ENV_FILE):
        return
    with open(_ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


_load_env_file_fallback()


class RecoveringPostgresqlDatabase(PooledPostgresqlDatabase):
    """Release dead thread-local connections after a PostgreSQL outage.

    The pool checks connections when they are checked out, but background
    monitors keep theirs across many iterations. Peewee's is_closed() tracks
    its own state, which can remain open after the driver connection dies.
    """

    def _discard_disconnected(self):
        if (not self.in_transaction() and not self.is_closed()
                and self.connection().closed):
            # Remove only this thread's broken connection from the pool and
            # reset Peewee's state so the next operation can reconnect.
            self.manual_close()

    def cursor(self, *args, **kwargs):
        self._discard_disconnected()
        return super().cursor(*args, **kwargs)

    def execute_sql(self, sql, params=None):
        try:
            return super().execute_sql(sql, params)
        except (InterfaceError, OperationalError):
            self._discard_disconnected()
            # Do not replay SQL: a write may have committed before the
            # connection was lost. Let the caller handle the failed operation.
            # Ingest keeps its pending batch for its next flush attempt.
            raise


def init_db():
    """Initialize the shared peewee `db` Proxy and return the concrete Database.
    Pooled (not plain PostgresqlDatabase) since FastAPI's sync handlers run
    concurrently in a threadpool - see master-db/db_backend.py for the full
    rationale."""
    dsn = os.environ["DATABASE_URL"]
    parsed = urlparse(dsn)
    database = RecoveringPostgresqlDatabase(
        parsed.path.lstrip("/"),
        max_connections=80,
        stale_timeout=300,
        user=parsed.username,
        password=parsed.password,
        host=parsed.hostname,
        port=parsed.port or 5432,
        options="-c TimeZone=UTC",
    )
    db.initialize(database)
    return database


def close_db():
    """Shutdown-time close - close_all() actually closes every pooled
    connection, not just checks the current one back into the pool."""
    if hasattr(db.obj, "close_all"):
        db.obj.close_all()
    elif not db.is_closed():
        db.close()
