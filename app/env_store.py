"""Safe, serialized updates to the systemd EnvironmentFile."""

import os
import tempfile
import threading
from pathlib import Path

ENV_FILE = Path(__file__).parent / ".env.postgres"
_lock = threading.Lock()


def _validated(value) -> str:
    value = "" if value is None else str(value)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("Setting values cannot contain control characters")
    return value


def update(updates: dict) -> None:
    """Atomically update assignments without allowing new assignment lines."""
    clean = {str(key): _validated(value) for key, value in updates.items()}
    if any(not key or not key.replace("_", "").isalnum() or not key[0].isalpha()
           for key in clean):
        raise ValueError("Invalid environment setting name")

    with _lock:
        lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
        output = []
        seen = set()
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else None
            if key in clean:
                output.append(f"{key}={clean[key]}")
                seen.add(key)
            else:
                output.append(line)
        for key, value in clean.items():
            if key not in seen:
                output.append(f"{key}={value}")

        fd, temporary = tempfile.mkstemp(prefix=".env.postgres.", dir=ENV_FILE.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write("\n".join(output) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, ENV_FILE)
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
