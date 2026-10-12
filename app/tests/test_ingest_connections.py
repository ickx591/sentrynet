"""Regression tests for database cleanup in short-lived ingest threads."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ingest


class BlocklistTimerConnectionTests(unittest.TestCase):
    def setUp(self):
        ingest._reload_timer = None
        ingest._blocklist_dirty = True

    def test_success_releases_timer_threads_connection(self):
        database = Mock()
        database.is_closed.return_value = False
        with patch.object(ingest, "db", database), \
                patch.object(ingest.webserver_backend, "regenerate_blocklist"):
            ingest._apply_pending_blocklist()
        database.close.assert_called_once_with()

    def test_failure_schedules_retry_and_releases_connection(self):
        database = Mock()
        database.is_closed.return_value = False
        with patch.object(ingest, "db", database), \
                patch.object(ingest.webserver_backend, "regenerate_blocklist", side_effect=RuntimeError("test")), \
                patch.object(ingest, "_schedule_blocklist_locked") as schedule:
            ingest._apply_pending_blocklist()
        schedule.assert_called_once_with(ingest.BLOCKLIST_RELOAD_INTERVAL)
        database.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
