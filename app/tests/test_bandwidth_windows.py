import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bandwidth_report


class BandwidthWindowTests(unittest.TestCase):
    def test_window_is_24_hours_from_0600_utc(self):
        start = bandwidth_report.window_start_for_date(
            datetime(2026, 10, 11, 19, 37, tzinfo=timezone.utc)
        )
        self.assertEqual(start, datetime(2026, 10, 11, 6, tzinfo=timezone.utc))
        self.assertEqual(
            start + timedelta(hours=bandwidth_report.WINDOW_HOURS),
            datetime(2026, 10, 12, 6, tzinfo=timezone.utc),
        )

    def test_latest_completed_window_changes_at_0600_utc(self):
        before = bandwidth_report.latest_completed_window_start(
            datetime(2026, 10, 11, 5, 59, 59, tzinfo=timezone.utc)
        )
        at_boundary = bandwidth_report.latest_completed_window_start(
            datetime(2026, 10, 11, 6, tzinfo=timezone.utc)
        )
        after = bandwidth_report.latest_completed_window_start(
            datetime(2026, 10, 11, 22, tzinfo=timezone.utc)
        )
        self.assertEqual(before, datetime(2026, 10, 9, 6, tzinfo=timezone.utc))
        self.assertEqual(at_boundary, datetime(2026, 10, 10, 6, tzinfo=timezone.utc))
        self.assertEqual(after, datetime(2026, 10, 10, 6, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
