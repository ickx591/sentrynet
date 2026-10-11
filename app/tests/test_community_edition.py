import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import license as sentrynet_license


class CommunityEditionTests(unittest.TestCase):
    def test_community_edition_is_unlocked_without_credentials(self):
        status = sentrynet_license.get_status()
        self.assertEqual(status["license_status"], "community")
        self.assertEqual(status["edition"], "Community Edition")
        self.assertFalse(status["locked"])
        self.assertFalse(sentrynet_license.is_locked())
        self.assertIsNone(sentrynet_license.get_credentials())

    def test_legacy_activation_call_is_a_noop(self):
        ok, message = sentrynet_license.activate("")
        self.assertTrue(ok)
        self.assertIn("does not require activation", message)


if __name__ == "__main__":
    unittest.main()
