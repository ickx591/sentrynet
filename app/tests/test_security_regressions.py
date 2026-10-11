import hashlib
import tempfile
import threading
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import env_store
import notify
import passkeys
import session_security
import users


class EnvironmentStoreTests(unittest.TestCase):
    def test_control_characters_cannot_add_assignments(self):
        with tempfile.TemporaryDirectory() as directory:
            original = env_store.ENV_FILE
            env_store.ENV_FILE = Path(directory) / ".env.postgres"
            env_store.ENV_FILE.write_text("DATABASE_URL=unchanged\n")
            try:
                with self.assertRaises(ValueError):
                    env_store.update({"DISCORD_WEBHOOK_URL": "https://example.invalid/hook\nINJECTED=yes"})
                self.assertEqual(env_store.ENV_FILE.read_text(), "DATABASE_URL=unchanged\n")
            finally:
                env_store.ENV_FILE = original

    def test_concurrent_updates_do_not_lose_assignments(self):
        with tempfile.TemporaryDirectory() as directory:
            original = env_store.ENV_FILE
            env_store.ENV_FILE = Path(directory) / ".env.postgres"
            env_store.ENV_FILE.write_text("DATABASE_URL=unchanged\n")
            try:
                threads = [threading.Thread(target=env_store.update, args=({f"TEST_{n}": str(n)},))
                           for n in range(20)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                text = env_store.ENV_FILE.read_text()
                for n in range(20):
                    self.assertIn(f"TEST_{n}={n}\n", text)
            finally:
                env_store.ENV_FILE = original


class PasskeyVerificationTests(unittest.TestCase):
    def test_user_verification_flag_is_required(self):
        rp = "net.example"
        present_only = hashlib.sha256(rp.encode()).digest() + bytes([0x01]) + (0).to_bytes(4, "big")
        with self.assertRaisesRegex(ValueError, "user verification"):
            passkeys._auth_data(present_only, rp)

        verified = hashlib.sha256(rp.encode()).digest() + bytes([0x05]) + (0).to_bytes(4, "big")
        parsed = passkeys._auth_data(verified, rp)
        self.assertEqual(parsed["flags"], 0x05)

    def test_unknown_user_does_not_get_an_explicit_not_found_response(self):
        with mock.patch.object(passkeys.User, "get_or_none", return_value=None):
            options = passkeys.authentication_options("missing-user", "net.example", "https://net.example")
        self.assertIn("challenge", options)
        self.assertEqual(options["allowCredentials"], [])


class PasswordHashTests(unittest.TestCase):
    def test_unreasonable_iteration_count_is_rejected_before_hashing(self):
        malicious = "pbkdf2_sha256$999999999$MTIzNDU2Nzg=$" + ("QQ==")
        with mock.patch.object(users.hashlib, "pbkdf2_hmac") as derive:
            self.assertFalse(users._verify_against("password", malicious))
        derive.assert_not_called()


class IntegrationUrlTests(unittest.TestCase):
    def test_private_and_loopback_destinations_are_rejected(self):
        for address in ("127.0.0.1", "10.0.0.8", "169.254.169.254", "::1"):
            with self.subTest(address=address), mock.patch.object(
                notify.socket, "getaddrinfo",
                return_value=[(None, None, None, None, (address, 443))],
            ):
                self.assertFalse(notify._safe_http_url("https://hooks.example.test/event"))

    def test_public_destination_is_accepted(self):
        with mock.patch.object(
            notify.socket, "getaddrinfo",
            return_value=[(None, None, None, None, ("93.184.216.34", 443))],
        ):
            self.assertTrue(notify._safe_http_url("https://hooks.example.test/event"))


class SessionLifetimeTests(unittest.TestCase):
    def test_absolute_lifetime_and_recent_authentication(self):
        now = datetime(2026, 10, 11, tzinfo=timezone.utc)
        fresh = {"role": "owner", "created_at": (now - timedelta(hours=1)).isoformat(),
                 "authenticated_at": (now - timedelta(minutes=2)).isoformat()}
        expired = {"role": "owner", "created_at": (now - timedelta(hours=25)).isoformat()}
        future = {"role": "owner", "created_at": (now + timedelta(minutes=1)).isoformat()}
        self.assertTrue(session_security.valid(fresh, 86400, now))
        self.assertFalse(session_security.valid(expired, 86400, now))
        self.assertFalse(session_security.valid(future, 86400, now))
        self.assertTrue(session_security.recently_authenticated(fresh, 300, now))


if __name__ == "__main__":
    unittest.main()
