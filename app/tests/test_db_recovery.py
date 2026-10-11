"""Connection recovery regressions using the real Peewee pool and fake drivers."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from peewee import InterfaceError, OperationalError
from db_backend import RecoveringPostgresqlDatabase


class Driver:
    server_version = 170000

    def __init__(self):
        self.closed = False
        self.statements = []
        self.error = None
        self.disconnect_on_execute = False

    def cursor(self):
        if self.closed:
            raise InterfaceError("connection already closed")
        return self

    def execute(self, sql, params):
        self.statements.append(sql)
        if self.disconnect_on_execute:
            self.closed = True
            raise OperationalError("SSL SYSCALL error: EOF detected")
        if self.error:
            raise self.error

    def close(self):
        self.closed = True


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.old, self.fresh = Driver(), Driver()
        self.connect = patch("peewee.PostgresqlDatabase._connect",
                             side_effect=[self.old, self.fresh]).start()
        self.addCleanup(patch.stopall)
        self.db = RecoveringPostgresqlDatabase("test-only", max_connections=2)
        self.db.connect()

    def test_closed_connection_is_replaced_before_query(self):
        self.old.close()
        result = self.db.execute_sql("SELECT 1")
        self.assertIs(result, self.fresh)
        self.assertEqual(self.old.statements, [])
        self.assertEqual(self.fresh.statements, ["SELECT 1"])
        self.assertNotIn(id(self.old), self.db._in_use)
        self.assertEqual(len(self.db._in_use), 1)

    def test_failure_during_write_is_not_replayed_and_next_query_recovers(self):
        self.old.disconnect_on_execute = True
        with self.assertRaises(OperationalError):
            self.db.execute_sql("INSERT INTO requests VALUES (...)")
        self.assertTrue(self.db.is_closed())
        self.assertEqual(self.connect.call_count, 1)
        self.assertEqual(self.fresh.statements, [])
        self.db.execute_sql("SELECT 1")
        self.assertEqual(self.fresh.statements, ["SELECT 1"])

    def test_reconnect_can_fail_until_database_returns(self):
        self.old.close()
        self.connect.side_effect = [OperationalError("database unavailable"), self.fresh]
        with self.assertRaises(OperationalError):
            self.db.execute_sql("SELECT 1")
        self.assertTrue(self.db.is_closed())
        self.db.execute_sql("SELECT 1")
        self.assertEqual(self.fresh.statements, ["SELECT 1"])

    def test_healthy_connection_is_retained_for_other_sql_errors(self):
        self.old.error = OperationalError("statement timeout")
        with self.assertRaises(OperationalError):
            self.db.execute_sql("SELECT 1")
        self.assertFalse(self.db.is_closed())
        self.assertIs(self.db.connection(), self.old)
        self.assertEqual(self.connect.call_count, 1)

    def test_transaction_is_not_silently_reconnected(self):
        self.db._state.transactions.append(object())
        self.old.close()
        with self.assertRaises(InterfaceError):
            self.db.execute_sql("SELECT 1")
        self.assertEqual(self.connect.call_count, 1)
        self.db._state.transactions.clear()
        self.db.execute_sql("SELECT 1")
        self.assertEqual(self.fresh.statements, ["SELECT 1"])


if __name__ == "__main__":
    unittest.main()
