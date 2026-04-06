import sqlite3
import unittest
from unittest.mock import patch

import sqli


def make_test_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE USERS(USERNAME VARCHAR(255), PASSWORD VARCHAR(255))")
    conn.execute("INSERT INTO USERS VALUES ('admin', 'secret')")
    conn.execute("INSERT INTO USERS VALUES ('mike', 'kaines')")
    conn.commit()
    return conn


class TestSQLiVuln(unittest.TestCase):
    def setUp(self):
        self.test_conn = make_test_db()
        self.patcher = patch.object(sqli, "conn", self.test_conn)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.test_conn.close()

    def test_valid_login_returns_user(self):
        response, status = sqli.sqlivuln({"username": "admin", "password": "secret"})
        self.assertEqual(status, 200)
        self.assertIn("admin", str(response["msg"]))

    def test_wrong_password_returns_empty(self):
        response, status = sqli.sqlivuln({"username": "admin", "password": "wrong"})
        self.assertEqual(status, 200)
        self.assertIn("[]", str(response["msg"]))

    def test_sqli_or_bypass_blocked(self):
        """' OR '1'='1 must not return rows — would have returned all users before fix."""
        response, status = sqli.sqlivuln({"username": "' OR '1'='1", "password": "x"})
        self.assertEqual(status, 200)
        self.assertIn("[]", str(response["msg"]))

    def test_sqli_comment_bypass_blocked(self):
        """admin'-- bypasses password check in vulnerable code; must fail after fix."""
        response, status = sqli.sqlivuln({"username": "admin'--", "password": "anything"})
        self.assertEqual(status, 200)
        self.assertIn("[]", str(response["msg"]))

    def test_missing_credentials_returns_400(self):
        _, status = sqli.sqlivuln({"username": "", "password": ""})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
