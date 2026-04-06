"""
Proof tests for credential exposure in sqli.py (lines 16-25).

Attack scenario:
  Attacker submits valid credentials (e.g. admin:admin).
  Vulnerable response: {"msg": "Hello, [('admin', 'admin')]"}
  The plaintext password is confirmed in the response body.

Fix: Return only the username — never the raw database row.
"""
from unittest.mock import MagicMock, patch

import sqli


def test_successful_login_does_not_leak_password():
    """
    Would FAIL on vulnerable code: f"Hello, {users}" → "Hello, [('admin', 'admin')]"
    Passes on fixed code: f"Hello, {users[0][0]}" → "Hello, admin"
    """
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [("admin", "admin")]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(sqli, "conn", mock_conn):
        result, status = sqli.sqlivuln({"username": "admin", "password": "admin"})

    assert status == 200
    # Raw tuple format must not appear
    assert "[(" not in result["msg"], f"Raw DB row in response: {result['msg']!r}"
    # Password value must not appear
    assert "'admin'" not in result["msg"], f"Password leaked: {result['msg']!r}"
    # Only the username should be returned
    assert result["msg"] == "Hello, admin", f"Unexpected response: {result['msg']!r}"


def test_successful_login_does_not_leak_arbitrary_password():
    """Verify the fix holds for non-trivial passwords, not just 'admin'."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [("bob", "s3cr3t!P@ss")]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(sqli, "conn", mock_conn):
        result, status = sqli.sqlivuln({"username": "bob", "password": "s3cr3t!P@ss"})

    assert status == 200
    assert "s3cr3t!P@ss" not in result["msg"], f"Password leaked: {result['msg']!r}"
    assert result["msg"] == "Hello, bob"


def test_failed_login_does_not_leak_row():
    """Empty fetchall (wrong credentials) should not expose any row data."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = []
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(sqli, "conn", mock_conn):
        result, status = sqli.sqlivuln({"username": "admin", "password": "wrong"})

    assert status == 200
    assert "[(" not in result["msg"]
