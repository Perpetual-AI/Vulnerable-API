import sqlite3
import pytest
from unittest.mock import patch, MagicMock
import sqli


@pytest.fixture
def test_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE USERS (USERNAME VARCHAR(255), PASSWORD VARCHAR(255))")
    conn.execute("INSERT INTO USERS VALUES ('admin', 'secret')")
    conn.execute("INSERT INTO USERS VALUES ('mike', 'kaines')")
    conn.commit()
    return conn


def test_sqli_injection_blocked(test_db):
    """SQL injection payload must not return rows — FAILS on vulnerable code."""
    with patch.object(sqli, "conn", test_db):
        payload = {"username": "' OR '1'='1", "password": "anything"}
        result, _ = sqli.sqlivuln(payload)
        # Vulnerable code: WHERE USERNAME='' OR '1'='1' returns all rows
        # Fixed code:  WHERE USERNAME=? AND PASSWORD=? treats the string literally → []
        assert result["msg"] == "Hello, []", (
            f"SQL injection succeeded (vuln not fixed): {result}"
        )


def test_sqli_union_injection_blocked(test_db):
    """UNION-based schema-leak payload must be treated as a literal string."""
    with patch.object(sqli, "conn", test_db):
        payload = {
            "username": "' UNION SELECT name,sql FROM sqlite_master--",
            "password": "x",
        }
        result, _ = sqli.sqlivuln(payload)
        assert result["msg"] == "Hello, []", (
            f"UNION injection succeeded: {result}"
        )


def test_sqli_valid_credentials_succeed(test_db):
    """Legitimate credentials must still authenticate after the fix."""
    with patch.object(sqli, "conn", test_db):
        result, status = sqli.sqlivuln({"username": "admin", "password": "secret"})
        assert status == 200
        assert "admin" in str(result["msg"])


def test_sqli_exception_does_not_leak_schema():
    """DB exception message must NOT be exposed to the client.

    Mocks cursor.execute() to raise a realistic sqlite3.OperationalError that
    names the USERS table — this is what the vulnerable handler returned verbatim.
    The fix must return a generic 401 instead.
    """
    leak_msg = "no such column: USERS.USERNAME"
    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = sqlite3.OperationalError(leak_msg)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(sqli, "conn", mock_conn):
        result, status = sqli.sqlivuln({"username": "'", "password": "x"})
        assert status == 401, f"Expected 401, got {status}"
        assert result["msg"] == "Login failed", (
            f"Raw DB exception leaked to client: {result['msg']}"
        )
        assert leak_msg not in str(result["msg"])


def test_sqli_wrong_password_rejected(test_db):
    """Correct username with wrong password must return no rows (password now checked)."""
    with patch.object(sqli, "conn", test_db):
        result, _ = sqli.sqlivuln({"username": "admin", "password": "wrong"})
        assert result["msg"] == "Hello, []", (
            f"Authentication bypassed with wrong password: {result}"
        )
