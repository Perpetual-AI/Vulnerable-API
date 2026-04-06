"""
Proof tests for the SQL injection fix in sqli.py (lines 9-22).

Attack vectors:
  1. Auth bypass:  username="' OR '1'='1"  → on vulnerable code the WHERE clause
     always evaluates to true, returning all rows regardless of password.
  2. UNION exfil:  username="' UNION SELECT name,sql FROM sqlite_master--"  →
     on vulnerable code this dumps the schema.

On the fixed code parameterized queries prevent both by treating the input as
data, not SQL.
"""

from sqli import sqlivuln, conn


# ---------------------------------------------------------------------------
# Helpers — seed a known user in the shared in-memory DB
# ---------------------------------------------------------------------------

def _seed_user(username: str = "alice", password: str = "secret123") -> None:
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS USERS (USERNAME TEXT, PASSWORD TEXT)"
    )
    cur.execute(
        "DELETE FROM USERS WHERE USERNAME=?", (username,)
    )
    cur.execute(
        "INSERT INTO USERS (USERNAME, PASSWORD) VALUES (?, ?)",
        (username, password),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Attack-vector tests (would FAIL on the vulnerable code)
# ---------------------------------------------------------------------------

def test_auth_bypass_or_injection_blocked():
    """
    Classic ' OR '1'='1 payload must NOT return a user.

    On the vulnerable code:
        SELECT * FROM USERS WHERE USERNAME='' OR '1'='1'
    always returns all rows, so the endpoint would return a non-empty user list.

    On the fixed code the payload is a literal string that matches no username,
    so the query returns no rows.
    """
    _seed_user()
    payload = {"username": "' OR '1'='1", "password": "x"}
    result, status = sqlivuln(payload)
    assert status == 200
    # The injected OR must not produce a match — msg should show empty list.
    assert "alice" not in result["msg"], (
        f"Auth bypass succeeded! Response: {result['msg']!r}"
    )


def test_union_schema_dump_blocked():
    """
    UNION-based exfiltration payload must not leak sqlite_master data.

    On the vulnerable code:
        SELECT * FROM USERS WHERE USERNAME='' UNION SELECT name,sql FROM sqlite_master--'
    would return schema rows.
    """
    _seed_user()
    payload = {
        "username": "' UNION SELECT name,sql FROM sqlite_master--",
        "password": "x",
    }
    result, status = sqlivuln(payload)
    assert status == 200
    assert "sqlite_master" not in result["msg"], (
        f"Schema leaked via UNION injection! Response: {result['msg']!r}"
    )
    assert "CREATE TABLE" not in result["msg"]


def test_correct_credentials_still_work():
    """Legitimate login must still succeed after the fix."""
    _seed_user("bob", "pass456")
    result, status = sqlivuln({"username": "bob", "password": "pass456"})
    assert status == 200
    assert "bob" in result["msg"]


def test_wrong_password_rejected():
    """
    Password is now part of the WHERE clause — wrong password must not match.

    On the vulnerable code the password was accepted but never checked, so any
    password for a real username would return the user.
    """
    _seed_user("carol", "correctpass")
    result, status = sqlivuln({"username": "carol", "password": "wrongpass"})
    assert status == 200
    # Row must not appear in the response.
    assert "carol" not in result["msg"], (
        f"Wrong password was accepted! Response: {result['msg']!r}"
    )


def test_missing_credentials_returns_error():
    """Explicitly empty strings trigger the 400 error path."""
    _, status = sqlivuln({"username": "", "password": ""})
    assert status == 400
