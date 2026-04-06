"""
Proof tests for information_disclosure in sqli.py (lines 17-20).

Attack scenario:
  A payload that triggers a DB exception (e.g. username="'") causes the raw
  sqlite3 error message to be returned in the response, e.g.:
      {"msg": "near \"'\": syntax error"}
  This confirms the injection point and reveals SQL syntax, column counts, and
  table names — giving an attacker a roadmap for further exploitation.

Fix: return a generic message; log the real exception server-side only.
"""

import sqlite3
from unittest.mock import MagicMock, patch

import sqli


# ---------------------------------------------------------------------------
# Information-disclosure proof test
# ---------------------------------------------------------------------------

def test_db_exception_does_not_leak_error_details():
    """
    When a DB exception is raised, the response MUST NOT contain the raw
    exception text.

    On the vulnerable code `return {"msg": f"{e}"}` reflects the full
    sqlite3 error message; on the fixed code a generic string is returned.
    """
    leaked_details = "near \"'\": syntax error"

    mock_cursor = MagicMock()
    mock_cursor.execute.side_effect = sqlite3.OperationalError(leaked_details)
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(sqli, "conn", mock_conn):
        result, status = sqli.sqlivuln({"username": "'", "password": "x"})

    assert status == 200
    # Must NOT echo the raw DB error back to the caller
    assert leaked_details not in result["msg"], (
        f"DB exception details leaked in response: {result['msg']!r}"
    )
    # Must return a safe, opaque message
    assert result["msg"] == "Authentication failed", (
        f"Unexpected response: {result['msg']!r}"
    )


def test_db_exception_generic_message_regardless_of_error_type():
    """
    Any DB exception — not just syntax errors — must yield the same
    generic response so no error category can be inferred by the caller.
    """
    for error_cls, msg in [
        (sqlite3.OperationalError, "no such table: USERS"),
        (sqlite3.DatabaseError, "disk I/O error"),
    ]:
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = error_cls(msg)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        with patch.object(sqli, "conn", mock_conn):
            result, status = sqli.sqlivuln({"username": "admin", "password": "x"})

        assert status == 200
        assert msg not in result["msg"], (
            f"{error_cls.__name__} message leaked: {result['msg']!r}"
        )
        assert result["msg"] == "Authentication failed"
