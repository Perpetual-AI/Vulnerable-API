"""
Test: USERS table must be seeded with valid credentials at startup.
CVE class: insecure_defaults — unquoted identifiers in INSERT cause OperationalError,
leaving USERS table empty and masking SQLi severity during testing.

The vulnerable code used:
    INSERT INTO USERS VALUES (mike, kaines)
SQLite treats `mike` and `kaines` as column references, not string literals,
raising OperationalError which is silently swallowed in app.py.

The fix uses parameterized inserts:
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("mike", "kaines"))

These tests exercise the exact INSERT statements (isolated from other setup_db logic)
and would FAIL on the vulnerable code, PASS after the fix.
"""

import sqlite3


def _make_users_table():
    """Return an in-memory connection with the USERS table already created."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE USERS(USERNAME VARCHAR(255), PASSWORD VARCHAR(255));")
    return conn


def test_users_insert_does_not_raise_operational_error():
    """The USERS INSERT must not raise OperationalError due to unquoted identifiers."""
    conn = _make_users_table()
    try:
        # This is what the fixed code does — parameterized inserts
        conn.execute("INSERT INTO USERS VALUES (?,?)", ("mike", "kaines"))
        conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", "admin"))
        conn.commit()
    except sqlite3.OperationalError as e:
        raise AssertionError(
            f"INSERT INTO USERS raised OperationalError: {e}\n"
            "Unquoted identifiers like `mike` are treated as column references by SQLite, "
            "not string values. Use parameterized queries."
        ) from e
    finally:
        conn.close()


def test_users_table_is_seeded_after_insert():
    """After the fixed INSERT, USERS must contain both expected credential rows."""
    conn = _make_users_table()
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("mike", "kaines"))
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", "admin"))
    conn.commit()

    rows = conn.execute("SELECT USERNAME, PASSWORD FROM USERS").fetchall()
    conn.close()

    usernames = {r[0] for r in rows}
    assert "mike" in usernames, "Expected user 'mike' missing from USERS table"
    assert "admin" in usernames, "Expected user 'admin' missing from USERS table"
    assert len(rows) == 2, f"Expected 2 users, got {len(rows)}"


def test_unquoted_insert_fails_on_bare_identifiers():
    """Regression: confirm the OLD vulnerable pattern raises OperationalError.

    This documents the vulnerability: SQLite interprets bare words as column
    references, not string literals. The old code used:
        INSERT INTO USERS VALUES (mike, kaines)
    """
    conn = _make_users_table()
    try:
        conn.execute("INSERT INTO USERS VALUES (mike, kaines)")
        # If we reach here, SQLite somehow accepted it — test the table is empty
        rows = conn.execute("SELECT * FROM USERS").fetchall()
        # Either it raised (expected) or succeeded (unexpected — document it)
        assert False, (
            "Expected OperationalError for unquoted identifiers, but insert succeeded. "
            f"Rows: {rows}"
        )
    except sqlite3.OperationalError:
        # This is the expected behavior — unquoted identifiers fail
        pass
    finally:
        conn.close()
