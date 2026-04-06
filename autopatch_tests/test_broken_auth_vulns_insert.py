"""
Test: vulns table INSERT must use parameterized queries, not f-string interpolation.
CVE class: broken_authentication

Vulnerable code (lines 31-33 of custom_db.py):
    vulns = ["xss, 1", "lfi, 2", ...]
    for vuln in vulns:
        ins = f"INSERT INTO vulns VALUES ({vuln})"   # → INSERT INTO vulns VALUES (xss, 1)
        conn.execute(ins)

SQLite treats bare `xss` as a column reference, not a string literal, raising:
    OperationalError: no such column: xss

This exception propagates before the USERS table is ever seeded, so every
authentication attempt against the empty USERS table silently fails.

Fix: change vulns to tuples and use parameterized inserts:
    conn.execute("INSERT INTO vulns VALUES (?, ?)", vuln)
"""

import sqlite3


def _make_vulns_table():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE vulns(NAME VARCHAR(255), ID VARCHAR(255));")
    return conn


def test_fstring_vulns_insert_raises_operational_error():
    """Regression: the OLD f-string pattern must raise OperationalError.

    Documents the vulnerability: INSERT INTO vulns VALUES (xss, 1) treats
    `xss` as a column reference, not a string — SQLite raises OperationalError.
    """
    conn = _make_vulns_table()
    try:
        conn.execute("INSERT INTO vulns VALUES (xss, 1)")
        conn.close()
        raise AssertionError(
            "Expected OperationalError for unquoted identifier 'xss', but insert succeeded. "
            "Vulnerability may already be patched or SQLite behaviour changed."
        )
    except sqlite3.OperationalError:
        pass  # Expected — this is the attack vector
    finally:
        conn.close()


def test_parameterized_vulns_insert_succeeds():
    """The fixed parameterized INSERT must not raise and must seed all rows."""
    vulns = [
        ("xss", "1"),
        ("lfi", "2"),
        ("rfi", "3"),
        ("hhi", "4"),
        ("sqli", "5"),
        ("ssti", "6"),
    ]
    conn = _make_vulns_table()
    for vuln in vulns:
        conn.execute("INSERT INTO vulns VALUES (?, ?)", vuln)
    conn.commit()

    rows = conn.execute("SELECT NAME FROM vulns").fetchall()
    conn.close()

    names = {r[0] for r in rows}
    assert names == {"xss", "lfi", "rfi", "hhi", "sqli", "ssti"}, (
        f"Expected all 6 vuln names, got: {names}"
    )


def test_setup_db_seeds_users_after_vulns_insert():
    """End-to-end: setup_db() must complete without exception and seed USERS.

    On vulnerable code the vulns INSERT raises OperationalError before USERS
    are ever inserted, leaving the authentication table permanently empty.
    """
    import os
    import tempfile

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ.setdefault("MIKE_PASSWORD", "testmike123")
    os.environ.setdefault("ADMIN_PASSWORD", "testadmin123")

    # Patch setup_db to use a temp DB path so we don't clobber vulns.db
    import sqlite3 as _sqlite3
    original_connect = _sqlite3.connect
    conn_holder = []

    def patched_connect(_path, **kwargs):
        c = original_connect(db_path, **kwargs)
        conn_holder.append(c)
        return c

    _sqlite3.connect = patched_connect
    try:
        import importlib
        import custom_db
        importlib.reload(custom_db)
        custom_db.setup_db()
    except Exception as e:
        raise AssertionError(
            f"setup_db() raised an exception: {e}\n"
            "Broken vulns INSERT propagates up and leaves USERS table empty."
        ) from e
    finally:
        _sqlite3.connect = original_connect

    # Verify USERS was seeded
    conn = _sqlite3.connect(db_path)
    rows = conn.execute("SELECT USERNAME FROM USERS").fetchall()
    conn.close()
    try:
        os.remove(db_path)
    except OSError:
        pass

    usernames = {r[0] for r in rows}
    assert "mike" in usernames, f"User 'mike' missing from USERS — setup_db() failed silently. Got: {usernames}"
    assert "admin" in usernames, f"User 'admin' missing from USERS — setup_db() failed silently. Got: {usernames}"
