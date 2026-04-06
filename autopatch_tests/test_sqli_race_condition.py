"""
Proof tests for the race-condition vulnerability in sqli.py (line 8).

Vulnerability: A single sqlite3.Connection is created at module import time and
shared globally across all threads.  check_same_thread=False silences the safety
warning but does NOT provide thread safety.  Concurrent cursor operations on the
shared connection can corrupt each other's query state, produce interleaved results,
or raise sqlite3.ProgrammingError: "Recursive use of cursors not allowed".

Fix: A threading.Lock (_conn_lock) serialises all cursor operations inside
sqlivuln(), ensuring only one thread accesses the shared connection at a time.
"""
import threading

from custom_db import hash_password
from sqli import sqlivuln, conn
import sqli


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------

def _seed():
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS USERS (USERNAME TEXT, PASSWORD TEXT)")
    for uname, pwd in [("rc_alice", "pw_alice"), ("rc_bob", "pw_bob")]:
        cur.execute("DELETE FROM USERS WHERE USERNAME=?", (uname,))
        cur.execute(
            "INSERT INTO USERS (USERNAME, PASSWORD) VALUES (?, ?)",
            (uname, hash_password(pwd)),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# Structural proof: the module must export a threading.Lock for DB access
# ---------------------------------------------------------------------------

def test_conn_lock_exists():
    """
    FAILS on vulnerable code: sqli._conn_lock does not exist → AttributeError.

    PASSES on fixed code: sqli._conn_lock is a threading.Lock that guards all
    cursor operations inside sqlivuln(), preventing concurrent connection access.
    """
    assert hasattr(sqli, "_conn_lock"), (
        "sqli._conn_lock is missing. "
        "The fix must add a threading.Lock to serialise access to the shared "
        "sqlite3.Connection and prevent the race-condition vulnerability."
    )
    assert isinstance(sqli._conn_lock, type(threading.Lock())), (
        f"sqli._conn_lock must be a threading.Lock, got {type(sqli._conn_lock)}"
    )


# ---------------------------------------------------------------------------
# Behavioural proof: 50 concurrent requests must not raise SQLite errors
# ---------------------------------------------------------------------------

def test_concurrent_requests_no_errors():
    """
    FAILS on vulnerable code: all threads share one sqlite3.Connection with no
    synchronisation; under concurrent load this raises sqlite3.ProgrammingError
    or returns corrupt/interleaved data.

    PASSES on fixed code: _conn_lock serialises access so no concurrent cursor
    corruption can occur.
    """
    _seed()

    errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(50)

    def worker():
        try:
            barrier.wait(timeout=10)
            result, status = sqlivuln({"username": "rc_alice", "password": "pw_alice"})
            assert status == 200, f"Unexpected status: {status}"
            assert "rc_alice" in result["msg"], (
                f"Wrong or contaminated result: {result['msg']!r}"
            )
        except Exception as exc:
            with lock:
                errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert not errors, (
        f"Concurrent requests violated thread safety ({len(errors)} failures). "
        f"First few: {errors[:3]}"
    )
