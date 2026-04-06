"""
Proof tests for the timing side-channel vulnerability in sqli.py (lines 40-42).

Vulnerability: _verify_password (PBKDF2-HMAC-SHA256, 100 000 iterations, ~100 ms)
was only called when the username existed in the database.  A missing username
returned immediately (~0 ms), letting an attacker distinguish valid from invalid
usernames purely by measuring response latency.

Fix: _verify_password is now always called.  When the username is not found, a
module-level _DUMMY_HASH is used so the ~100 ms PBKDF2 cost is paid regardless,
eliminating the timing oracle.
"""

import time

from custom_db import hash_password
from sqli import conn, sqlivuln

# PBKDF2 with 100k iterations takes ~20-100 ms depending on hardware.
# 10 ms is a conservative lower bound that proves the hash function ran;
# the unpatched code path (no PBKDF2) returns in <1 ms.
_PBKDF2_MIN_MS = 10


def _seed_user(username: str = "timing_user", password: str = "s3cr3t") -> None:
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS USERS (USERNAME TEXT, PASSWORD TEXT)")
    cur.execute("DELETE FROM USERS WHERE USERNAME=?", (username,))
    cur.execute(
        "INSERT INTO USERS (USERNAME, PASSWORD) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()


def test_nonexistent_username_timing_equalized():
    """
    FAILS on vulnerable code: a username that does not exist returns in ~0 ms
    because _verify_password is never called, leaking valid usernames via timing.

    PASSES on fixed code: _verify_password is always called (with _DUMMY_HASH),
    so the response takes ~100 ms even for non-existent usernames.
    """
    _seed_user()

    start = time.perf_counter()
    result, status = sqlivuln(
        {"username": "definitely_does_not_exist_xyz987", "password": "anypass"}
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert status == 200
    assert result["msg"] == "Hello, unknown"

    assert elapsed_ms >= _PBKDF2_MIN_MS, (
        f"Non-existent username returned in {elapsed_ms:.1f} ms — timing oracle exposed! "
        f"Expected >= {_PBKDF2_MIN_MS} ms (PBKDF2 must always run). "
        "An attacker can enumerate valid usernames by measuring response latency."
    )


def test_existing_username_wrong_password_also_slow():
    """
    Both branches (user exists, user missing) must take a similar amount of time.
    Confirms that the fix does not accidentally bypass PBKDF2 for existing users.
    """
    _seed_user("timing_user2", "correctpass")

    start = time.perf_counter()
    result, status = sqlivuln({"username": "timing_user2", "password": "wrongpass"})
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert status == 200
    assert result["msg"] == "Hello, unknown"
    assert elapsed_ms >= _PBKDF2_MIN_MS, (
        f"Existing username + wrong password returned in {elapsed_ms:.1f} ms — "
        "PBKDF2 may have been skipped."
    )


def test_correct_credentials_still_authenticate():
    """Regression: legitimate login must still succeed after the timing fix."""
    _seed_user("timing_user3", "mypass")
    result, status = sqlivuln({"username": "timing_user3", "password": "mypass"})
    assert status == 200
    assert "timing_user3" in result["msg"]
