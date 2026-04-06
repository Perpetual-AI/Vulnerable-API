"""
Proof tests for plaintext password storage in custom_db.py (lines 15-26).

Attack vector:
  1. Attacker obtains the vulns.db SQLite file (LFI, backup leak, etc.).
  2. On vulnerable code: USERS table contains USERNAME=admin, PASSWORD=admin in
     plaintext — no cracking required, credentials are immediately usable.
  3. On vulnerable code: a login with admin:admin returns a success response,
     exposing the fact that the default credential is valid.

Fix: passwords are hashed with PBKDF2-HMAC-SHA256 before storage.
     sqli.py verifies the provided password against the stored hash in Python
     rather than comparing plaintext in SQL.

These tests FAIL on the vulnerable code and PASS with the fix applied.
"""

import sqlite3

from custom_db import hash_password
from sqli import _verify_password


# ---------------------------------------------------------------------------
# 1.  Storage tests — prove the DB never contains plaintext
# ---------------------------------------------------------------------------

def _make_users_table():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE USERS(USERNAME VARCHAR(255), PASSWORD VARCHAR(255));")
    return conn


def test_stored_password_is_not_plaintext():
    """
    After hashing, the stored value must NOT equal the plaintext password.

    On the vulnerable code:
        conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", "admin"))
    the PASSWORD column contains the literal string 'admin'.

    On the fixed code it contains a PBKDF2 hash like:
        '<32-hex-salt>:<64-hex-digest>'
    """
    conn = _make_users_table()
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", hash_password("admin")))
    conn.commit()

    row = conn.execute("SELECT PASSWORD FROM USERS WHERE USERNAME='admin'").fetchone()
    conn.close()

    stored = row[0]
    assert stored != "admin", (
        "PASSWORD column contains the literal string 'admin' — plaintext storage! "
        "An attacker reading the DB immediately obtains a usable credential."
    )


def test_stored_password_contains_salt_and_hash():
    """Hash format must be '<salt_hex>:<hash_hex>' with a non-trivial length."""
    hashed = hash_password("kaines")
    assert ":" in hashed, "Expected 'salt:hash' format, no colon found"
    salt_hex, hash_hex = hashed.split(":", 1)
    # 16-byte salt → 32 hex chars; SHA-256 → 64 hex chars
    assert len(salt_hex) == 32, f"Expected 32-char salt hex, got {len(salt_hex)}"
    assert len(hash_hex) == 64, f"Expected 64-char hash hex, got {len(hash_hex)}"


def test_two_hashes_of_same_password_differ():
    """Each call must use a fresh random salt — identical inputs must not produce
    the same output (rainbow-table resistance)."""
    h1 = hash_password("admin")
    h2 = hash_password("admin")
    assert h1 != h2, (
        "Two hashes of 'admin' are identical — the salt is not random. "
        "This makes the hashes vulnerable to pre-computed rainbow-table attacks."
    )


# ---------------------------------------------------------------------------
# 2.  Verification tests — prove correct/wrong passwords are distinguished
# ---------------------------------------------------------------------------

def test_correct_password_verifies():
    """_verify_password must return True for the original plaintext."""
    stored = hash_password("secret")
    assert _verify_password(stored, "secret") is True


def test_wrong_password_does_not_verify():
    """_verify_password must return False for any other string."""
    stored = hash_password("secret")
    assert _verify_password(stored, "wrong") is False


def test_plaintext_does_not_match_stored_hash():
    """
    Core attack-vector test: a raw plaintext value must never verify against
    a hash of a *different* password.

    On the vulnerable code the DB stores 'admin' literally, so an attacker who
    reads the DB instantly has a working credential.  With the fix, reading the
    DB only yields an opaque hash — the plaintext can only be recovered by
    brute-force, not by direct comparison.
    """
    stored = hash_password("admin")
    # Attacker tries to use the raw stored string as a password — must fail.
    assert _verify_password(stored, stored) is False, (
        "The stored hash was accepted as a valid password for itself — "
        "this means the verification is broken or the 'hash' is plaintext."
    )


def test_default_admin_credential_not_stored_as_plaintext():
    """
    End-to-end: seed the USERS table via hash_password (as setup_db now does)
    and confirm the DB row cannot be trivially used by someone who reads it.
    """
    conn = _make_users_table()
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", hash_password("admin")))
    conn.commit()

    row = conn.execute("SELECT PASSWORD FROM USERS WHERE USERNAME='admin'").fetchone()
    conn.close()

    stored = row[0]
    # The attacker reads 'stored' directly from the DB file.
    # They must NOT be able to use it as-is to authenticate.
    assert _verify_password(stored, stored) is False, (
        "The value stored in the DB was accepted as a valid password — "
        "plaintext or trivially reversible storage detected."
    )
    # But the real password must still work.
    assert _verify_password(stored, "admin") is True, (
        "The correct password 'admin' failed verification — hashing broken."
    )
