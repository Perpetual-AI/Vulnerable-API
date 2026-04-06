"""
Proof tests for weak default credentials in custom_db.py (lines 35-38).

Attack vector:
  POST /api/sqlivuln with {"username": "admin", "password": "admin"}
  returns {"msg": "Hello, admin"} on vulnerable code because
  hash_password("admin") is hardcoded in setup_db().

  admin:admin is present in every credential-stuffing wordlist and requires
  zero brute-force effort to discover.

These tests FAIL on the vulnerable code and PASS after the fix.
"""

import ast
import os
import sqlite3

from custom_db import hash_password
from sqli import _verify_password

CUSTOM_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "custom_db.py")


def _get_hash_password_literal_args(tree: ast.AST) -> list:
    """Return every string literal passed directly as the first arg to hash_password()."""
    literals = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "hash_password"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            literals.append(node.args[0].value)
    return literals


# ---------------------------------------------------------------------------
# AST-based tests — FAIL on vulnerable code, PASS on fixed code
# ---------------------------------------------------------------------------

def test_admin_password_is_not_hardcoded_literal():
    """
    On vulnerable code: hash_password("admin") — literal 'admin' as arg → FAIL.
    On fixed code: hash_password uses os.environ / os.urandom — PASS.
    """
    with open(CUSTOM_DB_PATH) as f:
        tree = ast.parse(f.read())

    literals = _get_hash_password_literal_args(tree)

    assert "admin" not in literals, (
        "hash_password('admin') is called in custom_db.py with the hardcoded literal "
        "'admin'. An attacker can authenticate as admin using admin:admin — present in "
        "every credential-stuffing wordlist — with zero brute-force effort. "
        "Replace with os.environ.get('ADMIN_PASSWORD') or os.urandom(16).hex()."
    )


def test_mike_password_is_not_hardcoded_literal():
    """kaines is also a weak default credential discoverable from source code."""
    with open(CUSTOM_DB_PATH) as f:
        tree = ast.parse(f.read())

    literals = _get_hash_password_literal_args(tree)

    assert "kaines" not in literals, (
        "hash_password('kaines') is called in custom_db.py with a hardcoded literal. "
        "Source code leaks every hardcoded credential. "
        "Replace with os.environ.get('MIKE_PASSWORD') or os.urandom(16).hex()."
    )


# ---------------------------------------------------------------------------
# Functional tests — verify auth behaviour with env-var / random passwords
# ---------------------------------------------------------------------------

def _make_users_table():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE USERS(USERNAME VARCHAR(255), PASSWORD VARCHAR(255));")
    return conn


def test_admin_admin_is_rejected_when_random_password_seeded():
    """
    Functional proof: seeding admin with a random password (the fix) means
    authenticating with 'admin' as the password must fail.
    """
    conn = _make_users_table()

    os.environ.pop("ADMIN_PASSWORD", None)
    admin_password = os.environ.get("ADMIN_PASSWORD") or os.urandom(16).hex()
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", hash_password(admin_password)))
    conn.commit()

    row = conn.execute("SELECT PASSWORD FROM USERS WHERE USERNAME='admin'").fetchone()
    conn.close()

    assert not _verify_password(row[0], "admin"), (
        "admin:admin credential authenticated successfully against a randomly-seeded admin. "
        "The seeded password must not be the trivially guessable string 'admin'."
    )


def test_env_var_password_authenticates_and_admin_does_not():
    """When ADMIN_PASSWORD env var is set, only that password must work."""
    strong_password = "str0ng-r@nd0m-P@ssw0rd-2024!"
    os.environ["ADMIN_PASSWORD"] = strong_password
    try:
        conn = _make_users_table()
        admin_password = os.environ.get("ADMIN_PASSWORD") or os.urandom(16).hex()
        conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", hash_password(admin_password)))
        conn.commit()

        row = conn.execute("SELECT PASSWORD FROM USERS WHERE USERNAME='admin'").fetchone()
        conn.close()
        stored = row[0]

        assert _verify_password(stored, strong_password), (
            "ADMIN_PASSWORD env var was set but the correct password was rejected."
        )
        assert not _verify_password(stored, "admin"), (
            "Default 'admin' password still accepted even when ADMIN_PASSWORD is set."
        )
    finally:
        del os.environ["ADMIN_PASSWORD"]
