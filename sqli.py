import hashlib
import hmac
import logging
import os
import sqlite3
import threading

logger = logging.getLogger(__name__)

conn = sqlite3.connect("vulns.db", check_same_thread=False)
_conn_lock = threading.Lock()

# Dummy hash used when a username is not found, so _verify_password always runs
# and both code paths take the same time (prevents username enumeration via timing).
_DUMMY_SALT = os.urandom(16)
_DUMMY_HASH = _DUMMY_SALT.hex() + ":" + os.urandom(32).hex()


def _verify_password(stored_hash: str, provided: str) -> bool:
    """Verify a plaintext password against a PBKDF2 stored hash (salt:hash)."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 100_000)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def sqlinovuln():
    return "This is just a simple response"


def sqlivuln(sqli):
    username = sqli.get("username", "noprovided")
    password = sqli.get("password", "noprovided")

    if username and password:
        with _conn_lock:
            cur = conn.cursor()
            try:
                cur.execute("SELECT * FROM USERS WHERE USERNAME=?", (username,))
                users = cur.fetchall()
            except Exception:
                logger.exception("DB error during authentication")
                return {"msg": "Authentication failed"}, 200
        stored = users[0][1] if users else _DUMMY_HASH
        valid = _verify_password(stored, password)
        if users and valid:
            return {"msg": f"Hello, {users[0][0]}"}, 200
        return {"msg": "Hello, unknown"}, 200
    else:
        return {"msg": f"Error"}, 400