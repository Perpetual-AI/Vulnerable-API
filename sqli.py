import hashlib
import logging
import sqlite3
import threading

logger = logging.getLogger(__name__)

conn = sqlite3.connect("vulns.db", check_same_thread=False)
_conn_lock = threading.Lock()


def _verify_password(stored_hash: str, provided: str) -> bool:
    """Verify a plaintext password against a PBKDF2 stored hash (salt:hash)."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 100_000)
        return dk.hex() == hash_hex
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
        if users and _verify_password(users[0][1], password):
            return {"msg": f"Hello, {users[0][0]}"}, 200
        return {"msg": "Hello, unknown"}, 200
    else:
        return {"msg": f"Error"}, 400