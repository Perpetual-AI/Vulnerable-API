import logging
import sqlite3

logger = logging.getLogger(__name__)

conn = sqlite3.connect("vulns.db", check_same_thread=False)

def sqlinovuln():
    return "This is just a simple response"


def sqlivuln(sqli):
    username = sqli.get("username", "noprovided")
    password = sqli.get("password", "noprovided")

    if username and password:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM USERS WHERE USERNAME=? AND PASSWORD=?", (username, password))
            users = cur.fetchall()
        except Exception:
            logger.exception("DB error during authentication")
            return {"msg": "Authentication failed"}, 200
        return {"msg": f"Hello, {users}"}, 200
    else:
        return {"msg": f"Error"}, 400