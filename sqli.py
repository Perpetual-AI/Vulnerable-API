import sqlite3

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
        except Exception as e:
            print(f"[sqlivuln] DB error: {e}")
            return {"msg": "Login failed"}, 401
        return {"msg": f"Hello, {users}"}, 200
    else:
        return {"msg": f"Error"}, 400