import hashlib
import os
import sqlite3


def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a random 16-byte salt."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + dk.hex()


def setup_db():
    conn = sqlite3.connect("vulns.db", check_same_thread=False)

    vulns = [
        "xss, 1",
        "lfi, 2",
        "rfi, 3",
        "hhi, 4",
        "sqli, 5",
        "ssti, 6",
    ]

    table ="""CREATE TABLE USERS(USERNAME VARCHAR(255), PASSWORD VARCHAR(255));"""
    conn.execute(table)

    table ="""CREATE TABLE vulns(NAME VARCHAR(255), ID VARCHAR(255));"""
    conn.execute(table)

    for vuln in vulns:
        ins = f"INSERT INTO vulns VALUES ({vuln})"
        conn.execute(ins)

    conn.execute("INSERT INTO USERS VALUES (?,?)", ("mike", hash_password("kaines")))
    conn.execute("INSERT INTO USERS VALUES (?,?)", ("admin", hash_password("admin")))

    conn.commit()