import html
from flask import request

ALLOWED_HOSTS = ["localhost", "localhost:8000", "yourdomain.com"]

def hhinovuln():
    return f"This is hhi no vuln"


def hhivuln(hhi):
    headerss = request.headers
    print(f"headers: {headerss}")

    try:
        h  = headerss["Host"]
    except Exception as e:
        print(f"failed: {e}")
        h = "temo.com"

    if h not in ALLOWED_HOSTS:
        return {"msg": "failed"}, 400

    if headerss:
        return {"msg": f"response, <a href='http://{html.escape(h)}'>"}, 200
    else:
        return {"msg": f"failed"}, 400
