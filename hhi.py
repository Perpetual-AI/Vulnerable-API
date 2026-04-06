from flask import request

BASE_URL = "temo.com"


def hhinovuln():
    return f"This is hhi no vuln"


def hhivuln(hhi):
    headerss = request.headers
    print(f"headers: {headerss}")

    if headerss:
        return {"msg": f"response, <a href='{BASE_URL}'>"}, 200
    else:
        return {"msg": f"failed"}, 400
