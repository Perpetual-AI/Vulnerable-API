import html


def novuln():
    return "This is just a simple response"


def reflected(xss):
    username = xss.get("username", "noprovided")

    if username:
        return {"msg": f"Hello, {html.escape(username)}"}, 200
    else:
        return {"msg": f"Error"}, 400
