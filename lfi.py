import os

_BASE_DIR = os.path.realpath(os.path.dirname(__file__))

def fetchfile(name):
    try:
        file = open(name).read()
    except:
        file = ""
    return file

def lfinovuln():
    return f"This is just a simple response {fetchfile('req.txt')}"


def lfivuln(lfi):
    filename = lfi.get("filename", "readme.txt")

    if filename:
        resolved = os.path.realpath(os.path.join(_BASE_DIR, filename))
        if not resolved.startswith(_BASE_DIR + os.sep) and resolved != _BASE_DIR:
            return {"msg": "Error"}, 400
        return {"msg": f"response, {fetchfile(resolved)}" }, 200
    else:
        return {"msg": f"Error"} , 400
