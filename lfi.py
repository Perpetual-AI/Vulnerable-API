import os

def fetchfile(name):
    try:
        file = open(name).read()
    except:
        file = ""
    return file

def lfinovuln():
    return f"This is just a simple response {fetchfile('req.txt')}"


_SAFE_BASE = os.path.realpath(os.path.join(os.path.dirname(__file__), "safe_files"))

def lfivuln(lfi):
    filename = lfi.get("filename", "readme.txt")

    if filename:
        resolved = os.path.realpath(os.path.join(_SAFE_BASE, filename))
        if not resolved.startswith(_SAFE_BASE + os.sep):
            return {"msg": "Error"}, 400
        return {"msg": f"response, {fetchfile(resolved)}"}, 200
    else:
        return {"msg": f"Error"} , 400
