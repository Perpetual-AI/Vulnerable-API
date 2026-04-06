import ipaddress
import socket
from urllib.parse import urlparse

import requests

_ALLOWED_SCHEMES = {"http", "https"}


def _is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname or ""))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except Exception:
        return False
    return True


def fetchimage(name):
    try:
        if not _is_safe_url(name):
            return ""
        file = requests.get(url=name, timeout=2).text
    except:
        file = ""
    return file

def rfinovuln():
    return f"This is just a simple image"


def rfivuln(rfi):
    filename = rfi.get("imagelink", "http://google.com")

    if filename:
        return {"msg": f"response, {fetchimage(filename)}"}, 200
    else:
        return {"msg": f"Error"}, 400
