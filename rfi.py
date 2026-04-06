import ipaddress
import socket
import urllib.parse

import requests


def _is_safe_url(url):
    """Return True only for http/https URLs that resolve to public IPs."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
        return True
    except Exception:
        return False


def fetchimage(name):
    if not _is_safe_url(name):
        return ""
    try:
        file = requests.get(url=name, timeout=2).text
    except Exception:
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
