import ipaddress
import socket
from urllib.parse import urlparse

import requests

_ALLOWED_SCHEMES = {"http", "https"}


def _is_safe_url(url):
    """Return (is_safe, resolved_ip_str) to prevent TOCTOU DNS rebinding.

    The resolved IP is returned so the caller can use it directly in the
    request, ensuring the same address that passed the safety check is the
    one actually contacted (no second DNS resolution).
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, None
    try:
        resolved = socket.gethostbyname(parsed.hostname or "")
        ip = ipaddress.ip_address(resolved)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False, None
    except Exception:
        return False, None
    return True, resolved


def fetchimage(name):
    try:
        safe, resolved_ip = _is_safe_url(name)
        if not safe:
            return ""
        # Build the request URL using the pre-resolved IP to prevent DNS
        # rebinding: the IP checked above is the IP we connect to.
        parsed = urlparse(name)
        netloc = f"{resolved_ip}:{parsed.port}" if parsed.port else resolved_ip
        safe_url = parsed._replace(netloc=netloc).geturl()
        file = requests.get(url=safe_url, timeout=2, allow_redirects=False).text
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
