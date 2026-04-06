import html
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
        if not ip.is_global:
            return False
        return True
    except Exception:
        return False


def fetchimage(name):
    # Resolve hostname once and pin the IP to prevent DNS rebinding TOCTOU.
    # The same resolution is used for both the safety check and the actual request,
    # so an attacker cannot flip DNS between the two calls.
    try:
        parsed = urllib.parse.urlparse(name)
        if parsed.scheme not in ("http", "https"):
            return ""
        hostname = parsed.hostname
        if not hostname:
            return ""
        resolved_ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_global:
            return ""
        port = parsed.port
        netloc = f"{resolved_ip}:{port}" if port else resolved_ip
        pinned_url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    except Exception:
        return ""
    try:
        file = requests.get(
            url=pinned_url,
            timeout=2,
            allow_redirects=False,
            headers={"Host": hostname},
        ).text
    except Exception:
        file = ""
    return file

def rfinovuln():
    return f"This is just a simple image"


def rfivuln(rfi):
    filename = rfi.get("imagelink", "http://google.com")

    if filename:
        return {"msg": f"response, {html.escape(fetchimage(filename))}"}, 200
    else:
        return {"msg": f"Error"}, 400
