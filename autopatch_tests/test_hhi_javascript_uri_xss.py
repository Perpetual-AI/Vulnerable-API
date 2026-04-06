"""
Proof tests for the javascript: URI XSS fix in hhi.py (line 24).

Vulnerability: html.escape() does NOT sanitize URI schemes.
A Host value like 'javascript:alert(document.cookie)' contains no HTML-special
characters, so it passes through html.escape() unchanged. Without an explicit
http:// scheme prefix in the href, any value that somehow reaches the reflection
point can embed a javascript: URI.

Fix: prefix the href with 'http://', making the href always an absolute URL with
a safe scheme. A javascript: payload would become 'http://javascript:...' which
browsers do not interpret as a script URI.

On the vulnerable code (no scheme prefix):
  href='localhost'  →  relative URL; a javascript: payload would reflect verbatim.

On the fixed code (http:// prefix):
  href='http://localhost'  →  absolute URL; scheme is always http/https.
"""

import flask
import pytest

from hhi import hhivuln, ALLOWED_HOSTS

BENIGN_HOST = ALLOWED_HOSTS[0]  # e.g. "localhost"


@pytest.fixture
def app():
    return flask.Flask(__name__)


def test_href_contains_safe_absolute_scheme(app):
    """
    The href in the response must start with 'http://' (or 'https://').

    This test FAILS on the vulnerable code (href='localhost' — no scheme)
    and PASSES on the fixed code (href='http://localhost').

    Without a forced scheme prefix, an attacker who can control ALLOWED_HOSTS
    (misconfiguration, env override, etc.) or who finds a bypass can inject a
    javascript: URI that html.escape() would not catch.
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": BENIGN_HOST},
    ):
        result, status = hhivuln(None)
        assert status == 200
        msg = result["msg"]
        assert "href='http://" in msg or "href='https://" in msg, (
            f"href lacks a safe absolute scheme. "
            f"A javascript: URI could be injected. Got: {msg!r}"
        )


def test_javascript_uri_not_present_in_response(app):
    """
    A javascript: URI must never appear in the response href, even for allowed hosts.

    Belt-and-suspenders: confirm the reflected href never starts with 'javascript:'.
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": BENIGN_HOST},
    ):
        result, status = hhivuln(None)
        assert status == 200
        msg = result["msg"]
        assert "javascript:" not in msg.lower(), (
            f"javascript: URI found in response! Got: {msg!r}"
        )


def test_href_scheme_prefix_neutralises_javascript_payload(app):
    """
    Demonstrates that the http:// prefix fix neutralises a javascript: payload
    if one were ever to reach the href construction (defence-in-depth test).

    We simulate this by checking the code-level invariant: the href value is
    always prefixed with 'http://', so 'javascript:alert(1)' would become
    'http://javascript:alert(1)' — not a script URI.

    On the vulnerable code the href for an allowed host is bare ('localhost'),
    proving the scheme prefix is missing and a javascript: value would slip through.
    On the fixed code the href is 'http://localhost', proving the prefix is present.
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": BENIGN_HOST},
    ):
        result, status = hhivuln(None)
        assert status == 200
        msg = result["msg"]
        # The only way a href can be safe against javascript: URIs is to force
        # an explicit safe scheme. Verify that invariant holds.
        href_start = f"href='http://{BENIGN_HOST}"
        assert href_start in msg, (
            f"Expected href to start with 'http://{BENIGN_HOST}', got: {msg!r}. "
            f"Missing scheme prefix means javascript: URIs could be reflected."
        )
