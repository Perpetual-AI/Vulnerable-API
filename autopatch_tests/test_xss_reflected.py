"""
Proof tests for the reflected XSS fix in xss.py.

Attack vector: POST /api/xssreflected with {"username": "<img src=x onerror=alert(document.cookie)>"}
If the response field is rendered via innerHTML the payload fires.

On the vulnerable code  → username is interpolated raw into the JSON msg field.
On the fixed code       → html.escape(username) neutralises <, >, ', ", & before
                          they reach the response body.
"""

from xss import reflected


XSS_PAYLOAD = "<img src=x onerror=alert(document.cookie)>"
SCRIPT_PAYLOAD = "<script>alert(1)</script>"
BENIGN_USERNAME = "alice"


def _call(username):
    return reflected({"username": username})


def test_img_onerror_payload_is_escaped():
    """
    The canonical attack payload must NOT appear raw in the response msg.
    This test FAILS on the vulnerable code and PASSES after the fix.
    """
    result, status = _call(XSS_PAYLOAD)
    assert status == 200
    msg = result["msg"]
    # Tag delimiters must be escaped — the browser can't parse &lt;img ...&gt; as an element
    assert "<img" not in msg, f"Raw <img> tag reflected! Got: {msg!r}"
    assert "&lt;" in msg, f"Expected &lt; in escaped output, got: {msg!r}"
    assert "&gt;" in msg, f"Expected &gt; in escaped output, got: {msg!r}"


def test_script_tag_is_escaped():
    """A <script> tag in username must be HTML-escaped."""
    result, status = _call(SCRIPT_PAYLOAD)
    assert status == 200
    msg = result["msg"]
    assert "<script>" not in msg, f"Raw <script> reflected! Got: {msg!r}"
    assert "&lt;script&gt;" in msg, f"Expected escaped script tag, got: {msg!r}"


def test_benign_username_passes_through():
    """A normal username is returned and the greeting is intact."""
    result, status = _call(BENIGN_USERNAME)
    assert status == 200
    assert BENIGN_USERNAME in result["msg"]


def test_empty_username_returns_error():
    """An empty username string triggers the error branch (400)."""
    status = reflected({"username": ""})[1]
    assert status == 400
