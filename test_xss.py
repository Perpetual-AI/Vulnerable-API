import xss


def test_reflected_xss_payload_is_escaped():
    """XSS payload must be HTML-escaped — FAILS on vulnerable code."""
    payload = {"username": "<img src=x onerror=alert(document.cookie)>"}
    result, status = xss.reflected(payload)
    assert status == 200
    # The raw tag must not appear in the response
    assert "<img" not in result["msg"], (
        f"XSS payload returned unescaped: {result['msg']}"
    )
    # The escaped form must be present
    assert "&lt;img" in result["msg"], (
        f"Expected HTML-escaped output, got: {result['msg']}"
    )


def test_reflected_script_tag_escaped():
    """<script> injection must also be escaped."""
    payload = {"username": "<script>alert(1)</script>"}
    result, status = xss.reflected(payload)
    assert status == 200
    assert "<script>" not in result["msg"]
    assert "&lt;script&gt;" in result["msg"]


def test_reflected_normal_username_unaffected():
    """Legitimate usernames must pass through correctly."""
    payload = {"username": "alice"}
    result, status = xss.reflected(payload)
    assert status == 200
    assert result["msg"] == "Hello, alice"


def test_reflected_missing_username_returns_400():
    """Empty username must still return 400."""
    _, status = xss.reflected({"username": ""})
    assert status == 400
