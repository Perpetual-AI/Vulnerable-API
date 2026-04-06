from unittest.mock import MagicMock, patch
import hhi


def _mock_headers(host_header):
    headers = {"Host": host_header}
    mock = MagicMock()
    mock.__getitem__ = MagicMock(side_effect=headers.__getitem__)
    mock.__bool__ = MagicMock(return_value=True)
    return mock


def test_host_header_injection_blocked():
    """Attacker-controlled Host header must NOT appear in the response href — FAILS on vulnerable code."""
    mock_req = MagicMock()
    mock_req.headers = _mock_headers("evil.com")
    with patch.object(hhi, "request", mock_req):
        result, status = hhi.hhivuln({})

    assert status == 200
    assert "evil.com" not in result["msg"], (
        f"Host header injection succeeded: {result['msg']}"
    )


def test_xss_via_host_header_blocked():
    """XSS payload in Host header must not appear in the response — FAILS on vulnerable code."""
    xss_host = "x' onmouseover='alert(1)"
    mock_req = MagicMock()
    mock_req.headers = _mock_headers(xss_host)
    with patch.object(hhi, "request", mock_req):
        result, status = hhi.hhivuln({})

    assert status == 200
    assert xss_host not in result["msg"], (
        f"XSS via Host header succeeded: {result['msg']}"
    )


def test_response_uses_configured_base_url():
    """Response href must use the server-side BASE_URL, not the request Host."""
    mock_req = MagicMock()
    mock_req.headers = _mock_headers("attacker.net")
    with patch.object(hhi, "request", mock_req):
        result, status = hhi.hhivuln({})

    assert status == 200
    assert hhi.BASE_URL in result["msg"]
