from unittest.mock import MagicMock, patch

import rfi


def test_rfi_aws_metadata_endpoint_blocked():
    """AWS metadata SSRF must be blocked — FAILS on vulnerable code."""
    with patch("rfi.requests.get") as mock_get:
        result, _ = rfi.rfivuln(
            {"imagelink": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
        )
        mock_get.assert_not_called()
    assert result["msg"] == "response, "


def test_rfi_localhost_probe_blocked():
    """localhost probe (e.g. Redis) must be blocked — FAILS on vulnerable code."""
    with patch("rfi.requests.get") as mock_get:
        result, _ = rfi.rfivuln({"imagelink": "http://localhost:6379/"})
        mock_get.assert_not_called()
    assert result["msg"] == "response, "


def test_rfi_file_scheme_blocked():
    """file:// scheme must be rejected — FAILS on vulnerable code."""
    with patch("rfi.requests.get") as mock_get:
        result, _ = rfi.rfivuln({"imagelink": "file:///etc/passwd"})
        mock_get.assert_not_called()
    assert result["msg"] == "response, "


def test_rfi_private_ip_range_blocked():
    """RFC 1918 address reached via hostname must be blocked."""
    with patch("rfi.socket.gethostbyname", return_value="192.168.1.1"), \
         patch("rfi.requests.get") as mock_get:
        result, _ = rfi.rfivuln({"imagelink": "http://internal.corp/secret"})
        mock_get.assert_not_called()
    assert result["msg"] == "response, "


def test_rfi_public_url_allowed():
    """Legitimate public URL must still be fetched successfully."""
    mock_resp = MagicMock()
    mock_resp.text = "image data"
    with patch("rfi.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("rfi.requests.get", return_value=mock_resp) as mock_get:
        result, status = rfi.rfivuln({"imagelink": "http://example.com/image.png"})
        mock_get.assert_called_once()
    assert status == 200
    assert "image data" in result["msg"]


def test_rfi_redirect_to_private_ip_blocked():
    """Open-redirect SSRF bypass must be blocked — FAILS on vulnerable code (allow_redirects=True)."""
    mock_resp = MagicMock()
    mock_resp.text = "IAM credentials"
    with patch("rfi.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("rfi.requests.get", return_value=mock_resp) as mock_get:
        rfi.rfivuln({"imagelink": "http://attacker.com/redirect"})
        _, kwargs = mock_get.call_args
        assert kwargs.get("allow_redirects") is False, \
            "allow_redirects=False required to prevent SSRF via open redirect"


def test_rfi_ssl_verification_enabled():
    """requests.get must be called without verify=False (TLS enforced)."""
    mock_resp = MagicMock()
    mock_resp.text = "ok"
    with patch("rfi.socket.gethostbyname", return_value="93.184.216.34"), \
         patch("rfi.requests.get", return_value=mock_resp) as mock_get:
        rfi.rfivuln({"imagelink": "https://example.com/image.png"})
        _, kwargs = mock_get.call_args
        assert kwargs.get("verify") is not False, "verify=False must not be passed"
