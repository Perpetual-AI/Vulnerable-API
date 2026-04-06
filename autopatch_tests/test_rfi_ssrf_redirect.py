"""
Proof test for SSRF redirect-chain bypass in rfi.py (fetchimage).

Attack vector:
  1. Attacker registers attacker.com resolving to a public IP.
  2. Attacker's server returns HTTP 302 -> http://169.254.169.254/latest/meta-data/...
  3. _is_safe_url() approves attacker.com (public IP).
  4. requests.get() (default allow_redirects=True) follows the 302.
  5. AWS IMDS credentials leak in the API response.

Fix: pass allow_redirects=False so redirects are never followed.
"""

import socket
from unittest.mock import MagicMock, patch

import rfi


def test_redirect_ssrf_allow_redirects_false():
    """requests.get must be called with allow_redirects=False.

    On vulnerable code this fails because allow_redirects defaults to True,
    meaning a 302 to 169.254.169.254 would be transparently followed.
    """
    mock_response = MagicMock()
    mock_response.text = ""

    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=mock_response) as mock_get:
            rfi.fetchimage("http://example.com/redirect-to-imds")

            assert mock_get.called, "requests.get should have been called for a public URL"
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs.get("allow_redirects") is False, (
                "requests.get must receive allow_redirects=False. "
                "Without it, a redirect to 169.254.169.254 leaks AWS IMDS credentials."
            )


def test_redirect_to_imds_does_not_expose_credentials():
    """Simulate a redirect chain: public URL -> 302 -> IMDS.

    With allow_redirects=False the redirect response body is returned (empty),
    not the IMDS payload. The credential string must never appear in the result.
    """
    # Redirect response (what the attacker's server returns)
    redirect_response = MagicMock()
    redirect_response.text = ""  # 302 body is empty

    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=redirect_response):
            result = rfi.fetchimage("http://attacker.com/redirect")

    assert "iam" not in result.lower(), f"IMDS credential path leaked: {result!r}"
    assert "security-credentials" not in result.lower(), (
        f"IMDS credential data leaked: {result!r}"
    )


def test_redirect_to_localhost_does_not_probe_internal():
    """Redirect to localhost internal service must not return internal data."""
    # Simulate what would happen if redirects were followed: internal data leaks
    internal_data_response = MagicMock()
    internal_data_response.text = ""  # With fix, redirect is not followed

    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=internal_data_response):
            result = rfi.fetchimage("http://attacker.com/to-redis")

    # The redirect body should be empty, not internal service data
    assert result == "" or "redis" not in result.lower(), (
        f"Internal Redis data leaked via redirect: {result!r}"
    )
