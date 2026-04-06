"""
Proof test for SSRF bypass via RFC 6598 Shared Address Space (100.64.0.0/10).

Vulnerability: The five-property blocklist (is_private, is_loopback, is_link_local,
is_reserved, is_multicast) all return False for 100.64.0.0/10 on Python 3.10,
allowing requests to Tailscale VPN nodes, AWS EKS pod networking, and CGNAT
addresses that share this range.

Fix: Replace the blocklist with a whitelist — only allow IPs where is_global is True.
"""

import socket
from unittest.mock import patch, MagicMock

import rfi


def test_rfc6598_lowest_address_blocked():
    """100.64.0.1 (start of RFC 6598 range) must be rejected — would pass old blocklist."""
    with patch.object(socket, "gethostbyname", return_value="100.64.0.1"):
        with patch("requests.get") as mock_get:
            result = rfi.fetchimage("http://internal-tailscale-node/api/secrets")
            mock_get.assert_not_called()
    assert result == "", f"RFC 6598 (100.64.0.1) request was allowed! Got: {result!r}"


def test_rfc6598_mid_range_blocked():
    """100.100.100.100 (mid-range RFC 6598) must be rejected."""
    with patch.object(socket, "gethostbyname", return_value="100.100.100.100"):
        with patch("requests.get") as mock_get:
            result = rfi.fetchimage("http://vpn-host/internal")
            mock_get.assert_not_called()
    assert result == "", f"RFC 6598 (100.100.100.100) request was allowed! Got: {result!r}"


def test_rfc6598_highest_address_blocked():
    """100.127.255.255 (end of RFC 6598 range) must be rejected."""
    with patch.object(socket, "gethostbyname", return_value="100.127.255.255"):
        with patch("requests.get") as mock_get:
            result = rfi.fetchimage("http://cgnat-host/")
            mock_get.assert_not_called()
    assert result == "", f"RFC 6598 (100.127.255.255) request was allowed! Got: {result!r}"


def test_rfc6598_is_safe_url_rejects_shared_space():
    """_is_safe_url must return False for RFC 6598 addresses."""
    with patch.object(socket, "gethostbyname", return_value="100.64.0.1"):
        assert rfi._is_safe_url("http://tailscale-node/") is False, (
            "_is_safe_url allowed RFC 6598 address 100.64.0.1"
        )


def test_rfc6598_rfivuln_endpoint_blocked():
    """The rfivuln endpoint must not proxy requests to RFC 6598 addresses."""
    with patch.object(socket, "gethostbyname", return_value="100.64.42.7"):
        with patch("requests.get") as mock_get:
            payload = {"imagelink": "http://internal-service:8000/api/sqlivuln"}
            response, status = rfi.rfivuln(payload)
            mock_get.assert_not_called()
    assert status == 200
    assert "internal" not in response["msg"].lower()


def test_public_ip_still_allowed():
    """A normal public IP must still be allowed through (regression guard)."""
    mock_response = MagicMock()
    mock_response.text = "image-data"
    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=mock_response):
            result = rfi.fetchimage("http://example.com/image.png")
    assert result == "image-data", f"Public IP was incorrectly blocked. Got: {result!r}"
