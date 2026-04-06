"""
Proof tests for the SSRF fix in rfi.py.

Attack vectors exercised:
  1. Cloud IMDS: http://169.254.169.254/... (link-local — AWS/GCP metadata)
  2. Loopback internal services: http://localhost:6379/ (Redis)
  3. RFC 1918 private ranges: http://10.0.0.1:9200/ (Elasticsearch)
  4. Non-HTTP scheme bypass: file:///etc/passwd
  5. verify=False removed — confirmed requests is called without it

On the vulnerable code fetchimage() would attempt each request with no
restrictions. The fix rejects all non-public destinations before connecting.
"""

import socket
from unittest.mock import patch, MagicMock

import rfi


# ---------------------------------------------------------------------------
# Attack-vector tests (would FAIL on the vulnerable code)
# ---------------------------------------------------------------------------

def test_cloud_imds_link_local_blocked():
    """169.254.169.254 (AWS IMDS) must be rejected without making a request."""
    with patch("requests.get") as mock_get:
        result = rfi.fetchimage("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        mock_get.assert_not_called()
    assert result == "", f"IMDS request was allowed! Got: {result!r}"


def test_loopback_localhost_blocked():
    """http://localhost/ must be rejected — loopback is internal."""
    with patch("requests.get") as mock_get:
        result = rfi.fetchimage("http://localhost:6379/")
        mock_get.assert_not_called()
    assert result == "", f"Localhost request was allowed! Got: {result!r}"


def test_rfc1918_10x_blocked():
    """http://10.x.x.x/ must be rejected (RFC 1918 class A)."""
    with patch.object(socket, "gethostbyname", return_value="10.0.0.1"):
        with patch("requests.get") as mock_get:
            result = rfi.fetchimage("http://internal.corp/")
            mock_get.assert_not_called()
    assert result == "", f"RFC 1918 (10.x) request was allowed! Got: {result!r}"


def test_rfc1918_192168_blocked():
    """http://192.168.x.x/ must be rejected (RFC 1918 class C)."""
    with patch.object(socket, "gethostbyname", return_value="192.168.1.100"):
        with patch("requests.get") as mock_get:
            result = rfi.fetchimage("http://internal.corp/")
            mock_get.assert_not_called()
    assert result == "", f"RFC 1918 (192.168.x) request was allowed! Got: {result!r}"


def test_file_scheme_blocked():
    """file:/// scheme must be rejected before any I/O."""
    with patch("requests.get") as mock_get:
        result = rfi.fetchimage("file:///etc/passwd")
        mock_get.assert_not_called()
    assert result == "", f"file:// scheme was allowed! Got: {result!r}"


def test_verify_false_not_used():
    """requests.get must not be called with verify=False."""
    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):  # example.com
        mock_response = MagicMock()
        mock_response.text = "hello"
        with patch("requests.get", return_value=mock_response) as mock_get:
            rfi.fetchimage("http://example.com/image.png")
            if mock_get.called:
                _, kwargs = mock_get.call_args
                assert kwargs.get("verify") is not False, "verify=False must not be passed to requests.get"


# ---------------------------------------------------------------------------
# Integration: rfivuln() endpoint-level checks
# ---------------------------------------------------------------------------

def test_rfivuln_imds_payload_blocked():
    """POST payload with IMDS URL must not expose metadata."""
    payload = {"imagelink": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    response, status = rfi.rfivuln(payload)
    assert status == 200
    assert "iam" not in response["msg"].lower(), (
        f"IMDS metadata leaked! Response: {response['msg'][:80]!r}"
    )


def test_rfivuln_localhost_payload_blocked():
    """POST payload targeting localhost must not probe internal services."""
    payload = {"imagelink": "http://localhost:9200/_cat/indices"}
    response, status = rfi.rfivuln(payload)
    assert status == 200
    assert "indices" not in response["msg"].lower(), (
        f"Internal service probed! Response: {response['msg'][:80]!r}"
    )


# ---------------------------------------------------------------------------
# Regression guard: safe public URLs still pass through _is_safe_url
# ---------------------------------------------------------------------------

def test_safe_url_public_ip_allowed():
    """A URL resolving to a public IP must pass _is_safe_url validation."""
    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        assert rfi._is_safe_url("https://example.com/image.png") is True


def test_unsafe_private_ip_rejected():
    """A URL resolving to a private IP must fail _is_safe_url."""
    with patch.object(socket, "gethostbyname", return_value="172.16.0.1"):
        assert rfi._is_safe_url("https://internal.corp/") is False
