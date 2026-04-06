"""
Proof test for DNS rebinding SSRF TOCTOU bypass in rfi.py (fetchimage).

Attack vector (CVE class: DNS rebinding / TOCTOU):
  1. Attacker controls evil.com DNS with TTL=0.
  2. First resolution (validation): evil.com -> 93.184.216.34 (public) -> _is_safe_url passes.
  3. Attacker flips DNS:          evil.com -> 127.0.0.1 (loopback).
  4. Second resolution (request):  requests.get("http://evil.com/") -> 127.0.0.1 -> Redis.
  5. Internal service data leaks in the API response.

Fix: resolve hostname ONCE in fetchimage(), validate that IP, then replace the
hostname in the URL with the resolved IP before calling requests.get().  This
makes a second DNS lookup structurally impossible.
"""

import socket
from unittest.mock import MagicMock, patch

import rfi


def test_dns_rebinding_ip_is_pinned_in_request_url():
    """requests.get must receive the resolved IP in the URL, not the original hostname.

    On vulnerable code, requests.get is called with url="http://evil.com/..." which
    allows the OS to perform a second DNS lookup when establishing the TCP connection.
    With the fix the URL is replaced with the resolved IP (e.g. "http://93.184.216.34/"),
    so no second lookup is possible.

    This test FAILS on the vulnerable code and PASSES with the fix.
    """
    mock_response = MagicMock()
    mock_response.text = "ok"

    with patch.object(socket, "gethostbyname", return_value="93.184.216.34") as mock_resolve:
        with patch("requests.get", return_value=mock_response) as mock_get:
            rfi.fetchimage("http://evil.com/resource")

    assert mock_get.called, "requests.get should be called for a public URL"

    call_url = mock_get.call_args[1].get("url") or mock_get.call_args[0][0]

    # --- TOCTOU guard: hostname must NOT appear in the final URL ---
    assert "evil.com" not in call_url, (
        f"TOCTOU vulnerability: hostname 'evil.com' was passed to requests.get "
        f"as url={call_url!r}. An attacker can flip DNS between the validation "
        f"and the actual request to reach internal services."
    )

    # --- IP must be pinned ---
    assert "93.184.216.34" in call_url, (
        f"Expected the validated IP '93.184.216.34' to be pinned in the request "
        f"URL, but got: {call_url!r}"
    )

    # --- Exactly one DNS resolution ---
    assert mock_resolve.call_count == 1, (
        f"Expected exactly 1 DNS resolution to prevent TOCTOU, "
        f"got {mock_resolve.call_count}"
    )


def test_dns_rebinding_flipped_ip_never_reached():
    """Simulates the full rebinding attack: public IP on first call, loopback on second.

    On vulnerable code two resolutions happen:
      call 1 (inside _is_safe_url): evil.com -> 93.184.216.34  (passes check)
      call 2 (inside requests.get): evil.com -> 127.0.0.1      (reaches Redis)

    With the fix only one resolution happens and the IP is pinned, so the attacker's
    DNS flip has no effect.
    """
    resolutions = ["93.184.216.34", "127.0.0.1"]
    call_count = {"n": 0}

    def flipping_resolver(_):
        idx = min(call_count["n"], len(resolutions) - 1)
        call_count["n"] += 1
        return resolutions[idx]

    mock_response = MagicMock()
    mock_response.text = "INTERNAL_REDIS_DATA"

    with patch.object(socket, "gethostbyname", side_effect=flipping_resolver):
        with patch("requests.get", return_value=mock_response) as mock_get:
            rfi.fetchimage("http://evil.com:6379/")

    if mock_get.called:
        call_url = mock_get.call_args[1].get("url") or mock_get.call_args[0][0]
        assert "127.0.0.1" not in call_url, (
            f"DNS rebinding succeeded: the loopback IP appeared in the request URL "
            f"({call_url!r}), meaning internal Redis was reachable."
        )
        assert "evil.com" not in call_url, (
            "Hostname was not pinned — a real DNS client could have resolved to "
            "127.0.0.1 on the second lookup."
        )


def test_dns_rebinding_host_header_preserves_original_hostname():
    """When the IP is pinned, the Host header must still carry the original hostname.

    This ensures the HTTP request is well-formed (correct virtual hosting) while
    still preventing DNS rebinding.
    """
    mock_response = MagicMock()
    mock_response.text = "ok"

    with patch.object(socket, "gethostbyname", return_value="93.184.216.34"):
        with patch("requests.get", return_value=mock_response) as mock_get:
            rfi.fetchimage("http://evil.com/image.png")

    if mock_get.called:
        call_kwargs = mock_get.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert headers.get("Host") == "evil.com", (
            f"Expected Host header 'evil.com' to be preserved for correct HTTP "
            f"routing, got headers={headers!r}"
        )
