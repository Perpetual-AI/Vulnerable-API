"""
Proof test: placeholder domain 'yourdomain.com' removed from ALLOWED_HOSTS.

Attack vector: an attacker who controls yourdomain.com sends
  Host: yourdomain.com
The vulnerable code allowed this through the allowlist check and reflected
the domain into the href — enabling password-reset link poisoning.

On the fixed code yourdomain.com is no longer in ALLOWED_HOSTS, so the
request is rejected with 400 and the domain never appears in the response.
"""

import flask
import pytest

from hhi import hhivuln, ALLOWED_HOSTS


@pytest.fixture
def app():
    return flask.Flask(__name__)


def test_placeholder_domain_not_in_allowlist():
    """yourdomain.com must be absent from ALLOWED_HOSTS after the fix."""
    assert "yourdomain.com" not in ALLOWED_HOSTS, (
        "Placeholder domain 'yourdomain.com' must be removed from ALLOWED_HOSTS. "
        "An attacker who controls this domain can bypass the allowlist."
    )


def test_yourdomain_host_is_rejected(app):
    """
    A request with Host: yourdomain.com must be rejected (400).

    On vulnerable code: 'yourdomain.com' is in ALLOWED_HOSTS → returns 200
    with a link pointing to the attacker-controlled domain.
    On fixed code: 'yourdomain.com' is absent → returns 400.
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "yourdomain.com"},
    ):
        result, status = hhivuln(None)
        assert status == 400, (
            f"Expected 400 for placeholder domain, got {status}. "
            f"yourdomain.com passed the allowlist — fix is not applied."
        )
        assert "yourdomain.com" not in result.get("msg", ""), (
            "Placeholder domain must not be reflected in the response body."
        )


def test_yourdomain_href_not_reflected(app):
    """Belt-and-suspenders: yourdomain.com must never appear in an href."""
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "yourdomain.com"},
    ):
        result, _ = hhivuln(None)
        msg = result.get("msg", "")
        assert "yourdomain.com" not in msg, (
            f"Placeholder domain reflected in response href! Got: {msg!r}"
        )


def test_legitimate_hosts_still_work(app):
    """Removing yourdomain.com must not break legitimate allowed hosts."""
    for host in ALLOWED_HOSTS:
        with app.test_request_context(
            "/api/hhivuln",
            method="POST",
            headers={"Host": host},
        ):
            result, status = hhivuln(None)
            assert status == 200, (
                f"Legitimate host '{host}' was incorrectly rejected after fix."
            )
            assert host in result.get("msg", ""), (
                f"Legitimate host '{host}' not reflected in approved response."
            )
