"""
Proof tests for the Host Header Injection fix in hhi.py.

Attack vector: POST /api/hhivuln with a Host header pointing to an
attacker-controlled domain. On vulnerable code the attacker's domain
appears unvalidated in the href, enabling password-reset link poisoning.
On fixed code the Host is validated against ALLOWED_HOSTS; unknown
hosts receive a 400 and are never reflected into the response body.
"""

import flask
import pytest

from hhi import hhivuln, ALLOWED_HOSTS


@pytest.fixture
def app():
    return flask.Flask(__name__)


def test_malicious_host_is_rejected(app):
    """
    A Host header pointing to an attacker domain must be rejected (400).
    This test FAILS on the vulnerable code (returns 200 with attacker href)
    and PASSES on the fixed code (returns 400, attacker domain not used).
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "attacker.com"},
    ):
        result, status = hhivuln(None)
        assert status == 400, (
            f"Expected 400 for untrusted Host, got {status}. "
            f"Response: {result!r}"
        )
        assert "attacker.com" not in result.get("msg", ""), (
            "Attacker domain must not appear in the response body"
        )


def test_malicious_host_not_in_href(app):
    """
    Even if status were 200, the attacker domain must not appear in any href.
    Belt-and-suspenders check that the domain is never reflected.
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "evil.attacker.com"},
    ):
        result, _ = hhivuln(None)
        msg = result.get("msg", "")
        assert "evil.attacker.com" not in msg, (
            f"Attacker domain reflected in response! Got: {msg!r}"
        )


def test_allowed_host_succeeds(app):
    """An allowed Host header returns 200 and contains the expected href."""
    allowed = ALLOWED_HOSTS[0]
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": allowed},
    ):
        result, status = hhivuln(None)
        assert status == 200
        assert allowed in result["msg"]


def test_password_reset_poisoning_scenario(app):
    """
    Simulates the full poisoning scenario: attacker injects Host header to
    redirect a password-reset link to their server.
    The fix must reject the request before the attacker domain enters the body.
    """
    attacker_host = "steal-tokens.attacker.com"
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": attacker_host},
    ):
        result, _ = hhivuln(None)
        # Must not build a link to the attacker's server
        assert attacker_host not in result.get("msg", ""), (
            f"Password-reset link poisoning succeeded! href contains attacker host. "
            f"Got: {result!r}"
        )
