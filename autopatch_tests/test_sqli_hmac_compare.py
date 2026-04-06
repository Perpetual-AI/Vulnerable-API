"""
Proof test for the timing side-channel in sqli._verify_password (line 24).

Vulnerability: `dk.hex() == hash_hex` uses Python's non-constant-time string
comparison. Even after PBKDF2 always runs, the final hex comparison leaks partial
hash information via early-exit timing.

Fix: replaced with `hmac.compare_digest(dk.hex(), hash_hex)`, which is immune to
early-exit timing attacks.

These tests FAIL on the vulnerable code (== operator) and PASS on the fixed code
(hmac.compare_digest).
"""
import hashlib
import hmac
from unittest.mock import patch

from sqli import _verify_password


def _make_stored_hash(password: str) -> str:
    """Produce a valid PBKDF2 stored-hash string (salt_hex:hash_hex)."""
    import os
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + dk.hex()


def test_constant_time_compare_is_used():
    """
    FAILS on vulnerable code: _verify_password calls `==` not `hmac.compare_digest`,
    so the mock is never invoked and the assertion fails.

    PASSES on fixed code: hmac.compare_digest is called exactly once per
    _verify_password invocation.
    """
    stored = _make_stored_hash("correct_password")

    with patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as mock_cd:
        result = _verify_password(stored, "correct_password")

    assert result is True, "Password verification must return True for correct password"
    assert mock_cd.called, (
        "hmac.compare_digest was never called — "
        "the fix (replacing == with hmac.compare_digest) is not applied"
    )


def test_constant_time_compare_called_on_wrong_password():
    """
    Constant-time comparison must also be used when the password is wrong,
    not just when it's correct.
    """
    stored = _make_stored_hash("correct_password")

    with patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as mock_cd:
        result = _verify_password(stored, "wrong_password")

    assert result is False
    assert mock_cd.called, (
        "hmac.compare_digest was never called for a wrong password — "
        "timing side-channel is still present"
    )


def test_compare_digest_receives_hex_strings():
    """
    Verify the arguments passed to hmac.compare_digest are the hex-encoded digest
    and the stored hash hex — not raw bytes — confirming the correct call signature.
    """
    stored = _make_stored_hash("mypassword")
    _, hash_hex = stored.split(":")

    with patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as mock_cd:
        _verify_password(stored, "mypassword")

    call_args = mock_cd.call_args
    assert call_args is not None
    a, b = call_args.args
    assert isinstance(a, str), "First argument to compare_digest must be a str (hex)"
    assert isinstance(b, str), "Second argument to compare_digest must be a str (hex)"
    assert b == hash_hex, "compare_digest must receive the stored hash_hex as second arg"
